// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Syscall dispatch: routes incoming requests to the appropriate handler.

pub mod child_runner;
pub mod fork_with_policy;
pub mod ipc_connect;
pub mod ipc_send;
pub mod policy_propose;
pub mod policy_read;
pub mod ps;
pub mod request_port;
pub mod revoke_policy;
pub mod signal;

use super::audit;
use super::auth::{PeerCred, TokenKey};
use super::gid::GidAllocator;
use super::policy::MediationPolicy;
use super::policy::inherit;
use super::policy::trust_spec::TrustSpec;
use super::proto::{Method, Request, Response};
use super::registry::UidPolicyRegistry;
use super::store::MediatorStore;
use super::store::queries;
use super::uid::UidAllocator;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// Shared context available to all syscall handlers.
pub struct SyscallContext {
    pub store: MediatorStore,
    pub token_key: TokenKey,
    /// Approved policies keyed by policy_name.
    pub policies: Arc<tokio::sync::RwLock<HashMap<String, MediationPolicy>>>,
    /// Approval bridge base URL. When `None`, proposals auto-approve.
    pub approval_bridge_url: Option<String>,
    /// HMAC-SHA256 secret for signing webhook requests to the approval bridge.
    /// When `None`, requests are sent without a signature.
    pub webhook_secret: Option<String>,
    /// Trust specification for taint analysis. When `None`, taint analysis is skipped.
    pub trust_spec: Option<Arc<TrustSpec>>,
    /// Monotonic UID allocator for workflow isolation.
    pub uid_allocator: Arc<UidAllocator>,
    /// GID allocator mapping policy names to group IDs.
    pub gid_allocator: Arc<GidAllocator>,
    /// UID→policy registry shared with the proxy.
    pub uid_policy_registry: UidPolicyRegistry,
    /// Active IPC stream registry for lifecycle management.
    pub stream_registry: ipc_connect::StreamRegistry,
}

/// Sign a request body with HMAC-SHA256 and POST it to the bridge.
pub(crate) async fn post_to_bridge(
    client: &reqwest::Client,
    url: &str,
    payload: &serde_json::Value,
    webhook_secret: Option<&str>,
) -> Result<(), String> {
    let body = serde_json::to_vec(payload).unwrap_or_default();
    let mut req = client.post(url).header("Content-Type", "application/json");

    if let Some(secret) = webhook_secret {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&body);
        let signature = hex::encode(mac.finalize().into_bytes());
        req = req.header("X-OpenShell-Signature", signature);
    }

    req.body(body)
        .send()
        .await
        .map_err(|e| format!("failed to reach approval bridge: {e}"))?
        .error_for_status()
        .map_err(|e| format!("approval bridge rejected webhook: {e}"))?;

    Ok(())
}

/// Dispatch a request to the appropriate syscall handler.
///
/// Every call is audit-logged regardless of outcome.
pub async fn dispatch(ctx: &SyscallContext, req: &Request, _peer: &PeerCred) -> Response {
    let pool = ctx.store.pool();

    // Resolve the caller's workflow token and policy.
    let (caller_token, caller_policy) =
        match resolve_caller(pool, &ctx.policies, &req.workflow_token).await {
            Ok(pair) => pair,
            Err(resp) => {
                audit::audit_syscall(
                    pool,
                    "unknown",
                    &req.workflow_token,
                    &method_name(req.method),
                    &req.params,
                    "denied",
                    "none",
                    Some("invalid token"),
                )
                .await;
                return resp;
            }
        };

    let method = method_name(req.method);
    debug!(method = %method, workflow_id = %caller_token.workflow_id, "dispatching syscall");

    // Init's mutating syscalls (fork, ipc, signal, request_port, revoke) used to
    // go through a per-call operator approval gate. Removed: init was approved at
    // deployment time and the gate just produced noise — and double-prompted on
    // policy_propose, which has its own approval round-trip in handle_policy_propose.
    // The only operator gate that remains is policy_propose itself, where new
    // capabilities are actually being requested.

    let response = match req.method {
        Method::Ps => {
            match ps::handle_ps(pool, &caller_token, &caller_policy.allowed_ipc_targets).await {
                Ok(entries) => Response::ok(
                    req.id.clone(),
                    serde_json::to_value(&entries).unwrap_or_default(),
                ),
                Err(e) => Response::err(req.id.clone(), "EINTERNAL", e),
            }
        }
        Method::ForkWithPolicy => {
            let params: fork_with_policy::ForkParams =
                match serde_json::from_value(req.params.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                    }
                };
            match fork_with_policy::handle_fork_with_policy(
                pool,
                &ctx.token_key,
                &ctx.policies,
                &caller_token,
                &caller_policy,
                params,
                &ctx.uid_allocator,
                &ctx.gid_allocator,
                &ctx.uid_policy_registry,
            )
            .await
            {
                Ok(result) => Response::ok(
                    req.id.clone(),
                    serde_json::to_value(&result).unwrap_or_default(),
                ),
                Err(e) => Response::err(req.id.clone(), "EPERM", e),
            }
        }
        Method::IpcSend => {
            let params: ipc_send::IpcSendParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                }
            };
            match ipc_send::handle_ipc_send(
                pool,
                &ctx.policies,
                &caller_token,
                &caller_policy,
                params,
            )
            .await
            {
                Ok(v) => Response::ok(req.id.clone(), v),
                Err(e) => Response::err(req.id.clone(), "EPERM", e),
            }
        }
        Method::IpcConnect => {
            let params: ipc_connect::IpcConnectParams =
                match serde_json::from_value(req.params.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                    }
                };
            match ipc_connect::handle_ipc_connect(
                pool,
                &ctx.policies,
                &caller_token,
                &caller_policy,
                params,
                &ctx.stream_registry,
            )
            .await
            {
                Ok(v) => Response::ok(req.id.clone(), v),
                Err(e) => Response::err(req.id.clone(), "EPERM", e),
            }
        }
        Method::Signal => {
            let params: signal::SignalParams = match serde_json::from_value(req.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                }
            };
            match signal::handle_signal(pool, &ctx.policies, &caller_token, &caller_policy, params)
                .await
            {
                Ok(v) => Response::ok(req.id.clone(), v),
                Err(e) => Response::err(req.id.clone(), "EPERM", e),
            }
        }
        Method::RequestPort => {
            match request_port::handle_request_port(pool, &caller_token, &caller_policy).await {
                Ok(v) => Response::ok(req.id.clone(), v),
                Err(e) => Response::err(req.id.clone(), "ENOSPC", e),
            }
        }
        Method::PolicyPropose => {
            let params: policy_propose::PolicyProposeParams =
                match serde_json::from_value(req.params.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                    }
                };
            match policy_propose::handle_policy_propose(
                pool,
                &ctx.policies,
                params,
                ctx.approval_bridge_url.as_deref(),
                ctx.webhook_secret.as_deref(),
                ctx.trust_spec.as_ref(),
            )
            .await
            {
                Ok(v) => Response::ok(req.id.clone(), v),
                Err(e) => Response::err(req.id.clone(), "ENOPRIV", e),
            }
        }
        Method::RevokePolicy => {
            let params: revoke_policy::RevokePolicyParams =
                match serde_json::from_value(req.params.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                    }
                };
            match revoke_policy::handle_revoke_policy(
                pool,
                &ctx.policies,
                &caller_policy.policy_name,
                params,
            )
            .await
            {
                Ok(v) => Response::ok(req.id.clone(), v),
                Err(e) => Response::err(req.id.clone(), "EPERM", e),
            }
        }
        Method::PolicyList => {
            let guard = ctx.policies.read().await;
            let entries = policy_read::handle_policy_list(&guard, &caller_policy);
            Response::ok(
                req.id.clone(),
                serde_json::to_value(&entries).unwrap_or_default(),
            )
        }
        Method::PolicyGet => {
            let params: policy_read::PolicyGetParams =
                match serde_json::from_value(req.params.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        return Response::err(req.id.clone(), "EINVAL", format!("bad params: {e}"));
                    }
                };
            let guard = ctx.policies.read().await;
            match policy_read::handle_policy_get(&guard, &caller_policy, params) {
                Ok(p) => Response::ok(
                    req.id.clone(),
                    serde_json::to_value(&p).unwrap_or_default(),
                ),
                Err(e) => Response::err(req.id.clone(), "ENOENT", e),
            }
        }
    };

    let result_str = if response.ok { "allowed" } else { "denied" };
    audit::audit_syscall(
        pool,
        &caller_token.workflow_id,
        &req.workflow_token,
        &method,
        &req.params,
        result_str,
        &caller_token.policy_name,
        None,
    )
    .await;

    response
}

/// Look up the caller's token and associated policy.
async fn resolve_caller(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    token_str: &str,
) -> Result<(super::store::schema::WorkflowToken, MediationPolicy), Response> {
    let token = queries::get_token(pool, token_str)
        .await
        .map_err(|e| Response::err(String::new(), "EINTERNAL", format!("store error: {e}")))?
        .ok_or_else(|| Response::err(String::new(), "EPERM", "invalid workflow token"))?;

    let policies_guard = policies.read().await;
    let policy = policies_guard
        .get(&token.policy_name)
        .cloned()
        .ok_or_else(|| {
            Response::err(
                String::new(),
                "EPERM",
                format!("no approved policy named '{}'", token.policy_name),
            )
        })?;

    Ok((token, policy))
}

/// If the caller's token has `inherited_from`, look up the parent's policy.
async fn resolve_parent_policy(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    caller_token: &super::store::schema::WorkflowToken,
) -> Option<MediationPolicy> {
    let parent_token_str = caller_token.inherited_from.as_deref()?;
    let parent_token = queries::get_token(pool, parent_token_str).await.ok()??;
    let guard = policies.read().await;
    guard.get(&parent_token.policy_name).cloned()
}

fn method_name(m: Method) -> String {
    serde_json::to_value(m)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{m:?}"))
}
