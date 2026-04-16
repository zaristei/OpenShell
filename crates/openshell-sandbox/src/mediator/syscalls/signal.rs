// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `signal` syscall: send a control signal to another workflow.

use crate::mediator::gid;
use crate::mediator::namespace::iptables;
use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::validate::fnmatch;
use crate::mediator::registry::UidPolicyRegistry;
use crate::mediator::store::queries;
use crate::mediator::store::schema::WorkflowToken;
use crate::mediator::audit;
use super::ipc_connect::StreamRegistry;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing::{info, warn};

/// Parameters for `signal`.
#[derive(Debug, serde::Deserialize)]
pub struct SignalParams {
    pub target_workflow_id: String,
    /// One of `"term"`, `"kill"`, `"stop"`, `"cont"`.
    pub signal: String,
}

/// Execute the `signal` syscall.
///
/// # Errors
///
/// Returns an error if the signal is not allowed by policy or the target
/// doesn't exist.
pub async fn handle_signal(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    _caller_token: &WorkflowToken,
    caller_policy: &MediationPolicy,
    params: SignalParams,
) -> Result<serde_json::Value, String> {
    // Look up target workflow.
    let target_wf = queries::get_workflow(pool, &params.target_workflow_id)
        .await
        .map_err(|e| format!("store error: {e}"))?
        .ok_or_else(|| format!("workflow '{}' not found", params.target_workflow_id))?;

    // Look up target's policy name for validation.
    let guard = policies.read().await;
    let target_policy_name = guard
        .get(&target_wf.policy_name)
        .map(|p| p.policy_name.clone())
        .ok_or_else(|| format!("target policy '{}' not found", target_wf.policy_name))?;
    drop(guard);

    // Find matching signal target in caller's policy.
    let signal_target = caller_policy
        .allowed_signal_targets
        .iter()
        .find(|st| fnmatch(&st.policy_name, &target_policy_name))
        .ok_or_else(|| {
            format!(
                "caller policy '{}' has no signal permission for '{}'",
                caller_policy.policy_name, target_policy_name
            )
        })?;

    // Check signal type is in the allowed list.
    if !signal_target.signals.contains(&params.signal) {
        return Err(format!(
            "signal '{}' not allowed for target '{}' (allowed: {:?})",
            params.signal, target_policy_name, signal_target.signals
        ));
    }

    // Send the signal.
    send_signal(target_wf.root_pid, &params.signal)?;

    // For term/kill, also tear down the workflow.
    if params.signal == "term" || params.signal == "kill" {
        info!(
            target = %params.target_workflow_id,
            signal = %params.signal,
            "tearing down workflow after signal"
        );
        teardown_uid_workflow(
            pool,
            &params.target_workflow_id,
            &target_wf.workflow_token,
            target_wf.uid.map(|u| u as u32),
            None, // uid registry passed from dispatch when available
            None, // stream registry passed from dispatch when available
        )
        .await;
    }

    Ok(serde_json::json!({"ack": true}))
}

/// Tear down a UID-isolated workflow.
///
/// 1. Kill all processes running as this UID (if UID is known).
/// 2. Remove per-UID iptables rules.
/// 3. Remove UID from group.
/// 4. Clean up tables (workflow, token, ports).
/// 5. Audit log the teardown.
pub async fn teardown_uid_workflow(
    pool: &SqlitePool,
    workflow_id: &str,
    workflow_token: &str,
    uid: Option<u32>,
    registry: Option<&UidPolicyRegistry>,
    stream_registry: Option<&StreamRegistry>,
) {
    // Cancel any active IPC streams involving this workflow.
    if let Some(sr) = stream_registry {
        sr.teardown_workflow(workflow_id).await;
    }

    if let Some(uid) = uid {
        // Remove from proxy registry.
        if let Some(reg) = registry {
            reg.remove(uid);
        }
        // Kill all processes running as this UID.
        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("pkill")
                .args(["-U", &uid.to_string()])
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    info!(workflow_id, uid, "killed all processes for UID");
                }
                _ => {
                    warn!(workflow_id, uid, "pkill -U failed (processes may already be dead)");
                }
            }
        }

        // Remove iptables rules.
        iptables::remove_uid_rules(uid);

        // Remove UID from group (best effort).
        gid::remove_uid_from_group(uid, 0);
    }

    // Clean up store tables.
    if let Err(e) = queries::release_ports(pool, workflow_token).await {
        warn!(workflow_id, %e, "failed to release ports");
    }
    if let Err(e) = queries::delete_workflow(pool, workflow_id).await {
        warn!(workflow_id, %e, "failed to delete workflow");
    }
    if let Err(e) = queries::delete_token(pool, workflow_token).await {
        warn!(workflow_id, %e, "failed to delete token");
    }

    // Audit the teardown.
    audit::audit_syscall(
        pool,
        workflow_id,
        workflow_token,
        "teardown",
        &serde_json::json!({"uid": uid}),
        "allowed",
        "system",
        Some("UID workflow teardown"),
    )
    .await;

    info!(workflow_id, "workflow torn down");
}

/// Map signal name to OS signal and send it.
#[cfg(target_os = "linux")]
fn send_signal(pid: i64, signal: &str) -> Result<(), String> {
    let sig = match signal {
        "term" => nix::sys::signal::Signal::SIGTERM,
        "kill" => nix::sys::signal::Signal::SIGKILL,
        "stop" => nix::sys::signal::Signal::SIGSTOP,
        "cont" => nix::sys::signal::Signal::SIGCONT,
        other => return Err(format!("unknown signal: {other}")),
    };

    let nix_pid = nix::unistd::Pid::from_raw(pid as i32);
    nix::sys::signal::kill(nix_pid, sig).map_err(|e| format!("kill({pid}, {signal}): {e}"))
}

/// Non-Linux stub: just log and succeed.
#[cfg(not(target_os = "linux"))]
fn send_signal(pid: i64, signal: &str) -> Result<(), String> {
    warn!(pid, signal, "signal sending stubbed (not Linux)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::{MediationPolicy, SignalTarget};
    use crate::mediator::store::MediatorStore;
    use crate::mediator::store::queries::{insert_token, insert_workflow};
    use crate::mediator::store::schema::{ActiveWorkflow, WorkflowToken};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn caller_policy() -> MediationPolicy {
        MediationPolicy {
            policy_name: "parent_v1".into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![SignalTarget {
                policy_name: "child_*".into(),
                signals: vec!["term".into(), "kill".into()],
            }],
            allowed_launch_commands: vec![],
        }
    }

    fn child_policy() -> MediationPolicy {
        MediationPolicy {
            policy_name: "child_v1".into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        }
    }

    async fn setup() -> (MediatorStore, Arc<RwLock<HashMap<String, MediationPolicy>>>) {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let pool = store.pool();

        insert_token(
            pool,
            &WorkflowToken {
                token: "tok_caller".into(),
                workflow_id: "wf_caller".into(),
                pid: 1,
                policy_name: "parent_v1".into(),
                inherited_from: None,
                created_at: "t".into(),
                uid: None,
            },
        )
        .await
        .unwrap();

        insert_token(
            pool,
            &WorkflowToken {
                token: "tok_target".into(),
                workflow_id: "wf_target".into(),
                pid: 99999,
                policy_name: "child_v1".into(),
                inherited_from: None,
                created_at: "t".into(),
                uid: Some(100_000),
            },
        )
        .await
        .unwrap();

        insert_workflow(
            pool,
            &ActiveWorkflow {
                workflow_id: "wf_target".into(),
                policy_name: "child_v1".into(),
                root_pid: 99999,
                namespace_id: "uid_100000".into(),
                workflow_token: "tok_target".into(),
                parent_workflow_id: None,
                started_at: "t".into(),
                uid: Some(100_000),
            },
        )
        .await
        .unwrap();

        let mut policies = HashMap::new();
        policies.insert("parent_v1".into(), caller_policy());
        policies.insert("child_v1".into(), child_policy());

        (store, Arc::new(RwLock::new(policies)))
    }

    #[tokio::test]
    async fn signal_allowed() {
        let (store, policies) = setup().await;
        let caller_tok = WorkflowToken {
            token: "tok_caller".into(),
            workflow_id: "wf_caller".into(),
            pid: 1,
            policy_name: "parent_v1".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };

        let result = handle_signal(
            store.pool(),
            &policies,
            &caller_tok,
            &caller_policy(),
            SignalParams {
                target_workflow_id: "wf_target".into(),
                signal: "term".into(),
            },
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn signal_disallowed_type() {
        let (store, policies) = setup().await;
        let caller_tok = WorkflowToken {
            token: "tok_caller".into(),
            workflow_id: "wf_caller".into(),
            pid: 1,
            policy_name: "parent_v1".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };

        let result = handle_signal(
            store.pool(),
            &policies,
            &caller_tok,
            &caller_policy(),
            SignalParams {
                target_workflow_id: "wf_target".into(),
                signal: "stop".into(),
            },
        )
        .await;

        assert!(result.unwrap_err().contains("not allowed"));
    }

    #[tokio::test]
    async fn signal_disallowed_target() {
        let (store, policies) = setup().await;

        let no_signal_policy = MediationPolicy {
            policy_name: "parent_v1".into(),
            rationale: "t".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        };

        let caller_tok = WorkflowToken {
            token: "tok_caller".into(),
            workflow_id: "wf_caller".into(),
            pid: 1,
            policy_name: "parent_v1".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };

        let result = handle_signal(
            store.pool(),
            &policies,
            &caller_tok,
            &no_signal_policy,
            SignalParams {
                target_workflow_id: "wf_target".into(),
                signal: "term".into(),
            },
        )
        .await;

        assert!(result.unwrap_err().contains("no signal permission"));
    }
}
