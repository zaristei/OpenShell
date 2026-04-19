// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `fork_with_policy` syscall: spawn a child workflow with UID-based isolation.

use crate::mediator::auth::TokenKey;
use crate::mediator::gid;
use crate::mediator::namespace::iptables;
use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::convert;
use crate::mediator::policy::trust_spec::PolicyTaint;
use crate::mediator::policy::validate::fnmatch;
use crate::mediator::registry::UidPolicyRegistry;
use crate::mediator::store::queries;
use crate::mediator::store::schema::{ActiveWorkflow, WorkflowToken};
use crate::mediator::uid::UidAllocator;
use crate::mediator::gid::GidAllocator;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

/// Parameters for `fork_with_policy`.
#[derive(Debug, serde::Deserialize)]
pub struct ForkParams {
    pub workflow_id: String,
    pub policy_name: String,
    #[serde(default)]
    pub command: Vec<String>,
}

/// Successful result of `fork_with_policy`.
///
/// `inherited_from` is retained in the wire schema for backward compatibility
/// with stored `WorkflowToken` rows and external clients that deserialize it,
/// but the simplified mediator never populates it — every child policy
/// subset-checks against the live sandbox policy directly, not a parent.
#[derive(Debug, serde::Serialize)]
pub struct ForkResult {
    pub uid: u32,
    pub gid: u32,
    pub workflow_token: String,
    pub inherited_from: Option<String>,
}

/// Execute the `fork_with_policy` syscall.
///
/// Allocates a UID and GID for the new workflow, sets up iptables rules,
/// creates instance directories, and registers the workflow in the store.
///
/// # Errors
///
/// Returns an error string on validation failure or setup failure.
pub async fn handle_fork_with_policy(
    pool: &SqlitePool,
    token_key: &TokenKey,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    caller_token: &WorkflowToken,
    caller_policy: &MediationPolicy,
    params: ForkParams,
    uid_allocator: &UidAllocator,
    gid_allocator: &GidAllocator,
    uid_policy_registry: &UidPolicyRegistry,
    proxy_addr: std::net::SocketAddr,
) -> Result<ForkResult, String> {
    // 1. Validate the target policy exists.
    let policies_guard = policies.read().await;
    let _target_policy = policies_guard
        .get(&params.policy_name)
        .ok_or_else(|| format!("policy '{}' not found", params.policy_name))?;

    // 2. Check caller's allowed_child_policies (fnmatch on patterns).
    //
    // Every entry in caller_policy.allowed_child_policies is a glob pattern
    // (e.g. "web_fetcher_v*") matched against the target policy's name.
    // Missing match → auto-deny; the caller's policy authoring is the gate
    // that decides what children this policy-class may spawn.
    let allowed = caller_policy
        .allowed_child_policies
        .iter()
        .any(|pattern| fnmatch(pattern, &params.policy_name));
    if !allowed {
        return Err(format!(
            "policy '{}' is not in caller's allowed_child_policies (caller_policy='{}', patterns={:?})",
            params.policy_name, caller_policy.policy_name, caller_policy.allowed_child_policies
        ));
    }

    // 3. Validate command against allowed_launch_commands.
    if !_target_policy.allowed_launch_commands.is_empty() && !params.command.is_empty() {
        let command_str = params.command.join(" ");
        let allowed = _target_policy
            .allowed_launch_commands
            .iter()
            .any(|pattern| fnmatch(pattern, &command_str));
        if !allowed {
            return Err(format!(
                "command '{}' does not match any allowed_launch_commands in policy '{}'",
                command_str, params.policy_name
            ));
        }
    }

    // Clone external mounts before releasing the lock.
    let target_mounts = _target_policy.external_mounts.clone();
    drop(policies_guard);

    // 4. Allocate UID and GID.
    let uid = uid_allocator.allocate();
    let policy_gid = gid_allocator.ensure_gid(&params.policy_name);

    // 5. Set up UID-to-group mapping.
    gid::add_uid_to_group(uid, policy_gid);

    // 6. Install per-UID iptables rules.
    iptables::install_uid_rules(uid, proxy_addr);

    // 7. Create instance directory with setgid.
    setup_instance_dir(&params.policy_name, &params.workflow_id, policy_gid, &target_mounts);

    // 8. Generate workflow token.
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let token_value = token_key.generate(&params.workflow_id, uid, &timestamp);

    // Inheritance was dropped; the column is retained in the DB for schema
    // compat but always NULL in the simplified mediator.
    let _ = caller_token;
    let inherited_from: Option<String> = None;

    // Save policy_name before it's moved into the workflow record.
    let policy_name_for_spawn = params.policy_name.clone();

    // 9. Insert into workflow_tokens.
    let wf_token = WorkflowToken {
        token: token_value.as_str().into(),
        workflow_id: params.workflow_id.clone(),
        pid: i64::from(uid), // UID used in place of PID for identification
        policy_name: params.policy_name.clone(),
        inherited_from: inherited_from.clone(),
        created_at: timestamp,
        uid: Some(i64::from(uid)),
    };
    queries::insert_token(pool, &wf_token)
        .await
        .map_err(|e| format!("failed to insert token: {e}"))?;

    // 10. Insert into active_workflows.
    let workflow = ActiveWorkflow {
        workflow_id: params.workflow_id.clone(),
        policy_name: params.policy_name,
        root_pid: i64::from(uid), // UID as the identifier
        namespace_id: format!("uid_{uid}"), // Legacy field, stores UID reference
        workflow_token: token_value.as_str().into(),
        parent_workflow_id: Some(caller_token.workflow_id.clone()),
        started_at: wf_token.created_at.clone(),
        uid: Some(i64::from(uid)),
    };
    queries::insert_workflow(pool, &workflow)
        .await
        .map_err(|e| format!("failed to insert workflow: {e}"))?;

    // 11. Register UID→policy in the proxy registry.
    //
    // The child's own policy is authoritative — inheritance was removed and
    // every proposed policy subset-checks against the sandbox directly at
    // propose time, so there's nothing to merge here.
    let _ = &caller_policy;
    {
        let policies_guard = policies.read().await;
        if let Some(cp) = policies_guard.get(&workflow.policy_name) {
            let net_policy = convert::from_mediation_policy(cp, &params.workflow_id);
            uid_policy_registry.insert(uid, net_policy);
        }
    }

    // 12. Materialize pre-computed compromised resources from policy taint.
    materialize_compromises(pool, &workflow.policy_name, &params.workflow_id).await;

    // 13. Spawn the child process under the allocated UID.
    let mediator_socket = std::env::var("MEDIATOR_SOCKET")
        .unwrap_or_else(|_| "/sandbox/.mediator/mediator.sock".into());
    let instance_dir = format!("/sandbox/.mediator/workflows/{}", params.workflow_id);
    match super::child_runner::spawn_child_process(
        uid,
        policy_gid,
        &params.workflow_id,
        &policy_name_for_spawn,
        token_value.as_str(),
        &mediator_socket,
        &instance_dir,
        &params.command,
    ) {
        Ok(pid) => {
            info!(
                workflow_id = %params.workflow_id,
                uid,
                gid = policy_gid,
                pid,
                "forked workflow with UID isolation + child process"
            );
        }
        Err(e) => {
            // Process spawn failure is non-fatal — the workflow exists in the DB
            // and the parent can still IPC with it (messages queue). Log and continue.
            warn!(
                workflow_id = %params.workflow_id,
                uid,
                %e,
                "forked workflow but child process spawn failed (non-fatal)"
            );
        }
    }

    Ok(ForkResult {
        uid,
        gid: policy_gid,
        workflow_token: token_value.into_string(),
        inherited_from,
    })
}

/// Materialize pre-computed compromised resources from the policy_taint table.
///
/// Reads the `PolicyTaint` stored at propose time and bulk-inserts the
/// `pending_compromises` into the `compromised_resources` table.
async fn materialize_compromises(pool: &SqlitePool, policy_name: &str, workflow_id: &str) {
    let taint_json = match queries::get_policy_taint(pool, policy_name).await {
        Ok(Some(json)) => json,
        _ => return,
    };

    let taint: PolicyTaint = match serde_json::from_str(&taint_json) {
        Ok(t) => t,
        Err(e) => {
            warn!(policy_name, %e, "failed to parse stored policy taint");
            return;
        }
    };

    if taint.pending_compromises.is_empty() {
        return;
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let resources: Vec<queries::CompromisedResource> = taint
        .pending_compromises
        .iter()
        .map(|pc| queries::CompromisedResource {
            resource_path: pc.resource_path.clone(),
            resource_type: pc.resource_type.clone(),
            compromise_type: pc.compromise_type.clone(),
            data_type: pc.data_type.clone(),
            caused_by: policy_name.to_string(),
            via_path: pc.via_path.clone(),
            workflow_id: Some(workflow_id.to_string()),
            created_at: now.clone(),
        })
        .collect();

    if let Err(e) = queries::insert_compromised_resources(pool, &resources).await {
        warn!(
            policy_name,
            workflow_id, %e, "failed to materialize compromised resources"
        );
    } else {
        info!(
            policy_name,
            workflow_id,
            count = resources.len(),
            "materialized compromised resources"
        );
    }
}

/// Set up filesystem permissions for a workflow.
///
/// 1. Creates the instance directory (if OPENSHELL_DATA_ROOT is set)
/// 2. Enforces `external_mounts` — sets group permissions on each declared
///    path so the child's GID can access them based on the mode field.
fn setup_instance_dir(
    policy_name: &str,
    workflow_id: &str,
    gid: u32,
    external_mounts: &[crate::mediator::policy::ExternalMount],
) {
    if let Some(data_root) = std::env::var_os("OPENSHELL_DATA_ROOT") {
        let instance_dir = std::path::PathBuf::from(data_root)
            .join(policy_name)
            .join("instances")
            .join(workflow_id);

        if let Err(e) = std::fs::create_dir_all(&instance_dir) {
            tracing::warn!("failed to create instance dir {}: {e}", instance_dir.display());
            return;
        }

        let _ = std::fs::create_dir_all(instance_dir.join("inbox"));

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = std::fs::metadata(&instance_dir);
            if let Ok(m) = metadata {
                let mode = m.permissions().mode() | 0o2770;
                let _ = std::fs::set_permissions(
                    &instance_dir,
                    std::fs::Permissions::from_mode(mode),
                );
            }

            unsafe {
                let path_c = std::ffi::CString::new(
                    instance_dir.to_str().unwrap_or_default(),
                )
                .unwrap_or_default();
                libc::chown(path_c.as_ptr(), u32::MAX, gid);
            }
        }
    }

    // Enforce external_mounts: set group ownership and permissions on each
    // declared path so the child's GID can access them.
    #[cfg(target_os = "linux")]
    {
        for mount in external_mounts {
            let path = std::path::Path::new(&mount.path);

            // Create the path if it doesn't exist and mode includes write.
            if mount.mode.contains('w') {
                if let Err(e) = std::fs::create_dir_all(path) {
                    tracing::warn!(
                        path = %mount.path, %e,
                        "failed to create mount path"
                    );
                    continue;
                }
            }

            if !path.exists() {
                tracing::warn!(
                    path = %mount.path,
                    "external_mount path does not exist, skipping"
                );
                continue;
            }

            // chgrp to the child's GID.
            unsafe {
                let path_c = std::ffi::CString::new(mount.path.as_str())
                    .unwrap_or_default();
                if libc::chown(path_c.as_ptr(), u32::MAX, gid) != 0 {
                    tracing::warn!(
                        path = %mount.path, gid,
                        "failed to chgrp mount path"
                    );
                    continue;
                }
            }

            // Set group permissions based on mode.
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::metadata(path) {
                let current = m.permissions().mode();
                let group_bits = match mount.mode.as_str() {
                    "r" => 0o040,          // group read
                    "rw" => 0o060,         // group read + write
                    "rx" => 0o050,         // group read + execute
                    "rwx" => 0o070,        // group read + write + execute
                    "w" => 0o020,          // group write
                    _ => 0o040,            // default: group read
                };
                let new_mode = (current & !0o070) | group_bits; // replace group bits
                let _ = std::fs::set_permissions(
                    path,
                    std::fs::Permissions::from_mode(new_mode),
                );
                tracing::info!(
                    path = %mount.path,
                    mode = %mount.mode,
                    gid,
                    "enforced external_mount permissions"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::auth::TokenKey;
    use crate::mediator::policy::MediationPolicy;
    use crate::mediator::store::MediatorStore;
    use crate::mediator::store::queries::insert_token;
    use tokio::sync::RwLock;

    const TEST_PROXY_ADDR: std::net::SocketAddr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3128);

    fn make_policies() -> HashMap<String, MediationPolicy> {
        let mut m = HashMap::new();
        m.insert(
            "parent_v1".into(),
            MediationPolicy {
                policy_name: "parent_v1".into(),
                rationale: "parent".into(),
                http_allowlist: vec!["*".into()],
                external_mounts: vec![],
                allowed_child_policies: vec!["child_*".into()],
                bind_ports: None,
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
                allowed_launch_commands: vec![],
            },
        );
        m.insert(
            "child_v1".into(),
            MediationPolicy {
                policy_name: "child_v1".into(),
                rationale: "child".into(),
                http_allowlist: vec!["https://api.example.com/*".into()],
                external_mounts: vec![],
                allowed_child_policies: vec![],
                bind_ports: None,
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
                allowed_launch_commands: vec![],
            },
        );
        m
    }

    #[tokio::test]
    async fn fork_creates_token_and_workflow() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let key = TokenKey::new(b"fork-test".to_vec());
        let policies = Arc::new(RwLock::new(make_policies()));
        let uid_alloc = UidAllocator::new();
        let gid_alloc = GidAllocator::new();

        let caller_tok = WorkflowToken {
            token: "tok_parent".into(),
            workflow_id: "wf_parent".into(),
            pid: 1,
            policy_name: "parent_v1".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_token(store.pool(), &caller_tok).await.unwrap();

        let caller_policy = policies.read().await.get("parent_v1").unwrap().clone();

        let result = handle_fork_with_policy(
            store.pool(),
            &key,
            &policies,
            &caller_tok,
            &caller_policy,
            ForkParams {
                workflow_id: "wf_child_1".into(),
                policy_name: "child_v1".into(),
                command: vec![],
            },
            &uid_alloc,
            &gid_alloc,
            &UidPolicyRegistry::new(),
                TEST_PROXY_ADDR,
        )
        .await
        .unwrap();

        assert_eq!(result.uid, 100_000);
        assert_eq!(result.gid, 70_000);
        assert!(!result.workflow_token.is_empty());
        // Inheritance dropped — inherited_from is always None in the simplified mediator.
        assert!(result.inherited_from.is_none());

        // Verify token is in store.
        let stored = queries::get_token(store.pool(), &result.workflow_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.workflow_id, "wf_child_1");
        assert_eq!(stored.policy_name, "child_v1");
        assert_eq!(stored.uid, Some(100_000));

        // Verify workflow is in store.
        let wf = queries::get_workflow(store.pool(), "wf_child_1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(wf.parent_workflow_id.as_deref(), Some("wf_parent"));
        assert_eq!(wf.uid, Some(100_000));
    }

    #[tokio::test]
    async fn fork_rejects_disallowed_policy() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let key = TokenKey::new(b"k".to_vec());
        let policies = Arc::new(RwLock::new(make_policies()));
        let uid_alloc = UidAllocator::new();
        let gid_alloc = GidAllocator::new();

        let caller_tok = WorkflowToken {
            token: "tok_p".into(),
            workflow_id: "wf_p".into(),
            pid: 1,
            policy_name: "parent_v1".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };
        insert_token(store.pool(), &caller_tok).await.unwrap();

        let caller_policy = policies.read().await.get("parent_v1").unwrap().clone();

        let err = handle_fork_with_policy(
            store.pool(),
            &key,
            &policies,
            &caller_tok,
            &caller_policy,
            ForkParams {
                workflow_id: "wf_bad".into(),
                policy_name: "parent_v1".into(),

                command: vec![],
            },
            &uid_alloc,
            &gid_alloc,
            &UidPolicyRegistry::new(),
                TEST_PROXY_ADDR,
        )
        .await
        .unwrap_err();

        assert!(err.contains("not in caller's allowed_child_policies"));
    }

    // fork_rejects_inherit_mismatch removed — the `inherit` field was dropped
    // from ForkParams in the simplified mediator. See fork_rejects_unlisted_child
    // above for the remaining allowed_child_policies enforcement test.

    #[tokio::test]
    async fn fork_allocates_unique_uids() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let key = TokenKey::new(b"uid-test".to_vec());
        let policies = Arc::new(RwLock::new(make_policies()));
        let uid_alloc = UidAllocator::new();
        let gid_alloc = GidAllocator::new();

        let caller_tok = WorkflowToken {
            token: "tok_uid".into(),
            workflow_id: "wf_uid".into(),
            pid: 1,
            policy_name: "parent_v1".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };
        insert_token(store.pool(), &caller_tok).await.unwrap();

        let caller_policy = policies.read().await.get("parent_v1").unwrap().clone();

        let r1 = handle_fork_with_policy(
            store.pool(), &key, &policies, &caller_tok, &caller_policy,
            ForkParams { workflow_id: "wf_a".into(), policy_name: "child_v1".into(), command: vec![] },
            &uid_alloc, &gid_alloc, &UidPolicyRegistry::new(),
                TEST_PROXY_ADDR,
        ).await.unwrap();

        let r2 = handle_fork_with_policy(
            store.pool(), &key, &policies, &caller_tok, &caller_policy,
            ForkParams { workflow_id: "wf_b".into(), policy_name: "child_v1".into(), command: vec![] },
            &uid_alloc, &gid_alloc, &UidPolicyRegistry::new(),
                TEST_PROXY_ADDR,
        ).await.unwrap();

        // Different UIDs
        assert_ne!(r1.uid, r2.uid);
        // Same GID (same policy)
        assert_eq!(r1.gid, r2.gid);
    }
}
