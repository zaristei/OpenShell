// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `revoke_policy` syscall: remove an approved policy and handle active workflows.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::store::queries;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tracing::{info, warn};

/// Parameters for `revoke_policy`.
#[derive(Debug, serde::Deserialize)]
pub struct RevokePolicyParams {
    /// Name of the policy to revoke.
    pub policy_name: String,
    /// If true, SIGKILL all workflows using this policy.
    /// If false, just remove the policy (soft revoke).
    #[serde(default)]
    pub hard: bool,
}

/// Result of a revoke operation.
#[derive(Debug, serde::Serialize)]
pub struct RevokeResult {
    pub revoked: bool,
    pub affected_workflows: Vec<String>,
}

/// Execute the `revoke_policy` syscall.
///
/// Removes the named policy from the approved map. If `hard` is true,
/// kills all processes running under workflows that use this policy.
///
/// # Errors
///
/// Returns an error if the caller doesn't have permission (only init
/// can revoke) or on store errors.
pub async fn handle_revoke_policy(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    caller_policy_name: &str,
    params: RevokePolicyParams,
) -> Result<serde_json::Value, String> {
    // Only init_v0 (or wildcard child policy holders) can revoke.
    if caller_policy_name != "init_v0" {
        return Err("only init can revoke policies".into());
    }

    // Remove from approved policies map.
    let removed = {
        let mut guard = policies.write().await;
        guard.remove(&params.policy_name).is_some()
    };

    if !removed {
        // Policy wasn't in the map — no-op.
        return Ok(serde_json::to_value(&RevokeResult {
            revoked: false,
            affected_workflows: vec![],
        })
        .unwrap_or_default());
    }

    info!(policy = %params.policy_name, hard = params.hard, "policy revoked");

    // Find all active workflows using this policy.
    let all_workflows = queries::list_workflows(pool)
        .await
        .map_err(|e| format!("store error: {e}"))?;

    let affected: Vec<_> = all_workflows
        .iter()
        .filter(|w| w.policy_name == params.policy_name)
        .collect();

    let affected_ids: Vec<String> = affected.iter().map(|w| w.workflow_id.clone()).collect();

    if params.hard {
        // Hard revoke: kill all processes for affected workflows.
        for wf in &affected {
            let pid = wf.root_pid;
            if pid > 0 {
                #[cfg(target_os = "linux")]
                {
                    // Kill process group.
                    unsafe {
                        libc::kill(-(pid as i32), libc::SIGKILL);
                    }
                }
                info!(workflow_id = %wf.workflow_id, pid, "killed workflow (hard revoke)");
            }

            // Clean up workflow from store.
            if let Err(e) = queries::delete_workflow(pool, &wf.workflow_id).await {
                warn!("failed to delete workflow {}: {e}", wf.workflow_id);
            }
            if let Err(e) = queries::delete_token(pool, &wf.workflow_token).await {
                warn!("failed to delete token for {}: {e}", wf.workflow_id);
            }
        }
    }

    // Clear compromised resources and taint record for the revoked policy.
    if let Err(e) = queries::clear_compromised_by_policy(pool, &params.policy_name).await {
        warn!(policy = %params.policy_name, %e, "failed to clear compromised resources");
    }
    if let Err(e) = queries::delete_policy_taint(pool, &params.policy_name).await {
        warn!(policy = %params.policy_name, %e, "failed to delete policy taint");
    }

    Ok(
        serde_json::to_value(&RevokeResult {
            revoked: true,
            affected_workflows: affected_ids,
        })
        .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::MediationPolicy;
    use crate::mediator::store::MediatorStore;
    use crate::mediator::store::queries::{insert_token, insert_workflow};
    use crate::mediator::store::schema::{ActiveWorkflow, WorkflowToken};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn test_policy(name: &str) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
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

    #[tokio::test]
    async fn revoke_removes_policy() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let policies = Arc::new(RwLock::new(HashMap::from([
            ("target_v1".into(), test_policy("target_v1")),
        ])));

        let result = handle_revoke_policy(
            store.pool(),
            &policies,
            "init_v0",
            RevokePolicyParams {
                policy_name: "target_v1".into(),
                hard: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(result["revoked"], true);
        assert!(!policies.read().await.contains_key("target_v1"));
    }

    #[tokio::test]
    async fn revoke_nonexistent_is_noop() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let policies = Arc::new(RwLock::new(HashMap::new()));

        let result = handle_revoke_policy(
            store.pool(),
            &policies,
            "init_v0",
            RevokePolicyParams {
                policy_name: "missing".into(),
                hard: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(result["revoked"], false);
    }

    #[tokio::test]
    async fn revoke_non_init_denied() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let policies = Arc::new(RwLock::new(HashMap::new()));

        let err = handle_revoke_policy(
            store.pool(),
            &policies,
            "not_init",
            RevokePolicyParams {
                policy_name: "foo".into(),
                hard: false,
            },
        )
        .await
        .unwrap_err();

        assert!(err.contains("only init"));
    }

    #[tokio::test]
    async fn hard_revoke_cleans_up_workflows() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let policies = Arc::new(RwLock::new(HashMap::from([
            ("revoke_me_v1".into(), test_policy("revoke_me_v1")),
        ])));

        // Insert a token (FK requirement) and workflow using the policy.
        insert_token(
            store.pool(),
            &WorkflowToken {
                token: "tok_r".into(),
                workflow_id: "wf_revoke".into(),
                pid: 99999,
                policy_name: "revoke_me_v1".into(),
                inherited_from: None,
                created_at: "2026-01-01".into(),
                uid: None,
            },
        )
        .await
        .unwrap();
        insert_workflow(
            store.pool(),
            &ActiveWorkflow {
                workflow_id: "wf_revoke".into(),
                policy_name: "revoke_me_v1".into(),
                root_pid: 99999, // non-existent pid
                namespace_id: "ns_r".into(),
                workflow_token: "tok_r".into(),
                parent_workflow_id: None,
                started_at: "2026-01-01".into(),
                uid: None,
            },
        )
        .await
        .unwrap();

        let result = handle_revoke_policy(
            store.pool(),
            &policies,
            "init_v0",
            RevokePolicyParams {
                policy_name: "revoke_me_v1".into(),
                hard: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(result["revoked"], true);
        let affected = result["affected_workflows"].as_array().unwrap();
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0], "wf_revoke");

        // Workflow should be cleaned up.
        let wf = queries::get_workflow(store.pool(), "wf_revoke")
            .await
            .unwrap();
        assert!(wf.is_none());
    }
}
