// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ipc_send` syscall: one-shot message to another namespace's inbox.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::scrub;
use crate::mediator::policy::validate::fnmatch;
use crate::mediator::store::queries;
use crate::mediator::store::schema::{IpcMessage, WorkflowToken};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, warn};

/// Parameters for `ipc_send`.
#[derive(Debug, serde::Deserialize)]
pub struct IpcSendParams {
    pub target_workflow_id: String,
    pub message: serde_json::Value,
}

/// Check mutual IPC consent between sender and target.
///
/// Both sides must list the other's policy_name in their `allowed_ipc_targets`.
pub fn check_mutual_consent(
    sender_policy: &MediationPolicy,
    target_policy: &MediationPolicy,
) -> Result<(), String> {
    let sender_allows_target = sender_policy
        .allowed_ipc_targets
        .iter()
        .any(|p| fnmatch(p.policy_pattern(), &target_policy.policy_name));

    let target_allows_sender = target_policy
        .allowed_ipc_targets
        .iter()
        .any(|p| fnmatch(p.policy_pattern(), &sender_policy.policy_name));

    if !sender_allows_target {
        return Err(format!(
            "sender policy '{}' does not allow IPC to '{}'",
            sender_policy.policy_name, target_policy.policy_name
        ));
    }
    if !target_allows_sender {
        return Err(format!(
            "target policy '{}' does not allow IPC from '{}'",
            target_policy.policy_name, sender_policy.policy_name
        ));
    }
    Ok(())
}

/// Execute the `ipc_send` syscall.
///
/// # Errors
///
/// Returns an error if consent check fails or the target doesn't exist.
pub async fn handle_ipc_send(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    caller_token: &WorkflowToken,
    caller_policy: &MediationPolicy,
    params: IpcSendParams,
) -> Result<serde_json::Value, String> {
    // Look up target workflow.
    let target_wf = queries::get_workflow(pool, &params.target_workflow_id)
        .await
        .map_err(|e| format!("store error: {e}"))?
        .ok_or_else(|| format!("workflow '{}' not found", params.target_workflow_id))?;

    // Look up target policy.
    let guard = policies.read().await;
    let target_policy = guard
        .get(&target_wf.policy_name)
        .ok_or_else(|| format!("target policy '{}' not found", target_wf.policy_name))?;

    // Mutual consent check.
    check_mutual_consent(caller_policy, target_policy)?;
    let target_policy_name = target_policy.policy_name.clone();
    drop(guard);

    // Apply egress scrubber if configured on the sender's IPC target entry.
    let target_workflow_id = params.target_workflow_id;
    let message = {
        let scrub_entry = caller_policy
            .allowed_ipc_targets
            .iter()
            .find(|e| fnmatch(e.policy_pattern(), &target_policy_name));

        if let Some(scrub_config) = scrub_entry.and_then(|e| e.scrub_egress()) {
            let scrubber = scrub::create_scrubber(scrub_config);
            let result = scrubber.scrub(&params.message);
            if !result.redactions.is_empty() {
                debug!(
                    scrubber = scrubber.name(),
                    redactions = result.redactions.len(),
                    "scrubbed ipc_send message"
                );
            }
            result.output
        } else {
            params.message
        }
    };

    // Store message.
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let msg = IpcMessage {
        id: None,
        sender_workflow_id: caller_token.workflow_id.clone(),
        target_workflow_id: target_workflow_id.clone(),
        message: message.to_string(),
        created_at: timestamp.clone(),
    };
    queries::insert_ipc_message(pool, &msg)
        .await
        .map_err(|e| format!("failed to store message: {e}"))?;

    // Filesystem delivery: write to target's inbox directory.
    if let Some(data_root) = std::env::var_os("OPENSHELL_DATA_ROOT") {
        let inbox_path = PathBuf::from(data_root)
            .join(&target_wf.policy_name)
            .join("instances")
            .join(&target_workflow_id)
            .join("inbox");

        if let Err(e) = std::fs::create_dir_all(&inbox_path) {
            warn!("failed to create inbox dir {}: {e}", inbox_path.display());
        } else {
            let filename = format!("{}_{}.json", timestamp, caller_token.workflow_id);
            let file_path = inbox_path.join(&filename);
            let envelope = serde_json::json!({
                "sender_workflow_id": caller_token.workflow_id,
                "sender_policy": caller_policy.policy_name,
                "timestamp": timestamp,
                "message": message,
            });
            if let Err(e) = std::fs::write(&file_path, envelope.to_string()) {
                warn!("failed to write ipc message to {}: {e}", file_path.display());
            }
        }
    }

    Ok(serde_json::json!({"ack": true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::MediationPolicy;

    fn policy(name: &str, ipc_targets: &[&str]) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: ipc_targets.iter().map(|s| (*s).into()).collect(),
            allowed_signal_targets: vec![],
        }
    }

    #[test]
    fn mutual_consent_both_allow() {
        let sender = policy("sender_v1", &["target_*"]);
        let target = policy("target_v1", &["sender_*"]);
        assert!(check_mutual_consent(&sender, &target).is_ok());
    }

    #[test]
    fn mutual_consent_sender_denies() {
        let sender = policy("sender_v1", &[]); // no targets
        let target = policy("target_v1", &["sender_*"]);
        assert!(check_mutual_consent(&sender, &target).is_err());
    }

    #[test]
    fn mutual_consent_target_denies() {
        let sender = policy("sender_v1", &["target_*"]);
        let target = policy("target_v1", &[]); // doesn't allow sender
        assert!(check_mutual_consent(&sender, &target).is_err());
    }
}
