// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `request_port` syscall: allocate a port from the policy's declared range.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::store::queries;
use crate::mediator::store::schema::{PortAllocation, WorkflowToken};
use sqlx::SqlitePool;
use std::time::SystemTime;

/// Execute the `request_port` syscall.
///
/// Allocates the first available port in the caller's `bind_ports` range.
///
/// # Errors
///
/// Returns an error if the policy has no port range or all ports are taken.
pub async fn handle_request_port(
    pool: &SqlitePool,
    caller_token: &WorkflowToken,
    caller_policy: &MediationPolicy,
) -> Result<serde_json::Value, String> {
    let range = caller_policy
        .bind_ports
        .ok_or("policy does not declare bind_ports")?;

    let port = queries::first_available_port(pool, i64::from(range.0), i64::from(range.1))
        .await
        .map_err(|e| format!("store error: {e}"))?
        .ok_or("ENOSPC: no ports available in range")?;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let alloc = PortAllocation {
        port,
        workflow_token: caller_token.token.clone(),
        allocated_at: timestamp,
    };
    queries::insert_port(pool, &alloc)
        .await
        .map_err(|e| format!("failed to allocate port: {e}"))?;

    Ok(serde_json::json!({"port": port}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::PortRange;
    use crate::mediator::store::MediatorStore;
    use crate::mediator::store::queries::insert_token;

    fn policy_with_ports(min: u16, max: u16) -> MediationPolicy {
        MediationPolicy {
            policy_name: "p".into(),
            rationale: "t".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: Some(PortRange(min, max)),
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
        }
    }

    #[tokio::test]
    async fn allocate_port() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let tok = WorkflowToken {
            token: "tok_p".into(),
            workflow_id: "wf_p".into(),
            pid: 1,
            policy_name: "p".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };
        insert_token(store.pool(), &tok).await.unwrap();

        let result = handle_request_port(store.pool(), &tok, &policy_with_ports(9000, 9002))
            .await
            .unwrap();

        assert_eq!(result["port"], 9000);
    }

    #[tokio::test]
    async fn allocate_enospc() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let tok = WorkflowToken {
            token: "tok_full".into(),
            workflow_id: "wf_full".into(),
            pid: 1,
            policy_name: "p".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };
        insert_token(store.pool(), &tok).await.unwrap();

        // Range of 1 port.
        let policy = policy_with_ports(9090, 9090);

        // First allocation succeeds.
        let r1 = handle_request_port(store.pool(), &tok, &policy).await;
        assert!(r1.is_ok());

        // Second fails — range exhausted.
        let r2 = handle_request_port(store.pool(), &tok, &policy).await;
        assert!(r2.unwrap_err().contains("ENOSPC"));
    }

    #[tokio::test]
    async fn no_bind_ports_in_policy() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let tok = WorkflowToken {
            token: "tok_np".into(),
            workflow_id: "wf_np".into(),
            pid: 1,
            policy_name: "p".into(),
            inherited_from: None,
            created_at: "t".into(),
            uid: None,
        };
        insert_token(store.pool(), &tok).await.unwrap();

        let policy = MediationPolicy {
            policy_name: "p".into(),
            rationale: "t".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
        };

        let err = handle_request_port(store.pool(), &tok, &policy)
            .await
            .unwrap_err();
        assert!(err.contains("bind_ports"));
    }
}
