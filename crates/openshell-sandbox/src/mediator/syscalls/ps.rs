// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ps` syscall: discover active workflows visible to the caller.

use crate::mediator::policy::IpcTargetEntry;
use crate::mediator::policy::validate::fnmatch;
use crate::mediator::store::queries;
use crate::mediator::store::schema::WorkflowToken;
use sqlx::SqlitePool;

/// Result entry returned by the `ps` syscall.
#[derive(Debug, serde::Serialize)]
pub struct PsEntry {
    pub workflow_id: String,
    pub policy_name: String,
}

/// Execute the `ps` syscall.
///
/// Returns active workflows whose `policy_name` matches one of the caller's
/// `allowed_ipc_targets` patterns, excluding the caller's own workflow.
///
/// # Errors
///
/// Returns an error string if the token lookup or workflow query fails.
pub async fn handle_ps(
    pool: &SqlitePool,
    caller_token: &WorkflowToken,
    allowed_ipc_targets: &[IpcTargetEntry],
) -> Result<Vec<PsEntry>, String> {
    let all = queries::list_workflows(pool)
        .await
        .map_err(|e| format!("failed to list workflows: {e}"))?;

    let results = all
        .into_iter()
        .filter(|w| {
            // Exclude the caller's own entry.
            w.workflow_id != caller_token.workflow_id
        })
        .filter(|w| {
            // Include only entries matching allowed_ipc_targets patterns.
            allowed_ipc_targets
                .iter()
                .any(|entry| fnmatch(entry.policy_pattern(), &w.policy_name))
        })
        .map(|w| PsEntry {
            workflow_id: w.workflow_id,
            policy_name: w.policy_name,
        })
        .collect();

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::store::MediatorStore;
    use crate::mediator::store::queries::{insert_token, insert_workflow};
    use crate::mediator::store::schema::{ActiveWorkflow, WorkflowToken};

    async fn setup() -> (MediatorStore, WorkflowToken) {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let pool = store.pool();

        // Create caller token + workflow.
        let caller_tok = WorkflowToken {
            token: "tok_caller".into(),
            workflow_id: "wf_caller".into(),
            pid: 100,
            policy_name: "init_v0".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_token(pool, &caller_tok).await.unwrap();
        insert_workflow(
            pool,
            &ActiveWorkflow {
                workflow_id: "wf_caller".into(),
                policy_name: "init_v0".into(),
                root_pid: 100,
                namespace_id: "ns_0".into(),
                workflow_token: "tok_caller".into(),
                parent_workflow_id: None,
                started_at: "2026-01-01T00:00:00Z".into(),
                uid: None,
            },
        )
        .await
        .unwrap();

        // Create two other workflows.
        for (i, policy) in [("fetcher_v1", "tok_f1"), ("scraper_v2", "tok_s2")]
            .iter()
            .enumerate()
        {
            let tok = WorkflowToken {
                token: policy.1.into(),
                workflow_id: format!("wf_{i}"),
                pid: (200 + i) as i64,
                policy_name: policy.0.into(),
                inherited_from: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                uid: None,
            };
            insert_token(pool, &tok).await.unwrap();
            insert_workflow(
                pool,
                &ActiveWorkflow {
                    workflow_id: format!("wf_{i}"),
                    policy_name: policy.0.into(),
                    root_pid: (200 + i) as i64,
                    namespace_id: format!("ns_{i}"),
                    workflow_token: policy.1.into(),
                    parent_workflow_id: Some("wf_caller".into()),
                    started_at: "2026-01-01T00:00:00Z".into(),
                    uid: None,
                },
            )
            .await
            .unwrap();
        }

        (store, caller_tok)
    }

    #[tokio::test]
    async fn ps_filters_by_ipc_targets() {
        let (store, caller_tok) = setup().await;

        // Only allow fetcher_* targets.
        let targets = vec!["fetcher_*".into()];
        let results = handle_ps(store.pool(), &caller_tok, &targets)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].policy_name, "fetcher_v1");
    }

    #[tokio::test]
    async fn ps_wildcard_returns_all_except_self() {
        let (store, caller_tok) = setup().await;

        let targets = vec!["*".into()];
        let results = handle_ps(store.pool(), &caller_tok, &targets)
            .await
            .unwrap();

        // 2 other workflows, not the caller.
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.workflow_id != "wf_caller"));
    }

    #[tokio::test]
    async fn ps_no_targets_returns_empty() {
        let (store, caller_tok) = setup().await;

        let results = handle_ps(store.pool(), &caller_tok, &[]).await.unwrap();
        assert!(results.is_empty());
    }
}
