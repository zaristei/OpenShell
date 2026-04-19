// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SQLite-backed state store for the mediator layer.

pub mod queries;
pub mod schema;

use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;

/// Persistent store for mediator state (tokens, workflows, ports, audit).
#[derive(Clone)]
pub struct MediatorStore {
    pool: SqlitePool,
}

impl MediatorStore {
    /// Open (or create) a SQLite database at `path` and run migrations.
    ///
    /// Pass `":memory:"` for an in-memory database (useful for tests).
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrations fail.
    pub async fn open(path: &str) -> sqlx::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect(path)
            .await?;
        Self::migrate(&pool).await?;
        Ok(Self { pool })
    }

    /// Return a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run the mediator schema migrations.
    ///
    /// Each migration is idempotent: `CREATE TABLE IF NOT EXISTS` for new
    /// tables, and `ALTER TABLE ADD COLUMN` errors are silently ignored
    /// (the column already exists from a previous run).
    async fn migrate(pool: &SqlitePool) -> sqlx::Result<()> {
        sqlx::query(include_str!("../../../migrations/mediator/001_init.sql"))
            .execute(pool)
            .await?;
        // ALTER TABLE ADD COLUMN fails with "duplicate column" if re-run.
        // Ignore that specific error to make the migration idempotent.
        let alter_result = sqlx::query(include_str!(
            "../../../migrations/mediator/002_uid_isolation.sql"
        ))
        .execute(pool)
        .await;
        if let Err(ref e) = alter_result {
            let msg = e.to_string();
            if !msg.contains("duplicate column") {
                alter_result?;
            }
        }
        let alter_result = sqlx::query(include_str!(
            "../../../migrations/mediator/003_compromised_resources.sql"
        ))
        .execute(pool)
        .await;
        if let Err(ref e) = alter_result {
            let msg = e.to_string();
            if !msg.contains("duplicate column") && !msg.contains("already exists") {
                alter_result?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::queries::*;
    use super::schema::*;
    use super::*;

    async fn test_store() -> MediatorStore {
        MediatorStore::open("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn token_crud() {
        let store = test_store().await;
        let pool = store.pool();

        let t = WorkflowToken {
            token: "tok_abc".into(),
            workflow_id: "wf_1".into(),
            pid: 1234,
            policy_name: "test_policy_v1".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };

        insert_token(pool, &t).await.unwrap();

        let fetched = get_token(pool, "tok_abc").await.unwrap().unwrap();
        assert_eq!(fetched.workflow_id, "wf_1");
        assert_eq!(fetched.pid, 1234);

        // Not found
        assert!(get_token(pool, "nonexistent").await.unwrap().is_none());

        delete_token(pool, "tok_abc").await.unwrap();
        assert!(get_token(pool, "tok_abc").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn port_crud() {
        let store = test_store().await;
        let pool = store.pool();

        // Need a token first (FK constraint).
        let t = WorkflowToken {
            token: "tok_port".into(),
            workflow_id: "wf_2".into(),
            pid: 100,
            policy_name: "p".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_token(pool, &t).await.unwrap();

        let p = PortAllocation {
            port: 8080,
            workflow_token: "tok_port".into(),
            allocated_at: "2026-01-01T00:00:00Z".into(),
        };
        insert_port(pool, &p).await.unwrap();

        // 8080 taken, so first available in 8080..8082 should be 8081.
        let avail = first_available_port(pool, 8080, 8082).await.unwrap();
        assert_eq!(avail, Some(8081));

        release_ports(pool, "tok_port").await.unwrap();
        let avail = first_available_port(pool, 8080, 8082).await.unwrap();
        assert_eq!(avail, Some(8080));
    }

    #[tokio::test]
    async fn workflow_crud() {
        let store = test_store().await;
        let pool = store.pool();

        let t = WorkflowToken {
            token: "tok_wf".into(),
            workflow_id: "wf_3".into(),
            pid: 200,
            policy_name: "p".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_token(pool, &t).await.unwrap();

        let w = ActiveWorkflow {
            workflow_id: "wf_3".into(),
            policy_name: "p".into(),
            root_pid: 200,
            namespace_id: "ns_1".into(),
            workflow_token: "tok_wf".into(),
            parent_workflow_id: None,
            started_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_workflow(pool, &w).await.unwrap();

        let fetched = get_workflow(pool, "wf_3").await.unwrap().unwrap();
        assert_eq!(fetched.namespace_id, "ns_1");

        let all = list_workflows(pool).await.unwrap();
        assert_eq!(all.len(), 1);

        delete_workflow(pool, "wf_3").await.unwrap();
        assert!(get_workflow(pool, "wf_3").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn audit_append_and_recent() {
        let store = test_store().await;
        let pool = store.pool();

        for i in 0..5 {
            let e = AuditEntry {
                id: None,
                timestamp: format!("2026-01-01T00:0{i}:00Z"),
                workflow_id: "wf_a".into(),
                workflow_token: "tok_a".into(),
                syscall: "http_request".into(),
                args: format!("{{\"i\":{i}}}"),
                result: "allowed".into(),
                policy_used: "test_v1".into(),
                details: None,
            };
            append_audit(pool, &e).await.unwrap();
        }

        let recent = recent_audit(pool, 3).await.unwrap();
        assert_eq!(recent.len(), 3);
        // Most recent first (id DESC).
        assert!(recent[0].id.unwrap() > recent[1].id.unwrap());
    }
}
