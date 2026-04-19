// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CRUD operations for mediator tables.

use super::schema::{ActiveWorkflow, AuditEntry, IpcMessage, PortAllocation, WorkflowToken};
use sqlx::SqlitePool;

// ---------------------------------------------------------------------------
// workflow_tokens
// ---------------------------------------------------------------------------

/// Insert a new workflow token.
///
/// # Errors
///
/// Returns an error if the insert fails (e.g. duplicate token).
pub async fn insert_token(pool: &SqlitePool, t: &WorkflowToken) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO workflow_tokens (token, workflow_id, pid, policy_name, inherited_from, created_at, uid)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&t.token)
    .bind(&t.workflow_id)
    .bind(t.pid)
    .bind(&t.policy_name)
    .bind(&t.inherited_from)
    .bind(&t.created_at)
    .bind(t.uid)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a workflow token by its value.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn get_token(pool: &SqlitePool, token: &str) -> sqlx::Result<Option<WorkflowToken>> {
    sqlx::query_as::<_, (String, String, i64, String, Option<String>, String, Option<i64>)>(
        "SELECT token, workflow_id, pid, policy_name, inherited_from, created_at, uid
         FROM workflow_tokens WHERE token = ?",
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map(|row| {
        row.map(
            |(token, workflow_id, pid, policy_name, inherited_from, created_at, uid)| {
                WorkflowToken {
                    token,
                    workflow_id,
                    pid,
                    policy_name,
                    inherited_from,
                    created_at,
                    uid,
                }
            },
        )
    })
}

/// Delete a workflow token.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn delete_token(pool: &SqlitePool, token: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM workflow_tokens WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// port_allocations
// ---------------------------------------------------------------------------

/// Allocate a port for a workflow.
///
/// # Errors
///
/// Returns an error if the port is already allocated.
pub async fn insert_port(pool: &SqlitePool, p: &PortAllocation) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO port_allocations (port, workflow_token, allocated_at)
         VALUES (?, ?, ?)",
    )
    .bind(p.port)
    .bind(&p.workflow_token)
    .bind(&p.allocated_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Find the first available port in a range for a workflow.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn first_available_port(
    pool: &SqlitePool,
    min: i64,
    max: i64,
) -> sqlx::Result<Option<i64>> {
    // Get all allocated ports in range, then find the first gap.
    let allocated: Vec<(i64,)> = sqlx::query_as(
        "SELECT port FROM port_allocations WHERE port >= ? AND port <= ? ORDER BY port",
    )
    .bind(min)
    .bind(max)
    .fetch_all(pool)
    .await?;

    let used: std::collections::HashSet<i64> = allocated.into_iter().map(|(p,)| p).collect();
    for port in min..=max {
        if !used.contains(&port) {
            return Ok(Some(port));
        }
    }
    Ok(None)
}

/// Release all ports for a workflow token.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn release_ports(pool: &SqlitePool, workflow_token: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM port_allocations WHERE workflow_token = ?")
        .bind(workflow_token)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// active_workflows
// ---------------------------------------------------------------------------

/// Register an active workflow.
///
/// # Errors
///
/// Returns an error if a workflow with the same ID already exists.
pub async fn insert_workflow(pool: &SqlitePool, w: &ActiveWorkflow) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO active_workflows
         (workflow_id, policy_name, root_pid, namespace_id, workflow_token, parent_workflow_id, started_at, uid)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&w.workflow_id)
    .bind(&w.policy_name)
    .bind(w.root_pid)
    .bind(&w.namespace_id)
    .bind(&w.workflow_token)
    .bind(&w.parent_workflow_id)
    .bind(&w.started_at)
    .bind(w.uid)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get an active workflow by ID.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn get_workflow(
    pool: &SqlitePool,
    workflow_id: &str,
) -> sqlx::Result<Option<ActiveWorkflow>> {
    sqlx::query_as::<_, (String, String, i64, String, String, Option<String>, String, Option<i64>)>(
        "SELECT workflow_id, policy_name, root_pid, namespace_id, workflow_token, parent_workflow_id, started_at, uid
         FROM active_workflows WHERE workflow_id = ?",
    )
    .bind(workflow_id)
    .fetch_optional(pool)
    .await
    .map(|row| {
        row.map(
            |(workflow_id, policy_name, root_pid, namespace_id, workflow_token, parent_workflow_id, started_at, uid)| {
                ActiveWorkflow {
                    workflow_id,
                    policy_name,
                    root_pid,
                    namespace_id,
                    workflow_token,
                    parent_workflow_id,
                    started_at,
                    uid,
                }
            },
        )
    })
}

/// List all active workflows.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn list_workflows(pool: &SqlitePool) -> sqlx::Result<Vec<ActiveWorkflow>> {
    let rows: Vec<(String, String, i64, String, String, Option<String>, String, Option<i64>)> =
        sqlx::query_as(
            "SELECT workflow_id, policy_name, root_pid, namespace_id, workflow_token, parent_workflow_id, started_at, uid
             FROM active_workflows",
        )
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                workflow_id,
                policy_name,
                root_pid,
                namespace_id,
                workflow_token,
                parent_workflow_id,
                started_at,
                uid,
            )| {
                ActiveWorkflow {
                    workflow_id,
                    policy_name,
                    root_pid,
                    namespace_id,
                    workflow_token,
                    parent_workflow_id,
                    started_at,
                    uid,
                }
            },
        )
        .collect())
}

/// Remove an active workflow.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn delete_workflow(pool: &SqlitePool, workflow_id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM active_workflows WHERE workflow_id = ?")
        .bind(workflow_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// audit_log
// ---------------------------------------------------------------------------

/// Append an entry to the audit log.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn append_audit(pool: &SqlitePool, e: &AuditEntry) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (timestamp, workflow_id, workflow_token, syscall, args, result, policy_used, details)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&e.timestamp)
    .bind(&e.workflow_id)
    .bind(&e.workflow_token)
    .bind(&e.syscall)
    .bind(&e.args)
    .bind(&e.result)
    .bind(&e.policy_used)
    .bind(&e.details)
    .execute(pool)
    .await?;
    Ok(())
}

/// Retrieve the most recent N audit entries.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn recent_audit(pool: &SqlitePool, limit: i64) -> sqlx::Result<Vec<AuditEntry>> {
    let rows: Vec<(
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, timestamp, workflow_id, workflow_token, syscall, args, result, policy_used, details
         FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                timestamp,
                workflow_id,
                workflow_token,
                syscall,
                args,
                result,
                policy_used,
                details,
            )| {
                AuditEntry {
                    id: Some(id),
                    timestamp,
                    workflow_id,
                    workflow_token,
                    syscall,
                    args,
                    result,
                    policy_used,
                    details,
                }
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// ipc_messages
// ---------------------------------------------------------------------------

/// Insert an IPC message into the inbox.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn insert_ipc_message(pool: &SqlitePool, m: &IpcMessage) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO ipc_messages (sender_workflow_id, target_workflow_id, message, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&m.sender_workflow_id)
    .bind(&m.target_workflow_id)
    .bind(&m.message)
    .bind(&m.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// List IPC messages for a target workflow, oldest first.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn list_ipc_messages(
    pool: &SqlitePool,
    target_workflow_id: &str,
) -> sqlx::Result<Vec<IpcMessage>> {
    let rows: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT id, sender_workflow_id, target_workflow_id, message, created_at
         FROM ipc_messages WHERE target_workflow_id = ? ORDER BY id ASC",
    )
    .bind(target_workflow_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, sender_workflow_id, target_workflow_id, message, created_at)| IpcMessage {
                id: Some(id),
                sender_workflow_id,
                target_workflow_id,
                message,
                created_at,
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// compromised_resources
// ---------------------------------------------------------------------------

/// A compromised resource record.
pub struct CompromisedResource {
    pub resource_path: String,
    pub resource_type: String,
    pub compromise_type: String,
    pub data_type: String,
    pub caused_by: String,
    pub via_path: String,
    pub workflow_id: Option<String>,
    pub created_at: String,
}

/// Bulk-insert compromised resources (materialized at fork time).
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn insert_compromised_resources(
    pool: &SqlitePool,
    resources: &[CompromisedResource],
) -> sqlx::Result<()> {
    for r in resources {
        sqlx::query(
            "INSERT INTO compromised_resources
             (resource_path, resource_type, compromise_type, data_type, caused_by, via_path, workflow_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&r.resource_path)
        .bind(&r.resource_type)
        .bind(&r.compromise_type)
        .bind(&r.data_type)
        .bind(&r.caused_by)
        .bind(&r.via_path)
        .bind(&r.workflow_id)
        .bind(&r.created_at)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Clear compromised resources caused by a specific policy.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn clear_compromised_by_policy(
    pool: &SqlitePool,
    policy_name: &str,
) -> sqlx::Result<u64> {
    let result = sqlx::query("DELETE FROM compromised_resources WHERE caused_by = ?")
        .bind(policy_name)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// List all compromised resources.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn list_compromised_resources(
    pool: &SqlitePool,
) -> sqlx::Result<Vec<CompromisedResource>> {
    let rows: Vec<(String, String, String, String, String, String, Option<String>, String)> =
        sqlx::query_as(
            "SELECT resource_path, resource_type, compromise_type, data_type, caused_by, via_path, workflow_id, created_at
             FROM compromised_resources ORDER BY id ASC",
        )
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(
            |(resource_path, resource_type, compromise_type, data_type, caused_by, via_path, workflow_id, created_at)| {
                CompromisedResource {
                    resource_path,
                    resource_type,
                    compromise_type,
                    data_type,
                    caused_by,
                    via_path,
                    workflow_id,
                    created_at,
                }
            },
        )
        .collect())
}

// ---------------------------------------------------------------------------
// policy_taint
// ---------------------------------------------------------------------------

/// Store or update a policy's taint classification.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn upsert_policy_taint(
    pool: &SqlitePool,
    policy_name: &str,
    taint_json: &str,
    updated_at: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO policy_taint (policy_name, taint_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(policy_name) DO UPDATE SET taint_json = excluded.taint_json, updated_at = excluded.updated_at",
    )
    .bind(policy_name)
    .bind(taint_json)
    .bind(updated_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get a policy's stored taint classification.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn get_policy_taint(
    pool: &SqlitePool,
    policy_name: &str,
) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT taint_json FROM policy_taint WHERE policy_name = ?")
            .bind(policy_name)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(json,)| json))
}

/// Delete a policy's taint record.
///
/// # Errors
///
/// Returns an error on database failure.
pub async fn delete_policy_taint(pool: &SqlitePool, policy_name: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM policy_taint WHERE policy_name = ?")
        .bind(policy_name)
        .execute(pool)
        .await?;
    Ok(())
}
