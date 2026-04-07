// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Database row types for the mediator tables.

/// A row in the `workflow_tokens` table.
#[derive(Debug, Clone)]
pub struct WorkflowToken {
    pub token: String,
    pub workflow_id: String,
    pub pid: i64,
    pub policy_name: String,
    pub inherited_from: Option<String>,
    pub created_at: String,
    /// UID assigned to this workflow (UID-based isolation). `None` for legacy tokens.
    pub uid: Option<i64>,
}

/// A row in the `port_allocations` table.
#[derive(Debug, Clone)]
pub struct PortAllocation {
    pub port: i64,
    pub workflow_token: String,
    pub allocated_at: String,
}

/// A row in the `active_workflows` table.
#[derive(Debug, Clone)]
pub struct ActiveWorkflow {
    pub workflow_id: String,
    pub policy_name: String,
    pub root_pid: i64,
    pub namespace_id: String,
    pub workflow_token: String,
    pub parent_workflow_id: Option<String>,
    pub started_at: String,
    /// UID assigned to this workflow (UID-based isolation). `None` for legacy workflows.
    pub uid: Option<i64>,
}

/// A row in the `ipc_messages` table.
#[derive(Debug, Clone)]
pub struct IpcMessage {
    pub id: Option<i64>,
    pub sender_workflow_id: String,
    pub target_workflow_id: String,
    pub message: String,
    pub created_at: String,
}

/// A row in the `audit_log` table.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: Option<i64>,
    pub timestamp: String,
    pub workflow_id: String,
    pub workflow_token: String,
    pub syscall: String,
    pub args: String,
    pub result: String,
    pub policy_used: String,
    pub details: Option<String>,
}
