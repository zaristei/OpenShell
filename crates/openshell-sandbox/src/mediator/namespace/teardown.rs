// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Namespace teardown: graceful shutdown, table cleanup, port release.

use crate::mediator::audit;
use crate::mediator::store::queries;
use sqlx::SqlitePool;
use std::time::Duration;
use tracing::{info, warn};

/// Tear down a workflow: signal the process, clean up tables, release ports.
///
/// 1. Send SIGTERM to `root_pid` and wait up to 10 seconds.
/// 2. If still alive, send SIGKILL.
/// 3. Delete from `active_workflows`, invalidate `workflow_token`, release ports.
/// 4. Log the teardown to the audit log.
pub async fn teardown_workflow(
    pool: &SqlitePool,
    workflow_id: &str,
    workflow_token: &str,
    root_pid: i64,
) {
    let pid = nix::unistd::Pid::from_raw(root_pid as i32);

    // Send SIGTERM.
    if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
        warn!(workflow_id, %e, "SIGTERM failed (process may already be dead)");
    } else {
        // Wait up to 10 seconds for the process to exit.
        let mut exited = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if nix::sys::signal::kill(pid, None).is_err() {
                exited = true;
                break;
            }
        }

        if !exited {
            info!(workflow_id, "sending SIGKILL after 10s grace period");
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        }
    }

    // Clean up tables.
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
        &serde_json::json!({"root_pid": root_pid}),
        "allowed",
        "system",
        Some("namespace teardown"),
    )
    .await;

    info!(workflow_id, "workflow torn down");
}
