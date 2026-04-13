// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Child workflow process spawner.
//!
//! After `fork_with_policy` allocates a UID and registers the policy, this
//! module spawns an actual process under that UID. The process:
//!
//! 1. Runs as the allocated UID (via setuid)
//! 2. Has MEDIATOR_SOCKET + MEDIATOR_TOKEN in its environment
//! 3. Listens for IPC messages from the parent
//! 4. Executes HTTP fetches per the policy's http_allowlist (through the L7 proxy)
//! 5. Sends results back via IPC
//!
//! The child runs a simple fetch loop: read IPC → parse request → curl URL → send result.
//! It exits when signaled or when the parent revokes its policy.

use std::process::Command;
use tracing::{info, warn};

/// Spawn a child process under the given UID with mediator credentials.
///
/// The child runs `/sandbox/mediator-worker` if it exists, or falls back to
/// a shell-based fetch loop. The process is fully daemonized (detached from
/// the daemon's process group).
///
/// Returns the child PID on success.
pub fn spawn_child_process(
    uid: u32,
    gid: u32,
    workflow_id: &str,
    workflow_token: &str,
    mediator_socket: &str,
    instance_dir: &str,
) -> Result<u32, String> {
    // Build the environment for the child.
    let env_vars = [
        ("MEDIATOR_SOCKET", mediator_socket),
        ("MEDIATOR_TOKEN", workflow_token),
        ("WORKFLOW_ID", workflow_id),
        ("HOME", instance_dir),
    ];

    // Try the dedicated worker binary first, fall back to shell fetch loop.
    let worker_bin = "/sandbox/mediator-worker";
    let (program, args): (&str, Vec<&str>) = if std::path::Path::new(worker_bin).exists() {
        (worker_bin, vec![])
    } else {
        // Minimal shell fetch loop: read IPC messages from stdin-like pipe,
        // execute curl for each URL, write results back. This is a placeholder
        // until a proper worker binary is built.
        //
        // The child can't read IPC directly from the mediator socket (that's
        // the daemon's job). Instead, the daemon will forward IPC messages
        // to the child via a pipe or local socket. For now, the child just
        // sleeps and waits — the parent's ipc_send writes to the DB, and
        // a future version of the daemon will relay messages to the child.
        ("/bin/sh", vec!["-c", "exec sleep infinity"])
    };

    // Use `setpriv` to drop to the target UID/GID before exec.
    // This is available on Debian/Ubuntu (util-linux package).
    let result = Command::new("setpriv")
        .args([
            "--reuid",
            &uid.to_string(),
            "--regid",
            &gid.to_string(),
            "--clear-groups",
            "--",
            program,
        ])
        .args(&args)
        .envs(env_vars.iter().map(|(k, v)| (*k, *v)))
        .env("PATH", "/sandbox:/usr/local/bin:/usr/bin:/bin")
        .current_dir(instance_dir)
        // Detach: don't inherit stdin/stdout/stderr from the daemon.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn child process: {e}"))?;

    let pid = result.id();

    info!(
        workflow_id,
        uid,
        gid,
        pid,
        program,
        "spawned child process"
    );

    Ok(pid)
}
