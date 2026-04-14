// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Child workflow process spawner.
//!
//! After `fork_with_policy` allocates a UID and registers the policy, this
//! module spawns the child process under that UID via `setpriv`. The command
//! comes from `fork_with_policy`'s `command` field and has already been
//! validated against the policy's `allowed_launch_commands`.

use std::process::Command;
use tracing::{info, warn};

/// Spawn a child process under the given UID with mediator credentials.
///
/// If `command` is empty, falls back to `sleep infinity` (backward compat).
/// Returns the child PID on success.
pub fn spawn_child_process(
    uid: u32,
    gid: u32,
    workflow_id: &str,
    policy_name: &str,
    workflow_token: &str,
    mediator_socket: &str,
    instance_dir: &str,
    command: &[String],
) -> Result<u32, String> {
    let env_vars = [
        ("MEDIATOR_SOCKET", mediator_socket),
        ("MEDIATOR_TOKEN", workflow_token),
        ("WORKFLOW_ID", workflow_id),
        ("POLICY_NAME", policy_name),
        ("HOME", instance_dir),
    ];

    // Ensure the instance directory exists.
    if let Err(e) = std::fs::create_dir_all(instance_dir) {
        warn!(workflow_id, %e, "failed to create instance dir (child may fail)");
    }

    let (program, args): (String, Vec<String>) = if command.is_empty() {
        ("/bin/sh".into(), vec!["-c".into(), "exec sleep infinity".into()])
    } else {
        (command[0].clone(), command[1..].to_vec())
    };

    let mut cmd = Command::new("/usr/bin/setpriv");
    cmd.args([
        "--reuid",
        &uid.to_string(),
        "--regid",
        &gid.to_string(),
        "--clear-groups",
        "--",
        &program,
    ]);
    cmd.args(&args);
    cmd.envs(env_vars.iter().map(|(k, v)| (*k, *v)));
    cmd.env("PATH", "/sandbox:/usr/local/bin:/usr/bin:/bin");
    cmd.current_dir(instance_dir);
    cmd.stdin(std::process::Stdio::null());
    // Capture stdout/stderr to files in the instance dir so the parent
    // can read the child's output (e.g. openclaw agent --local --json).
    let stdout_path = format!("{instance_dir}/stdout.log");
    let stderr_path = format!("{instance_dir}/stderr.log");
    match (
        std::fs::File::create(&stdout_path),
        std::fs::File::create(&stderr_path),
    ) {
        (Ok(out), Ok(err)) => {
            cmd.stdout(out);
            cmd.stderr(err);
        }
        _ => {
            warn!(workflow_id, "failed to create output files, detaching stdio");
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
        }
    }

    let result = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn child process: {e}"))?;

    let pid = result.id();

    info!(
        workflow_id,
        uid,
        gid,
        pid,
        %program,
        "spawned child process"
    );

    Ok(pid)
}
