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

    // Ensure the instance directory and policy workspace exist, owned by the
    // child UID/GID. The daemon runs as root, so we must explicitly chown.
    for dir in &[
        instance_dir.to_string(),
        format!("/sandbox/.mediator/policies/{policy_name}/workspace"),
    ] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!(workflow_id, path = %dir, %e, "failed to create dir (child may fail)");
            continue;
        }
        unsafe {
            let c_path = std::ffi::CString::new(dir.as_str()).unwrap();
            // chown to child UID:GID so the child process can write here.
            if libc::chown(c_path.as_ptr(), uid, gid) != 0 {
                warn!(workflow_id, uid, gid, path = %dir, "failed to chown dir");
            }
        }
    }
    // Create shared results directory (world-writable) for file-based
    // message passing between parent and children.
    {
        let results_dir = "/sandbox/.mediator/results";
        let _ = std::fs::create_dir_all(results_dir);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                results_dir,
                std::fs::Permissions::from_mode(0o1777), // sticky + world-writable
            );
        }
    }

    // Ensure intermediate policy dirs are world-traversable (o+x) so the
    // child UID can reach the workspace leaf directory.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let policy_parent = format!("/sandbox/.mediator/policies/{policy_name}");
        for dir in &["/sandbox/.mediator/policies", &policy_parent] {
            if let Ok(m) = std::fs::metadata(dir) {
                let mode = m.permissions().mode() | 0o0711; // owner rwx, others traverse
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode));
            }
        }
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
