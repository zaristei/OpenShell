// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SELinux file context labeling for namespace mounts.

use std::process::Command;
use tracing::warn;

/// Check whether SELinux is available on this system.
pub fn is_selinux_enabled() -> bool {
    Command::new("getenforce")
        .output()
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim() == "Enforcing" || stdout.trim() == "Permissive"
        })
        .unwrap_or(false)
}

/// Label a mount path with an SELinux context appropriate for the policy.
///
/// Runs `chcon` to set the context. Gracefully skips with a warning if
/// SELinux is not available or `chcon` fails.
pub fn label_mount(path: &str, policy_name: &str, mode: &str) {
    if !is_selinux_enabled() {
        warn!(path, "SELinux not available, skipping mount labeling");
        return;
    }

    // Map mode to an SELinux type hint.
    let se_type = match mode {
        "r" => "sandbox_ro_t",
        "rx" => "sandbox_rx_t",
        "rw" | "rwx" => "sandbox_rw_t",
        _ => "sandbox_ro_t",
    };

    let context = format!("system_u:object_r:{se_type}:s0:c{policy_name}");

    match Command::new("chcon").args(["-R", &context, path]).output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(path, %stderr, "chcon failed for mount path");
        }
        Err(e) => {
            warn!(path, %e, "failed to run chcon");
        }
    }
}
