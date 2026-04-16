// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Namespace creation and management for forked workflows.

pub mod iptables;
pub mod selinux;
pub mod teardown;

use crate::mediator::policy::ExternalMount;
use tracing::{info, warn};

/// Handle to a created namespace.
///
/// On Linux, this represents a real PID + network + mount namespace created
/// via `clone()`. On other platforms, it's a stub wrapping a regular child PID.
#[derive(Debug)]
pub struct NamespaceHandle {
    /// Unique identifier for this namespace.
    pub namespace_id: String,
    /// Root PID of the process inside the namespace.
    pub root_pid: u32,
}

/// Create a new isolated namespace for a workflow.
///
/// On Linux, creates PID + network + mount namespaces. On other platforms,
/// returns a stub handle (the "child" is just conceptual for development).
///
/// # Errors
///
/// Returns an error string if namespace creation fails.
pub fn create_namespace(
    namespace_id: &str,
    external_mounts: &[ExternalMount],
) -> Result<NamespaceHandle, String> {
    #[cfg(target_os = "linux")]
    {
        create_namespace_linux(namespace_id, external_mounts)
    }

    #[cfg(not(target_os = "linux"))]
    {
        create_namespace_stub(namespace_id, external_mounts)
    }
}

/// Linux: create real PID + network + mount namespaces via clone().
#[cfg(target_os = "linux")]
fn create_namespace_linux(
    namespace_id: &str,
    external_mounts: &[ExternalMount],
) -> Result<NamespaceHandle, String> {
    use libc::{CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, SIGCHLD};

    const STACK_SIZE: usize = 1024 * 1024; // 1 MiB child stack

    // Allocate stack for the child.
    let mut stack = vec![0u8; STACK_SIZE];
    let stack_top = stack.as_mut_ptr().wrapping_add(STACK_SIZE);

    let flags = CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | SIGCHLD;

    // The child function: just pause (the parent will manage it).
    extern "C" fn child_fn(_arg: *mut libc::c_void) -> libc::c_int {
        // The child sits in pause() until signalled.
        unsafe { libc::pause() };
        0
    }

    let pid = unsafe { libc::clone(child_fn, stack_top.cast(), flags, std::ptr::null_mut()) };

    if pid == -1 {
        return Err(format!(
            "clone() failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    info!(namespace_id, pid, "created namespace via clone()");

    // Label external mounts with SELinux contexts.
    for mount in external_mounts {
        selinux::label_mount(&mount.path, namespace_id, &mount.mode);
    }

    Ok(NamespaceHandle {
        namespace_id: namespace_id.into(),
        root_pid: pid as u32,
    })
}

/// Non-Linux stub: just allocate a handle with a fake PID.
///
/// This allows development and testing on macOS. The "namespace" is purely
/// conceptual — no actual isolation is applied.
#[cfg(not(target_os = "linux"))]
fn create_namespace_stub(
    namespace_id: &str,
    external_mounts: &[ExternalMount],
) -> Result<NamespaceHandle, String> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT_PID: AtomicU32 = AtomicU32::new(10000);

    let fake_pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);

    warn!(
        namespace_id,
        fake_pid,
        mounts = external_mounts.len(),
        "namespace creation stubbed (not Linux)"
    );

    Ok(NamespaceHandle {
        namespace_id: namespace_id.into(),
        root_pid: fake_pid,
    })
}
