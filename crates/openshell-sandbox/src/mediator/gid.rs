// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! GID allocator and group management for policy-based storage isolation.
//!
//! Each unique policy name gets a GID starting at 70000. GIDs are allocated
//! once per policy name and reused across all workflows that share that policy.
//! UIDs are added to the policy's group when a workflow is forked, and removed
//! on teardown.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use tracing::{info, warn};

/// Starting GID for policy groups.
const BASE_GID: u32 = 70_000;

/// Thread-safe GID allocator with policy-to-GID mapping.
#[derive(Debug)]
pub struct GidAllocator {
    next: AtomicU32,
    /// Maps policy_name → assigned GID.
    policy_to_gid: std::sync::RwLock<HashMap<String, u32>>,
}

impl GidAllocator {
    /// Create a new allocator starting at `BASE_GID`.
    pub fn new() -> Self {
        Self {
            next: AtomicU32::new(BASE_GID),
            policy_to_gid: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Get or create the GID for a policy name.
    ///
    /// If this is the first workflow for this policy, allocates a new GID.
    /// Otherwise returns the existing one.
    pub fn ensure_gid(&self, policy_name: &str) -> u32 {
        // Fast path: already allocated.
        {
            let guard = self.policy_to_gid.read().unwrap();
            if let Some(&gid) = guard.get(policy_name) {
                return gid;
            }
        }

        // Slow path: allocate new GID.
        let mut guard = self.policy_to_gid.write().unwrap();
        // Double-check after acquiring write lock.
        if let Some(&gid) = guard.get(policy_name) {
            return gid;
        }

        let gid = self.next.fetch_add(1, Ordering::Relaxed);
        guard.insert(policy_name.to_string(), gid);
        info!(policy = policy_name, gid, "allocated GID for policy");
        gid
    }

    /// Look up the GID for a policy name without allocating.
    pub fn get_gid(&self, policy_name: &str) -> Option<u32> {
        self.policy_to_gid.read().unwrap().get(policy_name).copied()
    }
}

impl Default for GidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Add a UID to a group (Linux-only).
///
/// On non-Linux, this is a no-op stub.
pub fn add_uid_to_group(uid: u32, gid: u32) {
    #[cfg(target_os = "linux")]
    {
        // Use groupadd/usermod to manage system groups.
        let group_name = format!("mediator_{gid}");

        // Create group if it doesn't exist.
        let _ = std::process::Command::new("groupadd")
            .args(["-g", &gid.to_string(), &group_name])
            .output();

        // Create user if it doesn't exist.
        let _ = std::process::Command::new("useradd")
            .args([
                "-u",
                &uid.to_string(),
                "-g",
                &gid.to_string(),
                "-M", // no home dir
                "-s",
                "/bin/false",
                &format!("mediator_{uid}"),
            ])
            .output();

        info!(uid, gid, "added UID to group");
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!(uid, gid, "add_uid_to_group stubbed (not Linux)");
    }
}

/// Remove a UID from a group (Linux-only).
pub fn remove_uid_from_group(uid: u32, _gid: u32) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("userdel")
            .arg(&format!("mediator_{uid}"))
            .output();

        info!(uid, _gid, "removed UID from group");
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!(uid, _gid, "remove_uid_from_group stubbed (not Linux)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_gid_allocates_once() {
        let alloc = GidAllocator::new();
        let gid1 = alloc.ensure_gid("policy_a");
        let gid2 = alloc.ensure_gid("policy_a");
        assert_eq!(gid1, gid2);
        assert_eq!(gid1, 70_000);
    }

    #[test]
    fn different_policies_get_different_gids() {
        let alloc = GidAllocator::new();
        let gid_a = alloc.ensure_gid("policy_a");
        let gid_b = alloc.ensure_gid("policy_b");
        assert_ne!(gid_a, gid_b);
    }

    #[test]
    fn get_gid_without_allocating() {
        let alloc = GidAllocator::new();
        assert!(alloc.get_gid("missing").is_none());
        alloc.ensure_gid("exists");
        assert!(alloc.get_gid("exists").is_some());
    }
}
