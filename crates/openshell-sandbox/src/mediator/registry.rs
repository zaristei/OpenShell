// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! UID→policy registry shared between the mediator and L7 proxy.
//!
//! When the mediator forks a workflow (via `fork_with_policy`), it registers
//! the UID and its effective policy in this registry. The proxy reads the
//! registry on each connection to determine per-UID network policy without
//! needing /proc scanning.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Effective policy for a UID-isolated workflow, as seen by the proxy.
#[derive(Debug, Clone)]
pub struct WorkflowNetPolicy {
    /// The workflow's effective HTTP allowlist (union-merged if inherited).
    pub http_allowlist: Vec<String>,
    /// Policy name for logging/audit.
    pub policy_name: String,
    /// Workflow ID for logging/audit.
    pub workflow_id: String,
}

/// Thread-safe registry mapping UID → effective network policy.
///
/// Shared via `Arc` between the mediator (writer) and proxy (reader).
#[derive(Debug, Clone, Default)]
pub struct UidPolicyRegistry {
    inner: Arc<RwLock<HashMap<u32, WorkflowNetPolicy>>>,
}

impl UidPolicyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a workflow's effective policy for a UID.
    ///
    /// Called by `fork_with_policy` after UID allocation.
    pub fn insert(&self, uid: u32, policy: WorkflowNetPolicy) {
        let mut guard = self.inner.write().unwrap();
        guard.insert(uid, policy);
    }

    /// Look up the effective policy for a UID.
    ///
    /// Called by the proxy on each TCP connection.
    pub fn get(&self, uid: u32) -> Option<WorkflowNetPolicy> {
        let guard = self.inner.read().unwrap();
        guard.get(&uid).cloned()
    }

    /// Remove a UID's policy (on workflow teardown).
    pub fn remove(&self, uid: u32) -> Option<WorkflowNetPolicy> {
        let mut guard = self.inner.write().unwrap();
        guard.remove(&uid)
    }

    /// Number of registered UIDs.
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let reg = UidPolicyRegistry::new();
        reg.insert(
            100_000,
            WorkflowNetPolicy {
                http_allowlist: vec!["https://api.example.com/*".into()],
                policy_name: "test_v1".into(),
                workflow_id: "wf_1".into(),
            },
        );

        let p = reg.get(100_000).unwrap();
        assert_eq!(p.policy_name, "test_v1");
        assert_eq!(p.http_allowlist.len(), 1);
    }

    #[test]
    fn missing_uid_returns_none() {
        let reg = UidPolicyRegistry::new();
        assert!(reg.get(99999).is_none());
    }

    #[test]
    fn remove_cleans_up() {
        let reg = UidPolicyRegistry::new();
        reg.insert(
            100_000,
            WorkflowNetPolicy {
                http_allowlist: vec![],
                policy_name: "p".into(),
                workflow_id: "wf".into(),
            },
        );
        assert_eq!(reg.len(), 1);
        reg.remove(100_000);
        assert!(reg.is_empty());
    }

    #[test]
    fn thread_safe_access() {
        let reg = UidPolicyRegistry::new();
        let reg2 = reg.clone();

        let handle = std::thread::spawn(move || {
            reg2.insert(
                100_001,
                WorkflowNetPolicy {
                    http_allowlist: vec!["*".into()],
                    policy_name: "thread_v1".into(),
                    workflow_id: "wf_t".into(),
                },
            );
        });

        handle.join().unwrap();
        assert!(reg.get(100_001).is_some());
    }
}
