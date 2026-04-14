// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Convert mediator policy types to proxy-facing types.
//!
//! The mediator uses `MediationPolicy` / `ResolvedPolicy` for syscall-level
//! access control. The proxy needs a simpler view: the HTTP allowlist for
//! per-UID connection decisions.

use super::MediationPolicy;
use super::inherit::ResolvedPolicy;
use crate::mediator::registry::WorkflowNetPolicy;

/// Convert a `ResolvedPolicy` (inheritance-aware) to a `WorkflowNetPolicy`
/// for the proxy registry.
pub fn to_workflow_net_policy(
    resolved: &ResolvedPolicy,
    workflow_id: &str,
) -> WorkflowNetPolicy {
    WorkflowNetPolicy {
        http_allowlist: resolved.http_allowlist.clone(),
        policy_name: resolved.primary_policy_name.clone(),
        workflow_id: workflow_id.to_string(),
    }
}

/// Convert a raw `MediationPolicy` (no inheritance) to a `WorkflowNetPolicy`.
pub fn from_mediation_policy(
    policy: &MediationPolicy,
    workflow_id: &str,
) -> WorkflowNetPolicy {
    WorkflowNetPolicy {
        http_allowlist: policy.http_allowlist.clone(),
        policy_name: policy.policy_name.clone(),
        workflow_id: workflow_id.to_string(),
    }
}

/// Check if a URL is allowed by a workflow's HTTP allowlist.
///
/// Uses the same `fnmatch` matching as the mediator's `url_allowed`.
pub fn url_allowed_by_policy(url: &str, policy: &WorkflowNetPolicy) -> bool {
    use super::validate::fnmatch;
    policy
        .http_allowlist
        .iter()
        .any(|pattern| fnmatch(pattern, url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_to_workflow_net_policy() {
        let resolved = ResolvedPolicy {
            http_allowlist: vec!["https://api.example.com/*".into(), "https://data.io/*".into()],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
            primary_policy_name: "child_v1".into(),
            parent_policy_name: Some("parent_v1".into()),
        };

        let net = to_workflow_net_policy(&resolved, "wf_1");
        assert_eq!(net.policy_name, "child_v1");
        assert_eq!(net.workflow_id, "wf_1");
        assert_eq!(net.http_allowlist.len(), 2);
    }

    #[test]
    fn url_matching() {
        let policy = WorkflowNetPolicy {
            http_allowlist: vec!["https://api.example.com/*".into()],
            policy_name: "test".into(),
            workflow_id: "wf".into(),
        };

        assert!(url_allowed_by_policy("https://api.example.com/v1/data", &policy));
        assert!(!url_allowed_by_policy("https://evil.com/steal", &policy));
    }

    #[test]
    fn wildcard_allows_all() {
        let policy = WorkflowNetPolicy {
            http_allowlist: vec!["*".into()],
            policy_name: "init_v0".into(),
            workflow_id: "init".into(),
        };

        assert!(url_allowed_by_policy("https://anything.com/path", &policy));
    }
}
