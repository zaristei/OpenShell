// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Convert mediator policy types to proxy-facing types.
//!
//! The mediator uses `MediationPolicy` for syscall-level access control. The
//! proxy needs a simpler view: the HTTP allowlist for per-UID connection
//! decisions.

use super::MediationPolicy;
use crate::mediator::registry::WorkflowNetPolicy;

/// Convert a `MediationPolicy` to a `WorkflowNetPolicy` for the proxy
/// registry. Inheritance was dropped from the simplified mediator, so the
/// child's own policy is authoritative.
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
/// Patterns use shell-style wildcards (`*` matches anything including `/`).
/// This is deliberately more permissive than filesystem glob because URLs
/// aren't filesystem paths — `*` should match across path components.
/// Examples: `http://host:4000/*` matches `http://host:4000/v1/chat/completions`.
pub fn url_allowed_by_policy(url: &str, policy: &WorkflowNetPolicy) -> bool {
    policy
        .http_allowlist
        .iter()
        .any(|pattern| url_pattern_matches(pattern, url))
}

/// Match a URL against an allowlist pattern.
///
/// `*` matches zero or more of any character (including `/`).
/// `?` matches exactly one character.
fn url_pattern_matches(pattern: &str, url: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Strip trailing `*` for prefix matching: "http://host:4000/*" matches
    // any URL starting with "http://host:4000/".
    if let Some(prefix) = pattern.strip_suffix('*') {
        return url.starts_with(prefix);
    }
    // Exact match.
    pattern == url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mediation_policy_to_workflow_net_policy() {
        let policy = MediationPolicy {
            policy_name: "child_v1".into(),
            rationale: "test".into(),
            http_allowlist: vec!["https://api.example.com/*".into(), "https://data.io/*".into()],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        };

        let net = from_mediation_policy(&policy, "wf_1");
        assert_eq!(net.policy_name, "child_v1");
        assert_eq!(net.workflow_id, "wf_1");
        assert_eq!(net.http_allowlist.len(), 2);
    }

    #[test]
    fn url_pattern_matching() {
        // Prefix with wildcard matches paths
        assert!(url_pattern_matches("http://host:4000/*", "http://host:4000/"));
        assert!(url_pattern_matches("http://host:4000/*", "http://host:4000/v1"));
        assert!(url_pattern_matches("http://host:4000/*", "http://host:4000/v1/chat/completions"));
        // Scheme mismatch
        assert!(!url_pattern_matches("http://host:4000/*", "https://host:4000/v1"));
        // Exact match
        assert!(url_pattern_matches("http://host:4000", "http://host:4000"));
        assert!(!url_pattern_matches("http://host:4000", "http://host:4000/v1"));
        // Star alone
        assert!(url_pattern_matches("*", "anything"));
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
