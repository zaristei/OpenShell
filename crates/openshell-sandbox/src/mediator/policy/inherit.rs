// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy inheritance resolution.
//!
//! When a workflow token has `inherited_from` set, syscalls are evaluated
//! against both the child's own policy and the parent's policy. This module
//! computes the effective (resolved) policy.

use super::{IpcTargetEntry, MediationPolicy};
use super::validate::fnmatch;

/// The effective policy after resolving inheritance.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// HTTP allowlist: union of parent and child when inheriting.
    pub http_allowlist: Vec<String>,
    /// Child's own child-fork permissions (not inherited).
    pub allowed_child_policies: Vec<super::ChildPolicyRef>,
    /// Child's own port range (not inherited).
    pub bind_ports: Option<super::PortRange>,
    /// IPC targets: union of parent and child when inheriting.
    pub allowed_ipc_targets: Vec<IpcTargetEntry>,
    /// Signal targets: union of parent and child when inheriting.
    pub allowed_signal_targets: Vec<super::SignalTarget>,
    /// Which policy was primary (for audit logging).
    pub primary_policy_name: String,
    /// Parent policy name, if inherited.
    pub parent_policy_name: Option<String>,
}

/// Resolve the effective policy for a workflow.
///
/// If `parent` is `None`, the child's own policy is used as-is.
/// If `parent` is `Some`, inheritable fields (`http_allowlist`,
/// `allowed_ipc_targets`, `allowed_signal_targets`) are the union of both
/// policies. Inheritance is one-directional: the child gains access to
/// everything in the parent's allowlists, but the parent's policy is never
/// modified.
pub fn resolve(child: &MediationPolicy, parent: Option<&MediationPolicy>) -> ResolvedPolicy {
    let (http_allowlist, allowed_ipc_targets, allowed_signal_targets) = match parent {
        Some(p) => (
            union_allowlists(&child.http_allowlist, &p.http_allowlist),
            union_ipc_targets(&child.allowed_ipc_targets, &p.allowed_ipc_targets),
            union_signal_targets(&child.allowed_signal_targets, &p.allowed_signal_targets),
        ),
        None => (
            child.http_allowlist.clone(),
            child.allowed_ipc_targets.clone(),
            child.allowed_signal_targets.clone(),
        ),
    };

    ResolvedPolicy {
        http_allowlist,
        allowed_child_policies: child.allowed_child_policies.clone(),
        bind_ports: child.bind_ports,
        allowed_ipc_targets,
        allowed_signal_targets,
        primary_policy_name: child.policy_name.clone(),
        parent_policy_name: parent.map(|p| p.policy_name.clone()),
    }
}

/// Compute the union of two URL allowlists, deduplicating exact matches.
fn union_allowlists(child: &[String], parent: &[String]) -> Vec<String> {
    let mut combined = child.to_vec();
    for p in parent {
        if !combined.iter().any(|c| c == p) {
            combined.push(p.clone());
        }
    }
    combined
}

/// Compute the union of two IPC target lists, deduplicating by policy pattern.
fn union_ipc_targets(child: &[IpcTargetEntry], parent: &[IpcTargetEntry]) -> Vec<IpcTargetEntry> {
    let mut combined = child.to_vec();
    for p in parent {
        if !combined
            .iter()
            .any(|c| c.policy_pattern() == p.policy_pattern())
        {
            combined.push(p.clone());
        }
    }
    combined
}

/// Compute the union of two signal target lists, deduplicating exact matches.
fn union_signal_targets(
    child: &[super::SignalTarget],
    parent: &[super::SignalTarget],
) -> Vec<super::SignalTarget> {
    let mut combined = child.to_vec();
    for p in parent {
        if !combined.iter().any(|c| c.policy_name == p.policy_name && c.signals == p.signals) {
            combined.push(p.clone());
        }
    }
    combined
}

/// Check at request time whether a concrete URL is allowed by a resolved
/// policy's `http_allowlist`.
pub fn url_allowed(url: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|pattern| fnmatch(pattern, url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::{MediationPolicy, PortRange};

    fn policy(name: &str, http: &[&str]) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
            rationale: "test".into(),
            http_allowlist: http.iter().map(|s| (*s).into()).collect(),
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        }
    }

    #[test]
    fn no_parent_uses_child_as_is() {
        let child = policy("c", &["https://api.example.com/*"]);
        let resolved = resolve(&child, None);
        assert_eq!(resolved.http_allowlist.len(), 1);
        assert!(resolved.parent_policy_name.is_none());
    }

    #[test]
    fn wildcard_parent_adds_to_child() {
        let child = policy("c", &["https://api.example.com/*", "https://data.io/*"]);
        let parent = policy("p", &["*"]);
        let resolved = resolve(&child, Some(&parent));
        // Union: child's 2 patterns + parent's "*" = 3
        assert_eq!(resolved.http_allowlist.len(), 3);
        assert!(resolved.http_allowlist.contains(&"*".to_string()));
    }

    #[test]
    fn disjoint_allowlists_produce_union() {
        let child = policy("c", &["https://child-only.com/*"]);
        let parent = policy("p", &["https://parent-only.com/*"]);
        let resolved = resolve(&child, Some(&parent));
        assert_eq!(resolved.http_allowlist.len(), 2);
        assert!(resolved.http_allowlist.contains(&"https://child-only.com/*".to_string()));
        assert!(resolved.http_allowlist.contains(&"https://parent-only.com/*".to_string()));
    }

    #[test]
    fn overlapping_patterns_deduplicated() {
        let child = policy("c", &["https://api.example.com/*", "https://evil.com/*"]);
        let parent = policy("p", &["https://api.example.com/*"]);
        let resolved = resolve(&child, Some(&parent));
        // Union with dedup: child's two + parent's one (already present) = 2
        assert_eq!(resolved.http_allowlist.len(), 2);
        assert!(resolved.http_allowlist.contains(&"https://api.example.com/*".to_string()));
        assert!(resolved.http_allowlist.contains(&"https://evil.com/*".to_string()));
    }

    #[test]
    fn child_gets_union_parent_unchanged() {
        let child = policy("c", &["https://child.com/*"]);
        let parent = policy("p", &["https://parent.com/*"]);
        let resolved = resolve(&child, Some(&parent));
        // Child's effective policy is union
        assert_eq!(resolved.http_allowlist.len(), 2);
        // Parent's original policy is NOT mutated
        assert_eq!(parent.http_allowlist, vec!["https://parent.com/*"]);
    }

    #[test]
    fn bind_ports_and_child_policies_not_inherited() {
        let mut child = policy("c", &["*"]);
        child.bind_ports = Some(PortRange(8080, 8099));

        let mut parent = policy("p", &["*"]);
        parent.bind_ports = Some(PortRange(9000, 9099));

        let resolved = resolve(&child, Some(&parent));

        // bind_ports comes from child only
        assert_eq!(resolved.bind_ports, Some(PortRange(8080, 8099)));
    }

    #[test]
    fn ipc_targets_inherited_as_union() {
        let mut child = policy("c", &["*"]);
        child.allowed_ipc_targets = vec!["fetcher_*".into()];

        let mut parent = policy("p", &["*"]);
        parent.allowed_ipc_targets = vec!["logger_*".into()];

        let resolved = resolve(&child, Some(&parent));

        assert_eq!(resolved.allowed_ipc_targets.len(), 2);
        assert!(resolved
            .allowed_ipc_targets
            .iter()
            .any(|t| t.policy_pattern() == "fetcher_*"));
        assert!(resolved
            .allowed_ipc_targets
            .iter()
            .any(|t| t.policy_pattern() == "logger_*"));
    }

    #[test]
    fn url_allowed_matches() {
        let list = vec![
            "https://api.example.com/*".into(),
            "https://data.io/v1/*".into(),
        ];
        assert!(url_allowed("https://api.example.com/foo", &list));
        assert!(url_allowed("https://data.io/v1/bar", &list));
        assert!(!url_allowed("https://evil.com/steal", &list));
    }
}
