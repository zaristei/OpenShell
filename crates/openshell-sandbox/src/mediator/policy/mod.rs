// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mediation policy schema and validation.

pub mod convert;
pub mod inherit;
pub mod scrub;
pub mod trust_spec;
pub mod validate;

use serde::{Deserialize, Serialize};

/// A mediation policy that governs what a workflow can do.
///
/// Once approved, policies are immutable — a new version must be proposed
/// under a new `policy_name`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MediationPolicy {
    /// Unique, immutable, versioned name (e.g. `"research_scraper_v1"`).
    pub policy_name: String,

    /// Free-text rationale for operator review.
    pub rationale: String,

    /// URL patterns for `http_request` (wildcards via `fnmatch`/glob).
    #[serde(default)]
    pub http_allowlist: Vec<String>,

    /// Filesystem paths provisioned via SELinux at fork.
    #[serde(default)]
    pub external_mounts: Vec<ExternalMount>,

    /// Policies that this one may fork into child namespaces.
    #[serde(default)]
    pub allowed_child_policies: Vec<ChildPolicyRef>,

    /// Inclusive port range for `request_port` `[min, max]`.
    #[serde(default)]
    pub bind_ports: Option<PortRange>,

    /// IPC targets reachable via `ipc_send`/`ipc_connect`/`ps`.
    /// Each entry is either a simple wildcard pattern or a configured
    /// target with optional per-direction scrubbing.
    #[serde(default)]
    pub allowed_ipc_targets: Vec<IpcTargetEntry>,

    /// Policies and signal types for the `signal` syscall.
    #[serde(default)]
    pub allowed_signal_targets: Vec<SignalTarget>,
}

/// A filesystem mount declared by a policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExternalMount {
    /// Absolute path to mount into the namespace.
    pub path: String,
    /// Access mode: `"r"`, `"rw"`, `"rx"`, or `"rwx"`.
    pub mode: String,
}

/// Reference to a child policy that may be forked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChildPolicyRef {
    /// Name or wildcard pattern for the child policy.
    pub policy_name: String,
    /// Whether the child inherits the parent's policy constraints.
    pub inherit: bool,
}

/// Inclusive port range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct PortRange(pub u16, pub u16);

/// A signal target declaration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalTarget {
    /// Policy name or wildcard pattern.
    pub policy_name: String,
    /// Allowed signal types (subset of `["term", "kill", "stop", "cont"]`).
    pub signals: Vec<String>,
}

/// An IPC target entry — either a bare string (backward compat) or a
/// configured target with optional scrub settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum IpcTargetEntry {
    /// Simple wildcard pattern (e.g. `"fetcher_*"`).
    Simple(String),
    /// Configured target with optional per-direction scrubbing.
    Configured(IpcTarget),
}

impl From<String> for IpcTargetEntry {
    fn from(s: String) -> Self {
        Self::Simple(s)
    }
}

impl From<&str> for IpcTargetEntry {
    fn from(s: &str) -> Self {
        Self::Simple(s.to_string())
    }
}

impl IpcTargetEntry {
    /// Extract the policy name pattern regardless of variant.
    pub fn policy_pattern(&self) -> &str {
        match self {
            Self::Simple(s) => s,
            Self::Configured(t) => &t.policy_name,
        }
    }

    /// Get the egress scrub config, if any.
    pub fn scrub_egress(&self) -> Option<&ScrubConfig> {
        match self {
            Self::Simple(_) => None,
            Self::Configured(t) => t.scrub_egress.as_ref(),
        }
    }

    /// Get the ingress scrub config, if any.
    pub fn scrub_ingress(&self) -> Option<&ScrubConfig> {
        match self {
            Self::Simple(_) => None,
            Self::Configured(t) => t.scrub_ingress.as_ref(),
        }
    }
}

/// A configured IPC target with per-direction scrubbing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpcTarget {
    /// Policy name or wildcard pattern.
    pub policy_name: String,
    /// Scrubber for caller → target direction.
    #[serde(default)]
    pub scrub_egress: Option<ScrubConfig>,
    /// Scrubber for target → caller direction.
    #[serde(default)]
    pub scrub_ingress: Option<ScrubConfig>,
}

/// Configuration for an IPC scrubber applied to a channel direction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScrubConfig {
    /// Scrubber name (e.g. `"regex_pii"`, `"field_pii"`, `"schema_enforcer"`,
    /// `"canary"`, `"delimiter"`, `"instruction_strip"`, `"ner_pii"`).
    pub scrubber: String,
    /// Which data-type tags this scrubber handles.
    pub data_types: Vec<String>,
    /// Whether scrubbing makes the data safe for these tags (removes taint).
    #[serde(default)]
    pub de_taints: bool,
    /// Scrubber-specific configuration (schema, fields, endpoint, etc.).
    #[serde(default)]
    pub config: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_YAML: &str = r#"
policy_name: "research_scraper_v1"
rationale: "Scrape whitelisted sites for research"
http_allowlist:
  - "https://api.example.com/*"
  - "https://*.wikipedia.org/*"
external_mounts:
  - path: "/data/research"
    mode: "rw"
  - path: "/usr/bin"
    mode: "rx"
allowed_child_policies:
  - policy_name: "fetcher_v1"
    inherit: true
bind_ports: [8080, 8099]
allowed_ipc_targets:
  - "fetcher_*"
allowed_signal_targets:
  - policy_name: "fetcher_*"
    signals: ["term", "kill"]
"#;

    #[test]
    fn round_trip() {
        let policy: MediationPolicy = serde_yml::from_str(EXAMPLE_YAML).unwrap();
        assert_eq!(policy.policy_name, "research_scraper_v1");
        assert_eq!(policy.http_allowlist.len(), 2);
        assert_eq!(policy.external_mounts.len(), 2);
        assert_eq!(policy.bind_ports, Some(PortRange(8080, 8099)));
        assert_eq!(policy.allowed_signal_targets[0].signals.len(), 2);
        // Simple IPC target deserialized via untagged
        assert_eq!(policy.allowed_ipc_targets.len(), 1);
        assert_eq!(policy.allowed_ipc_targets[0].policy_pattern(), "fetcher_*");

        // Serialize back and re-parse.
        let yaml = serde_yml::to_string(&policy).unwrap();
        let reparsed: MediationPolicy = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn ipc_target_entry_compat() {
        // Simple string form
        let simple: IpcTargetEntry = serde_json::from_str(r#""fetcher_*""#).unwrap();
        assert_eq!(simple.policy_pattern(), "fetcher_*");
        assert!(simple.scrub_egress().is_none());
        assert!(simple.scrub_ingress().is_none());

        // Configured form with scrub
        let configured: IpcTargetEntry = serde_json::from_str(
            r#"{"policy_name":"reader_*","scrub_egress":{"scrubber":"regex_pii","data_types":["pii"],"de_taints":true}}"#,
        )
        .unwrap();
        assert_eq!(configured.policy_pattern(), "reader_*");
        let egress = configured.scrub_egress().unwrap();
        assert_eq!(egress.scrubber, "regex_pii");
        assert_eq!(egress.data_types, vec!["pii"]);
        assert!(egress.de_taints);
        assert!(configured.scrub_ingress().is_none());
    }

    #[test]
    fn mixed_ipc_targets_in_policy() {
        let yaml = r#"
policy_name: "mixed_v1"
rationale: "test"
allowed_ipc_targets:
  - "simple_*"
  - policy_name: "configured_*"
    scrub_egress:
      scrubber: "regex_pii"
      data_types: ["pii"]
      de_taints: true
    scrub_ingress:
      scrubber: "passthrough"
      data_types: ["web_content"]
"#;
        let policy: MediationPolicy = serde_yml::from_str(yaml).unwrap();
        assert_eq!(policy.allowed_ipc_targets.len(), 2);
        assert_eq!(policy.allowed_ipc_targets[0].policy_pattern(), "simple_*");
        assert_eq!(
            policy.allowed_ipc_targets[1].policy_pattern(),
            "configured_*"
        );
        assert!(policy.allowed_ipc_targets[1].scrub_egress().is_some());
        assert!(policy.allowed_ipc_targets[1].scrub_ingress().is_some());
    }
}
