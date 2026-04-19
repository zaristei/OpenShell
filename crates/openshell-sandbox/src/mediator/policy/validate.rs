// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Policy validation rules.

use super::{MediationPolicy, PortRange};
use std::collections::HashSet;

/// Errors produced during policy validation.
#[derive(Debug, thiserror::Error)]
pub enum PolicyValidationError {
    #[error("policy_name is empty")]
    EmptyName,

    #[error("policy_name '{0}' already exists (policies are immutable)")]
    NameConflict(String),

    #[error("bind_ports: min ({0}) > max ({1})")]
    PortRangeInverted(u16, u16),

    #[error("bind_ports: port {0} is below 1024 (reserved)")]
    PortReserved(u16),

    #[error("external_mount path must be absolute: '{0}'")]
    RelativeMountPath(String),

    #[error("external_mount path must not contain '..': '{0}'")]
    TraversalInMountPath(String),

    #[error("external_mount mode '{0}' is invalid (expected r, rw, rx, rwx)")]
    InvalidMountMode(String),

    #[error("signal '{0}' is not recognised (expected term, kill, stop, cont)")]
    InvalidSignal(String),
}

const VALID_MODES: &[&str] = &["r", "rw", "rx", "rwx"];
const VALID_SIGNALS: &[&str] = &["term", "kill", "stop", "cont"];

/// Validate a policy against the schema rules.
///
/// `existing_names` is the set of already-approved policy names; used to
/// enforce immutability (no duplicate names).
///
/// # Errors
///
/// Returns the first validation error found.
pub fn validate(
    policy: &MediationPolicy,
    existing_names: &HashSet<String>,
) -> Result<(), PolicyValidationError> {
    if policy.policy_name.is_empty() {
        return Err(PolicyValidationError::EmptyName);
    }
    if existing_names.contains(&policy.policy_name) {
        return Err(PolicyValidationError::NameConflict(
            policy.policy_name.clone(),
        ));
    }

    // Port range.
    if let Some(PortRange(min, max)) = policy.bind_ports {
        if min > max {
            return Err(PolicyValidationError::PortRangeInverted(min, max));
        }
        if min < 1024 {
            return Err(PolicyValidationError::PortReserved(min));
        }
    }

    // External mounts.
    for m in &policy.external_mounts {
        if !m.path.starts_with('/') {
            return Err(PolicyValidationError::RelativeMountPath(m.path.clone()));
        }
        if m.path.contains("..") {
            return Err(PolicyValidationError::TraversalInMountPath(m.path.clone()));
        }
        if !VALID_MODES.contains(&m.mode.as_str()) {
            return Err(PolicyValidationError::InvalidMountMode(m.mode.clone()));
        }
    }

    // Signal targets.
    for st in &policy.allowed_signal_targets {
        for sig in &st.signals {
            if !VALID_SIGNALS.contains(&sig.as_str()) {
                return Err(PolicyValidationError::InvalidSignal(sig.clone()));
            }
        }
    }

    Ok(())
}

/// Check whether `name` matches a `pattern` using shell-style wildcards.
///
/// Supports `*` (match any sequence) and `?` (match one character).
pub fn fnmatch(pattern: &str, name: &str) -> bool {
    glob::Pattern::new(pattern).is_ok_and(|p| p.matches(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::{ExternalMount, MediationPolicy, PortRange, SignalTarget};

    fn base_policy() -> MediationPolicy {
        MediationPolicy {
            policy_name: "test_v1".into(),
            rationale: "testing".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        }
    }

    #[test]
    fn valid_policy_passes() {
        let p = base_policy();
        assert!(validate(&p, &HashSet::new()).is_ok());
    }

    #[test]
    fn empty_name_rejected() {
        let mut p = base_policy();
        p.policy_name = String::new();
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::EmptyName)
        ));
    }

    #[test]
    fn duplicate_name_rejected() {
        let p = base_policy();
        let mut existing = HashSet::new();
        existing.insert("test_v1".into());
        assert!(matches!(
            validate(&p, &existing),
            Err(PolicyValidationError::NameConflict(_))
        ));
    }

    #[test]
    fn port_range_inverted() {
        let mut p = base_policy();
        p.bind_ports = Some(PortRange(9000, 8000));
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::PortRangeInverted(9000, 8000))
        ));
    }

    #[test]
    fn port_range_reserved() {
        let mut p = base_policy();
        p.bind_ports = Some(PortRange(80, 8080));
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::PortReserved(80))
        ));
    }

    #[test]
    fn relative_mount_path_rejected() {
        let mut p = base_policy();
        p.external_mounts = vec![ExternalMount {
            path: "relative/path".into(),
            mode: "r".into(),
        }];
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::RelativeMountPath(_))
        ));
    }

    #[test]
    fn traversal_mount_path_rejected() {
        let mut p = base_policy();
        p.external_mounts = vec![ExternalMount {
            path: "/data/../etc/shadow".into(),
            mode: "r".into(),
        }];
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::TraversalInMountPath(_))
        ));
    }

    #[test]
    fn invalid_mount_mode() {
        let mut p = base_policy();
        p.external_mounts = vec![ExternalMount {
            path: "/data".into(),
            mode: "rwxs".into(),
        }];
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::InvalidMountMode(_))
        ));
    }

    #[test]
    fn invalid_signal() {
        let mut p = base_policy();
        p.allowed_signal_targets = vec![SignalTarget {
            policy_name: "*".into(),
            signals: vec!["hup".into()],
        }];
        assert!(matches!(
            validate(&p, &HashSet::new()),
            Err(PolicyValidationError::InvalidSignal(_))
        ));
    }

    #[test]
    fn fnmatch_basics() {
        assert!(fnmatch("fetcher_*", "fetcher_v1"));
        assert!(fnmatch("fetcher_*", "fetcher_v2_beta"));
        assert!(!fnmatch("fetcher_*", "scraper_v1"));
        assert!(fnmatch("*", "anything"));
        assert!(fnmatch("test_?", "test_a"));
        assert!(!fnmatch("test_?", "test_ab"));
    }
}
