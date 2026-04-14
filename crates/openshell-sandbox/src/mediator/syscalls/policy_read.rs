// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `policy_list` and `policy_get` syscalls: read approved policies.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::validate::fnmatch;
use std::collections::HashMap;

/// Parameters for `policy_get`.
#[derive(Debug, serde::Deserialize)]
pub struct PolicyGetParams {
    pub policy_name: String,
}

/// Entry returned by `policy_list` — just the name and rationale.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyListEntry {
    pub policy_name: String,
    pub rationale: String,
}

/// Execute the `policy_list` syscall.
///
/// Returns names of all approved policies visible to the caller
/// (matching `allowed_ipc_targets` patterns, plus own policy).
pub fn handle_policy_list(
    policies: &HashMap<String, MediationPolicy>,
    caller_policy: &MediationPolicy,
) -> Vec<PolicyListEntry> {
    policies
        .values()
        .filter(|p| {
            p.policy_name == caller_policy.policy_name
            || caller_policy
                .allowed_ipc_targets
                .iter()
                .any(|t| fnmatch(t.policy_pattern(), &p.policy_name))
        })
        .map(|p| PolicyListEntry {
            policy_name: p.policy_name.clone(),
            rationale: p.rationale.clone(),
        })
        .collect()
}

/// Execute the `policy_get` syscall.
///
/// Returns a single policy by name if it exists and is visible to the caller.
///
/// # Errors
///
/// Returns an error if the policy doesn't exist or isn't visible.
pub fn handle_policy_get(
    policies: &HashMap<String, MediationPolicy>,
    caller_policy: &MediationPolicy,
    params: PolicyGetParams,
) -> Result<MediationPolicy, String> {
    let policy = policies
        .get(&params.policy_name)
        .ok_or_else(|| format!("policy '{}' not found", params.policy_name))?;

    // Visibility check: caller can see own policy or policies matching IPC targets.
    let visible = policy.policy_name == caller_policy.policy_name
        || caller_policy
            .allowed_ipc_targets
            .iter()
            .any(|t| fnmatch(t.policy_pattern(), &policy.policy_name));

    if !visible {
        return Err(format!(
            "policy '{}' not visible to '{}'",
            params.policy_name, caller_policy.policy_name
        ));
    }

    Ok(policy.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::MediationPolicy;

    fn policy(name: &str) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        }
    }

    fn policy_with_targets(name: &str, targets: &[&str]) -> MediationPolicy {
        let mut p = policy(name);
        p.allowed_ipc_targets = targets.iter().map(|s| (*s).into()).collect();
        p
    }

    #[test]
    fn list_returns_names_of_own_and_targeted() {
        let mut all = HashMap::new();
        all.insert("coordinator_v1".into(), policy("coordinator_v1"));
        all.insert("fetcher_v1".into(), policy("fetcher_v1"));
        all.insert("analyzer_v1".into(), policy("analyzer_v1"));
        all.insert("secret_v1".into(), policy("secret_v1"));

        let caller = policy_with_targets("coordinator_v1", &["fetcher_*", "analyzer_*"]);
        let result = handle_policy_list(&all, &caller);

        let names: Vec<&str> = result.iter().map(|e| e.policy_name.as_str()).collect();
        assert!(names.contains(&"coordinator_v1"), "should see own policy");
        assert!(names.contains(&"fetcher_v1"), "should see fetcher");
        assert!(names.contains(&"analyzer_v1"), "should see analyzer");
        assert!(!names.contains(&"secret_v1"), "should NOT see secret");
    }

    #[test]
    fn list_with_wildcard_sees_all() {
        let mut all = HashMap::new();
        all.insert("a_v1".into(), policy("a_v1"));
        all.insert("b_v1".into(), policy("b_v1"));

        let caller = policy_with_targets("init_v0", &["*"]);
        let result = handle_policy_list(&all, &caller);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn list_with_no_targets_sees_only_own() {
        let mut all = HashMap::new();
        all.insert("lonely_v1".into(), policy("lonely_v1"));
        all.insert("other_v1".into(), policy("other_v1"));

        let caller = policy("lonely_v1");
        let result = handle_policy_list(&all, &caller);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].policy_name, "lonely_v1");
    }

    #[test]
    fn get_visible_policy() {
        let mut all = HashMap::new();
        all.insert("fetcher_v1".into(), policy("fetcher_v1"));

        let caller = policy_with_targets("coordinator_v1", &["fetcher_*"]);
        let result = handle_policy_get(&all, &caller, PolicyGetParams {
            policy_name: "fetcher_v1".into(),
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap().policy_name, "fetcher_v1");
    }

    #[test]
    fn get_own_policy() {
        let mut all = HashMap::new();
        all.insert("my_v1".into(), policy("my_v1"));

        let caller = policy("my_v1");
        let result = handle_policy_get(&all, &caller, PolicyGetParams {
            policy_name: "my_v1".into(),
        });
        assert!(result.is_ok());
    }

    #[test]
    fn get_invisible_policy_denied() {
        let mut all = HashMap::new();
        all.insert("secret_v1".into(), policy("secret_v1"));

        let caller = policy_with_targets("coordinator_v1", &["fetcher_*"]);
        let result = handle_policy_get(&all, &caller, PolicyGetParams {
            policy_name: "secret_v1".into(),
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not visible"));
    }

    #[test]
    fn get_nonexistent_policy() {
        let all = HashMap::new();
        let caller = policy("coordinator_v1");
        let result = handle_policy_get(&all, &caller, PolicyGetParams {
            policy_name: "nope_v1".into(),
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}
