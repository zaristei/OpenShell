// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `policy_propose` syscall: request new capabilities.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::trust_spec::{self, TrustSpec};
use crate::mediator::policy::validate::{self, PolicyValidationError};
use crate::mediator::store::queries;
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

/// Validate that a proposed policy's filesystem mounts are subpaths of the
/// sandbox's allowed paths (`FilesystemPolicy.read_only ∪ read_write`).
///
/// Returns `Ok(())` if every mount is a subpath of at least one entry in
/// `sandbox_fs_paths`. Returns `Err(detail)` with the first offending mount
/// on failure. When `sandbox_fs_paths` is empty the check is skipped —
/// used in tests and for backward compat with deployments that don't yet
/// plumb the sandbox policy.
pub(crate) fn check_fs_subset(
    proposed: &MediationPolicy,
    sandbox_fs_paths: &[PathBuf],
) -> Result<(), String> {
    if sandbox_fs_paths.is_empty() {
        return Ok(());
    }
    for mount in &proposed.external_mounts {
        let mount_path = Path::new(&mount.path);
        let admissible = sandbox_fs_paths
            .iter()
            .any(|allowed| mount_path.starts_with(allowed));
        if !admissible {
            return Err(format!(
                "external_mount '{}' is not a subpath of any sandbox filesystem entry (sandbox allows: {:?})",
                mount.path, sandbox_fs_paths
            ));
        }
    }
    Ok(())
}

/// Parameters for `policy_propose`.
#[derive(Debug, serde::Deserialize)]
pub struct PolicyProposeParams {
    pub config: MediationPolicy,
}

/// Execute the `policy_propose` syscall.
///
/// When `approval_bridge_url` is `Some`, sends the proposal to the Telegram
/// approval bridge and polls for a decision. When `None`, the proposal is
/// auto-DENIED — fail-closed by default. Tests that need auto-approval must
/// opt in via `MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE=1`. This prevents an agent
/// from silently escalating its own privileges in a misconfigured deployment
/// where the operator forgot to wire up the approval bridge.
///
/// # Errors
///
/// Returns an error if validation fails or the proposal is denied.
pub async fn handle_policy_propose(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    params: PolicyProposeParams,
    approval_bridge_url: Option<&str>,
    webhook_secret: Option<&str>,
    trust_spec: Option<&Arc<TrustSpec>>,
    sandbox_fs_paths: &[PathBuf],
) -> Result<serde_json::Value, String> {
    // Subset check against the live sandbox policy. Filesystem only for
    // now — network subset is still enforced at runtime by the proxy's
    // UidPolicyRegistry fast path. This check catches mounts that the
    // sandbox never granted, so the bridge is never asked to approve
    // something the sandbox filesystem can't actually deliver.
    check_fs_subset(&params.config, sandbox_fs_paths)
        .map_err(|detail| format!("subset_check_failed: {detail}"))?;

    // Build existing names set for immutability check.
    let taint_warnings = {
        let guard = policies.read().await;
        let existing: HashSet<String> = guard.keys().cloned().collect();
        validate::validate(&params.config, &existing)
            .map_err(|e: PolicyValidationError| e.to_string())?;

        // Run taint analysis if trust spec is available.
        trust_spec.map(|spec| {
            let approved: HashMap<String, MediationPolicy> =
                guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            let self_taint = trust_spec::analyze_policy(&params.config, &approved, spec);
            let affected = trust_spec::analyze_affected(&params.config, &approved, spec);
            (self_taint, affected)
        })
    };

    // Log any taint warnings.
    if let Some((ref self_taint, ref affected)) = taint_warnings {
        if self_taint.any_trifecta {
            warn!(
                policy = %params.config.policy_name,
                violations = self_taint.violation_paths.len(),
                "proposed policy has lethal trifecta violations"
            );
        }
        for a in affected {
            if a.any_trifecta {
                warn!(
                    affected_policy = %a.policy_name,
                    violations = a.violation_paths.len(),
                    "approving '{}' would create trifecta for '{}'",
                    params.config.policy_name,
                    a.policy_name,
                );
            }
        }
    }

    // Re-read approval bridge URL at runtime from the config file. This
    // solves the boot-ordering problem: the PVC is empty when PID 1 boots,
    // so the config file (with the bridge URL) is written AFTER bootstrap.
    // Reading it here means policy_propose picks up the bridge URL as soon
    // as the config file appears — no pod restart needed.
    let runtime_bridge: Option<String> = approval_bridge_url.map(String::from).or_else(|| {
        std::fs::read_to_string("/sandbox/.mediator/config.json")
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|c| c.get("APPROVAL_BRIDGE_URL")?.as_str().map(String::from))
            .filter(|s| !s.is_empty())
    });

    // If no approval bridge, fail-closed: auto-DENY unless the test escape
    // hatch is set.
    let Some(bridge_url) = runtime_bridge.as_deref() else {
        let auto_approve = std::env::var("MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or_else(|_| {
                // Fall back to config file (embedded mode may not have env vars).
                std::fs::read_to_string("/sandbox/.mediator/config.json")
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|c| c.get("MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE")?.as_str().map(String::from))
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
            });
        if !auto_approve {
            warn!(
                policy = %params.config.policy_name,
                "policy_propose denied: no approval bridge configured (set MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE=1 in tests only)"
            );
            return Err(
                "policy_propose denied: no approval bridge configured. \
                 Configure --approval-bridge-url to enable operator review, \
                 or set MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE=1 for tests."
                    .to_string(),
            );
        }
        let mut guard = policies.write().await;
        let mut result = serde_json::json!({"approved": true, "reason": "auto-approved (no approval bridge, test mode)"});
        // Include taint warnings in result even for auto-approve.
        if let Some((ref self_taint, ref affected)) = taint_warnings {
            if self_taint.any_trifecta || !affected.is_empty() {
                result["taint_warnings"] = serde_json::json!({
                    "self": self_taint,
                    "affected": affected,
                });
            }
        }
        guard.insert(params.config.policy_name.clone(), params.config);
        drop(guard);
        // Store taint classification.
        if let Some((self_taint, affected)) = taint_warnings {
            store_taint_on_approval(pool, &self_taint, &affected).await;
        }
        return Ok(result);
    };

    // Generate a unique proposal ID.
    let proposal_id = format!(
        "prop_{}_{}",
        params.config.policy_name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );

    // POST to approval bridge.
    let client = reqwest::Client::new();
    let webhook_url = format!("{bridge_url}/webhook");
    let mut payload = serde_json::json!({
        "event": "mediator_policy_proposal",
        "proposal_id": proposal_id,
        "config": params.config,
    });

    // Include taint warnings in the approval bridge payload.
    if let Some((ref self_taint, ref affected)) = taint_warnings {
        if self_taint.any_trifecta || !affected.is_empty() {
            payload["taint_warnings"] = serde_json::json!({
                "self": self_taint,
                "affected": affected,
            });
        }
    }

    // Read webhook_secret from config file if not passed at boot (same
    // boot-ordering fix as APPROVAL_BRIDGE_URL).
    let runtime_secret: Option<String> = webhook_secret.map(String::from).or_else(|| {
        std::fs::read_to_string("/sandbox/.mediator/config.json")
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|c| c.get("WEBHOOK_SECRET")?.as_str().map(String::from))
            .filter(|s| !s.is_empty())
    });

    info!(proposal_id = %proposal_id, policy = %params.config.policy_name, "sending policy proposal to approval bridge");

    super::post_to_bridge(&client, &webhook_url, &payload, runtime_secret.as_deref()).await?;

    // Poll for decision.
    let poll_url = format!("{bridge_url}/policy-decisions");
    let poll_interval = std::time::Duration::from_secs(2);
    let timeout = std::time::Duration::from_secs(300); // 5 minute timeout
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err("policy proposal timed out waiting for approval".into());
        }

        tokio::time::sleep(poll_interval).await;

        let resp = client
            .get(&poll_url)
            .send()
            .await
            .map_err(|e| format!("failed to poll decisions: {e}"))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("bad decision response: {e}"))?;

        let decisions = body["decisions"].as_array();
        if let Some(decisions) = decisions {
            for decision in decisions {
                if decision["proposal_id"].as_str() == Some(&proposal_id) {
                    let approved = decision["approved"].as_bool().unwrap_or(false);
                    let reason = decision["reason"]
                        .as_str()
                        .unwrap_or("no reason")
                        .to_string();

                    if approved {
                        info!(proposal_id = %proposal_id, "policy approved: {reason}");
                        let mut guard = policies.write().await;
                        guard.insert(params.config.policy_name.clone(), params.config);
                        drop(guard);
                        if let Some((self_taint, affected)) = taint_warnings {
                            store_taint_on_approval(pool, &self_taint, &affected).await;
                        }
                        return Ok(serde_json::json!({"approved": true, "reason": reason}));
                    } else {
                        warn!(proposal_id = %proposal_id, "policy denied: {reason}");
                        return Err(format!("policy denied: {reason}"));
                    }
                }
            }
        }
    }
}

/// Store policy taint classification and update affected policies on approval.
async fn store_taint_on_approval(
    pool: &SqlitePool,
    self_taint: &trust_spec::PolicyTaint,
    affected: &[trust_spec::PolicyTaint],
) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    // Store the new policy's taint.
    if let Ok(json) = serde_json::to_string(self_taint) {
        if let Err(e) = queries::upsert_policy_taint(pool, &self_taint.policy_name, &json, &now)
            .await
        {
            warn!(policy = %self_taint.policy_name, %e, "failed to store policy taint");
        }
    }

    // Update affected policies' taint.
    for a in affected {
        if let Ok(json) = serde_json::to_string(a) {
            if let Err(e) = queries::upsert_policy_taint(pool, &a.policy_name, &json, &now).await {
                warn!(policy = %a.policy_name, %e, "failed to update affected policy taint");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::ExternalMount;
    use crate::mediator::store::MediatorStore;
    use tokio::sync::RwLock;

    fn policy_with_mounts(name: &str, paths: &[&str]) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: paths
                .iter()
                .map(|p| ExternalMount {
                    path: (*p).into(),
                    mode: "r".into(),
                })
                .collect(),
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        }
    }

    #[test]
    fn fs_subset_skipped_when_sandbox_paths_empty() {
        let p = policy_with_mounts("test", &["/anywhere"]);
        assert!(check_fs_subset(&p, &[]).is_ok());
    }

    #[test]
    fn fs_subset_accepts_exact_match() {
        let p = policy_with_mounts("test", &["/workspace"]);
        let sandbox = vec![PathBuf::from("/workspace")];
        assert!(check_fs_subset(&p, &sandbox).is_ok());
    }

    #[test]
    fn fs_subset_accepts_subpath() {
        let p = policy_with_mounts("test", &["/workspace/fetcher"]);
        let sandbox = vec![PathBuf::from("/workspace")];
        assert!(check_fs_subset(&p, &sandbox).is_ok());
    }

    #[test]
    fn fs_subset_rejects_path_outside_sandbox() {
        let p = policy_with_mounts("test", &["/etc/secrets"]);
        let sandbox = vec![PathBuf::from("/workspace"), PathBuf::from("/tmp")];
        let err = check_fs_subset(&p, &sandbox).unwrap_err();
        assert!(err.contains("/etc/secrets"));
        assert!(err.contains("not a subpath"));
    }

    #[test]
    fn fs_subset_rejects_sibling_prefix_trap() {
        // /workspace-other is NOT a subpath of /workspace even though
        // "/workspace-other".starts_with("/workspace") is true as a string.
        // PathBuf::starts_with handles components correctly.
        let p = policy_with_mounts("test", &["/workspace-other/data"]);
        let sandbox = vec![PathBuf::from("/workspace")];
        assert!(check_fs_subset(&p, &sandbox).is_err());
    }

    fn empty_policies() -> Arc<RwLock<HashMap<String, MediationPolicy>>> {
        Arc::new(RwLock::new(HashMap::new()))
    }

    async fn test_pool() -> MediatorStore {
        // Unit tests opt in to the legacy auto-approve fallback. Production
        // fail-closes when no approval bridge is configured.
        // SAFETY: cargo test runs each test binary in its own process.
        unsafe { std::env::set_var("MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE", "1") };
        MediatorStore::open("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn propose_valid_policy_auto_approve() {
        let store = test_pool().await;
        let policies = empty_policies();
        let params = PolicyProposeParams {
            config: MediationPolicy {
                policy_name: "new_v1".into(),
                rationale: "testing".into(),
                http_allowlist: vec!["https://api.example.com/*".into()],
                external_mounts: vec![],
                allowed_child_policies: vec![],
                bind_ports: None,
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
            },
        };

        let result = handle_policy_propose(store.pool(), &policies, params, None, None, None, &[])
            .await
            .unwrap();
        assert_eq!(result["approved"], true);
        assert!(policies.read().await.contains_key("new_v1"));
    }

    #[tokio::test]
    async fn propose_duplicate_rejected() {
        let store = test_pool().await;
        let policies = empty_policies();

        let p = MediationPolicy {
            policy_name: "dup_v1".into(),
            rationale: "t".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
        };
        policies.write().await.insert("dup_v1".into(), p.clone());

        let params = PolicyProposeParams { config: p };
        let err = handle_policy_propose(store.pool(), &policies, params, None, None, None, &[])
            .await
            .unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[tokio::test]
    async fn propose_invalid_policy_rejected() {
        let store = test_pool().await;
        let policies = empty_policies();
        let params = PolicyProposeParams {
            config: MediationPolicy {
                policy_name: String::new(),
                rationale: "t".into(),
                http_allowlist: vec![],
                external_mounts: vec![],
                allowed_child_policies: vec![],
                bind_ports: None,
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
            },
        };

        let err = handle_policy_propose(store.pool(), &policies, params, None, None, None, &[])
            .await
            .unwrap_err();
        assert!(err.contains("empty"));
    }

    #[tokio::test]
    async fn propose_with_unreachable_bridge_fails() {
        let store = test_pool().await;
        let policies = empty_policies();
        let params = PolicyProposeParams {
            config: MediationPolicy {
                policy_name: "bridge_test_v1".into(),
                rationale: "testing".into(),
                http_allowlist: vec![],
                external_mounts: vec![],
                allowed_child_policies: vec![],
                bind_ports: None,
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
            },
        };

        let err = handle_policy_propose(
            store.pool(),
            &policies,
            params,
            Some("http://127.0.0.1:19999"),
            None,
            None,
            &[],
        )
        .await
        .unwrap_err();
        assert!(err.contains("failed to reach approval bridge"));
    }

    #[tokio::test]
    async fn propose_with_taint_warnings() {
        use crate::mediator::policy::{ExternalMount, PortRange};

        let store = test_pool().await;
        let policies = empty_policies();
        let spec = Arc::new(
            TrustSpec::load_from_str(
                r#"
sensitive_data:
  - path: "/data/customer_records"
    data_types: ["pii"]
untrusted_sources: []
trusted_external: []
"#,
            )
            .unwrap(),
        );

        let params = PolicyProposeParams {
            config: MediationPolicy {
                policy_name: "trifecta_v1".into(),
                rationale: "testing taint".into(),
                http_allowlist: vec!["https://evil.example.com/*".into()],
                external_mounts: vec![ExternalMount {
                    path: "/data/customer_records".into(),
                    mode: "r".into(),
                }],
                allowed_child_policies: vec![],
                bind_ports: Some(PortRange(8080, 8099)),
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
            allowed_launch_commands: vec![],
            },
        };

        let result = handle_policy_propose(store.pool(), &policies, params, None, None, Some(&spec), &[])
            .await
            .unwrap();

        assert_eq!(result["approved"], true);
        assert!(
            result["taint_warnings"].is_object(),
            "should include taint warnings"
        );
        assert!(result["taint_warnings"]["self"]["any_trifecta"]
            .as_bool()
            .unwrap_or(false));

        // Verify taint was stored in DB.
        let stored = queries::get_policy_taint(store.pool(), "trifecta_v1")
            .await
            .unwrap();
        assert!(stored.is_some(), "taint should be stored in DB");
    }
}
