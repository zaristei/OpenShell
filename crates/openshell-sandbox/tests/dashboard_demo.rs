// Demo: starts a mediator with policies (including trifecta violations)
// and serves the taint dashboard on port 8091.
//
// Run with:
//   cargo test -p openshell-sandbox --test dashboard_demo -- --nocapture
//
// Then open http://localhost:8091 in your browser.

use openshell_sandbox::mediator::init::{bootstrap, MediatorConfig};
use openshell_sandbox::mediator::policy::trust_spec::TrustSpec;
use openshell_sandbox::mediator::policy::{ExternalMount, IpcTarget, IpcTargetEntry, MediationPolicy, PortRange, ScrubConfig};
use openshell_sandbox::mediator::syscalls::policy_propose::{handle_policy_propose, PolicyProposeParams};
use openshell_sandbox::mediator::syscalls::fork_with_policy::{handle_fork_with_policy, ForkParams};
use std::path::PathBuf;
use std::sync::Arc;

const TRUST_SPEC_YAML: &str = r#"
sensitive_data:
  - path: "/data/customer_records"
    data_types: ["pii"]
  - path: "/data/financial"
    data_types: ["pii", "financial"]
  - path: "/secrets"
    data_types: ["credentials"]

untrusted_sources:
  - pattern: "https://*.wikipedia.org/*"
    data_types: ["web_content"]
  - pattern: "https://pastebin.com/*"
    data_types: ["web_content"]

trusted_external:
  - pattern: "https://internal-api.corp.com/*"
    data_types: ["*"]
  - pattern: "https://logging.corp.com/*"
    data_types: ["pii", "financial"]
  - pattern: "https://vault.corp.com/*"
    data_types: ["credentials"]
"#;

#[tokio::test]
async fn dashboard_demo() {
    // Set up tracing.
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let spec = Arc::new(TrustSpec::load_from_str(TRUST_SPEC_YAML).unwrap());

    let dir = tempfile::tempdir().unwrap();
    let config = MediatorConfig {
        socket_path: dir.path().join("demo.sock"),
        db_path: "sqlite::memory:".into(),
        hmac_key_bytes: Some(b"demo-key-exactly-32-bytes-long!!".to_vec()),
        approval_bridge_url: None,
        trust_spec_path: None,
        init_inference_endpoint: None,
    };

    let result = bootstrap(&config).await.unwrap();
    let ctx = result.daemon.context();
    let pool = ctx.store.pool();
    let policies = &ctx.policies;

    // Inject trust spec into context (it was None since we didn't use trust_spec_path).
    // We'll pass it directly to propose calls instead.

    // ── Propose policies ─────────────────────────────────────────────

    // 1. Clean logger: only talks to trusted internal API
    propose(pool, policies, &spec, MediationPolicy {
        policy_name: "logger_v1".into(),
        rationale: "Internal logging service — writes audit data to trusted corp endpoint".into(),
        http_allowlist: vec!["https://logging.corp.com/*".into()],
        external_mounts: vec![ExternalMount { path: "/data/customer_records".into(), mode: "r".into() }],
        allowed_child_policies: vec![],
        bind_ports: None,
        allowed_ipc_targets: vec![],
        allowed_signal_targets: vec![],
    }).await;

    // 2. Fetcher: grabs untrusted content from the web
    propose(pool, policies, &spec, MediationPolicy {
        policy_name: "fetcher_v1".into(),
        rationale: "Web content fetcher — retrieves pages from Wikipedia and other sources".into(),
        http_allowlist: vec!["https://*.wikipedia.org/*".into(), "https://pastebin.com/*".into()],
        external_mounts: vec![
            ExternalMount { path: "/tmp/fetched".into(), mode: "rw".into() },
        ],
        allowed_child_policies: vec![],
        bind_ports: None,
        allowed_ipc_targets: vec!["analyzer_*".into()],
        allowed_signal_targets: vec![],
    }).await;

    // 3. Analyzer: reads sensitive PII data AND talks to fetcher (IPC)
    //    This creates a TRIFECTA via IPC: source(pii) + IPC-from-fetcher(untrusted) + sink through fetcher
    propose(pool, policies, &spec, MediationPolicy {
        policy_name: "analyzer_v1".into(),
        rationale: "Data analyzer — processes customer records against web content".into(),
        http_allowlist: vec!["https://evil.example.com/report".into()],
        external_mounts: vec![
            ExternalMount { path: "/data/customer_records".into(), mode: "r".into() },
            ExternalMount { path: "/tmp/fetched".into(), mode: "r".into() },
        ],
        allowed_child_policies: vec![],
        bind_ports: Some(PortRange(8080, 8089)),
        allowed_ipc_targets: vec!["fetcher_*".into()],
        allowed_signal_targets: vec![],
    }).await;

    // 4. Vault accessor: reads credentials, talks to trusted vault only
    propose(pool, policies, &spec, MediationPolicy {
        policy_name: "vault_accessor_v1".into(),
        rationale: "Credential manager — syncs secrets with corporate vault".into(),
        http_allowlist: vec!["https://vault.corp.com/*".into()],
        external_mounts: vec![ExternalMount { path: "/secrets".into(), mode: "r".into() }],
        allowed_child_policies: vec![],
        bind_ports: None,
        allowed_ipc_targets: vec![],
        allowed_signal_targets: vec![],
    }).await;

    // 5. Scrubbed reader: has PII source but egress scrubber protects IPC to fetcher
    propose(pool, policies, &spec, MediationPolicy {
        policy_name: "scrubbed_reader_v1".into(),
        rationale: "Safe reader — PII scrubber on egress to fetcher".into(),
        http_allowlist: vec![],
        external_mounts: vec![
            ExternalMount { path: "/data/financial".into(), mode: "r".into() },
        ],
        allowed_child_policies: vec![],
        bind_ports: None,
        allowed_ipc_targets: vec![IpcTargetEntry::Configured(IpcTarget {
            policy_name: "fetcher_*".into(),
            scrub_egress: Some(ScrubConfig {
                scrubber: "regex_pii".into(),
                data_types: vec!["pii".into(), "financial".into()],
                de_taints: true,
                config: serde_json::Value::default(),
            }),
            scrub_ingress: None,
        })],
        allowed_signal_targets: vec![],
    }).await;

    // 6. Leaker: writes to shared path that fetcher reads — filesystem taint edge
    propose(pool, policies, &spec, MediationPolicy {
        policy_name: "leaker_v1".into(),
        rationale: "DANGEROUS — reads PII, writes to shared dir, has external HTTP".into(),
        http_allowlist: vec!["https://pastebin.com/*".into()],
        external_mounts: vec![
            ExternalMount { path: "/data/customer_records".into(), mode: "r".into() },
            ExternalMount { path: "/tmp/fetched".into(), mode: "rw".into() },
        ],
        allowed_child_policies: vec![],
        bind_ports: Some(PortRange(9000, 9009)),
        allowed_ipc_targets: vec![],
        allowed_signal_targets: vec![],
    }).await;

    // ── Fork some workflows ──────────────────────────────────────────

    let caller_token = openshell_sandbox::mediator::store::queries::get_token(pool, &result.root_token)
        .await.unwrap().unwrap();
    let caller_policy = policies.read().await.get("init_v0").cloned().unwrap();

    for (name, wf_id) in [
        ("logger_v1", "wf_logger_001"),
        ("fetcher_v1", "wf_fetcher_001"),
        ("analyzer_v1", "wf_analyzer_001"),
        ("leaker_v1", "wf_leaker_001"),
    ] {
        let _ = handle_fork_with_policy(
            pool,
            &ctx.token_key,
            policies,
            &caller_token,
            &caller_policy,
            ForkParams {
                policy_name: name.into(),
                workflow_id: wf_id.into(),
                inherit: true,
            },
            &ctx.uid_allocator,
            &ctx.gid_allocator,
            &ctx.uid_policy_registry,
        ).await;
    }

    // ── Start dashboard ──────────────────────────────────────────────

    let cancel = tokio_util::sync::CancellationToken::new();

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   OpenShell Taint Dashboard running on port 8091        ║");
    println!("║   Open http://localhost:8091 in your browser            ║");
    println!("║                                                         ║");
    println!("║   API endpoints:                                        ║");
    println!("║     GET http://localhost:8091/api/graph                  ║");
    println!("║     GET http://localhost:8091/api/health                 ║");
    println!("║                                                         ║");
    println!("║   Press Ctrl+C to stop                                  ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    openshell_sandbox::mediator::dashboard::serve_dashboard(
        8091,
        pool.clone(),
        Arc::clone(&ctx.policies),
        Some(spec),
        cancel.clone(),
    ).await;
}

async fn propose(
    pool: &sqlx::SqlitePool,
    policies: &tokio::sync::RwLock<std::collections::HashMap<String, MediationPolicy>>,
    spec: &Arc<TrustSpec>,
    config: MediationPolicy,
) {
    let name = config.policy_name.clone();
    match handle_policy_propose(
        pool,
        policies,
        PolicyProposeParams { config },
        None,
        Some(spec),
    ).await {
        Ok(result) => {
            let has_taint = result.get("taint_warnings").is_some();
            if has_taint {
                println!("  ⚠ {name}: approved WITH taint warnings");
            } else {
                println!("  ✓ {name}: approved (clean)");
            }
        }
        Err(e) => println!("  ✗ {name}: {e}"),
    }
}
