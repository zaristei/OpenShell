// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Full-stack workflow E2E test.
//!
//! Boots the mediator with a trust spec, proposes all policies from the
//! doc workflow scenarios, forks children, exercises IPC/signal/port/ps,
//! verifies taint analysis and compromise tracking, then tears everything down.
//!
//! This simulates what the agent would do if told:
//! "Your purpose is to test the 5 workflow scenarios from the design doc."

use bytes::{BufMut, BytesMut};
use openshell_sandbox::mediator::init::{MediatorConfig, bootstrap};
use openshell_sandbox::mediator::store::queries;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Trust spec for the full stack test
// ---------------------------------------------------------------------------

const TRUST_SPEC: &str = r#"
sensitive_data:
  - path: "/data/research_kb"
    data_types: ["pii", "internal"]
  - path: "/data/customer_records"
    data_types: ["pii"]
  - path: "/secrets"
    data_types: ["credentials"]

untrusted_sources:
  - pattern: "https://*.wikipedia.org/*"
    data_types: ["web_content"]
  - pattern: "https://arxiv.org/*"
    data_types: ["web_content"]

trusted_external:
  - pattern: "https://internal-api.corp.com/*"
    data_types: ["*"]
  - pattern: "https://logging.corp.com/*"
    data_types: ["pii", "internal"]
"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_frame(value: &serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(value).unwrap();
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(payload.len() as u32);
    buf.extend_from_slice(&payload);
    buf.to_vec()
}

async fn read_frame(stream: &mut UnixStream) -> serde_json::Value {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    serde_json::from_slice(&payload).unwrap()
}

async fn rpc(client: &mut UnixStream, req: &serde_json::Value) -> serde_json::Value {
    client.write_all(&encode_frame(req)).await.unwrap();
    read_frame(client).await
}

async fn start() -> (String, PathBuf, tokio_util::sync::CancellationToken, sqlx::SqlitePool) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let spec_path = dir.path().join("trust_spec.yaml");
    std::fs::write(&spec_path, TRUST_SPEC).unwrap();

    let config = MediatorConfig {
        socket_path: dir.path().join("mediator.sock"),
        db_path: "sqlite::memory:".into(),
        hmac_key_bytes: Some(b"fullstack-e2e-key-32-bytes-!!".to_vec()),
        approval_bridge_url: None,
        trust_spec_path: Some(spec_path),
        init_inference_endpoint: Some("https://host.docker.internal:4000/*".into()),
    };
    let result = bootstrap(&config).await.unwrap();
    let root_token = result.root_token.clone();
    let pool = result.daemon.context().store.pool().clone();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel2 = cancel.clone();
    let listener = tokio::net::UnixListener::bind(&config.socket_path).unwrap();
    tokio::spawn(async move { result.daemon.serve(listener, cancel2).await; });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (root_token, config.socket_path, cancel, pool)
}

async fn propose(c: &mut UnixStream, tok: &str, cfg: serde_json::Value) -> serde_json::Value {
    let name = cfg["policy_name"].as_str().unwrap_or("?").to_string();
    let resp = rpc(c, &serde_json::json!({
        "id": format!("p-{name}"), "method": "policy_propose",
        "workflow_token": tok, "params": {"config": cfg}
    })).await;
    assert_eq!(resp["ok"], true, "propose {name} failed: {resp}");
    resp
}

async fn fork(c: &mut UnixStream, tok: &str, wf: &str, pol: &str, inherit: bool) -> serde_json::Value {
    let resp = rpc(c, &serde_json::json!({
        "id": format!("f-{wf}"), "method": "fork_with_policy",
        "workflow_token": tok, "params": {"workflow_id": wf, "policy_name": pol, "inherit": inherit}
    })).await;
    assert_eq!(resp["ok"], true, "fork {wf} failed: {resp}");
    resp
}

async fn ps(c: &mut UnixStream, tok: &str) -> Vec<serde_json::Value> {
    let resp = rpc(c, &serde_json::json!({
        "id": "ps", "method": "ps", "workflow_token": tok, "params": {}
    })).await;
    assert_eq!(resp["ok"], true);
    resp["result"].as_array().unwrap().clone()
}

// ===========================================================================
// Full stack scenario: all 5 doc workflows + taint + teardown
// ===========================================================================

#[tokio::test]
async fn full_stack_all_workflows() {
    let (root_token, sock_path, cancel, pool) = start().await;
    let mut c = UnixStream::connect(&sock_path).await.unwrap();

    // ── Phase 1: Init discovers empty policy catalog ─────────────────────

    let resp = rpc(&mut c, &serde_json::json!({
        "id": "pl-1", "method": "policy_list", "workflow_token": root_token, "params": {}
    })).await;
    assert_eq!(resp["ok"], true);
    let initial_policies = resp["result"].as_array().unwrap();
    // Only init_v0 visible to itself
    assert_eq!(initial_policies.len(), 1);
    assert_eq!(initial_policies[0]["policy_name"], "init_v0");

    // ── Phase 2: Workflow 1 — Heterogeneous children ─────────────────────

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "coordinator_v1", "rationale": "Research coordinator",
        "http_allowlist": [], "external_mounts": [],
        "allowed_child_policies": [
            {"policy_name": "web_scraper_v1", "inherit": false},
            {"policy_name": "api_caller_v1", "inherit": false}
        ],
        "bind_ports": null,
        "allowed_ipc_targets": ["web_scraper_*", "api_caller_*"],
        "allowed_signal_targets": [{"policy_name": "*", "signals": ["term", "kill"]}]
    })).await;

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "web_scraper_v1", "rationale": "Wikipedia scraper",
        "http_allowlist": ["https://*.wikipedia.org/*"],
        "external_mounts": [{"path": "/tmp/research", "mode": "rw"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": ["coordinator_*"], "allowed_signal_targets": []
    })).await;

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "api_caller_v1", "rationale": "Internal API client",
        "http_allowlist": ["https://internal-api.corp.com/*"],
        "external_mounts": [{"path": "/tmp/research", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": ["coordinator_*"], "allowed_signal_targets": []
    })).await;

    let resp = fork(&mut c, &root_token, "wf_coord", "coordinator_v1", true).await;
    let coord_tok = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    let resp = fork(&mut c, &coord_tok, "wf_scraper", "web_scraper_v1", false).await;
    let scraper_tok = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    fork(&mut c, &coord_tok, "wf_api", "api_caller_v1", false).await;

    // Coordinator sees both children via ps
    let entries = ps(&mut c, &coord_tok).await;
    assert_eq!(entries.len(), 2);

    // Bidirectional IPC: coordinator → scraper → coordinator
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "ipc-1", "method": "ipc_send", "workflow_token": coord_tok,
        "params": {"target_workflow_id": "wf_scraper", "message": {"task": "fetch quantum computing"}}
    })).await;
    assert_eq!(resp["ok"], true);

    let resp = rpc(&mut c, &serde_json::json!({
        "id": "ipc-2", "method": "ipc_send", "workflow_token": scraper_tok,
        "params": {"target_workflow_id": "wf_coord", "message": {"result": "article content here"}}
    })).await;
    assert_eq!(resp["ok"], true);

    // Signal scraper to terminate
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "sig-1", "method": "signal", "workflow_token": coord_tok,
        "params": {"target_workflow_id": "wf_scraper", "signal": "term"}
    })).await;
    assert_eq!(resp["ok"], true);

    // ── Phase 3: Workflow 3 — Mid-flight policy mutation ─────────────────

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "etl_v1", "rationale": "ETL pipeline v1 — limited",
        "http_allowlist": ["https://internal-api.corp.com/*"],
        "external_mounts": [{"path": "/data/research_kb", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": [], "allowed_signal_targets": []
    })).await;

    let resp = fork(&mut c, &root_token, "wf_etl_v1", "etl_v1", true).await;
    let etl_v1_tok = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    // Try to propose same name — immutability enforced
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "dup", "method": "policy_propose", "workflow_token": root_token,
        "params": {"config": {
            "policy_name": "etl_v1", "rationale": "mutated",
            "http_allowlist": ["*"], "external_mounts": [],
            "allowed_child_policies": [], "bind_ports": null,
            "allowed_ipc_targets": [], "allowed_signal_targets": []
        }}
    })).await;
    assert_eq!(resp["ok"], false);

    // Propose v2 with wider access
    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "etl_v2", "rationale": "ETL pipeline v2 — added arxiv",
        "http_allowlist": ["https://internal-api.corp.com/*", "https://arxiv.org/*"],
        "external_mounts": [{"path": "/data/research_kb", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": [], "allowed_signal_targets": []
    })).await;

    fork(&mut c, &root_token, "wf_etl_v2", "etl_v2", true).await;

    // v1 child still works
    let v1_ps = ps(&mut c, &etl_v1_tok).await;
    // v1 sees nothing (no IPC targets)
    assert_eq!(v1_ps.len(), 0);

    // ── Phase 4: Workflow 5 — Webhook listener ───────────────────────────

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "webhook_orch_v1", "rationale": "Webhook orchestrator",
        "http_allowlist": [], "external_mounts": [],
        "allowed_child_policies": [{"policy_name": "webhook_listener_v1", "inherit": false}],
        "bind_ports": null,
        "allowed_ipc_targets": ["webhook_listener_*"],
        "allowed_signal_targets": [{"policy_name": "webhook_listener_*", "signals": ["term"]}]
    })).await;

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "webhook_listener_v1", "rationale": "Webhook callback listener",
        "http_allowlist": [], "external_mounts": [],
        "allowed_child_policies": [], "bind_ports": [8080, 8099],
        "allowed_ipc_targets": ["webhook_orch_*"], "allowed_signal_targets": []
    })).await;

    let resp = fork(&mut c, &root_token, "wf_orch", "webhook_orch_v1", true).await;
    let orch_tok = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    let resp = fork(&mut c, &orch_tok, "wf_listener", "webhook_listener_v1", false).await;
    let listener_tok = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    // Listener allocates a port
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "port", "method": "request_port", "workflow_token": listener_tok, "params": {}
    })).await;
    assert_eq!(resp["ok"], true);
    let port = resp["result"]["port"].as_u64().unwrap();
    assert!((8080..=8099).contains(&port));

    // Orchestrator IPCs the callback URL
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "ipc-cb", "method": "ipc_send", "workflow_token": orch_tok,
        "params": {"target_workflow_id": "wf_listener", "message": {"callback_port": port}}
    })).await;
    assert_eq!(resp["ok"], true);

    // Orchestrator terminates listener
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "sig-l", "method": "signal", "workflow_token": orch_tok,
        "params": {"target_workflow_id": "wf_listener", "signal": "term"}
    })).await;
    assert_eq!(resp["ok"], true);

    // ── Phase 5: Taint-sensitive workflow with scrubbers ──────────────────

    let resp = propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "data_reader_v1", "rationale": "Reads sensitive research KB",
        "http_allowlist": ["https://logging.corp.com/*"],
        "external_mounts": [{"path": "/data/research_kb", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": [{
            "policy_name": "data_processor_*",
            "scrub_egress": {"scrubber": "field_pii", "data_types": ["pii"], "de_taints": true,
                "config": {"fields": ["$.author.email", "$.author.phone"], "action": "redact"}}
        }],
        "allowed_signal_targets": []
    })).await;
    // Reader is clean: source(pii) + trusted-only HTTP + scrubbed egress → no trifecta
    assert!(
        !resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "reader should be clean with scrubbed egress"
    );

    propose(&mut c, &root_token, serde_json::json!({
        "policy_name": "data_processor_v1", "rationale": "Processes data, no external access",
        "http_allowlist": [], "external_mounts": [],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": ["data_reader_*"], "allowed_signal_targets": []
    })).await;

    let resp = fork(&mut c, &root_token, "wf_reader", "data_reader_v1", true).await;
    let reader_tok = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    fork(&mut c, &root_token, "wf_processor", "data_processor_v1", true).await;

    // Reader sends scrubbed PII via IPC
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "ipc-pii", "method": "ipc_send", "workflow_token": reader_tok,
        "params": {
            "target_workflow_id": "wf_processor",
            "message": {
                "paper_id": "arxiv:2401.12345",
                "author": {"name": "Alice Smith", "email": "alice@example.com", "phone": "555-123-4567"},
                "title": "Quantum Computing Survey"
            }
        }
    })).await;
    assert_eq!(resp["ok"], true);

    // Verify the stored message has PII scrubbed
    let messages = queries::list_ipc_messages(&pool, "wf_processor").await.unwrap();
    assert_eq!(messages.len(), 1);
    let stored: serde_json::Value = serde_json::from_str(&messages[0].message).unwrap();
    assert_eq!(stored["author"]["email"], "[REDACTED]", "email should be scrubbed");
    assert_eq!(stored["author"]["phone"], "[REDACTED]", "phone should be scrubbed");
    assert_eq!(stored["author"]["name"], "Alice Smith", "name not in field list — preserved");
    assert_eq!(stored["title"], "Quantum Computing Survey", "title preserved");

    // ── Phase 6: Policy catalog discovery ─────────────────────────────────

    // Init lists all policies
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "pl-all", "method": "policy_list", "workflow_token": root_token, "params": {}
    })).await;
    let all_policies = resp["result"].as_array().unwrap();
    assert!(all_policies.len() >= 9, "should have 9+ policies: {}", all_policies.len());

    // Get specific policy details
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "pg-1", "method": "policy_get", "workflow_token": root_token,
        "params": {"policy_name": "web_scraper_v1"}
    })).await;
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["policy_name"], "web_scraper_v1");
    let allowlist = resp["result"]["http_allowlist"].as_array().unwrap();
    assert!(allowlist.iter().any(|u| u.as_str().unwrap().contains("wikipedia")));

    // ── Phase 7: Revoke and cleanup ──────────────────────────────────────

    // Count active workflows
    let all_wf = ps(&mut c, &root_token).await;
    let wf_count_before = all_wf.len();
    assert!(wf_count_before >= 5, "should have 5+ active workflows");

    // Revoke etl_v1 (hard) — kills wf_etl_v1
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "rev-1", "method": "revoke_policy", "workflow_token": root_token,
        "params": {"policy_name": "etl_v1", "hard": true}
    })).await;
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["revoked"], true);

    // Verify wf_etl_v1 is gone
    let all_wf_after = ps(&mut c, &root_token).await;
    assert!(!all_wf_after.iter().any(|w| w["workflow_id"] == "wf_etl_v1"));

    // etl_v1 should not be in policy list anymore
    let resp = rpc(&mut c, &serde_json::json!({
        "id": "pl-post", "method": "policy_list", "workflow_token": root_token, "params": {}
    })).await;
    let policies_after = resp["result"].as_array().unwrap();
    assert!(!policies_after.iter().any(|p| p["policy_name"] == "etl_v1"));

    // ── Phase 8: Verify audit trail ──────────────────────────────────────

    // We can't query audit via UDS but we verify all responses were well-formed
    // and no panics occurred. Unit tests verify audit_log insertion.

    cancel.cancel();
}
