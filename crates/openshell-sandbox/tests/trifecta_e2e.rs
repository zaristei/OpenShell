// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for lethal trifecta enforcement.
//!
//! These tests exercise the full taint analysis pipeline over the UDS protocol,
//! mirroring the 6-policy scenario from the dashboard demo:
//!
//!   - logger_v1:          clean (trusted external, no trifecta)
//!   - fetcher_v1:         trifecta (untrusted web + external sink)
//!   - analyzer_v1:        trifecta (PII source + bind_ports + untrusted http)
//!   - vault_accessor_v1:  clean (credentials source, trusted vault)
//!   - scrubbed_reader_v1: clean (PII source, egress scrubber breaks chain)
//!   - leaker_v1:          trifecta (PII + bind_ports + pastebin + shared fs)

use bytes::{BufMut, BytesMut};
use openshell_sandbox::mediator::init::{MediatorConfig, bootstrap};
use openshell_sandbox::mediator::policy::trust_spec::TrustSpec;
use openshell_sandbox::mediator::store::queries;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Trust spec matching the dashboard demo
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Helpers (same protocol as mediator_integration.rs)
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

/// Bootstrap a mediator with the trifecta trust spec loaded.
async fn start_mediator_with_trust_spec() -> (
    String,
    PathBuf,
    tokio_util::sync::CancellationToken,
    sqlx::SqlitePool,
) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));

    // Write trust spec to a temp file.
    let spec_path = dir.path().join("trust_spec.yaml");
    std::fs::write(&spec_path, TRUST_SPEC_YAML).unwrap();

    let config = MediatorConfig {
        socket_path: dir.path().join("mediator.sock"),
        db_path: "sqlite::memory:".into(),
        hmac_key_bytes: Some(b"trifecta-test-key-32bytes-ok!".to_vec()),
        approval_bridge_url: None,
        trust_spec_path: Some(spec_path),
        init_inference_endpoint: None,
    };

    let result = bootstrap(&config).await.unwrap();
    let root_token = result.root_token.clone();
    let pool = result.daemon.context().store.pool().clone();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel2 = cancel.clone();

    let listener = tokio::net::UnixListener::bind(&config.socket_path).unwrap();
    tokio::spawn(async move {
        result.daemon.serve(listener, cancel2).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (root_token, config.socket_path, cancel, pool)
}

async fn propose(
    client: &mut UnixStream,
    token: &str,
    id: &str,
    config: serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({
        "id": id,
        "method": "policy_propose",
        "workflow_token": token,
        "params": { "config": config }
    });
    rpc(client, &req).await
}

async fn fork(
    client: &mut UnixStream,
    token: &str,
    id: &str,
    workflow_id: &str,
    policy_name: &str,
) -> serde_json::Value {
    let req = serde_json::json!({
        "id": id,
        "method": "fork_with_policy",
        "workflow_token": token,
        "params": {
            "workflow_id": workflow_id,
            "policy_name": policy_name,
            "inherit": true
        }
    });
    rpc(client, &req).await
}

// ---------------------------------------------------------------------------
// Test: clean policy gets no taint warnings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clean_policy_no_taint_warnings() {
    let (root_token, sock_path, cancel, _pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // logger_v1: reads PII but only sends to trusted logging endpoint.
    let resp = propose(&mut client, &root_token, "p-logger", serde_json::json!({
        "policy_name": "logger_v1",
        "rationale": "Internal logger",
        "http_allowlist": ["https://logging.corp.com/*"],
        "external_mounts": [{"path": "/data/customer_records", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    assert_eq!(resp["ok"], true, "propose failed: {resp}");
    // No taint_warnings key means clean.
    assert!(
        !resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "logger self taint should be clean, got: {}",
        resp["result"]
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: vault accessor is clean (trusted for credentials)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vault_accessor_clean() {
    let (root_token, sock_path, cancel, _pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    let resp = propose(&mut client, &root_token, "p-vault", serde_json::json!({
        "policy_name": "vault_accessor_v1",
        "rationale": "Credential manager",
        "http_allowlist": ["https://vault.corp.com/*"],
        "external_mounts": [{"path": "/secrets", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    assert_eq!(resp["ok"], true);
    assert!(
        !resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "vault accessor self taint should be clean"
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: trifecta policy gets warnings (analyzer: PII + bind_ports + untrusted HTTP)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn trifecta_policy_gets_warnings() {
    let (root_token, sock_path, cancel, _pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // analyzer_v1: reads PII, has bind_ports (untrusted input), sends to evil.com
    let resp = propose(&mut client, &root_token, "p-analyzer", serde_json::json!({
        "policy_name": "analyzer_v1",
        "rationale": "Data analyzer",
        "http_allowlist": ["https://evil.example.com/report"],
        "external_mounts": [{"path": "/data/customer_records", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": [8080, 8089],
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    assert_eq!(resp["ok"], true, "propose failed: {resp}");
    let warnings = &resp["result"]["taint_warnings"];
    assert!(warnings.is_object(), "should have taint warnings: {}", resp["result"]);
    assert!(
        warnings["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "analyzer should be trifecta"
    );

    // Verify PII tag specifically has trifecta.
    let tags = warnings["self"]["tags"].as_array().unwrap();
    let pii_tag = tags.iter().find(|t| t["data_type"] == "pii").unwrap();
    assert!(pii_tag["trifecta"].as_bool().unwrap(), "pii should be trifecta");
    assert!(pii_tag["has_source"].as_bool().unwrap(), "pii source via mount");
    assert!(pii_tag["has_untrusted_input"].as_bool().unwrap(), "untrusted via bind_ports");
    assert!(pii_tag["has_sink"].as_bool().unwrap(), "sink via evil.example.com");

    // Should have pending_compromises pre-computed.
    let compromises = warnings["self"]["pending_compromises"].as_array().unwrap();
    assert!(!compromises.is_empty(), "should have pending compromises");

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: scrubber on IPC egress breaks the taint chain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scrubber_breaks_taint_chain() {
    let (root_token, sock_path, cancel, _pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // First propose the fetcher (has untrusted http + external sink).
    let resp = propose(&mut client, &root_token, "p-fetcher", serde_json::json!({
        "policy_name": "fetcher_v1",
        "rationale": "Web fetcher",
        "http_allowlist": ["https://*.wikipedia.org/*", "https://evil.example.com/*"],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": ["scrubbed_reader_*"],
        "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);

    // scrubbed_reader: has PII source, but egress scrubber to fetcher de-taints PII.
    let resp = propose(&mut client, &root_token, "p-scrubbed", serde_json::json!({
        "policy_name": "scrubbed_reader_v1",
        "rationale": "Safe reader with PII scrubber",
        "http_allowlist": [],
        "external_mounts": [{"path": "/data/financial", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [{
            "policy_name": "fetcher_*",
            "scrub_egress": {
                "scrubber": "regex_pii",
                "data_types": ["pii", "financial"],
                "de_taints": true
            }
        }],
        "allowed_signal_targets": []
    })).await;

    assert_eq!(resp["ok"], true, "propose failed: {resp}");
    // The scrubber should prevent PII trifecta.
    assert!(
        !resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "scrubbed reader self taint should be clean — scrubber breaks chain, got: {}",
        resp["result"]
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: fork materializes compromised resources from stored taint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fork_materializes_compromises() {
    let (root_token, sock_path, cancel, pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose trifecta policy.
    let resp = propose(&mut client, &root_token, "p-leaker", serde_json::json!({
        "policy_name": "leaker_v1",
        "rationale": "DANGEROUS",
        "http_allowlist": ["https://pastebin.com/*"],
        "external_mounts": [
            {"path": "/data/customer_records", "mode": "r"},
            {"path": "/tmp/shared", "mode": "rw"}
        ],
        "allowed_child_policies": [],
        "bind_ports": [9000, 9009],
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    assert!(resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false));

    // Verify taint stored in DB.
    let stored = queries::get_policy_taint(&pool, "leaker_v1").await.unwrap();
    assert!(stored.is_some(), "policy taint should be stored in DB");

    // No compromised resources yet (not forked).
    let cr_before = queries::list_compromised_resources(&pool).await.unwrap();
    assert!(cr_before.is_empty(), "no compromises before fork");

    // Fork the trifecta workflow — should materialize compromises.
    let resp = fork(&mut client, &root_token, "f-leaker", "wf_leaker", "leaker_v1").await;
    assert_eq!(resp["ok"], true, "fork failed: {resp}");

    // Now compromised_resources should be populated.
    let cr_after = queries::list_compromised_resources(&pool).await.unwrap();
    assert!(
        !cr_after.is_empty(),
        "compromised resources should be materialized after fork"
    );

    // All should be caused by leaker_v1.
    assert!(
        cr_after.iter().all(|c| c.caused_by == "leaker_v1"),
        "all compromises should be caused by leaker_v1"
    );

    // Should include read-compromise for /data/customer_records (PII exfil risk).
    assert!(
        cr_after.iter().any(|c| c.resource_path == "/data/customer_records"
            && c.compromise_type == "read"
            && c.data_type == "pii"),
        "should have read-compromise for customer_records PII"
    );

    // Should include write-compromise for /tmp/shared (poisoning risk).
    assert!(
        cr_after.iter().any(|c| c.resource_path == "/tmp/shared"
            && c.compromise_type == "write"),
        "should have write-compromise for shared dir"
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: revoke clears compromised resources and taint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_clears_compromises() {
    let (root_token, sock_path, cancel, pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose + fork trifecta policy.
    propose(&mut client, &root_token, "p-rev", serde_json::json!({
        "policy_name": "revokable_trifecta_v1",
        "rationale": "to be revoked",
        "http_allowlist": ["https://pastebin.com/*"],
        "external_mounts": [{"path": "/data/customer_records", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": [9000, 9009],
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    fork(&mut client, &root_token, "f-rev", "wf_revokable_t", "revokable_trifecta_v1").await;

    // Verify compromises exist.
    let cr = queries::list_compromised_resources(&pool).await.unwrap();
    assert!(!cr.is_empty());

    // Verify taint record exists.
    let taint = queries::get_policy_taint(&pool, "revokable_trifecta_v1").await.unwrap();
    assert!(taint.is_some());

    // Revoke the policy.
    let revoke = serde_json::json!({
        "id": "revoke-1",
        "method": "revoke_policy",
        "workflow_token": root_token,
        "params": { "policy_name": "revokable_trifecta_v1", "hard": true }
    });
    let resp = rpc(&mut client, &revoke).await;
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["revoked"], true);

    // Compromised resources should be cleared.
    let cr_after = queries::list_compromised_resources(&pool).await.unwrap();
    assert!(
        cr_after.is_empty(),
        "compromised resources should be cleared after revoke"
    );

    // Taint record should be gone.
    let taint_after = queries::get_policy_taint(&pool, "revokable_trifecta_v1").await.unwrap();
    assert!(taint_after.is_none(), "taint should be deleted after revoke");

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: IPC with scrubber redacts PII in messages
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ipc_send_scrubs_pii() {
    let (root_token, sock_path, cancel, pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose sender with egress scrubber and receiver.
    propose(&mut client, &root_token, "p-sender", serde_json::json!({
        "policy_name": "scrub_sender_v1",
        "rationale": "sender with PII scrubber",
        "http_allowlist": [],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [{
            "policy_name": "scrub_receiver_*",
            "scrub_egress": {
                "scrubber": "regex_pii",
                "data_types": ["pii"],
                "de_taints": true
            }
        }],
        "allowed_signal_targets": []
    })).await;

    propose(&mut client, &root_token, "p-receiver", serde_json::json!({
        "policy_name": "scrub_receiver_v1",
        "rationale": "receiver",
        "http_allowlist": [],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": ["scrub_sender_*"],
        "allowed_signal_targets": []
    })).await;

    // Fork both.
    let resp = fork(&mut client, &root_token, "f-ss", "wf_scrub_sender", "scrub_sender_v1").await;
    let sender_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    fork(&mut client, &root_token, "f-sr", "wf_scrub_receiver", "scrub_receiver_v1").await;

    // Send a message containing PII (SSN and email).
    let ipc = serde_json::json!({
        "id": "ipc-scrub",
        "method": "ipc_send",
        "workflow_token": sender_token,
        "params": {
            "target_workflow_id": "wf_scrub_receiver",
            "message": {
                "user": "Alice",
                "ssn": "123-45-6789",
                "email": "alice@example.com",
                "safe_field": 42
            }
        }
    });
    let resp = rpc(&mut client, &ipc).await;
    assert_eq!(resp["ok"], true, "ipc_send failed: {resp}");

    // Verify the stored message has PII redacted.
    let messages = queries::list_ipc_messages(&pool, "wf_scrub_receiver")
        .await
        .unwrap();
    assert_eq!(messages.len(), 1, "should have 1 stored message");

    let stored: serde_json::Value = serde_json::from_str(&messages[0].message).unwrap();
    assert_eq!(stored["ssn"], "[REDACTED]", "SSN should be redacted");
    assert_eq!(stored["email"], "[REDACTED]", "email should be redacted");
    assert_eq!(stored["user"], "Alice", "non-PII should be preserved");
    assert_eq!(stored["safe_field"], 42, "numbers should be preserved");

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: affected policy analysis — adding fetcher worsens reader's taint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn affected_policy_warned_on_propose() {
    let (root_token, sock_path, cancel, _pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // First propose reader: has PII source + bind_ports, IPC targets fetcher.
    // Without fetcher in the graph, reader has no sink → no PII trifecta.
    let resp = propose(&mut client, &root_token, "p-reader", serde_json::json!({
        "policy_name": "reader_v1",
        "rationale": "PII reader",
        "http_allowlist": [],
        "external_mounts": [{"path": "/data/customer_records", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": [8080, 8089],
        "allowed_ipc_targets": ["fetcher_*"],
        "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    // No taint warnings (no fetcher to create a sink).
    assert!(
        !resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "reader self taint should be clean without fetcher in graph"
    );

    // Now propose fetcher: has untrusted external access.
    // This should trigger an "affected" warning for reader_v1.
    let resp = propose(&mut client, &root_token, "p-fetcher", serde_json::json!({
        "policy_name": "fetcher_v1",
        "rationale": "Web fetcher with external sink",
        "http_allowlist": ["https://evil.example.com/*"],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": ["reader_*"],
        "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);

    let warnings = &resp["result"]["taint_warnings"];
    assert!(warnings.is_object(), "fetcher propose should trigger warnings");

    // The "affected" array should include reader_v1 with worsened taint.
    let affected = warnings["affected"].as_array().unwrap();
    assert!(
        affected.iter().any(|a| a["policy_name"] == "reader_v1" && a["any_trifecta"].as_bool().unwrap_or(false)),
        "reader_v1 should be flagged as affected with new trifecta: {affected:?}"
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: filesystem edge creates trifecta across policies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn filesystem_edge_trifecta() {
    let (root_token, sock_path, cancel, _pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // writer: has PII source, writes to shared path.
    propose(&mut client, &root_token, "p-writer", serde_json::json!({
        "policy_name": "writer_v1",
        "rationale": "PII data writer",
        "http_allowlist": [],
        "external_mounts": [
            {"path": "/data/customer_records", "mode": "r"},
            {"path": "/shared/output", "mode": "rw"}
        ],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    // leaker: reads from shared path, has external sink + bind_ports.
    // Gets PII source via filesystem edge (writer writes to /shared/output).
    let resp = propose(&mut client, &root_token, "p-fs-leaker", serde_json::json!({
        "policy_name": "fs_leaker_v1",
        "rationale": "reads shared output",
        "http_allowlist": ["https://evil.example.com/*"],
        "external_mounts": [{"path": "/shared/output", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": [9000, 9009],
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    assert_eq!(resp["ok"], true);
    let warnings = &resp["result"]["taint_warnings"];
    assert!(warnings.is_object(), "should have taint warnings");
    assert!(
        warnings["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "fs_leaker should be trifecta via filesystem edge"
    );

    // Check that PII source comes through filesystem edge.
    let tags = warnings["self"]["tags"].as_array().unwrap();
    let pii_tag = tags.iter().find(|t| t["data_type"] == "pii").unwrap();
    assert!(pii_tag["has_source"].as_bool().unwrap());
    let source_paths = pii_tag["source_paths"].as_array().unwrap();
    assert!(
        source_paths.iter().any(|s| s.as_str().unwrap().contains("fs edge")),
        "PII source should come via filesystem edge: {source_paths:?}"
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Test: full 6-policy scenario — matches dashboard demo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_dashboard_scenario() {
    let (root_token, sock_path, cancel, pool) = start_mediator_with_trust_spec().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // 1. logger_v1 — clean
    let resp = propose(&mut client, &root_token, "p1", serde_json::json!({
        "policy_name": "logger_v1",
        "rationale": "Internal logger",
        "http_allowlist": ["https://logging.corp.com/*"],
        "external_mounts": [{"path": "/data/customer_records", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": [], "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    assert!(!resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false), "logger should be clean");

    // 2. fetcher_v1 — will get taint once connected to analyzer
    let resp = propose(&mut client, &root_token, "p2", serde_json::json!({
        "policy_name": "fetcher_v1",
        "rationale": "Web fetcher",
        "http_allowlist": ["https://*.wikipedia.org/*", "https://pastebin.com/*"],
        "external_mounts": [{"path": "/tmp/fetched", "mode": "rw"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": ["analyzer_*"], "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);

    // 3. analyzer_v1 — trifecta (PII + bind_ports + evil.com)
    let resp = propose(&mut client, &root_token, "p3", serde_json::json!({
        "policy_name": "analyzer_v1",
        "rationale": "Data analyzer",
        "http_allowlist": ["https://evil.example.com/report"],
        "external_mounts": [
            {"path": "/data/customer_records", "mode": "r"},
            {"path": "/tmp/fetched", "mode": "r"}
        ],
        "allowed_child_policies": [], "bind_ports": [8080, 8089],
        "allowed_ipc_targets": ["fetcher_*"], "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    assert!(resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "analyzer should be trifecta");

    // 4. vault_accessor_v1 — clean
    let resp = propose(&mut client, &root_token, "p4", serde_json::json!({
        "policy_name": "vault_accessor_v1",
        "rationale": "Credential manager",
        "http_allowlist": ["https://vault.corp.com/*"],
        "external_mounts": [{"path": "/secrets", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": [], "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    assert!(!resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false), "vault should be clean");

    // 5. scrubbed_reader_v1 — clean (scrubber protects)
    let resp = propose(&mut client, &root_token, "p5", serde_json::json!({
        "policy_name": "scrubbed_reader_v1",
        "rationale": "Safe reader",
        "http_allowlist": [],
        "external_mounts": [{"path": "/data/financial", "mode": "r"}],
        "allowed_child_policies": [], "bind_ports": null,
        "allowed_ipc_targets": [{
            "policy_name": "fetcher_*",
            "scrub_egress": {"scrubber": "regex_pii", "data_types": ["pii", "financial"], "de_taints": true}
        }],
        "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    assert!(!resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false), "scrubbed reader should be clean");

    // 6. leaker_v1 — trifecta (PII + bind_ports + pastebin + shared fs)
    let resp = propose(&mut client, &root_token, "p6", serde_json::json!({
        "policy_name": "leaker_v1",
        "rationale": "DANGEROUS",
        "http_allowlist": ["https://pastebin.com/*"],
        "external_mounts": [
            {"path": "/data/customer_records", "mode": "r"},
            {"path": "/tmp/fetched", "mode": "rw"}
        ],
        "allowed_child_policies": [], "bind_ports": [9000, 9009],
        "allowed_ipc_targets": [], "allowed_signal_targets": []
    })).await;
    assert_eq!(resp["ok"], true);
    assert!(resp["result"]["taint_warnings"]["self"]["any_trifecta"].as_bool().unwrap_or(false),
        "leaker should be trifecta");

    // Fork the 4 active workflows from the demo.
    for (name, wf_id) in [
        ("logger_v1", "wf_logger"),
        ("fetcher_v1", "wf_fetcher"),
        ("analyzer_v1", "wf_analyzer"),
        ("leaker_v1", "wf_leaker"),
    ] {
        let resp = fork(&mut client, &root_token, &format!("f-{name}"), wf_id, name).await;
        assert_eq!(resp["ok"], true, "fork {name} failed: {resp}");
    }

    // Verify ps shows all 4 workflows.
    let ps = serde_json::json!({
        "id": "ps-final", "method": "ps", "workflow_token": root_token, "params": {}
    });
    let resp = rpc(&mut client, &ps).await;
    let workflows = resp["result"].as_array().unwrap();
    assert_eq!(workflows.len(), 4, "should have 4 active workflows");

    // Verify compromised resources materialized for trifecta policies.
    let cr = queries::list_compromised_resources(&pool).await.unwrap();
    assert!(!cr.is_empty(), "should have compromised resources");

    let analyzer_cr: Vec<_> = cr.iter().filter(|c| c.caused_by == "analyzer_v1").collect();
    let leaker_cr: Vec<_> = cr.iter().filter(|c| c.caused_by == "leaker_v1").collect();
    assert!(!analyzer_cr.is_empty(), "analyzer should have compromised resources");
    assert!(!leaker_cr.is_empty(), "leaker should have compromised resources");

    // Clean policies should have no compromised resources.
    let logger_cr: Vec<_> = cr.iter().filter(|c| c.caused_by == "logger_v1").collect();
    assert!(logger_cr.is_empty(), "logger should have no compromises");

    cancel.cancel();
}
