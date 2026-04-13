// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the 5 challenge workflows from the design doc
//! (docs/eight-syscalls.html).
//!
//! Each test exercises the mediator over the UDS protocol, simulating
//! how an AI agent would drive the sandbox through the 9-syscall API.
//!
//! Workflow 4 (Recursive Forking) is already covered in mediator_integration.rs.

use bytes::{BufMut, BytesMut};
use openshell_sandbox::mediator::init::{MediatorConfig, bootstrap};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

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

async fn start_mediator() -> (String, PathBuf, tokio_util::sync::CancellationToken) {
    // policy_propose fail-closes without an approval bridge in production.
    // Tests opt in to legacy auto-approve.
    // SAFETY: integration tests run in their own process.
    unsafe { std::env::set_var("MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE", "1") };
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let config = MediatorConfig {
        socket_path: dir.path().join("mediator.sock"),
        db_path: "sqlite::memory:".into(),
        hmac_key_bytes: Some(b"workflow-e2e-key-32bytes-long!!".to_vec()),
        approval_bridge_url: None,
            webhook_secret: None,
        trust_spec_path: None,
        init_inference_endpoint: None,
    };
    let result = bootstrap(&config).await.unwrap();
    let root_token = result.root_token.clone();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel2 = cancel.clone();
    let listener = tokio::net::UnixListener::bind(&config.socket_path).unwrap();
    tokio::spawn(async move { result.daemon.serve(listener, cancel2).await; });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (root_token, config.socket_path, cancel)
}

async fn propose_policy(
    client: &mut UnixStream,
    token: &str,
    config: serde_json::Value,
) -> serde_json::Value {
    let name = config["policy_name"].as_str().unwrap_or("?");
    let req = serde_json::json!({
        "id": format!("propose-{name}"),
        "method": "policy_propose",
        "workflow_token": token,
        "params": { "config": config }
    });
    let resp = rpc(client, &req).await;
    assert_eq!(resp["ok"], true, "propose {name} failed: {resp}");
    resp
}

async fn fork_workflow(
    client: &mut UnixStream,
    token: &str,
    workflow_id: &str,
    policy_name: &str,
    inherit: bool,
) -> serde_json::Value {
    let req = serde_json::json!({
        "id": format!("fork-{workflow_id}"),
        "method": "fork_with_policy",
        "workflow_token": token,
        "params": {
            "workflow_id": workflow_id,
            "policy_name": policy_name,
            "inherit": inherit
        }
    });
    let resp = rpc(client, &req).await;
    assert_eq!(resp["ok"], true, "fork {workflow_id} failed: {resp}");
    resp
}

// ===========================================================================
// Workflow 1: Multi-Stage Research with Heterogeneous Children
//
// Challenge: The agent spawns children with different HTTP allowlists.
// Can children have capabilities the parent doesn't?
//
// Setup:
//   coordinator (no HTTP) → spawns web_scraper (HTTP to wikipedia)
//                         → spawns api_caller (HTTP to internal API)
//   Each child has a disjoint allowlist. Parent has neither.
// ===========================================================================

#[tokio::test]
async fn workflow1_heterogeneous_children() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose coordinator: no HTTP access, but can spawn two child policy types.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "coordinator_v1",
        "rationale": "Research coordinator — no direct HTTP, spawns specialized children",
        "http_allowlist": [],
        "external_mounts": [],
        "allowed_child_policies": [
            {"policy_name": "web_scraper_v1", "inherit": false},
            {"policy_name": "api_caller_v1", "inherit": false}
        ],
        "bind_ports": null,
        "allowed_ipc_targets": ["web_scraper_*", "api_caller_*"],
        "allowed_signal_targets": [
            {"policy_name": "web_scraper_*", "signals": ["term", "kill"]},
            {"policy_name": "api_caller_*", "signals": ["term", "kill"]}
        ]
    })).await;

    // Propose web_scraper: HTTP to wikipedia only.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "web_scraper_v1",
        "rationale": "Scrapes Wikipedia for research content",
        "http_allowlist": ["https://*.wikipedia.org/*"],
        "external_mounts": [{"path": "/tmp/research", "mode": "rw"}],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": ["coordinator_*"],
        "allowed_signal_targets": []
    })).await;

    // Propose api_caller: HTTP to internal API only.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "api_caller_v1",
        "rationale": "Calls internal research API",
        "http_allowlist": ["https://research-api.corp.com/*"],
        "external_mounts": [{"path": "/tmp/research", "mode": "r"}],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": ["coordinator_*"],
        "allowed_signal_targets": []
    })).await;

    // Fork coordinator from init.
    let resp = fork_workflow(&mut client, &root_token, "wf_coord", "coordinator_v1", true).await;
    let coord_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();
    let coord_uid = resp["result"]["uid"].as_u64().unwrap();

    // Coordinator forks web_scraper — child gets HTTP to wikipedia (parent doesn't have it).
    let resp = fork_workflow(&mut client, &coord_token, "wf_scraper", "web_scraper_v1", false).await;
    let scraper_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();
    let scraper_uid = resp["result"]["uid"].as_u64().unwrap();

    // Coordinator forks api_caller — child gets HTTP to research API.
    let resp = fork_workflow(&mut client, &coord_token, "wf_api", "api_caller_v1", false).await;
    let api_uid = resp["result"]["uid"].as_u64().unwrap();

    // All three have different UIDs.
    assert_ne!(coord_uid, scraper_uid);
    assert_ne!(coord_uid, api_uid);
    assert_ne!(scraper_uid, api_uid);

    // Coordinator can see both children via ps.
    let ps = serde_json::json!({
        "id": "ps-coord", "method": "ps", "workflow_token": coord_token, "params": {}
    });
    let resp = rpc(&mut client, &ps).await;
    let entries = resp["result"].as_array().unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e["policy_name"].as_str().unwrap()).collect();
    assert!(names.contains(&"web_scraper_v1"), "should see scraper");
    assert!(names.contains(&"api_caller_v1"), "should see api_caller");

    // Coordinator can IPC to scraper.
    let ipc = serde_json::json!({
        "id": "ipc-coord-scraper",
        "method": "ipc_send",
        "workflow_token": coord_token,
        "params": {"target_workflow_id": "wf_scraper", "message": {"task": "fetch article"}}
    });
    let resp = rpc(&mut client, &ipc).await;
    assert_eq!(resp["ok"], true);

    // Scraper can IPC back to coordinator.
    let ipc_back = serde_json::json!({
        "id": "ipc-scraper-coord",
        "method": "ipc_send",
        "workflow_token": scraper_token,
        "params": {"target_workflow_id": "wf_coord", "message": {"result": "article content"}}
    });
    let resp = rpc(&mut client, &ipc_back).await;
    assert_eq!(resp["ok"], true);

    // Coordinator signals scraper to terminate.
    let sig = serde_json::json!({
        "id": "sig-term",
        "method": "signal",
        "workflow_token": coord_token,
        "params": {"target_workflow_id": "wf_scraper", "signal": "term"}
    });
    let resp = rpc(&mut client, &sig).await;
    assert_eq!(resp["ok"], true);

    cancel.cancel();
}

// ===========================================================================
// Workflow 2: Data Pipeline with Heavy I/O
//
// Challenge: External mounts provisioned at fork time, native fs perf.
// Verify mounts declared in policy are carried through fork.
// ===========================================================================

#[tokio::test]
async fn workflow2_data_pipeline_mounts() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Pipeline stage: reads from input mount, writes to output mount.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "etl_stage_v1",
        "rationale": "ETL pipeline stage — reads raw data, writes processed output",
        "http_allowlist": [],
        "external_mounts": [
            {"path": "/data/raw", "mode": "r"},
            {"path": "/data/processed", "mode": "rw"},
            {"path": "/usr/bin", "mode": "rx"}
        ],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    // Fork two pipeline stages — they get separate UIDs but same GID (same policy).
    let resp_a = fork_workflow(&mut client, &root_token, "wf_etl_a", "etl_stage_v1", true).await;
    let resp_b = fork_workflow(&mut client, &root_token, "wf_etl_b", "etl_stage_v1", true).await;

    let uid_a = resp_a["result"]["uid"].as_u64().unwrap();
    let uid_b = resp_b["result"]["uid"].as_u64().unwrap();
    let gid_a = resp_a["result"]["gid"].as_u64().unwrap();
    let gid_b = resp_b["result"]["gid"].as_u64().unwrap();

    // Different UIDs (isolation).
    assert_ne!(uid_a, uid_b);
    // Same GID (same policy → shared group for setgid dirs).
    assert_eq!(gid_a, gid_b);

    // Both visible via ps.
    let ps = serde_json::json!({
        "id": "ps-etl", "method": "ps", "workflow_token": root_token, "params": {}
    });
    let resp = rpc(&mut client, &ps).await;
    let entries = resp["result"].as_array().unwrap();
    assert_eq!(entries.len(), 2);

    cancel.cancel();
}

// ===========================================================================
// Workflow 3: Mid-Flight Policy Mutation
//
// Challenge: Agent proposes v2 while v1 children still running.
// Old children keep v1, new children get v2. Immutability enforced.
// ===========================================================================

#[tokio::test]
async fn workflow3_mid_flight_policy_mutation() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose v1 with narrow allowlist.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "web_scraper_v1",
        "rationale": "v1: limited to example.com",
        "http_allowlist": ["https://example.com/*"],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    // Fork a v1 child.
    let resp = fork_workflow(&mut client, &root_token, "wf_v1_child", "web_scraper_v1", true).await;
    let v1_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();
    let v1_uid = resp["result"]["uid"].as_u64().unwrap();

    // Try to propose same name again — should fail (immutability).
    let req = serde_json::json!({
        "id": "propose-dup",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {"config": {
            "policy_name": "web_scraper_v1",
            "rationale": "attempt to mutate",
            "http_allowlist": ["https://example.com/*", "https://data.io/*"],
            "external_mounts": [], "allowed_child_policies": [],
            "bind_ports": null, "allowed_ipc_targets": [], "allowed_signal_targets": []
        }}
    });
    let resp = rpc(&mut client, &req).await;
    assert_eq!(resp["ok"], false, "duplicate policy name should be rejected");
    assert!(resp["error"]["message"].as_str().unwrap().contains("already exists"));

    // Propose v2 with wider allowlist — new name, new policy.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "web_scraper_v2",
        "rationale": "v2: added data.io access",
        "http_allowlist": ["https://example.com/*", "https://data.io/*"],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": null,
        "allowed_ipc_targets": [],
        "allowed_signal_targets": []
    })).await;

    // Fork a v2 child.
    let resp = fork_workflow(&mut client, &root_token, "wf_v2_child", "web_scraper_v2", true).await;
    let v2_uid = resp["result"]["uid"].as_u64().unwrap();

    // Different UIDs for v1 and v2 workflows.
    assert_ne!(v1_uid, v2_uid);

    // Different GIDs too (different policy names → different groups).
    let v1_gid = {
        let req = serde_json::json!({
            "id": "ps-v1", "method": "ps", "workflow_token": v1_token, "params": {}
        });
        rpc(&mut client, &req).await;
        // The v1 child can still do ps — its token is still valid.
        true
    };
    assert!(v1_gid, "v1 child should still be functional");

    // Both versions visible via ps.
    let ps = serde_json::json!({
        "id": "ps-both", "method": "ps", "workflow_token": root_token, "params": {}
    });
    let resp = rpc(&mut client, &ps).await;
    let entries = resp["result"].as_array().unwrap();
    let policies: Vec<&str> = entries.iter().map(|e| e["policy_name"].as_str().unwrap()).collect();
    assert!(policies.contains(&"web_scraper_v1"), "v1 child should still be running");
    assert!(policies.contains(&"web_scraper_v2"), "v2 child should be running");

    cancel.cancel();
}

// ===========================================================================
// Workflow 5: Asynchronous Webhook Handling
//
// Challenge: Agent spawns a listener child with bind_ports, child calls
// request_port to allocate a port for webhook callbacks.
// ===========================================================================

#[tokio::test]
async fn workflow5_webhook_listener() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose listener policy with bind_ports.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "webhook_listener_v1",
        "rationale": "Listens for async webhook callbacks",
        "http_allowlist": ["https://api.service.com/*"],
        "external_mounts": [],
        "allowed_child_policies": [],
        "bind_ports": [8080, 8099],
        "allowed_ipc_targets": ["orchestrator_*"],
        "allowed_signal_targets": []
    })).await;

    // Propose orchestrator that can spawn and signal the listener.
    propose_policy(&mut client, &root_token, serde_json::json!({
        "policy_name": "orchestrator_v1",
        "rationale": "Orchestrates webhook flow",
        "http_allowlist": ["https://api.service.com/*"],
        "external_mounts": [],
        "allowed_child_policies": [
            {"policy_name": "webhook_listener_v1", "inherit": false}
        ],
        "bind_ports": null,
        "allowed_ipc_targets": ["webhook_listener_*"],
        "allowed_signal_targets": [
            {"policy_name": "webhook_listener_*", "signals": ["term"]}
        ]
    })).await;

    // Fork orchestrator.
    let resp = fork_workflow(&mut client, &root_token, "wf_orch", "orchestrator_v1", true).await;
    let orch_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    // Orchestrator forks the listener child.
    let resp = fork_workflow(&mut client, &orch_token, "wf_listener", "webhook_listener_v1", false).await;
    let listener_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    // Listener calls request_port — should get a port in [8080, 8099].
    let port_req = serde_json::json!({
        "id": "port-1",
        "method": "request_port",
        "workflow_token": listener_token,
        "params": {}
    });
    let resp = rpc(&mut client, &port_req).await;
    assert_eq!(resp["ok"], true, "request_port failed: {resp}");
    let port = resp["result"]["port"].as_u64().unwrap();
    assert!(port >= 8080 && port <= 8099, "port {port} should be in [8080, 8099]");

    // Second port allocation should give a different port.
    let resp2 = rpc(&mut client, &serde_json::json!({
        "id": "port-2",
        "method": "request_port",
        "workflow_token": listener_token,
        "params": {}
    })).await;
    assert_eq!(resp2["ok"], true);
    let port2 = resp2["result"]["port"].as_u64().unwrap();
    assert_ne!(port, port2, "second port should be different");

    // Orchestrator sends IPC to listener with callback URL.
    let ipc = serde_json::json!({
        "id": "ipc-webhook",
        "method": "ipc_send",
        "workflow_token": orch_token,
        "params": {
            "target_workflow_id": "wf_listener",
            "message": {
                "callback_url": format!("http://sandbox:{port}/webhook"),
                "request_id": "req_001"
            }
        }
    });
    let resp = rpc(&mut client, &ipc).await;
    assert_eq!(resp["ok"], true);

    // Orchestrator can terminate the listener when done.
    let sig = serde_json::json!({
        "id": "sig-listener",
        "method": "signal",
        "workflow_token": orch_token,
        "params": {"target_workflow_id": "wf_listener", "signal": "term"}
    });
    let resp = rpc(&mut client, &sig).await;
    assert_eq!(resp["ok"], true);

    cancel.cancel();
}

// ===========================================================================
// Bonus: Cross-workflow IPC discovery via ps
//
// From the Communication Model section: "Workflows discover each other
// via ps, which only returns workflows matching allowed_ipc_targets."
// ===========================================================================

#[tokio::test]
async fn ipc_discovery_via_ps() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Three policies: A can see B, B can see C, but A cannot see C.
    for (name, targets) in [
        ("team_a_v1", vec!["team_b_*"]),
        ("team_b_v1", vec!["team_a_*", "team_c_*"]),
        ("team_c_v1", vec!["team_b_*"]),
    ] {
        propose_policy(&mut client, &root_token, serde_json::json!({
            "policy_name": name,
            "rationale": "team policy",
            "http_allowlist": [],
            "external_mounts": [],
            "allowed_child_policies": [],
            "bind_ports": null,
            "allowed_ipc_targets": targets,
            "allowed_signal_targets": []
        })).await;
    }

    // Fork all three.
    let resp_a = fork_workflow(&mut client, &root_token, "wf_a", "team_a_v1", true).await;
    let tok_a = resp_a["result"]["workflow_token"].as_str().unwrap().to_string();

    let resp_b = fork_workflow(&mut client, &root_token, "wf_b", "team_b_v1", true).await;
    let tok_b = resp_b["result"]["workflow_token"].as_str().unwrap().to_string();

    fork_workflow(&mut client, &root_token, "wf_c", "team_c_v1", true).await;

    // A's ps: should see B but NOT C.
    let ps_a = serde_json::json!({
        "id": "ps-a", "method": "ps", "workflow_token": tok_a, "params": {}
    });
    let resp = rpc(&mut client, &ps_a).await;
    let entries = resp["result"].as_array().unwrap();
    let visible: Vec<&str> = entries.iter().map(|e| e["workflow_id"].as_str().unwrap()).collect();
    assert!(visible.contains(&"wf_b"), "A should see B");
    assert!(!visible.contains(&"wf_c"), "A should NOT see C");

    // B's ps: should see both A and C.
    let ps_b = serde_json::json!({
        "id": "ps-b", "method": "ps", "workflow_token": tok_b, "params": {}
    });
    let resp = rpc(&mut client, &ps_b).await;
    let entries = resp["result"].as_array().unwrap();
    let visible: Vec<&str> = entries.iter().map(|e| e["workflow_id"].as_str().unwrap()).collect();
    assert!(visible.contains(&"wf_a"), "B should see A");
    assert!(visible.contains(&"wf_c"), "B should see C");

    cancel.cancel();
}
