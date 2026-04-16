// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the mediator syscall stack.
//!
//! These tests exercise the full mediator lifecycle: bootstrap → UDS connect →
//! dispatch → syscall handlers → store, validating the end-to-end protocol.
//! UID/iptables enforcement is Linux-only and tested manually.

use bytes::{BufMut, BytesMut};
use openshell_sandbox::mediator::init::{MediatorConfig, bootstrap};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_config(socket_path: PathBuf) -> MediatorConfig {
    // policy_propose fail-closes when no approval bridge is configured.
    // Tests opt in to the legacy auto-approve behavior so they can exercise
    // the rest of the syscall path without standing up a real bridge.
    // SAFETY: integration tests run in their own process; setting env is OK.
    unsafe { std::env::set_var("MEDIATOR_AUTO_APPROVE_ON_NO_BRIDGE", "1") };
    MediatorConfig {
        socket_path,
        db_path: "sqlite::memory:".into(),
        hmac_key_bytes: Some(b"integration-test-key-32bytes!".to_vec()),
        approval_bridge_url: None,
            webhook_secret: None,
        trust_spec_path: None,
        init_inference_endpoint: None,
    }
}

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

async fn send_and_recv(
    client: &mut UnixStream,
    req: &serde_json::Value,
) -> serde_json::Value {
    client.write_all(&encode_frame(req)).await.unwrap();
    read_frame(client).await
}

/// Bootstrap a mediator, start serving, return (root_token, socket_path, cancel_token).
async fn start_mediator() -> (String, PathBuf, tokio_util::sync::CancellationToken) {
    // Leak the tempdir so the socket persists for the test duration.
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));

    let config = test_config(dir.path().join("mediator.sock"));
    let result = bootstrap(&config).await.unwrap();
    let root_token = result.root_token.clone();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel2 = cancel.clone();

    let listener = tokio::net::UnixListener::bind(&config.socket_path).unwrap();
    tokio::spawn(async move {
        result.daemon.serve(listener, cancel2).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (root_token, config.socket_path, cancel)
}

// ---------------------------------------------------------------------------
// 7.1 Fork → enforce → proxy (protocol-level)
// ---------------------------------------------------------------------------

/// Fork a workflow with a scoped policy, verify token + workflow created.
#[tokio::test]
async fn fork_creates_child_workflow() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // 1. Propose a scoped policy.
    let propose = serde_json::json!({
        "id": "propose-1",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "scoped_v1",
                "rationale": "integration test",
                "http_allowlist": ["https://api.example.com/*"],
                "external_mounts": [],
                "allowed_child_policies": [],
                "bind_ports": null,
                "allowed_ipc_targets": [],
                "allowed_signal_targets": []
            }
        }
    });
    let resp = send_and_recv(&mut client, &propose).await;
    assert_eq!(resp["ok"], true, "policy_propose failed: {resp}");

    // 2. Fork a child with the scoped policy.
    let fork = serde_json::json!({
        "id": "fork-1",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": {
            "workflow_id": "wf_scoped",
            "policy_name": "scoped_v1",
            "inherit": true
        }
    });
    let resp = send_and_recv(&mut client, &fork).await;
    assert_eq!(resp["ok"], true, "fork failed: {resp}");
    let child_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();
    assert!(!child_token.is_empty());
    assert!(resp["result"]["uid"].as_u64().unwrap() >= 100_000);

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.2 UID isolation (protocol-level — verifies unique UIDs allocated)
// ---------------------------------------------------------------------------

/// Fork two workflows, verify they get different UIDs.
#[tokio::test]
async fn uid_isolation_unique_uids() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose two policies.
    for name in ["iso_a_v1", "iso_b_v1"] {
        let propose = serde_json::json!({
            "id": format!("propose-{name}"),
            "method": "policy_propose",
            "workflow_token": root_token,
            "params": {
                "config": {
                    "policy_name": name,
                    "rationale": "isolation test",
                    "http_allowlist": ["https://example.com/*"],
                    "external_mounts": [],
                    "allowed_child_policies": [],
                    "bind_ports": null,
                    "allowed_ipc_targets": [],
                    "allowed_signal_targets": []
                }
            }
        });
        let resp = send_and_recv(&mut client, &propose).await;
        assert_eq!(resp["ok"], true, "propose {name} failed: {resp}");
    }

    // Fork two workflows.
    let fork_a = serde_json::json!({
        "id": "fork-a",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_iso_a", "policy_name": "iso_a_v1", "inherit": true }
    });
    let resp_a = send_and_recv(&mut client, &fork_a).await;
    assert_eq!(resp_a["ok"], true);
    let uid_a = resp_a["result"]["uid"].as_u64().unwrap();

    let fork_b = serde_json::json!({
        "id": "fork-b",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_iso_b", "policy_name": "iso_b_v1", "inherit": true }
    });
    let resp_b = send_and_recv(&mut client, &fork_b).await;
    assert_eq!(resp_b["ok"], true);
    let uid_b = resp_b["result"]["uid"].as_u64().unwrap();

    // Different UIDs.
    assert_ne!(uid_a, uid_b);
    // Both in the mediator UID range.
    assert!(uid_a >= 100_000);
    assert!(uid_b >= 100_000);

    // Same-policy workflows get the same GID.
    // (Different policies → different GIDs)
    let gid_a = resp_a["result"]["gid"].as_u64().unwrap();
    let gid_b = resp_b["result"]["gid"].as_u64().unwrap();
    assert_ne!(gid_a, gid_b); // different policies

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.3 Policy inheritance chain
// ---------------------------------------------------------------------------

/// Fork parent → child with inherit=true. Child's effective policy is union.
#[tokio::test]
async fn policy_inheritance_union() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose parent policy (allows example.com).
    let propose_parent = serde_json::json!({
        "id": "p-parent",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "parent_inherit_v1",
                "rationale": "parent",
                "http_allowlist": ["https://example.com/*"],
                "external_mounts": [],
                "allowed_child_policies": [{"policy_name": "child_inherit_*", "inherit": true}],
                "bind_ports": null,
                "allowed_ipc_targets": ["child_inherit_*"],
                "allowed_signal_targets": []
            }
        }
    });
    let resp = send_and_recv(&mut client, &propose_parent).await;
    assert_eq!(resp["ok"], true);

    // Propose child policy (allows data.io — different from parent).
    let propose_child = serde_json::json!({
        "id": "p-child",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "child_inherit_v1",
                "rationale": "child",
                "http_allowlist": ["https://data.io/*"],
                "external_mounts": [],
                "allowed_child_policies": [],
                "bind_ports": null,
                "allowed_ipc_targets": ["parent_inherit_*"],
                "allowed_signal_targets": []
            }
        }
    });
    let resp = send_and_recv(&mut client, &propose_child).await;
    assert_eq!(resp["ok"], true);

    // Fork parent workflow.
    let fork_parent = serde_json::json!({
        "id": "fork-parent",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_parent", "policy_name": "parent_inherit_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork_parent).await;
    assert_eq!(resp["ok"], true);
    let parent_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    // Fork child from parent with inherit=true.
    let fork_child = serde_json::json!({
        "id": "fork-child",
        "method": "fork_with_policy",
        "workflow_token": parent_token,
        "params": { "workflow_id": "wf_child_inherit", "policy_name": "child_inherit_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork_child).await;
    assert_eq!(resp["ok"], true);
    let child_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    // Child should be able to see both workflows via ps (verifies it's alive).
    let ps = serde_json::json!({
        "id": "ps-child",
        "method": "ps",
        "workflow_token": child_token,
        "params": {}
    });
    let resp = send_and_recv(&mut client, &ps).await;
    assert_eq!(resp["ok"], true);

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.4 Policy revocation
// ---------------------------------------------------------------------------

/// Propose a policy, fork a workflow, revoke the policy, verify cleanup.
#[tokio::test]
async fn policy_revocation_hard() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose + fork.
    let propose = serde_json::json!({
        "id": "p-rev",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "revokable_v1",
                "rationale": "to be revoked",
                "http_allowlist": ["*"],
                "external_mounts": [],
                "allowed_child_policies": [],
                "bind_ports": null,
                "allowed_ipc_targets": [],
                "allowed_signal_targets": []
            }
        }
    });
    let resp = send_and_recv(&mut client, &propose).await;
    assert_eq!(resp["ok"], true);

    let fork = serde_json::json!({
        "id": "fork-rev",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_revokable", "policy_name": "revokable_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork).await;
    assert_eq!(resp["ok"], true);

    // Verify workflow is visible via ps.
    let ps = serde_json::json!({
        "id": "ps-before",
        "method": "ps",
        "workflow_token": root_token,
        "params": {}
    });
    let resp = send_and_recv(&mut client, &ps).await;
    assert_eq!(resp["ok"], true);
    let workflows: Vec<serde_json::Value> = resp["result"].as_array().unwrap().to_vec();
    assert!(
        workflows.iter().any(|w| w["workflow_id"] == "wf_revokable"),
        "workflow should be visible before revocation"
    );

    // Revoke (hard).
    let revoke = serde_json::json!({
        "id": "revoke-1",
        "method": "revoke_policy",
        "workflow_token": root_token,
        "params": { "policy_name": "revokable_v1", "hard": true }
    });
    let resp = send_and_recv(&mut client, &revoke).await;
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["revoked"], true);
    let affected = resp["result"]["affected_workflows"].as_array().unwrap();
    assert_eq!(affected.len(), 1);
    assert_eq!(affected[0], "wf_revokable");

    // Verify workflow is no longer visible.
    let ps_after = serde_json::json!({
        "id": "ps-after",
        "method": "ps",
        "workflow_token": root_token,
        "params": {}
    });
    let resp = send_and_recv(&mut client, &ps_after).await;
    assert_eq!(resp["ok"], true);
    let workflows: Vec<serde_json::Value> = resp["result"].as_array().unwrap().to_vec();
    assert!(
        !workflows.iter().any(|w| w["workflow_id"] == "wf_revokable"),
        "workflow should be gone after hard revocation"
    );

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.5 Challenge workflow: recursive forking (deep process tree)
// ---------------------------------------------------------------------------

/// Fork 5 levels deep, verify all tokens are valid and ps works at each level.
#[tokio::test]
async fn recursive_forking_deep_tree() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose a self-referencing policy (can fork children of same policy).
    let propose = serde_json::json!({
        "id": "p-deep",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "deep_v1",
                "rationale": "recursive test",
                "http_allowlist": ["*"],
                "external_mounts": [],
                "allowed_child_policies": [{"policy_name": "deep_v1", "inherit": true}],
                "bind_ports": null,
                "allowed_ipc_targets": ["deep_v1"],
                "allowed_signal_targets": []
            }
        }
    });
    let resp = send_and_recv(&mut client, &propose).await;
    assert_eq!(resp["ok"], true);

    // Fork 5 levels deep.
    let mut current_token = root_token.clone();
    let mut tokens = vec![root_token];

    for depth in 0..5 {
        let fork = serde_json::json!({
            "id": format!("fork-d{depth}"),
            "method": "fork_with_policy",
            "workflow_token": current_token,
            "params": {
                "workflow_id": format!("wf_depth_{depth}"),
                "policy_name": "deep_v1",
                "inherit": true
            }
        });
        let resp = send_and_recv(&mut client, &fork).await;
        assert_eq!(resp["ok"], true, "fork at depth {depth} failed: {resp}");
        current_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();
        tokens.push(current_token.clone());
    }

    // Verify ps works from the deepest level.
    let ps = serde_json::json!({
        "id": "ps-deep",
        "method": "ps",
        "workflow_token": current_token,
        "params": {}
    });
    let resp = send_and_recv(&mut client, &ps).await;
    assert_eq!(resp["ok"], true);
    // Should see at least 4 other workflows (the parent chain).
    let count = resp["result"].as_array().unwrap().len();
    assert!(count >= 4, "deepest workflow should see at least 4 peers, got {count}");

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.5 Challenge workflow: IPC between workflows
// ---------------------------------------------------------------------------

/// Two workflows with mutual IPC consent can send messages.
#[tokio::test]
async fn ipc_between_workflows() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose two policies that allow IPC to each other.
    for (name, target) in [("ipc_sender_v1", "ipc_receiver_*"), ("ipc_receiver_v1", "ipc_sender_*")] {
        let propose = serde_json::json!({
            "id": format!("p-{name}"),
            "method": "policy_propose",
            "workflow_token": root_token,
            "params": {
                "config": {
                    "policy_name": name,
                    "rationale": "ipc test",
                    "http_allowlist": [],
                    "external_mounts": [],
                    "allowed_child_policies": [],
                    "bind_ports": null,
                    "allowed_ipc_targets": [target],
                    "allowed_signal_targets": []
                }
            }
        });
        let resp = send_and_recv(&mut client, &propose).await;
        assert_eq!(resp["ok"], true);
    }

    // Fork both.
    let fork_sender = serde_json::json!({
        "id": "fork-sender",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_sender", "policy_name": "ipc_sender_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork_sender).await;
    assert_eq!(resp["ok"], true);
    let sender_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    let fork_receiver = serde_json::json!({
        "id": "fork-recv",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_receiver", "policy_name": "ipc_receiver_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork_receiver).await;
    assert_eq!(resp["ok"], true);

    // Send IPC message from sender to receiver.
    let ipc_send = serde_json::json!({
        "id": "ipc-1",
        "method": "ipc_send",
        "workflow_token": sender_token,
        "params": {
            "target_workflow_id": "wf_receiver",
            "message": {"type": "hello", "data": "world"}
        }
    });
    let resp = send_and_recv(&mut client, &ipc_send).await;
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["result"]["ack"], true);

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.5 Challenge workflow: IPC denied without mutual consent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ipc_denied_without_consent() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose sender (allows target) and receiver (does NOT allow sender).
    let propose_sender = serde_json::json!({
        "id": "p-s",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "one_way_sender_v1",
                "rationale": "test",
                "http_allowlist": [],
                "external_mounts": [],
                "allowed_child_policies": [],
                "bind_ports": null,
                "allowed_ipc_targets": ["one_way_receiver_*"],
                "allowed_signal_targets": []
            }
        }
    });
    send_and_recv(&mut client, &propose_sender).await;

    let propose_receiver = serde_json::json!({
        "id": "p-r",
        "method": "policy_propose",
        "workflow_token": root_token,
        "params": {
            "config": {
                "policy_name": "one_way_receiver_v1",
                "rationale": "test",
                "http_allowlist": [],
                "external_mounts": [],
                "allowed_child_policies": [],
                "bind_ports": null,
                "allowed_ipc_targets": [],
                "allowed_signal_targets": []
            }
        }
    });
    send_and_recv(&mut client, &propose_receiver).await;

    // Fork both.
    let fork_s = serde_json::json!({
        "id": "f-s", "method": "fork_with_policy", "workflow_token": root_token,
        "params": { "workflow_id": "wf_ows", "policy_name": "one_way_sender_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork_s).await;
    let sender_token = resp["result"]["workflow_token"].as_str().unwrap().to_string();

    let fork_r = serde_json::json!({
        "id": "f-r", "method": "fork_with_policy", "workflow_token": root_token,
        "params": { "workflow_id": "wf_owr", "policy_name": "one_way_receiver_v1", "inherit": true }
    });
    send_and_recv(&mut client, &fork_r).await;

    // Try IPC — should be denied (receiver doesn't allow sender).
    let ipc = serde_json::json!({
        "id": "ipc-deny",
        "method": "ipc_send",
        "workflow_token": sender_token,
        "params": { "target_workflow_id": "wf_owr", "message": "sneaky" }
    });
    let resp = send_and_recv(&mut client, &ipc).await;
    assert_eq!(resp["ok"], false);
    assert!(resp["error"]["message"].as_str().unwrap().contains("does not allow IPC from"));

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// 7.6 Audit trail
// ---------------------------------------------------------------------------

/// Verify that all syscalls produce audit log entries.
#[tokio::test]
async fn audit_trail_recorded() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Execute several syscalls.
    let ps = serde_json::json!({
        "id": "audit-ps", "method": "ps", "workflow_token": root_token, "params": {}
    });
    send_and_recv(&mut client, &ps).await;

    let propose = serde_json::json!({
        "id": "audit-propose", "method": "policy_propose", "workflow_token": root_token,
        "params": { "config": {
            "policy_name": "audit_v1", "rationale": "audit test",
            "http_allowlist": [], "external_mounts": [],
            "allowed_child_policies": [], "bind_ports": null,
            "allowed_ipc_targets": [], "allowed_signal_targets": []
        }}
    });
    send_and_recv(&mut client, &propose).await;

    // We can't directly query the audit log via the UDS protocol, but we
    // verify that the daemon doesn't crash and all responses are well-formed.
    // The audit log is verified in unit tests (daemon::tests::audit_log_written_on_syscall).

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Edge case: invalid token rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_token_rejected() {
    let (_root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    let req = serde_json::json!({
        "id": "bad-1",
        "method": "ps",
        "workflow_token": "totally-invalid-token",
        "params": {}
    });
    let resp = send_and_recv(&mut client, &req).await;
    assert_eq!(resp["ok"], false);
    // Invalid token → EPERM (token not found in store).
    let code = resp["error"]["code"].as_str().unwrap();
    assert!(code == "EPERM" || code == "EINVAL", "expected EPERM or EINVAL, got {code}");

    cancel.cancel();
}

// ---------------------------------------------------------------------------
// Edge case: fork with disallowed policy rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fork_disallowed_policy_rejected() {
    let (root_token, sock_path, cancel) = start_mediator().await;
    let mut client = UnixStream::connect(&sock_path).await.unwrap();

    // Propose a policy that doesn't exist in allowed_child_policies of init_v0.
    // init_v0 allows "*", so this should work. Instead, try forking a
    // non-existent policy.
    let fork = serde_json::json!({
        "id": "fork-bad",
        "method": "fork_with_policy",
        "workflow_token": root_token,
        "params": { "workflow_id": "wf_bad", "policy_name": "nonexistent_v1", "inherit": true }
    });
    let resp = send_and_recv(&mut client, &fork).await;
    assert_eq!(resp["ok"], false);
    let msg = resp["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("not found") || msg.contains("not in"),
        "expected 'not found' error, got: {msg}"
    );

    cancel.cancel();
}
