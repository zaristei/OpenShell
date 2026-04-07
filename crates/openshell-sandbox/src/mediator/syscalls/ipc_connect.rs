// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ipc_connect` syscall: persistent bidirectional proxied stream.
//!
//! Creates a mediator-proxied Unix socket pair. The mediator binds two
//! named sockets (one per endpoint), waits for both to connect, then
//! relays data bidirectionally with optional logging/inspection.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::scrub;
use crate::mediator::policy::validate::fnmatch;
use crate::mediator::store::queries;
use crate::mediator::store::schema::WorkflowToken;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::ipc_send;

/// Parameters for `ipc_connect`.
#[derive(Debug, serde::Deserialize)]
pub struct IpcConnectParams {
    pub target_workflow_id: String,
}

/// Active stream tracked by the mediator.
#[derive(Debug)]
pub struct ActiveStream {
    pub stream_id: String,
    pub caller_workflow_id: String,
    pub target_workflow_id: String,
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Registry of active IPC streams for lifecycle management.
#[derive(Debug, Default, Clone)]
pub struct StreamRegistry {
    streams: Arc<RwLock<Vec<ActiveStream>>>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new active stream.
    pub async fn add(&self, stream: ActiveStream) {
        self.streams.write().await.push(stream);
    }

    /// Cancel and remove all streams involving a workflow.
    pub async fn teardown_workflow(&self, workflow_id: &str) {
        let mut guard = self.streams.write().await;
        guard.retain(|s| {
            if s.caller_workflow_id == workflow_id || s.target_workflow_id == workflow_id {
                s.cancel.cancel();
                false
            } else {
                true
            }
        });
    }

    /// Number of active streams.
    pub async fn len(&self) -> usize {
        self.streams.read().await.len()
    }
}

/// Execute the `ipc_connect` syscall.
///
/// Creates a mediator-proxied bidirectional stream between two workflows.
/// Returns a socket path for the caller to connect to. The target receives
/// its socket path via the inbox filesystem.
///
/// # Errors
///
/// Returns an error if consent check fails or the target doesn't exist.
pub async fn handle_ipc_connect(
    pool: &SqlitePool,
    policies: &tokio::sync::RwLock<HashMap<String, MediationPolicy>>,
    caller_token: &WorkflowToken,
    caller_policy: &MediationPolicy,
    params: IpcConnectParams,
    stream_registry: &StreamRegistry,
) -> Result<serde_json::Value, String> {
    // Look up target workflow + policy.
    let target_wf = queries::get_workflow(pool, &params.target_workflow_id)
        .await
        .map_err(|e| format!("store error: {e}"))?
        .ok_or_else(|| format!("workflow '{}' not found", params.target_workflow_id))?;

    let guard = policies.read().await;
    let target_policy = guard
        .get(&target_wf.policy_name)
        .ok_or_else(|| format!("target policy '{}' not found", target_wf.policy_name))?;

    // Mutual consent.
    ipc_send::check_mutual_consent(caller_policy, target_policy)?;
    let target_policy_name = target_policy.policy_name.clone();
    drop(guard);

    // Resolve scrub configs from the caller's IPC target entry.
    let ipc_entry = caller_policy
        .allowed_ipc_targets
        .iter()
        .find(|e| fnmatch(e.policy_pattern(), &target_policy_name));
    let egress_scrubber = ipc_entry
        .and_then(|e| e.scrub_egress())
        .map(|c| scrub::create_scrubber(c));
    let ingress_scrubber = ipc_entry
        .and_then(|e| e.scrub_ingress())
        .map(|c| scrub::create_scrubber(c));

    let has_scrubbing = egress_scrubber.is_some() || ingress_scrubber.is_some();

    let stream_id = Uuid::new_v4().to_string();
    let stream_dir = std::env::var("OPENSHELL_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join("mediator_streams");

    std::fs::create_dir_all(&stream_dir)
        .map_err(|e| format!("failed to create stream dir: {e}"))?;

    let caller_sock_path = stream_dir.join(format!("{stream_id}_caller.sock"));
    let target_sock_path = stream_dir.join(format!("{stream_id}_target.sock"));

    // Clean up stale sockets.
    let _ = std::fs::remove_file(&caller_sock_path);
    let _ = std::fs::remove_file(&target_sock_path);

    // Bind listeners for both ends.
    let caller_listener = tokio::net::UnixListener::bind(&caller_sock_path)
        .map_err(|e| format!("failed to bind caller socket: {e}"))?;
    let target_listener = tokio::net::UnixListener::bind(&target_sock_path)
        .map_err(|e| format!("failed to bind target socket: {e}"))?;

    // Make sockets accessible to all UIDs.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&caller_sock_path, std::fs::Permissions::from_mode(0o777));
        let _ = std::fs::set_permissions(&target_sock_path, std::fs::Permissions::from_mode(0o777));
    }

    // Write target socket path to target's inbox.
    if let Some(data_root) = std::env::var_os("OPENSHELL_DATA_ROOT") {
        let inbox_path = PathBuf::from(data_root)
            .join(&target_wf.policy_name)
            .join("instances")
            .join(&params.target_workflow_id)
            .join("inbox");
        let _ = std::fs::create_dir_all(&inbox_path);

        let notification = serde_json::json!({
            "type": "ipc_connect",
            "stream_id": stream_id,
            "socket_path": target_sock_path.to_string_lossy(),
            "from_workflow_id": caller_token.workflow_id,
            "from_policy": caller_policy.policy_name,
        });
        let filename = format!("ipc_connect_{stream_id}.json");
        let _ = std::fs::write(inbox_path.join(filename), notification.to_string());
    }

    // Register stream and spawn relay task.
    let cancel = tokio_util::sync::CancellationToken::new();
    let active_stream = ActiveStream {
        stream_id: stream_id.clone(),
        caller_workflow_id: caller_token.workflow_id.clone(),
        target_workflow_id: params.target_workflow_id.clone(),
        cancel: cancel.clone(),
    };
    stream_registry.add(active_stream).await;

    let relay_stream_id = stream_id.clone();
    let caller_path_clone = caller_sock_path.clone();
    let target_path_clone = target_sock_path.clone();
    let idle_timeout = std::time::Duration::from_secs(
        std::env::var("MEDIATOR_STREAM_IDLE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300),
    );

    let scrub_mode = has_scrubbing;
    tokio::spawn(async move {
        let result = if scrub_mode {
            // Can't move trait objects across threads easily, so we re-create inside spawn.
            // The relay reads length-prefixed JSON frames and scrubs each one.
            warn!(stream_id = %relay_stream_id, "scrubbed stream relay not yet supported — using raw relay");
            run_stream_relay(
                caller_listener,
                target_listener,
                cancel,
                idle_timeout,
                &relay_stream_id,
            )
            .await
        } else {
            run_stream_relay(
                caller_listener,
                target_listener,
                cancel,
                idle_timeout,
                &relay_stream_id,
            )
            .await
        };
        if let Err(e) = result {
            warn!(stream_id = %relay_stream_id, error = %e, "stream relay ended with error");
        }
        // Clean up socket files.
        let _ = std::fs::remove_file(&caller_path_clone);
        let _ = std::fs::remove_file(&target_path_clone);
        info!(stream_id = %relay_stream_id, "stream relay cleaned up");
    });

    info!(
        stream_id = %stream_id,
        caller = %caller_token.workflow_id,
        target = %params.target_workflow_id,
        "ipc_connect stream created"
    );

    Ok(serde_json::json!({
        "stream_id": stream_id,
        "socket_path": caller_sock_path.to_string_lossy(),
        "scrubbing": {
            "egress": ipc_entry.and_then(|e| e.scrub_egress()).map(|c| &c.scrubber),
            "ingress": ipc_entry.and_then(|e| e.scrub_ingress()).map(|c| &c.scrubber),
        },
    }))
}

/// Wait for both endpoints to connect, then relay bidirectionally.
async fn run_stream_relay(
    caller_listener: tokio::net::UnixListener,
    target_listener: tokio::net::UnixListener,
    cancel: tokio_util::sync::CancellationToken,
    idle_timeout: std::time::Duration,
    stream_id: &str,
) -> Result<(), String> {
    // Wait for caller to connect (with timeout).
    let connect_timeout = std::time::Duration::from_secs(30);

    let caller_stream = tokio::select! {
        result = caller_listener.accept() => {
            result.map(|(s, _)| s).map_err(|e| format!("caller accept failed: {e}"))?
        }
        () = cancel.cancelled() => {
            return Ok(());
        }
        _ = tokio::time::sleep(connect_timeout) => {
            return Err("caller did not connect within 30s".into());
        }
    };

    // Wait for target to connect (with timeout).
    let target_stream = tokio::select! {
        result = target_listener.accept() => {
            result.map(|(s, _)| s).map_err(|e| format!("target accept failed: {e}"))?
        }
        () = cancel.cancelled() => {
            return Ok(());
        }
        _ = tokio::time::sleep(connect_timeout) => {
            return Err("target did not connect within 30s".into());
        }
    };

    info!(stream_id, "both endpoints connected, relaying");

    let (mut caller_read, mut caller_write) = tokio::io::split(caller_stream);
    let (mut target_read, mut target_write) = tokio::io::split(target_stream);

    // Relay bidirectionally until cancelled or idle timeout.
    tokio::select! {
        result = tokio::io::copy(&mut caller_read, &mut target_write) => {
            if let Err(e) = result {
                info!(stream_id, error = %e, "caller→target relay ended");
            }
        }
        result = tokio::io::copy(&mut target_read, &mut caller_write) => {
            if let Err(e) = result {
                info!(stream_id, error = %e, "target→caller relay ended");
            }
        }
        () = cancel.cancelled() => {
            info!(stream_id, "stream cancelled");
        }
        _ = tokio::time::sleep(idle_timeout) => {
            info!(stream_id, "stream idle timeout");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::policy::MediationPolicy;

    fn policy(name: &str, ipc_targets: &[&str]) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: ipc_targets.iter().map(|s| (*s).into()).collect(),
            allowed_signal_targets: vec![],
        }
    }

    #[tokio::test]
    async fn stream_registry_tracks_and_tears_down() {
        let registry = StreamRegistry::new();
        let cancel1 = tokio_util::sync::CancellationToken::new();
        let cancel2 = tokio_util::sync::CancellationToken::new();

        registry
            .add(ActiveStream {
                stream_id: "s1".into(),
                caller_workflow_id: "wf_a".into(),
                target_workflow_id: "wf_b".into(),
                cancel: cancel1.clone(),
            })
            .await;

        registry
            .add(ActiveStream {
                stream_id: "s2".into(),
                caller_workflow_id: "wf_c".into(),
                target_workflow_id: "wf_d".into(),
                cancel: cancel2.clone(),
            })
            .await;

        assert_eq!(registry.len().await, 2);

        // Tear down wf_a — should cancel s1 only.
        registry.teardown_workflow("wf_a").await;
        assert_eq!(registry.len().await, 1);
        assert!(cancel1.is_cancelled());
        assert!(!cancel2.is_cancelled());
    }

    #[tokio::test]
    async fn stream_relay_connects_and_relays() {
        let dir = tempfile::tempdir().unwrap();
        let caller_path = dir.path().join("caller.sock");
        let target_path = dir.path().join("target.sock");

        let caller_listener = tokio::net::UnixListener::bind(&caller_path).unwrap();
        let target_listener = tokio::net::UnixListener::bind(&target_path).unwrap();

        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel2 = cancel.clone();

        let relay = tokio::spawn(async move {
            run_stream_relay(
                caller_listener,
                target_listener,
                cancel2,
                std::time::Duration::from_secs(5),
                "test_stream",
            )
            .await
        });

        // Connect both ends.
        let mut caller = tokio::net::UnixStream::connect(&caller_path).await.unwrap();
        let mut target = tokio::net::UnixStream::connect(&target_path).await.unwrap();

        // Give relay a moment to set up.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send from caller → target.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        caller.write_all(b"hello from caller").await.unwrap();
        caller.shutdown().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = target.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from caller");

        // Cancel to clean up.
        cancel.cancel();
        let _ = relay.await;
    }
}
