// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mediator daemon: Unix domain socket server that dispatches syscalls.

use super::auth::{self, PeerCred, TokenKey};
use super::gid::GidAllocator;
use super::policy::MediationPolicy;
use super::policy::trust_spec::TrustSpec;
use super::proto::{LengthPrefixedJson, Request, Response};
use super::registry::UidPolicyRegistry;
use super::store::MediatorStore;
use super::syscalls::{self, SyscallContext};
use super::uid::UidAllocator;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

/// Configuration for the mediator daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Path for the Unix domain socket.
    pub socket_path: PathBuf,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/openshell/mediator.sock"),
        }
    }
}

/// The mediator daemon.
///
/// Listens on a Unix domain socket, authenticates callers via `SO_PEERCRED`,
/// and dispatches syscall requests to the appropriate handler.
pub struct MediatorDaemon {
    ctx: Arc<SyscallContext>,
    config: DaemonConfig,
}

impl MediatorDaemon {
    /// Create a new daemon with the given store, signing key, and config.
    pub fn new(
        store: MediatorStore,
        token_key: TokenKey,
        policies: HashMap<String, MediationPolicy>,
        config: DaemonConfig,
    ) -> Self {
        Self::with_approval_bridge(store, token_key, policies, config, None, None)
    }

    /// Create a new daemon with an optional approval bridge URL.
    pub fn with_approval_bridge(
        store: MediatorStore,
        token_key: TokenKey,
        policies: HashMap<String, MediationPolicy>,
        config: DaemonConfig,
        approval_bridge_url: Option<String>,
        trust_spec: Option<Arc<TrustSpec>>,
    ) -> Self {
        Self::with_shared_registry(
            store,
            token_key,
            policies,
            config,
            approval_bridge_url,
            trust_spec,
            UidPolicyRegistry::new(),
        )
    }

    /// Create a new daemon with shared UID policy registry (for embedded mode).
    pub fn with_shared_registry(
        store: MediatorStore,
        token_key: TokenKey,
        policies: HashMap<String, MediationPolicy>,
        config: DaemonConfig,
        approval_bridge_url: Option<String>,
        trust_spec: Option<Arc<TrustSpec>>,
        uid_policy_registry: UidPolicyRegistry,
    ) -> Self {
        let ctx = Arc::new(SyscallContext {
            store,
            token_key,
            policies: Arc::new(RwLock::new(policies)),
            approval_bridge_url,
            trust_spec,
            uid_allocator: Arc::new(UidAllocator::new()),
            gid_allocator: Arc::new(GidAllocator::new()),
            uid_policy_registry,
            stream_registry: super::syscalls::ipc_connect::StreamRegistry::new(),
        });
        Self { ctx, config }
    }

    /// Return a reference to the syscall context (useful for tests).
    pub fn context(&self) -> &Arc<SyscallContext> {
        &self.ctx
    }

    /// Run the daemon on a pre-bound listener.
    ///
    /// This is the primary entry point for both production and testing. In
    /// production, bind a `UnixListener` at `config.socket_path` and pass it
    /// here. In tests, bind on a temp-dir path instead.
    ///
    /// The daemon runs until `cancel` is cancelled.
    pub async fn serve(&self, listener: UnixListener, cancel: tokio_util::sync::CancellationToken) {
        info!(path = %self.config.socket_path.display(), "mediator daemon listening");

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("mediator daemon shutting down");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _addr)) => {
                            let fd = stream.as_raw_fd();
                            let peer = match auth::peer_cred(fd) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!("failed to get peer credentials: {e}");
                                    PeerCred { pid: 0, uid: 0, gid: 0 }
                                }
                            };

                            let ctx = Arc::clone(&self.ctx);
                            tokio::spawn(async move {
                                handle_connection(ctx, stream, peer).await;
                            });
                        }
                        Err(e) => {
                            error!("accept error: {e}");
                        }
                    }
                }
            }
        }
    }

    /// Convenience: bind and serve in one call.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn bind_and_serve(
        &self,
        cancel: tokio_util::sync::CancellationToken,
    ) -> std::io::Result<()> {
        // Remove stale socket file if present.
        let _ = std::fs::remove_file(&self.config.socket_path);
        let listener = UnixListener::bind(&self.config.socket_path)?;
        self.serve(listener, cancel).await;
        Ok(())
    }

    /// Return the configured socket path.
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }
}

/// Handle a single client connection: read requests, dispatch, write responses.
async fn handle_connection(
    ctx: Arc<SyscallContext>,
    stream: tokio::net::UnixStream,
    peer: PeerCred,
) {
    let mut framed = Framed::new(stream, LengthPrefixedJson);

    while let Some(frame) = framed.next().await {
        let value = match frame {
            Ok(v) => v,
            Err(e) => {
                warn!("frame read error: {e}");
                break;
            }
        };

        let req: Request = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = Response::err(String::new(), "EINVAL", format!("bad request: {e}"));
                let _ = framed
                    .send(serde_json::to_value(&err_resp).unwrap_or_default())
                    .await;
                continue;
            }
        };

        let resp = syscalls::dispatch(&ctx, &req, &peer).await;
        if let Err(e) = framed
            .send(serde_json::to_value(&resp).unwrap_or_default())
            .await
        {
            warn!("frame write error: {e}");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::auth::TokenKey;
    use crate::mediator::store::MediatorStore;
    use crate::mediator::store::queries::{insert_token, insert_workflow};
    use crate::mediator::store::schema::{ActiveWorkflow, WorkflowToken};
    use bytes::{BufMut, BytesMut};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Helper: encode a JSON value into a length-prefixed frame.
    fn encode_frame(value: &serde_json::Value) -> Vec<u8> {
        let payload = serde_json::to_vec(value).unwrap();
        let len = payload.len() as u32;
        let mut buf = BytesMut::with_capacity(4 + payload.len());
        buf.put_u32(len);
        buf.extend_from_slice(&payload);
        buf.to_vec()
    }

    /// Helper: read one length-prefixed JSON frame from a stream.
    async fn read_frame(stream: &mut UnixStream) -> serde_json::Value {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await.unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    #[tokio::test]
    async fn daemon_accepts_and_responds() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let key = TokenKey::new(b"test-key".to_vec());

        // Seed a caller token, workflow, and policy.
        let tok = WorkflowToken {
            token: "tok_test".into(),
            workflow_id: "wf_test".into(),
            pid: 1,
            policy_name: "test_policy".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_token(store.pool(), &tok).await.unwrap();
        insert_workflow(
            store.pool(),
            &ActiveWorkflow {
                workflow_id: "wf_test".into(),
                policy_name: "test_policy".into(),
                root_pid: 1,
                namespace_id: "ns_test".into(),
                workflow_token: "tok_test".into(),
                parent_workflow_id: None,
                started_at: "2026-01-01T00:00:00Z".into(),
                uid: None,
            },
        )
        .await
        .unwrap();

        let mut policies = HashMap::new();
        policies.insert(
            "test_policy".into(),
            MediationPolicy {
                policy_name: "test_policy".into(),
                rationale: "test".into(),
                http_allowlist: vec![],
                external_mounts: vec![],
                allowed_child_policies: vec![],
                bind_ports: None,
                allowed_ipc_targets: vec!["*".into()],
                allowed_signal_targets: vec![],
            },
        );

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let config = DaemonConfig {
            socket_path: sock_path.clone(),
        };

        let daemon = MediatorDaemon::new(store, key, policies, config);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel2 = cancel.clone();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let serve_handle = tokio::spawn(async move {
            daemon.serve(listener, cancel2).await;
        });

        // Give the server a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send a ps request.
        let mut client = UnixStream::connect(&sock_path).await.unwrap();

        let req = serde_json::json!({
            "id": "req-1",
            "method": "ps",
            "workflow_token": "tok_test",
            "params": {}
        });
        client.write_all(&encode_frame(&req)).await.unwrap();

        let resp = read_frame(&mut client).await;
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["id"], "req-1");
        // ps returns empty because no *other* workflows exist.
        assert!(resp["result"].as_array().unwrap().is_empty());

        // Send signal with bad params — should get EINVAL (all methods are now routed).
        let req2 = serde_json::json!({
            "id": "req-2",
            "method": "signal",
            "workflow_token": "tok_test",
            "params": {}
        });
        client.write_all(&encode_frame(&req2)).await.unwrap();

        let resp2 = read_frame(&mut client).await;
        assert_eq!(resp2["ok"], false);
        assert_eq!(resp2["error"]["code"], "EINVAL");

        // Shutdown.
        cancel.cancel();
        serve_handle.await.unwrap();
    }

    #[tokio::test]
    async fn daemon_rejects_invalid_token() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let key = TokenKey::new(b"k".to_vec());

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test2.sock");
        let config = DaemonConfig {
            socket_path: sock_path.clone(),
        };

        let daemon = MediatorDaemon::new(store, key, HashMap::new(), config);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel2 = cancel.clone();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let serve_handle = tokio::spawn(async move {
            daemon.serve(listener, cancel2).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&sock_path).await.unwrap();
        let req = serde_json::json!({
            "id": "req-bad",
            "method": "ps",
            "workflow_token": "nonexistent",
            "params": {}
        });
        client.write_all(&encode_frame(&req)).await.unwrap();

        let resp = read_frame(&mut client).await;
        assert_eq!(resp["ok"], false);
        assert_eq!(resp["error"]["code"], "EPERM");

        cancel.cancel();
        serve_handle.await.unwrap();
    }

    #[tokio::test]
    async fn audit_log_written_on_syscall() {
        let store = MediatorStore::open("sqlite::memory:").await.unwrap();
        let key = TokenKey::new(b"audit-key".to_vec());

        let tok = WorkflowToken {
            token: "tok_audit".into(),
            workflow_id: "wf_audit".into(),
            pid: 1,
            policy_name: "audit_policy".into(),
            inherited_from: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            uid: None,
        };
        insert_token(store.pool(), &tok).await.unwrap();
        insert_workflow(
            store.pool(),
            &ActiveWorkflow {
                workflow_id: "wf_audit".into(),
                policy_name: "audit_policy".into(),
                root_pid: 1,
                namespace_id: "ns_a".into(),
                workflow_token: "tok_audit".into(),
                parent_workflow_id: None,
                started_at: "2026-01-01T00:00:00Z".into(),
                uid: None,
            },
        )
        .await
        .unwrap();

        let mut policies = HashMap::new();
        policies.insert(
            "audit_policy".into(),
            MediationPolicy {
                policy_name: "audit_policy".into(),
                rationale: "t".into(),
                http_allowlist: vec![],
                external_mounts: vec![],
                allowed_child_policies: vec![],
                bind_ports: None,
                allowed_ipc_targets: vec![],
                allowed_signal_targets: vec![],
            },
        );

        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("audit.sock");
        let config = DaemonConfig {
            socket_path: sock_path.clone(),
        };

        let pool_clone = store.pool().clone();
        let daemon = MediatorDaemon::new(store, key, policies, config);
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel2 = cancel.clone();

        let listener = UnixListener::bind(&sock_path).unwrap();
        let serve_handle = tokio::spawn(async move {
            daemon.serve(listener, cancel2).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut client = UnixStream::connect(&sock_path).await.unwrap();
        let req = serde_json::json!({
            "id": "req-a",
            "method": "ps",
            "workflow_token": "tok_audit",
            "params": {}
        });
        client.write_all(&encode_frame(&req)).await.unwrap();
        let _ = read_frame(&mut client).await;

        // Allow audit write to flush.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Check audit log.
        let audit = crate::mediator::store::queries::recent_audit(&pool_clone, 10)
            .await
            .unwrap();
        assert!(!audit.is_empty());
        assert_eq!(audit[0].syscall, "ps");
        assert_eq!(audit[0].workflow_id, "wf_audit");

        cancel.cancel();
        serve_handle.await.unwrap();
    }
}
