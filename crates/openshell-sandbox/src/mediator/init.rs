// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Mediator bootstrap: init process, root token, and daemon creation.

use super::auth::TokenKey;
use super::daemon::{DaemonConfig, MediatorDaemon};
use super::policy::trust_spec::TrustSpec;
use super::policy::{MediationPolicy, PortRange, SignalTarget};
use super::store::MediatorStore;
use super::store::queries;
use super::store::schema::WorkflowToken;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

/// Configuration for bootstrapping the mediator.
#[derive(Debug, Clone)]
pub struct MediatorConfig {
    /// Path for the Unix domain socket.
    pub socket_path: PathBuf,
    /// SQLite database path (use `"sqlite::memory:"` for tests).
    pub db_path: String,
    /// HMAC key bytes. If `None`, 32 random bytes are generated.
    pub hmac_key_bytes: Option<Vec<u8>>,
    /// Approval bridge base URL (e.g. `http://localhost:8090`).
    /// When set, `policy_propose` sends proposals to Telegram for human approval.
    /// When `None`, proposals are auto-approved (useful for tests).
    pub approval_bridge_url: Option<String>,
    /// HMAC-SHA256 secret for signing webhook requests to the approval bridge.
    pub webhook_secret: Option<String>,
    /// Path to the trust specification YAML file for taint analysis.
    /// When set, `policy_propose` performs per-tag taint analysis and includes
    /// violation warnings in the approval payload.
    pub trust_spec_path: Option<PathBuf>,
    /// Inference endpoint URL pattern for init's HTTP allowlist.
    /// This is the only HTTP endpoint init can reach (e.g. `https://host.docker.internal:4000/*`).
    /// When `None`, init has no HTTP access at all.
    pub init_inference_endpoint: Option<String>,
    /// L7 proxy address. Passed to iptables rules so child UIDs route
    /// through the correct proxy address (e.g. `10.200.0.1:3128` in netns).
    pub proxy_addr: std::net::SocketAddr,
    /// Filesystem paths the sandbox's `SandboxPolicy` allows (union of
    /// `read_only` + `read_write`). Used by `policy_propose` to subset-check
    /// proposed child `external_mounts` against the sandbox's ceiling: a
    /// mount is admissible iff its absolute path is a subpath of one of
    /// these. Empty vec → no filesystem subset check runs (permissive).
    pub sandbox_fs_paths: Vec<PathBuf>,
}

impl Default for MediatorConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/sandbox/.mediator/mediator.sock"),
            db_path: "sqlite:///sandbox/.mediator/mediator.db?mode=rwc".into(),
            hmac_key_bytes: None,
            approval_bridge_url: None,
            webhook_secret: None,
            trust_spec_path: None,
            init_inference_endpoint: None,
            proxy_addr: ([127, 0, 0, 1], 3128).into(),
            sandbox_fs_paths: Vec::new(),
        }
    }
}

/// Result of a successful bootstrap.
pub struct BootstrapResult {
    /// The configured daemon, ready to serve.
    pub daemon: MediatorDaemon,
    /// The root workflow token (hex string) for the init process.
    pub root_token: String,
}

/// Bootstrap the mediator: open store, generate keys, create init policy
/// and root token, return a daemon ready to serve.
///
/// # Errors
///
/// Returns an error if the store cannot be opened or the root token
/// cannot be inserted.
pub async fn bootstrap(config: &MediatorConfig) -> Result<BootstrapResult, String> {
    // 1. Open store.
    let store = MediatorStore::open(&config.db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;

    // 2. Generate or use provided HMAC key.
    let key_bytes = match &config.hmac_key_bytes {
        Some(bytes) => bytes.clone(),
        None => {
            let mut buf = vec![0u8; 32];
            OsRng.fill_bytes(&mut buf);
            buf
        }
    };
    let token_key = TokenKey::new(key_bytes);

    // 3. Create init_v0 policy.
    let init_policy = create_init_policy(config.init_inference_endpoint.as_deref());
    let mut policies = HashMap::new();
    policies.insert("init_v0".into(), init_policy);

    // 4. Generate root workflow token.
    let pid = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let root_token_value = token_key.generate("init", pid, &timestamp);

    // 5. Insert root token into store.
    let wf_token = WorkflowToken {
        token: root_token_value.as_str().into(),
        workflow_id: "init".into(),
        pid: i64::from(pid),
        policy_name: "init_v0".into(),
        inherited_from: None,
        created_at: timestamp,
        uid: None, // init process runs as root, no UID isolation
    };
    queries::insert_token(store.pool(), &wf_token)
        .await
        .map_err(|e| format!("failed to insert root token: {e}"))?;

    // Remount /proc with hidepid=2 so processes can only see their own entries.
    #[cfg(target_os = "linux")]
    {
        let result = std::process::Command::new("mount")
            .args(["-o", "remount,hidepid=2", "/proc"])
            .output();
        match result {
            Ok(o) if o.status.success() => {
                info!("remounted /proc with hidepid=2");
            }
            _ => {
                tracing::warn!("failed to remount /proc with hidepid=2 (non-fatal)");
            }
        }
    }

    // 6. Load trust spec if configured.
    let trust_spec = load_trust_spec(config)?;

    info!(
        workflow_id = "init",
        pid,
        trust_spec = trust_spec.is_some(),
        "mediator bootstrapped with init_v0 policy"
    );

    // 7. Build daemon.
    let daemon_config = DaemonConfig {
        socket_path: config.socket_path.clone(),
        proxy_addr: config.proxy_addr,
    };
    let daemon = MediatorDaemon::with_shared_registry(
        store,
        token_key,
        policies,
        daemon_config,
        config.approval_bridge_url.clone(),
        config.webhook_secret.clone(),
        trust_spec,
        super::registry::UidPolicyRegistry::new(),
        config.sandbox_fs_paths.clone(),
    );

    Ok(BootstrapResult {
        daemon,
        root_token: root_token_value.into_string(),
    })
}

/// Bootstrap the mediator with an externally-provided `UidPolicyRegistry`.
///
/// Used when embedding the mediator in the sandbox process so the proxy
/// and mediator share the same registry.
pub async fn bootstrap_embedded(
    config: &MediatorConfig,
    registry: super::registry::UidPolicyRegistry,
) -> Result<BootstrapResult, String> {
    // Ensure parent directories exist for socket and DB.
    if let Some(parent) = config.socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // SQLite path: strip the "sqlite://" prefix to get the filesystem path.
    if let Some(path) = config.db_path.strip_prefix("sqlite://") {
        let db_file = path.split('?').next().unwrap_or(path);
        if let Some(parent) = std::path::Path::new(db_file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    let store = MediatorStore::open(&config.db_path)
        .await
        .map_err(|e| format!("failed to open store: {e}"))?;

    let key_bytes = match &config.hmac_key_bytes {
        Some(bytes) => bytes.clone(),
        None => {
            let mut buf = vec![0u8; 32];
            OsRng.fill_bytes(&mut buf);
            buf
        }
    };
    let token_key = TokenKey::new(key_bytes);

    let init_policy = create_init_policy(config.init_inference_endpoint.as_deref());
    let mut policies = HashMap::new();
    policies.insert("init_v0".into(), init_policy);

    let pid = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let root_token_value = token_key.generate("init", pid, &timestamp);

    let wf_token = WorkflowToken {
        token: root_token_value.as_str().into(),
        workflow_id: "init".into(),
        pid: i64::from(pid),
        policy_name: "init_v0".into(),
        inherited_from: None,
        created_at: timestamp,
        uid: None,
    };
    queries::insert_token(store.pool(), &wf_token)
        .await
        .map_err(|e| format!("failed to insert root token: {e}"))?;

    let trust_spec = load_trust_spec(config)?;

    info!(
        workflow_id = "init",
        pid,
        trust_spec = trust_spec.is_some(),
        "mediator bootstrapped (embedded)"
    );

    let daemon_config = DaemonConfig {
        socket_path: config.socket_path.clone(),
        proxy_addr: config.proxy_addr,
    };
    let daemon = MediatorDaemon::with_shared_registry(
        store,
        token_key,
        policies,
        daemon_config,
        config.approval_bridge_url.clone(),
        config.webhook_secret.clone(),
        trust_spec,
        registry,
        config.sandbox_fs_paths.clone(),
    );

    Ok(BootstrapResult {
        daemon,
        root_token: root_token_value.into_string(),
    })
}

/// Load the trust spec from the configured path, or from `MEDIATOR_TRUST_SPEC` env var.
fn load_trust_spec(config: &MediatorConfig) -> Result<Option<Arc<TrustSpec>>, String> {
    let path = config
        .trust_spec_path
        .clone()
        .or_else(|| std::env::var_os("MEDIATOR_TRUST_SPEC").map(PathBuf::from));

    match path {
        Some(p) => {
            let spec = TrustSpec::load_from_file(&p)?;
            info!(path = %p.display(), "loaded trust spec");
            Ok(Some(Arc::new(spec)))
        }
        None => Ok(None),
    }
}

/// Create the init_v0 policy.
///
/// Init is a coordinator — it proposes policies, forks children, coordinates
/// via IPC, signals them, and reads results from shared filesystem paths.
///
/// Init's only HTTP access is the inference endpoint (LiteLLM sensitive tier).
/// This endpoint must be classified as `trusted_external` in the trust spec
/// to avoid the sink leg of the trifecta. The trust classification is valid
/// because init uses the sensitive-only API key (ZDR providers only).
///
/// For general web access, init forks children with appropriate HTTP policies.
/// Init's syscalls do not require per-call operator approval; the only operator
/// gate is `policy_propose`, where new capabilities are actually being requested.
fn create_init_policy(inference_endpoint: Option<&str>) -> MediationPolicy {
    let http_allowlist = match inference_endpoint {
        Some(endpoint) => vec![endpoint.to_string()],
        None => vec![],
    };
    MediationPolicy {
        policy_name: "init_v0".into(),
        rationale: "Root coordinator — inference only via sensitive-tier LiteLLM. Forks children for web access.".into(),
        http_allowlist,
        external_mounts: vec![],
        allowed_child_policies: vec!["*".into()],
        bind_ports: None,
        allowed_ipc_targets: vec![],
        allowed_signal_targets: vec![SignalTarget {
            policy_name: "*".into(),
            signals: vec!["term".into(), "kill".into(), "stop".into(), "cont".into()],
        }],
        allowed_launch_commands: vec![],
    }
}

/// Run the mediator daemon end-to-end: bootstrap then serve.
///
/// This is the primary public entry point for launching the mediator.
/// If `MEDIATOR_DASHBOARD_PORT` is set, also starts the taint dashboard.
///
/// # Errors
///
/// Returns an error if bootstrap or socket binding fails.
pub async fn run_mediator(
    config: &MediatorConfig,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<String, String> {
    let result = bootstrap(config).await?;
    info!(root_token = %result.root_token, "mediator starting");

    // Optionally start the taint dashboard.
    if let Ok(port_str) = std::env::var("MEDIATOR_DASHBOARD_PORT") {
        if let Ok(port) = port_str.parse::<u16>() {
            let ctx = result.daemon.context();
            tokio::spawn(super::dashboard::serve_dashboard(
                port,
                ctx.store.pool().clone(),
                Arc::clone(&ctx.policies),
                ctx.trust_spec.clone(),
                cancel.clone(),
            ));
        }
    }

    result
        .daemon
        .bind_and_serve(cancel)
        .await
        .map_err(|e| format!("serve failed: {e}"))?;

    Ok(result.root_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediator::store::queries;

    fn test_config() -> MediatorConfig {
        MediatorConfig {
            socket_path: PathBuf::from("/tmp/test-mediator.sock"),
            db_path: "sqlite::memory:".into(),
            hmac_key_bytes: Some(b"deterministic-test-key-32bytes!!".to_vec()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn bootstrap_creates_root_token() {
        let result = bootstrap(&test_config()).await.unwrap();
        assert!(!result.root_token.is_empty());

        // Token should be in the store.
        let stored = queries::get_token(result.daemon.context().store.pool(), &result.root_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.workflow_id, "init");
        assert_eq!(stored.policy_name, "init_v0");
        assert!(stored.inherited_from.is_none());
    }

    #[tokio::test]
    async fn bootstrap_init_v0_coordinator_policy() {
        let result = bootstrap(&test_config()).await.unwrap();
        let policies = result.daemon.context().policies.read().await;
        let init = policies.get("init_v0").unwrap();

        // Init has NO HTTP — forks children for web access.
        assert!(init.http_allowlist.is_empty(), "init should have no HTTP access");

        // Init has wildcard child/signal for coordination. IPC targets are
        // retained in the schema for compat but unused at runtime.
        assert_eq!(init.allowed_child_policies, vec!["*".to_string()]);
        assert!(init.allowed_ipc_targets.is_empty());
        assert_eq!(init.allowed_signal_targets[0].policy_name, "*");
        assert_eq!(init.allowed_signal_targets[0].signals.len(), 4);

        // No bind_ports, no sensitive mounts.
        assert!(init.bind_ports.is_none());
        assert!(init.external_mounts.is_empty());
    }

    #[tokio::test]
    async fn bootstrap_and_serve_ps() {
        let config = MediatorConfig {
            socket_path: PathBuf::from("/tmp/unused"), // won't bind
            db_path: "sqlite::memory:".into(),
            hmac_key_bytes: Some(b"test-key-exactly-32-bytes-long!!".to_vec()),
            ..Default::default()
        };

        let result = bootstrap(&config).await.unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel2 = cancel.clone();

        // Serve on a temp socket.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        let root_token = result.root_token.clone();
        let serve_handle = tokio::spawn(async move {
            result.daemon.serve(listener, cancel2).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect and send ps with the root token.
        use bytes::{BufMut, BytesMut};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();

        let req = serde_json::json!({
            "id": "req-1",
            "method": "ps",
            "workflow_token": root_token,
            "params": {}
        });
        let payload = serde_json::to_vec(&req).unwrap();
        let mut buf = BytesMut::with_capacity(4 + payload.len());
        buf.put_u32(payload.len() as u32);
        buf.extend_from_slice(&payload);
        client.write_all(&buf).await.unwrap();

        // Read response.
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).await.unwrap();
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; len];
        client.read_exact(&mut resp_buf).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&resp_buf).unwrap();

        assert_eq!(resp["ok"], true);
        assert_eq!(resp["id"], "req-1");

        cancel.cancel();
        serve_handle.await.unwrap();
    }
}
