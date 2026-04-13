// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone mediator daemon.
//!
//! Bootstraps the mediator, writes the root token to a file, and serves
//! until SIGTERM. Designed to run as a background process in the sandbox
//! container alongside the OpenClaw gateway.
//!
//! Usage:
//!   mediator-daemon [--socket PATH] [--db PATH] [--token-file PATH] [--trust-spec PATH]
//!
//! Environment (fallbacks):
//!   MEDIATOR_SOCKET       UDS path (default: /sandbox/.mediator/mediator.sock)
//!   MEDIATOR_DB           SQLite path (default: sqlite:///sandbox/.mediator/mediator.db?mode=rwc)
//!   MEDIATOR_TRUST_SPEC   Trust spec YAML path (optional)
//!   INIT_INFERENCE_ENDPOINT  Inference URL for init policy (optional)

use openshell_sandbox::mediator::init::{MediatorConfig, run_mediator};
use std::path::PathBuf;

fn main() {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Parse args (simple flag parsing, no clap dependency for this binary).
    let args: Vec<String> = std::env::args().collect();
    let mut socket = std::env::var("MEDIATOR_SOCKET")
        .unwrap_or_else(|_| "/sandbox/.mediator/mediator.sock".into());
    let mut db = std::env::var("MEDIATOR_DB")
        .unwrap_or_else(|_| "sqlite:///sandbox/.mediator/mediator.db?mode=rwc".into());
    let mut token_file = String::new();
    let mut trust_spec: Option<PathBuf> = std::env::var("MEDIATOR_TRUST_SPEC")
        .ok()
        .map(PathBuf::from);
    let mut inference_endpoint = std::env::var("INIT_INFERENCE_ENDPOINT").ok();
    let mut approval_bridge_url = std::env::var("APPROVAL_BRIDGE_URL").ok();
    let mut webhook_secret = std::env::var("WEBHOOK_SECRET").ok();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                socket = args.get(i + 1).cloned().unwrap_or(socket);
                i += 2;
            }
            "--db" => {
                db = args.get(i + 1).cloned().unwrap_or(db);
                i += 2;
            }
            "--token-file" => {
                token_file = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--trust-spec" => {
                trust_spec = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--inference-endpoint" => {
                inference_endpoint = args.get(i + 1).cloned();
                i += 2;
            }
            "--approval-bridge-url" => {
                approval_bridge_url = args.get(i + 1).cloned();
                i += 2;
            }
            "--webhook-secret" => {
                webhook_secret = args.get(i + 1).cloned();
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!(
                    "mediator-daemon — standalone mediator for sandbox containers\n\n\
                     Usage: mediator-daemon [OPTIONS]\n\n\
                     Options:\n  \
                       --socket <path>              UDS path (env: MEDIATOR_SOCKET)\n  \
                       --db <path>                  SQLite path (env: MEDIATOR_DB)\n  \
                       --token-file <path>          Write root token here (default: <socket>.token)\n  \
                       --trust-spec <path>          Trust spec YAML (env: MEDIATOR_TRUST_SPEC)\n  \
                       --inference-endpoint <url>   Init's inference URL (env: INIT_INFERENCE_ENDPOINT)\n  \
                       --approval-bridge-url <url>  Operator approval bridge (env: APPROVAL_BRIDGE_URL)\n  \
                                                    When unset, policy_propose fail-CLOSES.\n  \
                       --webhook-secret <secret>    HMAC-SHA256 secret for signing bridge requests (env: WEBHOOK_SECRET)"
                );
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    // Default token file: socket path + .token suffix.
    if token_file.is_empty() {
        token_file = format!("{socket}.token");
    }

    let config = MediatorConfig {
        socket_path: PathBuf::from(&socket),
        db_path: db,
        hmac_key_bytes: None,
        approval_bridge_url,
        webhook_secret,
        trust_spec_path: trust_spec,
        init_inference_endpoint: inference_endpoint,
    };

    // Create runtime and run.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel2 = cancel.clone();

        // Handle SIGTERM for graceful shutdown.
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("received shutdown signal");
            cancel2.cancel();
        });

        // Also handle SIGTERM (not just SIGINT).
        #[cfg(unix)]
        {
            let cancel3 = cancel.clone();
            tokio::spawn(async move {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to register SIGTERM handler");
                sigterm.recv().await;
                tracing::info!("received SIGTERM");
                cancel3.cancel();
            });
        }

        match run_mediator_with_token_file(&config, cancel, &token_file).await {
            Ok(()) => tracing::info!("mediator daemon exited cleanly"),
            Err(e) => {
                tracing::error!("mediator daemon failed: {e}");
                std::process::exit(1);
            }
        }
    });
}

/// Bootstrap the mediator, write the root token, then serve.
async fn run_mediator_with_token_file(
    config: &MediatorConfig,
    cancel: tokio_util::sync::CancellationToken,
    token_file: &str,
) -> Result<(), String> {
    use openshell_sandbox::mediator::init::bootstrap;

    // Ensure parent directories exist.
    if let Some(parent) = PathBuf::from(&config.socket_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create socket dir: {e}"))?;
    }
    if let Some(parent) = PathBuf::from(token_file).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create token dir: {e}"))?;
    }

    let result = bootstrap(config).await?;

    // Write root token to file (readable by sandbox user).
    std::fs::write(token_file, &result.root_token)
        .map_err(|e| format!("write token file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(token_file, std::fs::Permissions::from_mode(0o444));
    }

    tracing::info!(
        socket = %config.socket_path.display(),
        token_file,
        "mediator daemon ready"
    );

    // Serve until cancelled.
    result
        .daemon
        .bind_and_serve(cancel)
        .await
        .map_err(|e| format!("serve failed: {e}"))?;

    // Clean up.
    let _ = std::fs::remove_file(token_file);
    let _ = std::fs::remove_file(&config.socket_path);

    Ok(())
}
