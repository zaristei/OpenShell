// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::content_inspect::{ContentInspectionPolicy, ContentRuleRegistry, ScanInput};
use crate::l7::provider::{L7Provider, RelayOutcome};
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::secrets::{self, SecretResolver};
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, SeverityId, Url as OcsfUrl, ocsf_emit,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Context for L7 request policy evaluation.
pub struct L7EvalContext {
    /// Host from the CONNECT request.
    pub host: String,
    /// Port from the CONNECT request.
    pub port: u16,
    /// Matched policy name from L4 evaluation.
    pub policy_name: String,
    /// Binary path (for cross-layer Rego evaluation).
    pub binary_path: String,
    /// Ancestor paths.
    pub ancestors: Vec<String>,
    /// Cmdline paths.
    pub cmdline_paths: Vec<String>,
    /// Supervisor-only placeholder resolver for outbound headers.
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
    /// Content inspection rule registry (constructed from endpoint config).
    pub(crate) content_registry: Option<Arc<ContentRuleRegistry>>,
    /// Content inspection policy for this endpoint.
    pub(crate) content_inspection: Option<ContentInspectionPolicy>,
}

/// Run protocol-aware L7 inspection on a tunnel.
///
/// This replaces `copy_bidirectional` for L7-enabled endpoints.
/// Protocol detection (peek) is the caller's responsibility — this function
/// assumes the streams are already proven to carry the expected protocol.
/// For TLS-terminated connections, ALPN proves HTTP; for plaintext, the
/// caller peeks on the raw `TcpStream` before calling this.
pub async fn relay_with_inspection<C, U>(
    config: &L7EndpointConfig,
    engine: Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match config.protocol {
        L7Protocol::Rest => relay_rest(config, &engine, client, upstream, ctx).await,
        L7Protocol::Sql => {
            // SQL provider is Phase 3 — fall through to passthrough with warning
            {
                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Other)
                    .severity(SeverityId::Low)
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message("SQL L7 provider not yet implemented, falling back to passthrough")
                    .build();
                ocsf_emit!(event);
            }
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
    }
}

/// Handle an upgraded connection (101 Switching Protocols).
///
/// Forwards any overflow bytes from the upgrade response to the client, then
/// switches to raw bidirectional TCP copy for the upgraded protocol (WebSocket,
/// HTTP/2, etc.). L7 policy enforcement does not apply after the upgrade —
/// the initial HTTP request was already evaluated.
async fn handle_upgrade<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    ocsf_emit!(
        NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Other)
            .activity_name("Upgrade")
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain(host, port))
            .message(format!(
                "101 Switching Protocols — raw bidirectional relay (L7 enforcement no longer active) \
                 [host:{host} port:{port} overflow_bytes:{}]",
                overflow.len()
            ))
            .build()
    );
    if !overflow.is_empty() {
        client.write_all(&overflow).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
    }
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .into_diagnostic()?;
    Ok(())
}

/// REST relay loop: parse request -> evaluate -> allow/deny -> relay response -> repeat.
async fn relay_rest<C, U>(
    config: &L7EndpointConfig,
    engine: &Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        // Parse one HTTP request from client
        let req = match crate::l7::rest::RestProvider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // Client closed connection
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                        .message(format!("HTTP parse error in L7 relay: {e}"))
                        .build();
                    ocsf_emit!(event);
                }
                return Ok(()); // Close connection on parse error
            }
        };

        // Rewrite credential placeholders in the request target BEFORE OPA
        // evaluation. OPA sees the redacted path; the resolved path goes only
        // to the upstream write.
        let (eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
        };

        // Evaluate L7 policy via Rego (using redacted target)
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        // Check if this is an upgrade request for logging purposes.
        let header_end = req
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(req.raw_header.len(), |p| p + 4);
        let is_upgrade_request = {
            let h = String::from_utf8_lossy(&req.raw_header[..header_end]);
            h.lines()
                .skip(1)
                .any(|l| l.to_ascii_lowercase().starts_with("upgrade:"))
        };

        let decision_str = match (allowed, config.enforcement, is_upgrade_request) {
            (true, _, true) => "allow_upgrade",
            (true, _, false) => "allow",
            (false, EnforcementMode::Audit, _) => "audit",
            (false, EnforcementMode::Enforce, _) => "deny",
        };

        // Log every L7 decision as an OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        {
            let (action_id, disposition_id, severity) = match decision_str {
                "allow" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7")
                .message(format!(
                    "L7_REQUEST {decision_str} {} {}:{}{} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Store the resolved target for the deny response redaction
        let _ = &eval_target;

        if allowed || config.enforcement == EnforcementMode::Audit {
            // Content inspection: scan request body for PII if configured
            if let (Some(registry), Some(ci_policy)) =
                (&ctx.content_registry, &ctx.content_inspection)
            {
                if ci_policy.egress_mode == crate::l7::content_inspect::InspectionMode::Sync {
                    let scan_blocked = scan_and_maybe_block(
                        &req,
                        client,
                        upstream,
                        ctx,
                        registry,
                        ci_policy,
                        &request_info,
                    )
                    .await?;
                    match scan_blocked {
                        ScanResult::Blocked => return Ok(()),
                        ScanResult::Relayed(reusable) => {
                            if !reusable {
                                debug!(
                                    host = %ctx.host,
                                    port = ctx.port,
                                    "Upstream connection not reusable, closing L7 relay"
                                );
                                return Ok(());
                            }
                            continue;
                        }
                        ScanResult::Fallthrough => {
                            // Body too large for buffering, fall through to streaming
                        }
                    }
                }
            }

            // Forward request to upstream and relay response (streaming path)
            let outcome = crate::l7::rest::relay_http_request_with_resolver(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {} // continue loop
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded { overflow } => {
                    return handle_upgrade(client, upstream, overflow, &ctx.host, ctx.port).await;
                }
            }
        } else {
            // Enforce mode: deny with 403 and close connection (use redacted target)
            crate::l7::rest::RestProvider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                )
                .await?;
            return Ok(());
        }
    }
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_connection_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "client disconnected mid-request",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
pub fn evaluate_l7_request(
    engine: &Mutex<regorus::Engine>,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    let input_json = serde_json::json!({
        "network": {
            "host": ctx.host,
            "port": ctx.port,
        },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
            "query_params": request.query_params.clone(),
        }
    });

    let mut engine = engine
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;

    engine
        .set_input_json(&input_json.to_string())
        .map_err(|e| miette!("{e}"))?;

    let allowed = engine
        .eval_rule("data.openshell.sandbox.allow_request".into())
        .map_err(|e| miette!("{e}"))?;
    let allowed = allowed == regorus::Value::from(true);

    let reason = if allowed {
        String::new()
    } else {
        let val = engine
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .map_err(|e| miette!("{e}"))?;
        match val {
            regorus::Value::String(s) => s.to_string(),
            regorus::Value::Undefined => "request denied by policy".to_string(),
            other => other.to_string(),
        }
    };

    Ok((allowed, reason))
}

/// Result of content inspection + relay attempt.
enum ScanResult {
    /// Body was scanned and blocked (403 sent, connection closed).
    Blocked,
    /// Body was scanned, allowed, and relayed. Contains upstream reusability.
    Relayed(bool),
    /// Body too large to buffer — caller should fall through to streaming.
    Fallthrough,
}

/// Buffer request body, scan for PII, and either relay or block.
async fn scan_and_maybe_block<C, U>(
    req: &crate::l7::provider::L7Request,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
    registry: &ContentRuleRegistry,
    ci_policy: &ContentInspectionPolicy,
    request_info: &L7RequestInfo,
) -> Result<ScanResult>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    use crate::l7::content_inspect::{Action, EgressEnforcement};
    use crate::l7::rest::{buffer_request_body, forward_buffered_body};

    // Determine overflow bytes (body bytes read during header parsing)
    let header_end = req
        .raw_header
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(req.raw_header.len(), |p| p + 4);
    let overflow = &req.raw_header[header_end..];

    // Buffer body from client
    let body =
        match buffer_request_body(client, &req.body_length, overflow, ci_policy.max_body_bytes)
            .await?
        {
            Some(body) => body,
            None => {
                debug!(
                    host = %ctx.host,
                    port = ctx.port,
                    "Request body exceeds content inspection limit, skipping scan"
                );
                return Ok(ScanResult::Fallthrough);
            }
        };

    // Extract content-type from headers for scan input
    let header_str = std::str::from_utf8(&req.raw_header[..header_end]).unwrap_or("");
    let content_type = header_str
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-type:") {
                Some(
                    line.split_once(':')
                        .map_or("", |(_, v)| v.trim())
                        .to_string(),
                )
            } else {
                None
            }
        })
        .unwrap_or_default();

    // Run scan
    let scan_input = ScanInput {
        body: &body,
        content_type: &content_type,
        host: &ctx.host,
        port: ctx.port,
        method: &request_info.action,
        path: &request_info.target,
    };

    let results = registry.scan_egress(&scan_input);

    // Aggregate matches and determine action
    let total_matches: usize = results.iter().map(|r| r.matches.len()).sum();
    let has_block = results.iter().any(|r| r.action == Action::Block);

    if total_matches > 0 {
        let rule_names: Vec<&str> = results
            .iter()
            .filter(|r| !r.matches.is_empty())
            .flat_map(|r| r.matches.iter().map(|m| m.rule_name.as_str()))
            .collect();
        let pattern_types: Vec<&str> = results
            .iter()
            .flat_map(|r| r.matches.iter().map(|m| m.pattern_type.as_str()))
            .collect();

        info!(
            dst_host = %ctx.host,
            dst_port = ctx.port,
            policy = %ctx.policy_name,
            l7_action = %request_info.action,
            l7_target = %request_info.target,
            match_count = total_matches,
            rules = ?rule_names,
            pattern_types = ?pattern_types,
            action = if has_block { "block" } else { "flag" },
            enforcement = ?ci_policy.egress_enforcement,
            "CONTENT_SCAN",
        );
    }

    // Block if enforcement is Enforce and any rule returned Block
    if has_block && ci_policy.egress_enforcement == EgressEnforcement::Enforce {
        crate::l7::rest::RestProvider
            .deny(
                req,
                &ctx.policy_name,
                "content inspection: PII detected in request body",
                client,
            )
            .await?;
        return Ok(ScanResult::Blocked);
    }

    // Relay the buffered body to upstream
    let rewrite_result = crate::secrets::rewrite_http_header_block(
        &req.raw_header[..header_end],
        ctx.secret_resolver.as_deref(),
    )
    .map_err(|e| miette!("secret rewrite failed: {e}"))?;

    // Rewrite Content-Length if original was chunked (body is now flat)
    let rewritten_header = if matches!(req.body_length, crate::l7::provider::BodyLength::Chunked) {
        rewrite_chunked_to_content_length(&rewrite_result.rewritten, body.len())
    } else {
        rewrite_result.rewritten
    };

    upstream
        .write_all(&rewritten_header)
        .await
        .into_diagnostic()?;
    forward_buffered_body(upstream, &body).await?;
    upstream.flush().await.into_diagnostic()?;

    let outcome = crate::l7::rest::relay_response(&req.action, upstream, client).await?;
    let reusable = matches!(outcome, RelayOutcome::Reusable);
    Ok(ScanResult::Relayed(reusable))
}

/// Rewrite HTTP headers to replace Transfer-Encoding: chunked with Content-Length.
fn rewrite_chunked_to_content_length(header_bytes: &[u8], body_len: usize) -> Vec<u8> {
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut result = Vec::new();
    let mut replaced_te = false;

    for line in header_str.split("\r\n") {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            // Replace with Content-Length
            if !replaced_te {
                result.extend_from_slice(format!("Content-Length: {body_len}").as_bytes());
                result.extend_from_slice(b"\r\n");
                replaced_te = true;
            }
        } else {
            result.extend_from_slice(line.as_bytes());
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(b"\r\n");
    result
}

/// Relay HTTP traffic with credential injection only (no L7 OPA evaluation).
///
/// Used when TLS is auto-terminated but no L7 policy (`protocol` + `access`/`rules`)
/// is configured. Parses HTTP requests minimally to rewrite credential
/// placeholders and log requests for observability, then forwards everything.
pub async fn relay_passthrough_with_credentials<C, U>(
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let provider = crate::l7::rest::RestProvider;
    let mut request_count: u64 = 0;
    let resolver = ctx.secret_resolver.as_deref();

    loop {
        // Read next request from client.
        let req = match provider.parse_request(client).await {
            Ok(Some(req)) => req,
            Ok(None) => break, // Client closed connection.
            Err(e) => {
                if is_benign_connection_error(&e) {
                    break;
                }
                return Err(e);
            }
        };

        request_count += 1;

        // Resolve and redact the target for logging.
        let redacted_target = if let Some(ref res) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, res) {
                Ok(result) => result.redacted,
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            req.target.clone()
        };

        // Log for observability via OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        let has_creds = resolver.is_some();
        {
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .http_request(HttpRequest::new(
                    &req.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "HTTP_REQUEST {} {}:{}{} credentials_injected={has_creds} request_num={request_count}",
                    req.action, ctx.host, ctx.port, redacted_target,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Forward request with credential rewriting and relay the response.
        // relay_http_request_with_resolver handles both directions: it sends
        // the request upstream and reads the response back to the client.
        let outcome =
            crate::l7::rest::relay_http_request_with_resolver(&req, client, upstream, resolver)
                .await?;

        match outcome {
            RelayOutcome::Reusable => {} // continue loop
            RelayOutcome::Consumed => break,
            RelayOutcome::Upgraded { overflow } => {
                return handle_upgrade(client, upstream, overflow, &ctx.host, ctx.port).await;
            }
        }
    }

    debug!(
        host = %ctx.host,
        port = ctx.port,
        total_requests = request_count,
        "Credential injection relay completed"
    );

    Ok(())
}
