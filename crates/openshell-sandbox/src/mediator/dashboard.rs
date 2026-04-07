// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Taint dashboard: HTTP server serving the policy graph and taint state.
//!
//! Enabled via `MEDIATOR_DASHBOARD_PORT` env var. Read-only — no mutations.

use crate::mediator::policy::MediationPolicy;
use crate::mediator::policy::trust_spec::TrustSpec;
use crate::mediator::policy::validate::fnmatch;
use crate::mediator::store::queries;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Shared state for the dashboard HTTP server.
struct DashboardState {
    pool: SqlitePool,
    policies: Arc<RwLock<HashMap<String, MediationPolicy>>>,
    trust_spec: Option<Arc<TrustSpec>>,
}

/// Start the dashboard HTTP server on the given port.
///
/// Runs until the cancellation token is triggered. Non-blocking.
pub async fn serve_dashboard(
    port: u16,
    pool: SqlitePool,
    policies: Arc<RwLock<HashMap<String, MediationPolicy>>>,
    trust_spec: Option<Arc<TrustSpec>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let state = Arc::new(DashboardState {
        pool,
        policies,
        trust_spec,
    });

    let addr: std::net::SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(%e, port, "failed to bind dashboard port");
            return;
        }
    };

    info!(port, "taint dashboard listening");

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!("taint dashboard shutting down");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_http(stream, state).await;
                        });
                    }
                    Err(e) => {
                        warn!(%e, "dashboard accept error");
                    }
                }
            }
        }
    }
}

/// Minimal HTTP/1.1 handler — just enough for the dashboard.
async fn handle_http(mut stream: tokio::net::TcpStream, state: Arc<DashboardState>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).await.is_err() {
        return;
    }

    // Parse "GET /path HTTP/1.1"
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    // Consume remaining headers.
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    break;
                }
            }
        }
    }

    let (status, content_type, body) = match path.as_str() {
        "/" => ("200 OK", "text/html", DASHBOARD_HTML.to_string()),
        "/api/graph" => {
            let graph = build_graph(&state).await;
            let json = serde_json::to_string_pretty(&graph).unwrap_or_default();
            ("200 OK", "application/json", json)
        }
        "/api/health" => {
            let health = build_health(&state).await;
            let json = serde_json::to_string_pretty(&health).unwrap_or_default();
            ("200 OK", "application/json", json)
        }
        _ => (
            "404 Not Found",
            "text/plain",
            "not found".to_string(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

/// Build the full graph JSON for `/api/graph`.
async fn build_graph(state: &DashboardState) -> serde_json::Value {
    let guard = state.policies.read().await;

    // Build policy nodes.
    let mut policies_json = Vec::new();
    let mut edges_json = Vec::new();
    let mut trifecta_nodes = Vec::new();

    let all_policies: HashMap<String, MediationPolicy> =
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    for (name, policy) in &all_policies {
        // Get stored taint if available.
        let taint_json = queries::get_policy_taint(&state.pool, name)
            .await
            .ok()
            .flatten();
        let taint: Option<serde_json::Value> =
            taint_json.and_then(|j| serde_json::from_str(&j).ok());

        let any_trifecta = taint
            .as_ref()
            .and_then(|t| t["any_trifecta"].as_bool())
            .unwrap_or(false);

        if any_trifecta {
            trifecta_nodes.push(name.clone());
        }

        // Count active workflows.
        let wf_count = queries::list_workflows(&state.pool)
            .await
            .map(|ws| ws.iter().filter(|w| &w.policy_name == name).count())
            .unwrap_or(0);

        // IPC sources: other policies that target this one.
        let ipc_sources: Vec<String> = all_policies
            .iter()
            .filter(|(other_name, other)| {
                *other_name != name
                    && other
                        .allowed_ipc_targets
                        .iter()
                        .any(|t| fnmatch(t.policy_pattern(), name))
            })
            .map(|(n, _)| n.clone())
            .collect();

        policies_json.push(serde_json::json!({
            "name": name,
            "taint": taint,
            "ipc_targets": policy.allowed_ipc_targets.iter().map(|t| t.policy_pattern()).collect::<Vec<_>>(),
            "ipc_sources": ipc_sources,
            "mounts": policy.external_mounts.iter().map(|m| serde_json::json!({"path": m.path, "mode": m.mode})).collect::<Vec<_>>(),
            "http_allowlist": policy.http_allowlist,
            "active_workflows": wf_count,
        }));

        // Build edges for IPC targets.
        for target_entry in &policy.allowed_ipc_targets {
            for target_name in all_policies.keys() {
                if fnmatch(target_entry.policy_pattern(), target_name) {
                    edges_json.push(serde_json::json!({
                        "from": name,
                        "to": target_name,
                        "scrub_egress": target_entry.scrub_egress(),
                        "scrub_ingress": target_entry.scrub_ingress(),
                    }));
                }
            }
        }
    }
    drop(guard);

    // Get compromised resources.
    let compromised = queries::list_compromised_resources(&state.pool)
        .await
        .unwrap_or_default();
    let compromised_json: Vec<serde_json::Value> = compromised
        .iter()
        .map(|c| {
            serde_json::json!({
                "path": c.resource_path,
                "type": c.resource_type,
                "compromise": c.compromise_type,
                "data_type": c.data_type,
                "caused_by": c.caused_by,
                "via": c.via_path,
            })
        })
        .collect();

    serde_json::json!({
        "policies": policies_json,
        "edges": edges_json,
        "trifecta_nodes": trifecta_nodes,
        "compromised_resources": compromised_json,
        "trust_spec_loaded": state.trust_spec.is_some(),
    })
}

/// Build health summary for `/api/health`.
async fn build_health(state: &DashboardState) -> serde_json::Value {
    let guard = state.policies.read().await;
    let policy_count = guard.len();
    drop(guard);

    let workflow_count = queries::list_workflows(&state.pool)
        .await
        .map(|w| w.len())
        .unwrap_or(0);

    let compromised_count = queries::list_compromised_resources(&state.pool)
        .await
        .map(|c| c.len())
        .unwrap_or(0);

    serde_json::json!({
        "policies": policy_count,
        "active_workflows": workflow_count,
        "compromised_resources": compromised_count,
        "trust_spec_loaded": state.trust_spec.is_some(),
    })
}

/// Embedded HTML dashboard — single-page app using vis.js for graph rendering.
const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>OpenShell Taint Dashboard</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; background: #0d1117; color: #c9d1d9; }
  #header { padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
  #header h1 { margin: 0; font-size: 18px; }
  #health { font-size: 13px; color: #8b949e; }
  #container { display: flex; height: calc(100vh - 50px); }
  #graph { flex: 1; }
  #detail { width: 350px; padding: 16px; overflow-y: auto; border-left: 1px solid #30363d; background: #161b22; font-size: 13px; }
  #detail h3 { margin-top: 0; }
  .tag-clean { color: #3fb950; }
  .tag-partial { color: #d29922; }
  .tag-trifecta { color: #f85149; }
  pre { background: #0d1117; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
  .compromised { background: #f8514922; padding: 6px; border-radius: 4px; margin: 4px 0; }
</style>
</head>
<body>
<div id="header">
  <h1>OpenShell Taint Dashboard</h1>
  <div id="health">loading...</div>
</div>
<div id="container">
  <div id="graph"></div>
  <div id="detail"><h3>Select a policy node</h3><p>Click a node in the graph to view its taint classification.</p></div>
</div>
<script>
let graphData = null;
const container = document.getElementById('graph');

function nodeColor(name, data) {
  const p = data.policies.find(p => p.name === name);
  if (!p || !p.taint) return '#8b949e';
  if (data.trifecta_nodes.includes(name)) return '#f85149';
  const tags = p.taint.tags || [];
  const hasAnyLeg = tags.some(t => t.has_source || t.has_sink || t.has_untrusted_input);
  return hasAnyLeg ? '#d29922' : '#3fb950';
}

function renderGraph(data) {
  graphData = data;
  const nodes = data.policies.map(p => ({
    id: p.name, label: p.name + (p.active_workflows > 0 ? ` (${p.active_workflows})` : ''),
    color: { background: nodeColor(p.name, data), border: '#30363d' },
    font: { color: '#c9d1d9' }, shape: 'box', borderWidth: 2,
  }));
  const edges = data.edges.map((e, i) => ({
    id: 'e' + i, from: e.from, to: e.to, arrows: 'to',
    color: { color: e.scrub_egress ? '#3fb950' : '#8b949e' },
    dashes: !e.scrub_egress && !e.scrub_ingress,
  }));
  const network = new vis.Network(container, { nodes, edges }, {
    physics: { solver: 'forceAtlas2Based' },
    layout: { improvedLayout: true },
  });
  network.on('click', params => {
    if (params.nodes.length) showDetail(params.nodes[0]);
  });
}

function showDetail(name) {
  const p = graphData.policies.find(p => p.name === name);
  if (!p) return;
  const detail = document.getElementById('detail');
  let html = `<h3>${name}</h3>`;
  html += `<p>Workflows: ${p.active_workflows} | Mounts: ${p.mounts.length} | HTTP: ${p.http_allowlist.length}</p>`;
  if (p.taint) {
    const t = p.taint;
    html += `<p class="${t.any_trifecta ? 'tag-trifecta' : 'tag-clean'}">${t.any_trifecta ? 'TRIFECTA' : 'Clean'}</p>`;
    if (t.tags) t.tags.forEach(tag => {
      const cls = tag.trifecta ? 'tag-trifecta' : (tag.has_source || tag.has_sink || tag.has_untrusted_input) ? 'tag-partial' : 'tag-clean';
      html += `<p class="${cls}"><b>${tag.data_type}</b>: src=${tag.has_source} sink=${tag.has_sink} untrusted=${tag.has_untrusted_input}</p>`;
    });
    if (t.violation_paths && t.violation_paths.length) {
      html += '<h4>Violations</h4>';
      t.violation_paths.forEach(v => { html += `<pre>${v.data_type}: ${v.source} → ${v.untrusted_via} → ${v.sink}</pre>`; });
    }
  }
  const compromised = graphData.compromised_resources.filter(c => c.caused_by === name);
  if (compromised.length) {
    html += '<h4>Compromised Resources</h4>';
    compromised.forEach(c => { html += `<div class="compromised">${c.compromise} ${c.type}: ${c.path} (${c.data_type})</div>`; });
  }
  detail.innerHTML = html;
}

async function refresh() {
  try {
    const [graph, health] = await Promise.all([
      fetch('/api/graph').then(r => r.json()),
      fetch('/api/health').then(r => r.json()),
    ]);
    document.getElementById('health').textContent =
      `Policies: ${health.policies} | Workflows: ${health.active_workflows} | Compromised: ${health.compromised_resources} | TrustSpec: ${health.trust_spec_loaded ? 'loaded' : 'none'}`;
    renderGraph(graph);
  } catch(e) { console.error('refresh failed', e); }
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"#;
