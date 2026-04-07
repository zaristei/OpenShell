// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `http_request` syscall: batched outbound HTTP with allowlist enforcement.

use crate::mediator::policy::inherit::url_allowed;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::warn;

/// Regex to strip `<script>...</script>` tags from response bodies.
static SCRIPT_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap());

/// Batched request parameters.
#[derive(Debug, serde::Deserialize)]
pub struct HttpRequestParams {
    pub requests: Vec<SingleRequest>,
}

/// A single HTTP request in the batch.
#[derive(Debug, serde::Deserialize)]
pub struct SingleRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
}

/// Result for a single request in the batch.
#[derive(Debug, serde::Serialize)]
pub struct HttpResponseEntry {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
    /// Set when the request was denied by the allowlist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Execute the `http_request` syscall.
///
/// For each request in the batch, validates the URL against the caller's
/// `http_allowlist`, makes the HTTP call if allowed, and returns the
/// response (with basic script-tag sanitization).
pub async fn handle_http_request(
    http_allowlist: &[String],
    params: HttpRequestParams,
) -> Vec<HttpResponseEntry> {
    let client = reqwest::Client::new();
    let mut results = Vec::with_capacity(params.requests.len());

    for req in &params.requests {
        // 1. Allowlist check.
        if !url_allowed(&req.url, http_allowlist) {
            results.push(HttpResponseEntry {
                status: 0,
                headers: HashMap::new(),
                body: serde_json::Value::Null,
                error: Some(format!("ENETDENIED: URL '{}' not in allowlist", req.url)),
            });
            continue;
        }

        // 2. Build and send the request.
        let response = match execute_request(&client, req).await {
            Ok(r) => r,
            Err(e) => {
                results.push(HttpResponseEntry {
                    status: 0,
                    headers: HashMap::new(),
                    body: serde_json::Value::Null,
                    error: Some(format!("request failed: {e}")),
                });
                continue;
            }
        };

        results.push(response);
    }

    results
}

/// Build a reqwest request from a `SingleRequest` and execute it.
async fn execute_request(
    client: &reqwest::Client,
    req: &SingleRequest,
) -> Result<HttpResponseEntry, String> {
    let method: reqwest::Method = req
        .method
        .parse()
        .map_err(|e| format!("invalid method '{}': {e}", req.method))?;

    let mut builder = client.request(method, &req.url);

    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if let Some(body) = &req.body {
        builder = builder.json(body);
    }

    let resp = builder.send().await.map_err(|e| e.to_string())?;

    let status = resp.status().as_u16();
    let headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body_text = resp.text().await.map_err(|e| e.to_string())?;

    // 3. Sanitize: strip script tags.
    let sanitized = sanitize_response_body(&body_text);

    // Try to parse as JSON; fall back to string value.
    let body_value =
        serde_json::from_str(&sanitized).unwrap_or_else(|_| serde_json::Value::String(sanitized));

    Ok(HttpResponseEntry {
        status,
        headers,
        body: body_value,
        error: None,
    })
}

/// Strip `<script>` tags from response body text.
fn sanitize_response_body(body: &str) -> String {
    SCRIPT_TAG_RE.replace_all(body, "").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_script_tags() {
        let input = r#"Hello <script>alert("xss")</script> World"#;
        assert_eq!(sanitize_response_body(input), "Hello  World");
    }

    #[test]
    fn sanitize_strips_multiline_script() {
        let input =
            "<div>ok</div><script type=\"text/javascript\">\nvar x = 1;\n</script><p>safe</p>";
        assert_eq!(sanitize_response_body(input), "<div>ok</div><p>safe</p>");
    }

    #[test]
    fn sanitize_preserves_clean_content() {
        let input = r#"{"data": "hello"}"#;
        assert_eq!(sanitize_response_body(input), input);
    }

    #[tokio::test]
    async fn allowlist_denies_disallowed_url() {
        let allowlist = vec!["https://api.example.com/*".into()];
        let params = HttpRequestParams {
            requests: vec![SingleRequest {
                method: "GET".into(),
                url: "https://evil.com/steal".into(),
                headers: HashMap::new(),
                body: None,
            }],
        };

        let results = handle_http_request(&allowlist, params).await;
        assert_eq!(results.len(), 1);
        assert!(results[0].error.as_ref().unwrap().contains("ENETDENIED"));
        assert_eq!(results[0].status, 0);
    }

    #[tokio::test]
    async fn allowlist_allows_matching_url() {
        let allowlist = vec!["https://httpbin.org/*".into()];
        let params = HttpRequestParams {
            requests: vec![SingleRequest {
                method: "GET".into(),
                url: "https://httpbin.org/get".into(),
                headers: HashMap::new(),
                body: None,
            }],
        };

        let results = handle_http_request(&allowlist, params).await;
        assert_eq!(results.len(), 1);
        // Should either succeed (200) or fail with a network error — not ENETDENIED.
        assert!(
            results[0].error.is_none()
                || !results[0].error.as_ref().unwrap().contains("ENETDENIED")
        );
    }

    #[tokio::test]
    async fn batch_mixed_allowed_and_denied() {
        let allowlist = vec!["https://httpbin.org/*".into()];
        let params = HttpRequestParams {
            requests: vec![
                SingleRequest {
                    method: "GET".into(),
                    url: "https://httpbin.org/status/200".into(),
                    headers: HashMap::new(),
                    body: None,
                },
                SingleRequest {
                    method: "GET".into(),
                    url: "https://evil.com/bad".into(),
                    headers: HashMap::new(),
                    body: None,
                },
            ],
        };

        let results = handle_http_request(&allowlist, params).await;
        assert_eq!(results.len(), 2);
        // First should be allowed (may fail due to network, but not ENETDENIED).
        assert!(
            results[0].error.is_none()
                || !results[0].error.as_ref().unwrap().contains("ENETDENIED")
        );
        // Second should be denied.
        assert!(results[1].error.as_ref().unwrap().contains("ENETDENIED"));
    }
}
