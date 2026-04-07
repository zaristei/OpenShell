// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI wrapper for the mediator UDS protocol.
//!
//! Allows shell-level access to all mediator syscalls. Designed for agents
//! that interact with the mediator via shell commands.
//!
//! Usage:
//!   mediator-cli <method> [json-params]
//!   mediator-cli ps
//!   mediator-cli policy_list
//!   mediator-cli policy_get '{"policy_name": "fetcher_v1"}'
//!   mediator-cli policy_propose '{"config": {"policy_name": "...", ...}}'
//!   mediator-cli fork_with_policy '{"workflow_id": "wf_1", "policy_name": "fetcher_v1", "inherit": true}'
//!   mediator-cli ipc_send '{"target_workflow_id": "wf_2", "message": {...}}'
//!   mediator-cli signal '{"target_workflow_id": "wf_2", "signal": "term"}'
//!   mediator-cli request_port
//!   mediator-cli http_request '{"requests": [{"method": "GET", "url": "..."}]}'
//!   mediator-cli revoke_policy '{"policy_name": "...", "hard": true}'
//!
//! Environment:
//!   MEDIATOR_SOCKET     Path to mediator UDS (default: /run/openshell/mediator.sock)
//!   MEDIATOR_TOKEN      Workflow token for authentication

use bytes::{BufMut, BytesMut};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        std::process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let method = &args[1];
    let params_str = args.get(2).map(String::as_str).unwrap_or("{}");

    let params: serde_json::Value = match serde_json::from_str(params_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: invalid JSON params: {e}");
            eprintln!("  Input: {params_str}");
            std::process::exit(1);
        }
    };

    let socket_path = std::env::var("MEDIATOR_SOCKET")
        .unwrap_or_else(|_| "/run/openshell/mediator.sock".into());

    let token = match std::env::var("MEDIATOR_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            eprintln!("Error: MEDIATOR_TOKEN not set");
            eprintln!("  The workflow token is required for authentication.");
            std::process::exit(1);
        }
    };

    let request = serde_json::json!({
        "id": format!("cli-{}", std::process::id()),
        "method": method,
        "workflow_token": token,
        "params": params,
    });

    // Connect to mediator socket.
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: cannot connect to mediator at {socket_path}: {e}");
            std::process::exit(1);
        }
    };

    // Send length-prefixed JSON frame.
    let payload = serde_json::to_vec(&request).unwrap();
    let mut buf = BytesMut::with_capacity(4 + payload.len());
    buf.put_u32(payload.len() as u32);
    buf.extend_from_slice(&payload);
    if let Err(e) = stream.write_all(&buf) {
        eprintln!("Error: write failed: {e}");
        std::process::exit(1);
    }

    // Read length-prefixed response.
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        eprintln!("Error: read length failed: {e}");
        std::process::exit(1);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut resp_buf = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut resp_buf) {
        eprintln!("Error: read payload failed: {e}");
        std::process::exit(1);
    }

    let response: serde_json::Value = match serde_json::from_slice(&resp_buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: invalid response: {e}");
            std::process::exit(1);
        }
    };

    // Pretty-print response.
    if response["ok"].as_bool() == Some(true) {
        // Success: print result only (clean output for piping).
        if let Some(result) = response.get("result") {
            println!("{}", serde_json::to_string_pretty(result).unwrap());
        } else {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
    } else {
        // Error: print to stderr and exit non-zero.
        if let Some(error) = response.get("error") {
            eprintln!(
                "Error [{}]: {}",
                error["code"].as_str().unwrap_or("?"),
                error["message"].as_str().unwrap_or("unknown error")
            );
        } else {
            eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        r#"mediator-cli — shell interface to the mediator syscall API

USAGE:
  mediator-cli <method> [json-params]

METHODS:
  ps                     List visible workflows
  policy_list            List approved policies
  policy_get             Get policy details          {{"policy_name": "..."}}
  policy_propose         Propose new policy          {{"config": {{...}}}}
  fork_with_policy       Fork child workflow         {{"workflow_id": "...", "policy_name": "...", "inherit": true}}
  ipc_send               Send message                {{"target_workflow_id": "...", "message": {{...}}}}
  ipc_connect            Open bidirectional stream   {{"target_workflow_id": "..."}}
  signal                 Signal a workflow            {{"target_workflow_id": "...", "signal": "term"}}
  request_port           Allocate a port             {{}}
  revoke_policy          Revoke a policy             {{"policy_name": "...", "hard": true}}

ENVIRONMENT:
  MEDIATOR_SOCKET        UDS path (default: /run/openshell/mediator.sock)
  MEDIATOR_TOKEN         Workflow token (required)

EXAMPLES:
  mediator-cli ps
  mediator-cli policy_list
  mediator-cli policy_propose '{{"config": {{"policy_name": "fetcher_v1", "rationale": "web fetcher", "http_allowlist": ["https://*.wikipedia.org/*"], "external_mounts": [], "allowed_child_policies": [], "bind_ports": null, "allowed_ipc_targets": [], "allowed_signal_targets": []}}}}'
  mediator-cli fork_with_policy '{{"workflow_id": "wf_fetch", "policy_name": "fetcher_v1", "inherit": true}}'
  mediator-cli ipc_send '{{"target_workflow_id": "wf_fetch", "message": {{"task": "go"}}}}'
  mediator-cli signal '{{"target_workflow_id": "wf_fetch", "signal": "term"}}'
"#
    );
}
