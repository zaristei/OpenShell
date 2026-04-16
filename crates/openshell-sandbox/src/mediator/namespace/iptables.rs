// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-UID iptables rules for network isolation.
//!
//! Each workflow UID gets exactly 3 OUTPUT rules:
//! 1. ACCEPT traffic to the L7 proxy (127.0.0.1:proxy_port)
//! 2. ACCEPT ESTABLISHED/RELATED (return traffic for existing connections)
//! 3. REJECT all other traffic from this UID

use std::process::Command;
use tracing::{info, warn};

/// Chain name used for mediator per-UID rules.
const CHAIN: &str = "MEDIATOR_UID";

/// Check whether iptables is available.
fn iptables_available() -> bool {
    Command::new("iptables")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Ensure the MEDIATOR_UID chain exists and is linked from OUTPUT.
fn ensure_chain() {
    // Create chain (ignore error if exists).
    let _ = Command::new("iptables").args(["-N", CHAIN]).output();

    // Insert into OUTPUT if not already present.
    let needs_insert = match Command::new("iptables")
        .args(["-C", "OUTPUT", "-j", CHAIN])
        .output()
    {
        Ok(o) => !o.status.success(),
        Err(_) => true,
    };

    if needs_insert {
        let _ = Command::new("iptables")
            .args(["-I", "OUTPUT", "1", "-j", CHAIN])
            .output();
    }
}

/// Install the 3 per-UID OUTPUT rules.
///
/// 1. ACCEPT → proxy (proxy_addr)
/// 2. ACCEPT → ESTABLISHED,RELATED
/// 3. REJECT → everything else from this UID
///
/// Gracefully skips if iptables is unavailable.
pub fn install_uid_rules(uid: u32, proxy_addr: std::net::SocketAddr) {
    if !iptables_available() {
        warn!(uid, "iptables not available, skipping UID isolation rules");
        return;
    }

    ensure_chain();
    let uid_str = uid.to_string();
    let port_str = proxy_addr.port().to_string();
    let ip_str = proxy_addr.ip().to_string();

    // Rule 1: Allow traffic to proxy.
    let _ = Command::new("iptables")
        .args([
            "-A", CHAIN,
            "-m", "owner", "--uid-owner", &uid_str,
            "-d", &ip_str,
            "-p", "tcp", "--dport", &port_str,
            "-j", "ACCEPT",
        ])
        .output();

    // Rule 2: Allow ESTABLISHED/RELATED return traffic.
    let _ = Command::new("iptables")
        .args([
            "-A", CHAIN,
            "-m", "owner", "--uid-owner", &uid_str,
            "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ])
        .output();

    // Rule 3: Reject everything else from this UID.
    let _ = Command::new("iptables")
        .args([
            "-A", CHAIN,
            "-m", "owner", "--uid-owner", &uid_str,
            "-j", "REJECT",
        ])
        .output();

    info!(uid, %proxy_addr, "installed per-UID iptables rules");
}

/// Add an INPUT ACCEPT rule for a specific port (used by `request_port`).
pub fn add_port_rule(port: u16) {
    if !iptables_available() {
        return;
    }

    let _ = Command::new("iptables")
        .args([
            "-A", "INPUT",
            "-p", "tcp", "--dport", &port.to_string(),
            "-j", "ACCEPT",
        ])
        .output();
}

/// Remove the INPUT ACCEPT rule for a specific port.
pub fn remove_port_rule(port: u16) {
    if !iptables_available() {
        return;
    }

    let _ = Command::new("iptables")
        .args([
            "-D", "INPUT",
            "-p", "tcp", "--dport", &port.to_string(),
            "-j", "ACCEPT",
        ])
        .output();
}

/// Remove all iptables rules for a specific UID.
///
/// Iteratively deletes rules from the chain that match this UID.
pub fn remove_uid_rules(uid: u32) {
    if !iptables_available() {
        return;
    }

    let uid_str = uid.to_string();

    // Delete rules matching this UID. We run the delete repeatedly since
    // there may be up to 3 rules (proxy accept, established, reject).
    // iptables -D with just the match criteria deletes the first matching rule.
    loop {
        let result = Command::new("iptables")
            .args([
                "-D", CHAIN,
                "-m", "owner", "--uid-owner", &uid_str,
            ])
            .output();

        match result {
            Ok(o) if o.status.success() => continue, // deleted one, try again
            _ => break, // no more matching rules
        }
    }

    info!(uid, "removed per-UID iptables rules");
}

/// Legacy compatibility: alias for install_uid_rules with default proxy addr.
pub fn setup_agent_isolation(uid: u32) {
    install_uid_rules(uid, ([127, 0, 0, 1], 3128).into());
}

/// Legacy compatibility: alias for remove_uid_rules.
pub fn teardown_agent_isolation(uid: u32) {
    remove_uid_rules(uid);
}
