// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Peer credential extraction from TCP sockets.
//!
//! On Linux, extracts the peer UID from a TCP connection over loopback by
//! reading the UID column from `/proc/net/tcp`. This avoids the expensive
//! socket-inode-to-PID scan used for binary identity binding.

/// Peer credentials extracted from a socket connection.
#[derive(Debug, Clone)]
pub struct TcpPeerCred {
    pub uid: u32,
    pub pid: Option<u32>,
}

/// Extract the peer UID from a TCP connection by reading `/proc/net/tcp`.
///
/// Finds the remote endpoint by matching the peer's port in the tcp table
/// and reads the UID field (column 7).
///
/// Returns `None` if the peer can't be identified (non-Linux, no match, etc.).
#[cfg(target_os = "linux")]
pub fn tcp_peer_uid(local_port: u16, remote_port: u16) -> Option<TcpPeerCred> {
    // Read /proc/net/tcp (self) to find the connection by local+remote port.
    let tcp_data = std::fs::read_to_string("/proc/net/tcp").ok()?;

    for line in tcp_data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // fields[1] = local_address (hex_ip:hex_port)
        // fields[2] = rem_address (hex_ip:hex_port)
        // fields[3] = state (01 = ESTABLISHED)
        // fields[7] = uid

        let state = fields[3];
        if state != "01" {
            continue; // Only ESTABLISHED connections
        }

        // Parse local port from fields[1]
        let local_parts: Vec<&str> = fields[1].split(':').collect();
        if local_parts.len() != 2 {
            continue;
        }
        let lport = u16::from_str_radix(local_parts[1], 16).ok()?;

        // Parse remote port from fields[2]
        let remote_parts: Vec<&str> = fields[2].split(':').collect();
        if remote_parts.len() != 2 {
            continue;
        }
        let rport = u16::from_str_radix(remote_parts[1], 16).ok()?;

        // Match: our local port is the proxy port, remote port is the peer's port
        if lport == local_port && rport == remote_port {
            let uid: u32 = fields[7].parse().ok()?;
            return Some(TcpPeerCred { uid, pid: None });
        }
    }

    // Try /proc/net/tcp6 as fallback (IPv6 / IPv4-mapped)
    if let Ok(tcp6_data) = std::fs::read_to_string("/proc/net/tcp6") {
        for line in tcp6_data.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            if fields[3] != "01" {
                continue;
            }

            let local_parts: Vec<&str> = fields[1].split(':').collect();
            let remote_parts: Vec<&str> = fields[2].split(':').collect();
            if local_parts.len() != 2 || remote_parts.len() != 2 {
                continue;
            }

            let lport = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);
            let rport = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);

            if lport == local_port && rport == remote_port {
                let uid: u32 = fields[7].parse().ok()?;
                return Some(TcpPeerCred { uid, pid: None });
            }
        }
    }

    None
}

/// Non-Linux stub: always returns None.
#[cfg(not(target_os = "linux"))]
pub fn tcp_peer_uid(_local_port: u16, _remote_port: u16) -> Option<TcpPeerCred> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_existent_connection_returns_none() {
        // No connection on these ports should exist.
        assert!(tcp_peer_uid(59999, 59998).is_none());
    }
}
