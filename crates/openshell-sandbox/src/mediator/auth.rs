// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication helpers: SO_PEERCRED extraction and HMAC workflow tokens.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// Credentials extracted from a Unix domain socket peer via `SO_PEERCRED`.
#[derive(Debug, Clone, Copy)]
pub struct PeerCred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Extract peer credentials from a connected Unix stream.
///
/// Uses `getsockopt(SOL_SOCKET, SO_PEERCRED)` on Linux.
///
/// # Errors
///
/// Returns an error if the platform doesn't support `SO_PEERCRED` or the
/// socket option call fails.
#[cfg(target_os = "linux")]
pub fn peer_cred(fd: std::os::unix::io::RawFd) -> std::io::Result<PeerCred> {
    use std::mem;

    let mut cred: libc::ucred = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    };

    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(PeerCred {
        pid: cred.pid as u32,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Stub for non-Linux platforms (always returns pid=0, uid=0, gid=0).
#[cfg(not(target_os = "linux"))]
pub fn peer_cred(_fd: std::os::unix::io::RawFd) -> std::io::Result<PeerCred> {
    Ok(PeerCred {
        pid: 0,
        uid: 0,
        gid: 0,
    })
}

/// An HMAC-SHA256 key used to sign and verify workflow tokens.
pub struct TokenKey(Vec<u8>);

impl TokenKey {
    /// Create a key from raw bytes.
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    /// Generate a workflow token: `HMAC-SHA256(key, workflow_id + pid + timestamp)`.
    pub fn generate(&self, workflow_id: &str, pid: u32, timestamp: &str) -> WorkflowTokenValue {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        mac.update(workflow_id.as_bytes());
        mac.update(&pid.to_le_bytes());
        mac.update(timestamp.as_bytes());
        let result = mac.finalize();
        WorkflowTokenValue(hex::encode(result.into_bytes()))
    }

    /// Verify that `token` is a valid HMAC for the given inputs.
    pub fn verify(&self, token: &str, workflow_id: &str, pid: u32, timestamp: &str) -> bool {
        let expected = self.generate(workflow_id, pid, timestamp);
        expected.as_str() == token
    }
}

impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenKey")
            .field("len", &self.0.len())
            .finish()
    }
}

/// A hex-encoded HMAC-SHA256 workflow token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowTokenValue(String);

impl WorkflowTokenValue {
    /// Return the hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the inner string.
    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_generation_is_deterministic() {
        let key = TokenKey::new(b"secret-key-for-tests".to_vec());
        let t1 = key.generate("wf_1", 42, "2026-01-01T00:00:00Z");
        let t2 = key.generate("wf_1", 42, "2026-01-01T00:00:00Z");
        assert_eq!(t1, t2);
    }

    #[test]
    fn token_changes_with_inputs() {
        let key = TokenKey::new(b"secret".to_vec());
        let t1 = key.generate("wf_1", 42, "2026-01-01T00:00:00Z");
        let t2 = key.generate("wf_2", 42, "2026-01-01T00:00:00Z");
        let t3 = key.generate("wf_1", 43, "2026-01-01T00:00:00Z");
        let t4 = key.generate("wf_1", 42, "2026-01-01T00:01:00Z");
        assert_ne!(t1, t2);
        assert_ne!(t1, t3);
        assert_ne!(t1, t4);
    }

    #[test]
    fn verify_valid_token() {
        let key = TokenKey::new(b"my-key".to_vec());
        let token = key.generate("wf_x", 100, "ts");
        assert!(key.verify(token.as_str(), "wf_x", 100, "ts"));
    }

    #[test]
    fn verify_rejects_wrong_token() {
        let key = TokenKey::new(b"my-key".to_vec());
        assert!(!key.verify("badhex", "wf_x", 100, "ts"));
    }

    #[test]
    fn different_keys_produce_different_tokens() {
        let k1 = TokenKey::new(b"key-a".to_vec());
        let k2 = TokenKey::new(b"key-b".to_vec());
        let t1 = k1.generate("wf", 1, "ts");
        let t2 = k2.generate("wf", 1, "ts");
        assert_ne!(t1, t2);
    }
}
