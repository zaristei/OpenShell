// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Append-only audit logging for mediator syscalls.

use super::store::queries;
use super::store::schema::AuditEntry;
use sqlx::SqlitePool;
use std::time::SystemTime;
use tracing::warn;

/// Record a syscall invocation in the audit log.
///
/// This is called by the dispatch layer for every syscall, regardless of
/// whether it was allowed or denied. Failures to write the audit log are
/// logged as warnings but do not block the response.
pub async fn audit_syscall(
    pool: &SqlitePool,
    workflow_id: &str,
    workflow_token: &str,
    syscall: &str,
    args: &serde_json::Value,
    result: &str,
    policy_used: &str,
    details: Option<&str>,
) {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());

    let entry = AuditEntry {
        id: None,
        timestamp,
        workflow_id: workflow_id.into(),
        workflow_token: workflow_token.into(),
        syscall: syscall.into(),
        args: args.to_string(),
        result: result.into(),
        policy_used: policy_used.into(),
        details: details.map(String::from),
    };

    if let Err(e) = queries::append_audit(pool, &entry).await {
        warn!("failed to write audit log: {e}");
    }
}

/// Generate a minimal Syncthing XML config for replicating the audit database.
///
/// The config shares the directory containing `db_path` as a send-only folder
/// to `remote_device_id`. This is a helper for operators — it is not
/// auto-executed by the mediator.
pub fn generate_syncthing_config(db_path: &str, remote_device_id: &str) -> String {
    let folder_path = std::path::Path::new(db_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/var/lib/openshell".into());

    format!(
        r#"<configuration version="37">
  <folder id="mediator-audit" label="Mediator Audit" path="{folder_path}"
          type="sendonly" rescanIntervalS="60">
    <device id="{remote_device_id}" introducedBy="">
      <encryptionPassword></encryptionPassword>
    </device>
    <minDiskFree unit="%">1</minDiskFree>
  </folder>
  <device id="{remote_device_id}" name="audit-replica" compression="metadata">
    <address>dynamic</address>
  </device>
</configuration>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syncthing_config_contains_device() {
        let config =
            generate_syncthing_config("/var/lib/openshell/mediator.db", "ABCDEF-123456-GHIJKL");
        assert!(config.contains("ABCDEF-123456-GHIJKL"));
        assert!(config.contains("/var/lib/openshell"));
        assert!(config.contains("sendonly"));
        assert!(config.contains("mediator-audit"));
    }
}
