// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trust specification: global data-type classification for taint analysis.
//!
//! The trust spec defines which filesystem paths hold sensitive data, which
//! external sources are untrusted, and which external endpoints are trusted
//! for specific data types. This information drives per-tag taint analysis
//! at `policy_propose` time.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Global trust specification loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustSpec {
    /// Filesystem paths that hold sensitive data, tagged by type.
    #[serde(default)]
    pub sensitive_data: Vec<SensitiveEntry>,

    /// External sources that provide untrusted content, tagged by type.
    #[serde(default)]
    pub untrusted_sources: Vec<UntrustedSource>,

    /// External endpoints explicitly trusted for specific data types.
    #[serde(default)]
    pub trusted_external: Vec<TrustedExternal>,
}

/// A filesystem path or mount pattern holding sensitive data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SensitiveEntry {
    /// Exact path or glob pattern (e.g. `/data/customer_records`, `/secrets/*`).
    pub path: String,
    /// Data type tags (e.g. `["pii"]`, `["credentials"]`).
    pub data_types: Vec<String>,
}

/// An external source that provides untrusted/attacker-controlled content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UntrustedSource {
    /// URL pattern (e.g. `https://*.wikipedia.org/*`).
    pub pattern: String,
    /// Data type tags for the untrusted content.
    pub data_types: Vec<String>,
}

/// An external endpoint explicitly trusted for specific data types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedExternal {
    /// URL pattern (e.g. `https://internal-api.corp.com/*`).
    pub pattern: String,
    /// Data type tags this endpoint is trusted for. `["*"]` = trusted for all.
    pub data_types: Vec<String>,
}

// ── Per-tag taint state ──────────────────────────────────────────────

/// Taint analysis result for a single data-type tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagTaint {
    /// The data type being analyzed (e.g. `"pii"`, `"credentials"`).
    pub data_type: String,
    /// Can the policy read/receive data of this type?
    pub has_source: bool,
    /// Can the policy send data of this type to an untrusted external?
    pub has_sink: bool,
    /// Does the policy process attacker-controlled content of this type?
    pub has_untrusted_input: bool,
    /// All three legs present — lethal trifecta for this tag.
    pub trifecta: bool,
    /// Which mounts/IPC channels provide this data type.
    pub source_paths: Vec<String>,
    /// Which HTTP endpoints are untrusted sinks for this type.
    pub sink_targets: Vec<String>,
    /// Which sources inject untrusted content of this type.
    pub untrusted_inputs: Vec<String>,
}

/// Full taint classification for a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTaint {
    pub policy_name: String,
    /// One entry per data-type tag touched by this policy.
    pub tags: Vec<TagTaint>,
    /// True if any tag has all three trifecta legs.
    pub any_trifecta: bool,
    /// Human-readable trace for each violation.
    pub violation_paths: Vec<ViolationPath>,
    /// Resources that would be compromised if this policy is forked.
    /// Pre-computed at propose time, materialized at fork time.
    #[serde(default)]
    pub pending_compromises: Vec<PendingCompromise>,
}

/// A resource that would be compromised by a trifecta violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCompromise {
    pub resource_path: String,
    /// `"mount"`, `"file"`, or `"external_endpoint"`.
    pub resource_type: String,
    /// `"read"` (exfiltration risk) or `"write"` (poisoning risk).
    pub compromise_type: String,
    pub data_type: String,
    /// Trace of how the compromise propagates.
    pub via_path: String,
}

/// Traces a specific trifecta violation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationPath {
    /// Which data type tag is affected.
    pub data_type: String,
    /// Where the sensitive data comes from (e.g. `"mount /data/sensitive (pii)"`).
    pub source: String,
    /// Where data can leak to (e.g. `"http *.example.com (not trusted for pii)"`).
    pub sink: String,
    /// How untrusted content enters (e.g. `"IPC from fetcher_v1 (web_content)"`).
    pub untrusted_via: String,
    /// Missing scrubber info (e.g. `"IPC to fetcher_v1 has no scrubber for pii"`).
    pub scrub_gap: Option<String>,
}

// ── Analysis engine ──────────────────────────────────────────────────

use super::validate::fnmatch;
use super::{IpcTargetEntry, MediationPolicy};
use std::collections::HashMap;

/// Analyze a single policy for per-tag taint, given the current set of
/// approved policies and the global trust spec.
///
/// For each data-type tag T in the spec, checks:
/// - **Source**: can this policy access sensitive data of type T?
/// - **Untrusted input**: can attacker-controlled content reach this policy?
/// - **Sink**: can this policy send data to an untrusted external for type T?
///
/// The trifecta fires when all three are present for the same tag.
pub fn analyze_policy(
    policy: &MediationPolicy,
    all_approved: &HashMap<String, MediationPolicy>,
    spec: &TrustSpec,
) -> PolicyTaint {
    let all_tags = spec.all_data_types();
    let mut tags = Vec::new();
    let mut violation_paths = Vec::new();

    for data_type in &all_tags {
        let (has_source, source_paths) = check_source(policy, all_approved, spec, data_type);
        let (has_untrusted_input, untrusted_inputs) =
            check_untrusted_input(policy, all_approved, spec, data_type);
        let (has_sink, sink_targets) = check_sink(policy, all_approved, spec, data_type);

        let trifecta = has_source && has_untrusted_input && has_sink;

        if trifecta {
            // Build a violation path for the first source/sink/untrusted combo.
            violation_paths.push(ViolationPath {
                data_type: data_type.clone(),
                source: source_paths.first().cloned().unwrap_or_default(),
                sink: sink_targets.first().cloned().unwrap_or_default(),
                untrusted_via: untrusted_inputs.first().cloned().unwrap_or_default(),
                scrub_gap: None,
            });
        }

        tags.push(TagTaint {
            data_type: data_type.clone(),
            has_source,
            has_sink,
            has_untrusted_input,
            trifecta,
            source_paths,
            sink_targets,
            untrusted_inputs,
        });
    }

    let any_trifecta = tags.iter().any(|t| t.trifecta);

    // Pre-compute compromised resources for trifecta tags.
    let pending_compromises = if any_trifecta {
        compute_compromises(policy, all_approved, spec, &tags)
    } else {
        vec![]
    };

    PolicyTaint {
        policy_name: policy.policy_name.clone(),
        tags,
        any_trifecta,
        violation_paths,
        pending_compromises,
    }
}

/// Analyze which existing policies would be affected if `new_policy` were approved.
///
/// Returns a list of (policy_name, new taint) for policies whose taint would
/// worsen (gain a trifecta tag they didn't have before).
pub fn analyze_affected(
    new_policy: &MediationPolicy,
    all_approved: &HashMap<String, MediationPolicy>,
    spec: &TrustSpec,
) -> Vec<PolicyTaint> {
    // Build a hypothetical set that includes the new policy.
    let mut hypothetical = all_approved.clone();
    hypothetical.insert(new_policy.policy_name.clone(), new_policy.clone());

    let mut affected = Vec::new();
    for (name, existing) in all_approved {
        // Check if this policy has any IPC relationship with the new policy.
        let new_targets_existing = new_policy
            .allowed_ipc_targets
            .iter()
            .any(|t| fnmatch(t.policy_pattern(), name));
        let existing_targets_new = existing
            .allowed_ipc_targets
            .iter()
            .any(|t| fnmatch(t.policy_pattern(), &new_policy.policy_name));

        // Also check filesystem overlap.
        let has_fs_overlap = has_mount_overlap(new_policy, existing);

        if !new_targets_existing && !existing_targets_new && !has_fs_overlap {
            continue;
        }

        // Re-analyze this policy with the new one in the graph.
        let old_taint = analyze_policy(existing, all_approved, spec);
        let new_taint = analyze_policy(existing, &hypothetical, spec);

        // Only report if taint worsened.
        let worsened = new_taint.tags.iter().any(|nt| {
            nt.trifecta
                && !old_taint
                    .tags
                    .iter()
                    .any(|ot| ot.data_type == nt.data_type && ot.trifecta)
        });

        if worsened {
            affected.push(new_taint);
        }
    }
    affected
}

/// Check if two policies have overlapping mount paths (one can write, other can read).
fn has_mount_overlap(a: &MediationPolicy, b: &MediationPolicy) -> bool {
    for ma in &a.external_mounts {
        for mb in &b.external_mounts {
            if paths_overlap(&ma.path, &mb.path) {
                let a_writes = ma.mode.contains('w');
                let b_writes = mb.mode.contains('w');
                // Overlap if either can write and the other reads.
                if a_writes || b_writes {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if two paths overlap (one is a prefix of the other, or they match via glob).
fn paths_overlap(a: &str, b: &str) -> bool {
    a.starts_with(b) || b.starts_with(a) || fnmatch(a, b) || fnmatch(b, a)
}

// ── Compromise computation ───────────────────────────────────────────

/// Compute resources that would be compromised if a trifecta policy is forked.
///
/// For each tag with trifecta:
/// - Direct writable mounts → write-compromised
/// - Direct readable mounts with sensitive data → read-compromised
/// - HTTP endpoints not trusted for this tag → read-compromised (exfil target)
/// - IPC neighbors' resources (transitive, respecting scrubbers)
/// - Filesystem edges (always unscrubbed)
fn compute_compromises(
    policy: &MediationPolicy,
    all_approved: &HashMap<String, MediationPolicy>,
    spec: &TrustSpec,
    tags: &[TagTaint],
) -> Vec<PendingCompromise> {
    let mut compromises = Vec::new();

    for tag in tags {
        if !tag.trifecta {
            continue;
        }

        // Direct mounts.
        for mount in &policy.external_mounts {
            if mount.mode.contains('w') {
                compromises.push(PendingCompromise {
                    resource_path: mount.path.clone(),
                    resource_type: "mount".into(),
                    compromise_type: "write".into(),
                    data_type: tag.data_type.clone(),
                    via_path: format!("direct write by {}", policy.policy_name),
                });
            }
            // Check if mount path is sensitive for this tag.
            let is_sensitive = spec.sensitive_data.iter().any(|s| {
                s.data_types.contains(&tag.data_type)
                    && paths_overlap(&mount.path, &s.path)
            });
            if is_sensitive {
                compromises.push(PendingCompromise {
                    resource_path: mount.path.clone(),
                    resource_type: "mount".into(),
                    compromise_type: "read".into(),
                    data_type: tag.data_type.clone(),
                    via_path: format!("direct read by {}", policy.policy_name),
                });
            }
        }

        // HTTP endpoints not trusted for this tag.
        for url in &policy.http_allowlist {
            if !is_trusted_for(url, &tag.data_type, spec) {
                compromises.push(PendingCompromise {
                    resource_path: url.clone(),
                    resource_type: "external_endpoint".into(),
                    compromise_type: "read".into(),
                    data_type: tag.data_type.clone(),
                    via_path: format!(
                        "{} → {} (not trusted for {})",
                        policy.policy_name, url, tag.data_type
                    ),
                });
            }
        }

        // IPC neighbor resources (one hop — transitive walks would need BFS).
        for ipc_entry in &policy.allowed_ipc_targets {
            for (name, neighbor) in all_approved {
                if !fnmatch(ipc_entry.policy_pattern(), name) {
                    continue;
                }
                // Without egress scrubber: neighbor's writable resources → write-compromised.
                if !ipc_scrubs_egress(ipc_entry, &tag.data_type) {
                    for mount in &neighbor.external_mounts {
                        if mount.mode.contains('w') {
                            compromises.push(PendingCompromise {
                                resource_path: mount.path.clone(),
                                resource_type: "mount".into(),
                                compromise_type: "write".into(),
                                data_type: tag.data_type.clone(),
                                via_path: format!(
                                    "{} → IPC → {} → write {}",
                                    policy.policy_name, name, mount.path
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Filesystem edge: shared path readable by other policies.
        for mount in &policy.external_mounts {
            if !mount.mode.contains('w') {
                continue;
            }
            for (name, other) in all_approved {
                if name == &policy.policy_name {
                    continue;
                }
                for other_mount in &other.external_mounts {
                    if paths_overlap(&mount.path, &other_mount.path) {
                        compromises.push(PendingCompromise {
                            resource_path: other_mount.path.clone(),
                            resource_type: "mount".into(),
                            compromise_type: "write".into(),
                            data_type: tag.data_type.clone(),
                            via_path: format!(
                                "{} writes {} → {} reads {}",
                                policy.policy_name, mount.path, name, other_mount.path
                            ),
                        });
                    }
                }
            }
        }
    }

    compromises
}

// ── Source check ─────────────────────────────────────────────────────

/// Can this policy access sensitive data of type T?
///
/// Checks:
/// 1. Direct mount access to sensitive paths tagged with T
/// 2. Implicit sensitivity: writable mounts of policies with no untrusted input
///    are presumed to contain sensitive data (clean processes only write trusted data)
/// 3. IPC-receives from a partner that has source(T), without a scrubber for T
/// 4. Reads from shared path writable by a policy with source(T) (explicit or implicit)
fn check_source(
    policy: &MediationPolicy,
    all_approved: &HashMap<String, MediationPolicy>,
    spec: &TrustSpec,
    data_type: &str,
) -> (bool, Vec<String>) {
    let mut sources = Vec::new();

    // 1. Direct mount access to explicitly tagged sensitive paths.
    for mount in &policy.external_mounts {
        for sensitive in &spec.sensitive_data {
            if sensitive.data_types.contains(&data_type.to_string())
                && paths_overlap(&mount.path, &sensitive.path)
            {
                sources.push(format!("mount {} ({})", mount.path, data_type));
            }
        }
    }

    // 2. Implicit sensitivity: if this policy has no untrusted input and has
    //    writable mounts, those mounts are presumed sensitive (the policy only
    //    writes trusted data). Any readable mount is a source.
    if !policy_has_direct_untrusted(policy, spec) {
        for mount in &policy.external_mounts {
            // If this policy can write somewhere, and it's clean, that data is sensitive.
            // If it can also read its own writable paths, it has source.
            if mount.mode.contains('w') {
                sources.push(format!(
                    "implicit sensitive: {} writes {} (clean process, no untrusted input)",
                    policy.policy_name, mount.path
                ));
            }
        }
    }

    // 3. IPC from partner with source(T).
    for ipc_entry in &policy.allowed_ipc_targets {
        for (name, partner) in all_approved {
            if fnmatch(ipc_entry.policy_pattern(), name) {
                let partner_has_source = partner_has_direct_source(partner, spec, data_type);
                if partner_has_source && !ipc_scrubs_ingress(ipc_entry, data_type) {
                    sources.push(format!("IPC from {} ({})", name, data_type));
                }
            }
        }
    }

    // 4. Filesystem edge: shared path writable by a policy with source(T).
    //    This includes both explicitly-tagged sources and implicitly-sensitive writers.
    for mount in &policy.external_mounts {
        for (name, other) in all_approved {
            if name == &policy.policy_name {
                continue;
            }
            for other_mount in &other.external_mounts {
                if other_mount.mode.contains('w')
                    && paths_overlap(&mount.path, &other_mount.path)
                    && (partner_has_direct_source(other, spec, data_type)
                        || partner_is_implicitly_sensitive(other, spec))
                {
                    sources.push(format!(
                        "fs edge: {} writes {} ({})",
                        name, other_mount.path, data_type
                    ));
                }
            }
        }
    }

    let has = !sources.is_empty();
    (has, sources)
}

/// Does a policy directly have source(T) via explicitly-tagged sensitive mounts?
fn partner_has_direct_source(
    policy: &MediationPolicy,
    spec: &TrustSpec,
    data_type: &str,
) -> bool {
    policy.external_mounts.iter().any(|mount| {
        spec.sensitive_data.iter().any(|s| {
            s.data_types.contains(&data_type.to_string()) && paths_overlap(&mount.path, &s.path)
        })
    })
}

/// Is a policy implicitly sensitive? A policy with writable mounts and NO
/// untrusted input writes only trusted data — its output is presumed sensitive.
fn partner_is_implicitly_sensitive(policy: &MediationPolicy, spec: &TrustSpec) -> bool {
    let has_writable = policy.external_mounts.iter().any(|m| m.mode.contains('w'));
    has_writable && !policy_has_direct_untrusted(policy, spec)
}

/// Does a policy have any direct source of untrusted input?
/// (HTTP to untrusted sources, or bind_ports)
fn policy_has_direct_untrusted(policy: &MediationPolicy, spec: &TrustSpec) -> bool {
    if policy.bind_ports.is_some() {
        return true;
    }
    policy.http_allowlist.iter().any(|url_pat| {
        spec.untrusted_sources.iter().any(|src| {
            fnmatch(url_pat, &src.pattern)
                || fnmatch(&src.pattern, url_pat)
                || patterns_intersect(url_pat, &src.pattern)
        })
    })
}

// ── Untrusted input check ────────────────────────────────────────────

/// Can attacker-controlled content reach this policy for type T?
///
/// Checks:
/// 1. http_allowlist matches untrusted_sources for T
/// 2. bind_ports (inbound traffic is always untrusted)
/// 3. IPC from partner with untrusted_input(T) without ingress scrubber
/// 4. Reads from shared path writable by policy with untrusted_input(T)
fn check_untrusted_input(
    policy: &MediationPolicy,
    all_approved: &HashMap<String, MediationPolicy>,
    spec: &TrustSpec,
    data_type: &str,
) -> (bool, Vec<String>) {
    let mut inputs = Vec::new();

    // 1. HTTP allowlist matches untrusted sources.
    for url_pattern in &policy.http_allowlist {
        for source in &spec.untrusted_sources {
            if source.data_types.contains(&data_type.to_string())
                && (fnmatch(url_pattern, &source.pattern)
                    || fnmatch(&source.pattern, url_pattern)
                    || patterns_intersect(url_pattern, &source.pattern))
            {
                inputs.push(format!("http {} ({})", source.pattern, data_type));
            }
        }
    }

    // 2. bind_ports = inbound traffic.
    if policy.bind_ports.is_some() {
        inputs.push(format!("bind_ports (inbound, {})", data_type));
    }

    // 3. IPC from partner with untrusted input.
    for ipc_entry in &policy.allowed_ipc_targets {
        for (name, partner) in all_approved {
            if fnmatch(ipc_entry.policy_pattern(), name) {
                let partner_untrusted =
                    partner_has_direct_untrusted(partner, spec, data_type);
                if partner_untrusted && !ipc_scrubs_ingress(ipc_entry, data_type) {
                    inputs.push(format!("IPC from {} (untrusted {})", name, data_type));
                }
            }
        }
    }

    // 4. Filesystem edge: reads from path writable by policy with untrusted input.
    for mount in &policy.external_mounts {
        for (name, other) in all_approved {
            if name == &policy.policy_name {
                continue;
            }
            for other_mount in &other.external_mounts {
                if other_mount.mode.contains('w')
                    && paths_overlap(&mount.path, &other_mount.path)
                    && partner_has_direct_untrusted(other, spec, data_type)
                {
                    inputs.push(format!(
                        "fs edge: {} writes untrusted to {}",
                        name, other_mount.path
                    ));
                }
            }
        }
    }

    let has = !inputs.is_empty();
    (has, inputs)
}

/// Does a policy directly have untrusted input via HTTP or bind_ports?
fn partner_has_direct_untrusted(
    policy: &MediationPolicy,
    spec: &TrustSpec,
    data_type: &str,
) -> bool {
    if policy.bind_ports.is_some() {
        return true;
    }
    policy.http_allowlist.iter().any(|url_pat| {
        spec.untrusted_sources.iter().any(|src| {
            src.data_types.contains(&data_type.to_string())
                && (fnmatch(url_pat, &src.pattern)
                    || fnmatch(&src.pattern, url_pat)
                    || patterns_intersect(url_pat, &src.pattern))
        })
    })
}

// ── Sink check ───────────────────────────────────────────────────────

/// Can this policy send data to an untrusted external for type T?
///
/// An HTTP endpoint is an untrusted sink for T if it's in http_allowlist
/// but NOT in trusted_external for T (or wildcard).
fn check_sink(
    policy: &MediationPolicy,
    all_approved: &HashMap<String, MediationPolicy>,
    spec: &TrustSpec,
    data_type: &str,
) -> (bool, Vec<String>) {
    let mut sinks = Vec::new();

    // 1. HTTP endpoints not trusted for T.
    for url_pattern in &policy.http_allowlist {
        if !is_trusted_for(url_pattern, data_type, spec) {
            sinks.push(format!("http {} (not trusted for {})", url_pattern, data_type));
        }
    }

    // 2. IPC to partner that has a sink for T, without egress scrubber.
    for ipc_entry in &policy.allowed_ipc_targets {
        for (name, partner) in all_approved {
            if fnmatch(ipc_entry.policy_pattern(), name) {
                let partner_has_sink = partner_has_direct_sink(partner, spec, data_type);
                if partner_has_sink && !ipc_scrubs_egress(ipc_entry, data_type) {
                    sinks.push(format!("IPC to {} (sink for {})", name, data_type));
                }
            }
        }
    }

    // 3. Writes to shared path readable by policy with a sink.
    for mount in &policy.external_mounts {
        if !mount.mode.contains('w') {
            continue;
        }
        for (name, other) in all_approved {
            if name == &policy.policy_name {
                continue;
            }
            for other_mount in &other.external_mounts {
                if paths_overlap(&mount.path, &other_mount.path)
                    && partner_has_direct_sink(other, spec, data_type)
                {
                    sinks.push(format!(
                        "fs edge: {} reads from {} (sink for {})",
                        name, other_mount.path, data_type
                    ));
                }
            }
        }
    }

    let has = !sinks.is_empty();
    (has, sinks)
}

/// Does a policy directly have a sink for T (HTTP endpoint not trusted for T)?
fn partner_has_direct_sink(
    policy: &MediationPolicy,
    spec: &TrustSpec,
    data_type: &str,
) -> bool {
    policy
        .http_allowlist
        .iter()
        .any(|url_pat| !is_trusted_for(url_pat, data_type, spec))
}

/// Check if a URL pattern is trusted for a given data type.
fn is_trusted_for(url_pattern: &str, data_type: &str, spec: &TrustSpec) -> bool {
    spec.trusted_external.iter().any(|te| {
        (fnmatch(&te.pattern, url_pattern) || fnmatch(url_pattern, &te.pattern))
            && (te.data_types.contains(&"*".to_string())
                || te.data_types.contains(&data_type.to_string()))
    })
}

// ── Scrubber checks ──────────────────────────────────────────────────

/// Does this IPC entry have an ingress scrubber that de-taints the given data type?
fn ipc_scrubs_ingress(entry: &IpcTargetEntry, data_type: &str) -> bool {
    entry.scrub_ingress().is_some_and(|sc| {
        sc.de_taints && sc.data_types.contains(&data_type.to_string())
    })
}

/// Does this IPC entry have an egress scrubber that de-taints the given data type?
fn ipc_scrubs_egress(entry: &IpcTargetEntry, data_type: &str) -> bool {
    entry.scrub_egress().is_some_and(|sc| {
        sc.de_taints && sc.data_types.contains(&data_type.to_string())
    })
}

// ── Pattern intersection ─────────────────────────────────────────────

/// Conservative check: do two glob patterns potentially match the same string?
///
/// This is intentionally over-approximate — if either contains a wildcard,
/// we assume they could intersect. False positives are safe (more warnings);
/// false negatives would miss violations.
fn patterns_intersect(a: &str, b: &str) -> bool {
    if a.contains('*') || b.contains('*') {
        // Strip wildcards and check if the non-wildcard prefixes overlap.
        let a_prefix = a.split('*').next().unwrap_or("");
        let b_prefix = b.split('*').next().unwrap_or("");
        a_prefix.starts_with(b_prefix) || b_prefix.starts_with(a_prefix)
    } else {
        a == b
    }
}

// ── Loading ──────────────────────────────────────────────────────────

impl TrustSpec {
    /// Load a trust spec from a YAML file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Self::load_from_str(&content)
    }

    /// Parse a trust spec from a YAML string.
    pub fn load_from_str(yaml: &str) -> Result<Self, String> {
        serde_yml::from_str(yaml).map_err(|e| format!("parse trust spec: {e}"))
    }

    /// Collect all unique data-type tags mentioned anywhere in the spec.
    pub fn all_data_types(&self) -> Vec<String> {
        let mut types = std::collections::BTreeSet::new();
        for entry in &self.sensitive_data {
            for dt in &entry.data_types {
                types.insert(dt.clone());
            }
        }
        for src in &self.untrusted_sources {
            for dt in &src.data_types {
                types.insert(dt.clone());
            }
        }
        for ext in &self.trusted_external {
            for dt in &ext.data_types {
                if dt != "*" {
                    types.insert(dt.clone());
                }
            }
        }
        types.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_YAML: &str = r#"
sensitive_data:
  - path: "/data/customer_records"
    data_types: ["pii"]
  - path: "/secrets/*"
    data_types: ["credentials"]

untrusted_sources:
  - pattern: "https://*.wikipedia.org/*"
    data_types: ["web_content"]

trusted_external:
  - pattern: "https://internal-api.corp.com/*"
    data_types: ["*"]
  - pattern: "https://logging.corp.com/*"
    data_types: ["pii"]
"#;

    #[test]
    fn parse_trust_spec() {
        let spec = TrustSpec::load_from_str(EXAMPLE_YAML).unwrap();
        assert_eq!(spec.sensitive_data.len(), 2);
        assert_eq!(spec.sensitive_data[0].path, "/data/customer_records");
        assert_eq!(spec.sensitive_data[0].data_types, vec!["pii"]);
        assert_eq!(spec.sensitive_data[1].path, "/secrets/*");
        assert_eq!(spec.untrusted_sources.len(), 1);
        assert_eq!(
            spec.untrusted_sources[0].pattern,
            "https://*.wikipedia.org/*"
        );
        assert_eq!(spec.trusted_external.len(), 2);
        assert_eq!(spec.trusted_external[0].data_types, vec!["*"]);
    }

    #[test]
    fn all_data_types_collects_unique_tags() {
        let spec = TrustSpec::load_from_str(EXAMPLE_YAML).unwrap();
        let types = spec.all_data_types();
        assert!(types.contains(&"pii".to_string()));
        assert!(types.contains(&"credentials".to_string()));
        assert!(types.contains(&"web_content".to_string()));
        // Wildcard "*" should not appear
        assert!(!types.contains(&"*".to_string()));
    }

    #[test]
    fn round_trip_serialization() {
        let spec = TrustSpec::load_from_str(EXAMPLE_YAML).unwrap();
        let yaml = serde_yml::to_string(&spec).unwrap();
        let reparsed = TrustSpec::load_from_str(&yaml).unwrap();
        assert_eq!(spec, reparsed);
    }

    #[test]
    fn empty_spec_is_valid() {
        let spec = TrustSpec::load_from_str("{}").unwrap();
        assert!(spec.sensitive_data.is_empty());
        assert!(spec.untrusted_sources.is_empty());
        assert!(spec.trusted_external.is_empty());
        assert!(spec.all_data_types().is_empty());
    }

    // ── Analysis tests ───────────────────────────────────────────────

    use crate::mediator::policy::{
        ExternalMount, IpcTarget, IpcTargetEntry, MediationPolicy, ScrubConfig,
    };

    fn test_spec() -> TrustSpec {
        TrustSpec::load_from_str(EXAMPLE_YAML).unwrap()
    }

    fn base_policy(name: &str) -> MediationPolicy {
        MediationPolicy {
            policy_name: name.into(),
            rationale: "test".into(),
            http_allowlist: vec![],
            external_mounts: vec![],
            allowed_child_policies: vec![],
            bind_ports: None,
            allowed_ipc_targets: vec![],
            allowed_signal_targets: vec![],
        }
    }

    #[test]
    fn clean_policy_no_trifecta() {
        let spec = test_spec();
        let policy = base_policy("clean_v1");
        let approved = HashMap::new();
        let taint = analyze_policy(&policy, &approved, &spec);
        assert!(!taint.any_trifecta);
        assert!(taint.violation_paths.is_empty());
    }

    #[test]
    fn single_leg_source_only() {
        let spec = test_spec();
        let mut policy = base_policy("reader_v1");
        policy.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        let approved = HashMap::new();
        let taint = analyze_policy(&policy, &approved, &spec);

        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(pii_tag.has_source);
        assert!(!pii_tag.has_untrusted_input);
        assert!(!pii_tag.has_sink);
        assert!(!pii_tag.trifecta);
    }

    #[test]
    fn single_leg_untrusted_only() {
        let spec = test_spec();
        let mut policy = base_policy("fetcher_v1");
        policy.http_allowlist = vec!["https://*.wikipedia.org/*".into()];
        let approved = HashMap::new();
        let taint = analyze_policy(&policy, &approved, &spec);

        let wc_tag = taint
            .tags
            .iter()
            .find(|t| t.data_type == "web_content")
            .unwrap();
        assert!(wc_tag.has_untrusted_input);
        assert!(!wc_tag.has_source);
    }

    #[test]
    fn direct_trifecta_single_policy() {
        let spec = test_spec();
        let mut policy = base_policy("bad_v1");
        // Source: reads sensitive PII data
        policy.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        // Untrusted input: fetches from untrusted source
        // Sink: sends to untrusted external (same URL is both untrusted source and untrusted sink)
        policy.http_allowlist = vec![
            "https://*.wikipedia.org/*".into(),
            "https://evil.example.com/*".into(),
        ];
        let approved = HashMap::new();
        let taint = analyze_policy(&policy, &approved, &spec);

        // PII: has source (mount) + untrusted input (wikipedia) + sink (both URLs not trusted for PII)
        // Actually, wikipedia is untrusted for web_content, not pii.
        // For PII trifecta: source(pii) via mount, untrusted_input(pii) needs untrusted source tagged pii.
        // Our spec only has wikipedia tagged web_content.
        // So PII trifecta doesn't fire unless there's a source of untrusted PII input.
        // Let's check web_content: no source(web_content) mount, so no trifecta there either.
        // This policy has source(pii) + sink(pii) but NO untrusted_input(pii).
        assert!(!taint.any_trifecta);
    }

    #[test]
    fn direct_trifecta_with_bind_ports() {
        let spec = test_spec();
        let mut policy = base_policy("bad_v2");
        // Source: reads sensitive PII data
        policy.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        // Untrusted input: bind_ports means inbound traffic
        policy.bind_ports = Some(super::super::PortRange(8080, 8099));
        // Sink: sends to untrusted external
        policy.http_allowlist = vec!["https://evil.example.com/*".into()];
        let approved = HashMap::new();
        let taint = analyze_policy(&policy, &approved, &spec);

        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(pii_tag.has_source, "should have source(pii) via mount");
        assert!(
            pii_tag.has_untrusted_input,
            "should have untrusted input via bind_ports"
        );
        assert!(
            pii_tag.has_sink,
            "should have sink(pii) via untrusted http"
        );
        assert!(pii_tag.trifecta, "should be trifecta for pii");
        assert!(taint.any_trifecta);
        assert!(!taint.violation_paths.is_empty());
    }

    #[test]
    fn ipc_trifecta_through_partner() {
        let spec = test_spec();

        // reader: has sensitive PII data, IPC target = fetcher_*
        let mut reader = base_policy("reader_v1");
        reader.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        reader.allowed_ipc_targets = vec!["fetcher_*".into()];

        // fetcher: fetches untrusted content + has external communication
        let mut fetcher = base_policy("fetcher_v1");
        fetcher.http_allowlist = vec![
            "https://*.wikipedia.org/*".into(),
            "https://evil.example.com/*".into(),
        ];
        fetcher.allowed_ipc_targets = vec!["reader_*".into()];

        let mut approved = HashMap::new();
        approved.insert("fetcher_v1".into(), fetcher.clone());

        // Analyze reader: it IPCs to fetcher which has sink(pii) + untrusted_input(web_content).
        // For the PII tag specifically:
        // - source(pii): reader has mount (yes)
        // - sink(pii): reader IPCs to fetcher, fetcher has untrusted http endpoint (sink for pii) → yes
        // - untrusted_input(pii): needs untrusted source for pii specifically
        //   fetcher has untrusted input for web_content, not pii
        //   BUT bind_ports or IPC from untrusted partner could carry any type
        // Actually: our check_untrusted_input for reader on pii:
        //   - reader's http_allowlist is empty, no match for pii untrusted sources
        //   - reader has no bind_ports
        //   - IPC from fetcher: partner_has_direct_untrusted(fetcher, spec, "pii") →
        //     fetcher's http matches untrusted_sources tagged web_content, not pii. So false.
        // So pii trifecta doesn't fire here. This is correct: the untrusted content
        // flowing through fetcher is web_content, not pii.
        let taint = analyze_policy(&reader, &approved, &spec);
        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(pii_tag.has_source);
        assert!(pii_tag.has_sink, "IPC to fetcher which has untrusted http = sink");
        assert!(!pii_tag.has_untrusted_input, "no pii-tagged untrusted input");
        assert!(!pii_tag.trifecta, "no pii trifecta without pii untrusted input");
    }

    #[test]
    fn scrubber_breaks_taint_chain() {
        let spec = test_spec();

        let mut reader = base_policy("reader_v1");
        reader.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        // IPC with egress scrubber that de-taints pii
        reader.allowed_ipc_targets = vec![IpcTargetEntry::Configured(IpcTarget {
            policy_name: "fetcher_*".into(),
            scrub_egress: Some(ScrubConfig {
                scrubber: "regex_pii".into(),
                data_types: vec!["pii".into()],
                de_taints: true,
                config: serde_json::Value::default(),
            }),
            scrub_ingress: None,
        })];

        let mut fetcher = base_policy("fetcher_v1");
        fetcher.http_allowlist = vec!["https://evil.example.com/*".into()];
        fetcher.bind_ports = Some(super::super::PortRange(8080, 8099));

        let mut approved = HashMap::new();
        approved.insert("fetcher_v1".into(), fetcher);

        let taint = analyze_policy(&reader, &approved, &spec);
        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(pii_tag.has_source, "reader has pii source");
        // The egress scrubber blocks the sink path through IPC
        assert!(
            !pii_tag.has_sink,
            "egress scrubber should break the pii sink chain"
        );
        assert!(!pii_tag.trifecta);
    }

    #[test]
    fn affected_policy_analysis() {
        let spec = test_spec();

        // Existing approved: reader with PII access
        let mut reader = base_policy("reader_v1");
        reader.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        reader.allowed_ipc_targets = vec!["fetcher_*".into()];
        reader.bind_ports = Some(super::super::PortRange(8080, 8099));

        let mut approved = HashMap::new();
        approved.insert("reader_v1".into(), reader);

        // Proposed: fetcher with untrusted external access
        let mut fetcher = base_policy("fetcher_v1");
        fetcher.http_allowlist = vec!["https://evil.example.com/*".into()];
        fetcher.allowed_ipc_targets = vec!["reader_*".into()];

        let affected = analyze_affected(&fetcher, &approved, &spec);

        // Reader now has a sink path through fetcher for pii.
        // With bind_ports, reader has untrusted input for all types.
        // reader: source(pii) via mount, untrusted(pii) via bind_ports, sink(pii) via IPC to fetcher
        // → trifecta!
        // Before fetcher existed, reader had no sink, so this is a worsening.
        assert!(
            !affected.is_empty(),
            "reader_v1 should be flagged as affected"
        );
    }

    #[test]
    fn filesystem_edge_propagates_taint() {
        let spec = test_spec();

        // writer: has PII source, writes to shared path
        let mut writer = base_policy("writer_v1");
        writer.external_mounts = vec![
            ExternalMount {
                path: "/data/customer_records".into(),
                mode: "r".into(),
            },
            ExternalMount {
                path: "/shared/output".into(),
                mode: "rw".into(),
            },
        ];

        // leaker: reads from shared path, has external sink
        let mut leaker = base_policy("leaker_v1");
        leaker.external_mounts = vec![ExternalMount {
            path: "/shared/output".into(),
            mode: "r".into(),
        }];
        leaker.http_allowlist = vec!["https://evil.example.com/*".into()];
        leaker.bind_ports = Some(super::super::PortRange(8080, 8099));

        let mut approved = HashMap::new();
        approved.insert("writer_v1".into(), writer);

        let taint = analyze_policy(&leaker, &approved, &spec);
        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(
            pii_tag.has_source,
            "leaker gets pii source via fs edge from writer"
        );
        assert!(pii_tag.has_sink, "leaker has direct untrusted http sink");
        assert!(
            pii_tag.has_untrusted_input,
            "leaker has bind_ports for untrusted input"
        );
        assert!(
            pii_tag.trifecta,
            "leaker has pii trifecta via filesystem edge"
        );
    }

    #[test]
    fn trusted_external_suppresses_sink() {
        let spec = test_spec();
        let mut policy = base_policy("logger_v1");
        // This URL is trusted for all types
        policy.http_allowlist = vec!["https://internal-api.corp.com/log".into()];
        policy.external_mounts = vec![ExternalMount {
            path: "/data/customer_records".into(),
            mode: "r".into(),
        }];
        policy.bind_ports = Some(super::super::PortRange(8080, 8099));

        let approved = HashMap::new();
        let taint = analyze_policy(&policy, &approved, &spec);
        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(pii_tag.has_source);
        assert!(pii_tag.has_untrusted_input);
        // internal-api.corp.com is trusted for "*" (all types), so no sink
        assert!(
            !pii_tag.has_sink,
            "trusted external should suppress sink for pii"
        );
        assert!(!pii_tag.trifecta);
    }

    // ── Implicit sensitivity tests ───────────────────────────────────

    #[test]
    fn clean_writer_implicitly_sensitive() {
        let spec = test_spec();
        // A policy with writable mounts and NO untrusted input.
        // Its writable mounts are implicitly sensitive.
        let mut writer = base_policy("writer_v1");
        writer.external_mounts = vec![ExternalMount {
            path: "/workspace/output".into(),
            mode: "rw".into(),
        }];
        // No http_allowlist, no bind_ports → clean process.
        let approved = HashMap::new();
        let taint = analyze_policy(&writer, &approved, &spec);

        // Should have source for all data types (implicit sensitivity).
        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        assert!(
            pii_tag.has_source,
            "clean writer with writable mount should be implicitly sensitive"
        );
        assert!(
            pii_tag.source_paths.iter().any(|s| s.contains("implicit sensitive")),
            "source should be marked implicit: {:?}", pii_tag.source_paths
        );
        // But no trifecta — no untrusted input, no sink.
        assert!(!pii_tag.trifecta);
    }

    #[test]
    fn untrusted_writer_not_implicitly_sensitive() {
        let spec = test_spec();
        // A policy with writable mounts AND untrusted input.
        // Its output is contaminated, not sensitive.
        let mut fetcher = base_policy("fetcher_v1");
        fetcher.external_mounts = vec![ExternalMount {
            path: "/workspace/output".into(),
            mode: "rw".into(),
        }];
        fetcher.http_allowlist = vec!["https://*.wikipedia.org/*".into()];
        let approved = HashMap::new();
        let taint = analyze_policy(&fetcher, &approved, &spec);

        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();
        // Should NOT have implicit source — the writer has untrusted input.
        assert!(
            !pii_tag.source_paths.iter().any(|s| s.contains("implicit sensitive")),
            "untrusted writer should NOT be implicitly sensitive: {:?}", pii_tag.source_paths
        );
    }

    #[test]
    fn reader_inherits_implicit_sensitivity_via_fs_edge() {
        let spec = test_spec();
        // Clean writer writes to /shared/output.
        let mut writer = base_policy("writer_v1");
        writer.external_mounts = vec![ExternalMount {
            path: "/shared/output".into(),
            mode: "rw".into(),
        }];

        // Reader reads from /shared/output and has untrusted HTTP + external sink.
        let mut reader = base_policy("reader_v1");
        reader.external_mounts = vec![ExternalMount {
            path: "/shared/output".into(),
            mode: "r".into(),
        }];
        reader.http_allowlist = vec!["https://evil.example.com/*".into()];
        reader.bind_ports = Some(super::super::PortRange(8080, 8089));

        let mut approved = HashMap::new();
        approved.insert("writer_v1".into(), writer);

        let taint = analyze_policy(&reader, &approved, &spec);
        let pii_tag = taint.tags.iter().find(|t| t.data_type == "pii").unwrap();

        // Reader gets source(pii) via fs edge from the implicitly-sensitive writer.
        assert!(
            pii_tag.has_source,
            "reader should inherit implicit sensitivity via fs edge"
        );
        // Reader also has untrusted input (bind_ports) and sink (evil.com).
        assert!(pii_tag.has_untrusted_input);
        assert!(pii_tag.has_sink);
        // → trifecta!
        assert!(
            pii_tag.trifecta,
            "reader with fs edge from clean writer + untrusted input + sink = trifecta"
        );
    }
}
