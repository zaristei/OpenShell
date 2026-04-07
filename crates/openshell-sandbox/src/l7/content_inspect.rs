// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Content inspection framework for L7 proxy traffic.
//!
//! Provides a trait-based rule system for scanning HTTP request bodies in the
//! proxy pipeline. Sync rules are compiled Rust and run inline (nanoseconds).
//! Async rules are reserved for future external execution (no-op currently).
//!
//! # Adding a new rule
//!
//! 1. Implement [`ContentRule`] for your type.
//! 2. Add it to [`default_rules()`].
//! 3. It will be automatically available via the `enabled_rules` policy config.

use regex::{Regex, RegexSet};
use std::ops::Range;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Direction a content inspection rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Egress,
    Ingress,
}

/// Confidence level for a scan match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Action recommended by a rule after scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Action {
    /// No PII found or rule does not object.
    #[default]
    Pass,
    /// PII found, recommend logging but not blocking.
    Flag,
    /// PII found, recommend blocking the request.
    Block,
}

/// Input provided to every content inspection rule.
pub struct ScanInput<'a> {
    pub body: &'a [u8],
    pub content_type: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
}

/// A single match found by a rule.
#[derive(Debug, Clone)]
pub struct ScanMatch {
    /// Name of the rule that produced this match.
    pub rule_name: String,
    /// Category of the match (e.g. "ssn", "credit_card", "custom").
    pub pattern_type: String,
    /// Byte offset in the input body.
    pub byte_offset: usize,
    /// Length of the match in bytes.
    pub byte_length: usize,
    /// Confidence level.
    pub confidence: Confidence,
}

/// Output from a content inspection rule.
#[derive(Debug, Clone)]
pub struct ScanOutput {
    /// Matches found in the body.
    pub matches: Vec<ScanMatch>,
    /// Recommended action based on matches.
    pub action: Action,
}

impl ScanOutput {
    /// Create an output with no matches and a Pass action.
    pub fn pass() -> Self {
        Self {
            matches: Vec::new(),
            action: Action::Pass,
        }
    }
}

// ---------------------------------------------------------------------------
// ContentRule trait
// ---------------------------------------------------------------------------

/// Trait for sync content inspection rules.
///
/// Rules are compiled Rust that run inline in the proxy hot path. They must
/// be fast (<1ms) and thread-safe. The trait is object-safe so rules can be
/// stored in a heterogeneous registry.
pub trait ContentRule: Send + Sync {
    /// Unique rule name (e.g. "pii-regex", "api-key-detector").
    fn name(&self) -> &str;

    /// Which direction this rule applies to.
    fn direction(&self) -> Direction;

    /// Run the rule against the input. Must complete quickly.
    fn scan(&self, input: &ScanInput) -> ScanOutput;
}

// ---------------------------------------------------------------------------
// ContentRuleRegistry
// ---------------------------------------------------------------------------

/// Registry of content inspection rules.
///
/// Constructed once per endpoint config and shared via `Arc`. Dispatches
/// scan calls to all registered rules matching the requested direction.
pub struct ContentRuleRegistry {
    rules: Vec<Box<dyn ContentRule>>,
}

impl ContentRuleRegistry {
    /// Build a registry from default rules, optionally filtered by name.
    ///
    /// If `enabled` is empty, all default rules are included.
    /// If `enabled` is non-empty, only rules whose name is in the list are included.
    pub fn new(enabled: &[String]) -> Self {
        let all_rules = default_rules();
        let rules = if enabled.is_empty() {
            all_rules
        } else {
            all_rules
                .into_iter()
                .filter(|r| enabled.iter().any(|e| e == r.name()))
                .collect()
        };
        Self { rules }
    }

    /// Run all registered egress rules against input.
    pub fn scan_egress(&self, input: &ScanInput) -> Vec<ScanOutput> {
        self.rules
            .iter()
            .filter(|r| r.direction() == Direction::Egress)
            .map(|r| r.scan(input))
            .collect()
    }

    /// Returns true if the registry has any egress rules.
    pub fn has_egress_rules(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.direction() == Direction::Egress)
    }
}

/// Return all built-in content inspection rules.
pub fn default_rules() -> Vec<Box<dyn ContentRule>> {
    vec![Box::new(RegexPiiRule::new())]
}

// ---------------------------------------------------------------------------
// Content inspection policy (parsed from proto config)
// ---------------------------------------------------------------------------

/// Parsed content inspection configuration from policy data.
#[derive(Debug, Clone)]
pub struct ContentInspectionPolicy {
    pub egress_mode: InspectionMode,
    pub ingress_mode: InspectionMode,
    pub egress_enforcement: EgressEnforcement,
    pub max_body_bytes: usize,
    pub enabled_rules: Vec<String>,
}

/// Inspection execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InspectionMode {
    /// Compiled Rust rules run inline in the proxy pipeline.
    Sync,
    /// Deferred to external executor (no-op in current implementation).
    Async,
    /// Disabled.
    #[default]
    Noop,
}

impl InspectionMode {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "sync" => Self::Sync,
            "async" => Self::Async,
            _ => Self::Noop,
        }
    }
}

/// Enforcement mode for egress content scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EgressEnforcement {
    /// Log matches but relay the request (default).
    #[default]
    Audit,
    /// Block the request if any rule returns Block.
    Enforce,
}

impl EgressEnforcement {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "enforce" => Self::Enforce,
            _ => Self::Audit,
        }
    }
}

/// Default maximum body size for buffered inspection (1 MB).
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

/// Parse content inspection config from a regorus Value.
pub fn parse_content_inspection_config(val: &regorus::Value) -> Option<ContentInspectionPolicy> {
    let obj = match val {
        regorus::Value::Object(map) => map,
        _ => return None,
    };

    // At least egress_mode must be present and non-noop for the config to be active.
    let egress_mode_str = obj
        .get(&regorus::Value::String("egress_mode".into()))
        .and_then(|v| match v {
            regorus::Value::String(s) => Some(s.as_ref().to_string()),
            _ => None,
        })
        .unwrap_or_default();

    let egress_mode = InspectionMode::parse(&egress_mode_str);
    if egress_mode == InspectionMode::Noop {
        // Check ingress too — if both are noop, no config needed.
        let ingress_mode_str = obj
            .get(&regorus::Value::String("ingress_mode".into()))
            .and_then(|v| match v {
                regorus::Value::String(s) => Some(s.as_ref().to_string()),
                _ => None,
            })
            .unwrap_or_default();
        if InspectionMode::parse(&ingress_mode_str) == InspectionMode::Noop {
            return None;
        }
    }

    let ingress_mode_str = obj
        .get(&regorus::Value::String("ingress_mode".into()))
        .and_then(|v| match v {
            regorus::Value::String(s) => Some(s.as_ref().to_string()),
            _ => None,
        })
        .unwrap_or_default();

    let egress_enforcement_str = obj
        .get(&regorus::Value::String("egress_enforcement".into()))
        .and_then(|v| match v {
            regorus::Value::String(s) => Some(s.as_ref().to_string()),
            _ => None,
        })
        .unwrap_or_default();

    let max_body_bytes = obj
        .get(&regorus::Value::String("max_body_bytes".into()))
        .and_then(|v| match v {
            regorus::Value::Number(n) => match n.as_f64() {
                Some(f) if f > 0.0 => Some(f as usize),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);

    let enabled_rules = obj
        .get(&regorus::Value::String("enabled_rules".into()))
        .and_then(|v| match v {
            regorus::Value::Array(arr) => Some(
                arr.iter()
                    .filter_map(|item| match item {
                        regorus::Value::String(s) => Some(s.as_ref().to_string()),
                        _ => None,
                    })
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    Some(ContentInspectionPolicy {
        egress_mode,
        ingress_mode: InspectionMode::parse(&ingress_mode_str),
        egress_enforcement: EgressEnforcement::parse(&egress_enforcement_str),
        max_body_bytes,
        enabled_rules,
    })
}

// ---------------------------------------------------------------------------
// Built-in rule: RegexPiiRule
// ---------------------------------------------------------------------------

/// Pattern metadata.
struct PatternInfo {
    name: &'static str,
    confidence: Confidence,
    needs_luhn: bool,
}

const PATTERN_INFO: [PatternInfo; 5] = [
    PatternInfo {
        name: "ssn",
        confidence: Confidence::High,
        needs_luhn: false,
    },
    PatternInfo {
        name: "credit_card",
        confidence: Confidence::High,
        needs_luhn: true,
    },
    PatternInfo {
        name: "email",
        confidence: Confidence::Medium,
        needs_luhn: false,
    },
    PatternInfo {
        name: "api_key",
        confidence: Confidence::Medium,
        needs_luhn: false,
    },
    PatternInfo {
        name: "phone",
        confidence: Confidence::Low,
        needs_luhn: false,
    },
];

const PATTERN_REGEXES: [&str; 5] = [
    // SSN: 123-45-6789
    r"\b\d{3}-\d{2}-\d{4}\b",
    // Credit card: 13-19 digits with optional spaces/dashes
    r"\b(?:\d[ -]*?){13,19}\b",
    // Email
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    // API key: sk-, pk-, or api_key=/api-key: prefix followed by 20+ alphanum chars
    r"\b(?:sk-|pk-|api[_-]?key[=:]\s*)[a-zA-Z0-9_-]{20,}\b",
    // US phone number
    r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
];

/// Built-in PII detection rule using compiled regex patterns.
pub struct RegexPiiRule {
    regex_set: RegexSet,
    individual: Vec<Regex>,
}

impl RegexPiiRule {
    pub fn new() -> Self {
        let regex_set = RegexSet::new(PATTERN_REGEXES).expect("built-in PII regexes must compile");
        let individual = PATTERN_REGEXES
            .iter()
            .map(|p| Regex::new(p).expect("built-in PII regex must compile"))
            .collect();
        Self {
            regex_set,
            individual,
        }
    }
}

impl ContentRule for RegexPiiRule {
    fn name(&self) -> &str {
        "pii-regex"
    }

    fn direction(&self) -> Direction {
        Direction::Egress
    }

    fn scan(&self, input: &ScanInput) -> ScanOutput {
        // Skip binary content types.
        if is_binary_content_type(input.content_type) {
            return ScanOutput::pass();
        }

        // Convert body to string (lossy — binary fragments become replacement chars).
        let body_str = String::from_utf8_lossy(input.body);

        // Fast screening: which pattern categories have any match?
        let matched_indices: Vec<usize> = self.regex_set.matches(&body_str).into_iter().collect();
        if matched_indices.is_empty() {
            return ScanOutput::pass();
        }

        // Extract individual match spans for matched categories only.
        let mut matches = Vec::new();
        for &idx in &matched_indices {
            let info = &PATTERN_INFO[idx];
            let regex = &self.individual[idx];

            for m in regex.find_iter(&body_str) {
                // Apply Luhn check for credit card patterns.
                if info.needs_luhn && !luhn_check(m.as_str()) {
                    continue;
                }

                matches.push(ScanMatch {
                    rule_name: "pii-regex".to_string(),
                    pattern_type: info.name.to_string(),
                    byte_offset: m.start(),
                    byte_length: m.len(),
                    confidence: info.confidence,
                });
            }
        }

        if matches.is_empty() {
            return ScanOutput::pass();
        }

        ScanOutput {
            action: Action::Flag,
            matches,
        }
    }
}

/// Check if a content type represents binary data that should skip scanning.
fn is_binary_content_type(ct: &str) -> bool {
    let ct_lower = ct.to_ascii_lowercase();
    ct_lower.starts_with("image/")
        || ct_lower.starts_with("audio/")
        || ct_lower.starts_with("video/")
        || ct_lower == "application/octet-stream"
        || ct_lower == "application/zip"
        || ct_lower == "application/gzip"
        || ct_lower == "application/pdf"
        || ct_lower == "application/protobuf"
        || ct_lower == "application/grpc"
}

/// Luhn algorithm check for credit card number validation.
///
/// Strips non-digit characters and validates the check digit.
fn luhn_check(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum % 10 == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input<'a>(body: &'a [u8], content_type: &'a str) -> ScanInput<'a> {
        ScanInput {
            body,
            content_type,
            host: "example.com",
            port: 443,
            method: "POST",
            path: "/api/v1/data",
        }
    }

    // -- Trait + Registry tests --

    struct MockRule {
        rule_name: String,
        dir: Direction,
        action: Action,
    }

    impl ContentRule for MockRule {
        fn name(&self) -> &str {
            &self.rule_name
        }
        fn direction(&self) -> Direction {
            self.dir
        }
        fn scan(&self, _input: &ScanInput) -> ScanOutput {
            ScanOutput {
                matches: vec![ScanMatch {
                    rule_name: self.rule_name.clone(),
                    pattern_type: "mock".to_string(),
                    byte_offset: 0,
                    byte_length: 1,
                    confidence: Confidence::High,
                }],
                action: self.action,
            }
        }
    }

    #[test]
    fn registry_filters_by_enabled_rules() {
        let registry = ContentRuleRegistry {
            rules: vec![
                Box::new(MockRule {
                    rule_name: "rule-a".into(),
                    dir: Direction::Egress,
                    action: Action::Flag,
                }),
                Box::new(MockRule {
                    rule_name: "rule-b".into(),
                    dir: Direction::Egress,
                    action: Action::Block,
                }),
            ],
        };

        let input = make_input(b"test", "text/plain");
        let results = registry.scan_egress(&input);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn registry_new_filters_by_name() {
        let registry = ContentRuleRegistry::new(&["pii-regex".to_string()]);
        assert!(registry.has_egress_rules());

        let registry_none = ContentRuleRegistry::new(&["nonexistent".to_string()]);
        assert!(!registry_none.has_egress_rules());
    }

    #[test]
    fn registry_new_empty_includes_all_defaults() {
        let registry = ContentRuleRegistry::new(&[]);
        assert!(registry.has_egress_rules());
    }

    #[test]
    fn registry_skips_ingress_rules_in_scan_egress() {
        let registry = ContentRuleRegistry {
            rules: vec![Box::new(MockRule {
                rule_name: "ingress-only".into(),
                dir: Direction::Ingress,
                action: Action::Flag,
            })],
        };
        let input = make_input(b"test", "text/plain");
        let results = registry.scan_egress(&input);
        assert!(results.is_empty());
    }

    // -- RegexPiiRule tests --

    #[test]
    fn detects_ssn() {
        let rule = RegexPiiRule::new();
        let input = make_input(b"My SSN is 123-45-6789 ok", "application/json");
        let output = rule.scan(&input);
        assert_eq!(output.matches.len(), 1);
        assert_eq!(output.matches[0].pattern_type, "ssn");
        assert_eq!(output.matches[0].confidence, Confidence::High);
    }

    #[test]
    fn detects_credit_card_with_luhn() {
        let rule = RegexPiiRule::new();
        // 4111111111111111 passes Luhn check (standard Visa test number).
        let input = make_input(b"card: 4111111111111111", "text/plain");
        let output = rule.scan(&input);
        assert!(
            output
                .matches
                .iter()
                .any(|m| m.pattern_type == "credit_card"),
            "should detect valid credit card"
        );
    }

    #[test]
    fn rejects_credit_card_failing_luhn() {
        let rule = RegexPiiRule::new();
        // 4111111111111112 fails Luhn check.
        let input = make_input(b"card: 4111111111111112", "text/plain");
        let output = rule.scan(&input);
        assert!(
            !output
                .matches
                .iter()
                .any(|m| m.pattern_type == "credit_card"),
            "should not detect invalid credit card"
        );
    }

    #[test]
    fn detects_email() {
        let rule = RegexPiiRule::new();
        let input = make_input(b"contact: user@example.com please", "application/json");
        let output = rule.scan(&input);
        assert!(output.matches.iter().any(|m| m.pattern_type == "email"));
    }

    #[test]
    fn detects_api_key() {
        let rule = RegexPiiRule::new();
        let input = make_input(
            b"key: sk-abcdefghijklmnopqrstuvwxyz1234567890",
            "application/json",
        );
        let output = rule.scan(&input);
        assert!(output.matches.iter().any(|m| m.pattern_type == "api_key"));
    }

    #[test]
    fn detects_phone() {
        let rule = RegexPiiRule::new();
        let input = make_input(b"call me at (555) 123-4567", "text/plain");
        let output = rule.scan(&input);
        assert!(output.matches.iter().any(|m| m.pattern_type == "phone"));
    }

    #[test]
    fn skips_binary_content() {
        let rule = RegexPiiRule::new();
        let input = make_input(b"SSN is 123-45-6789", "image/png");
        let output = rule.scan(&input);
        assert!(output.matches.is_empty());
    }

    #[test]
    fn passes_clean_body() {
        let rule = RegexPiiRule::new();
        let input = make_input(b"just a normal request body", "application/json");
        let output = rule.scan(&input);
        assert!(output.matches.is_empty());
        assert_eq!(output.action, Action::Pass);
    }

    #[test]
    fn detects_multiple_patterns() {
        let rule = RegexPiiRule::new();
        let body = b"SSN: 123-45-6789, email: test@foo.com, card: 4111111111111111";
        let input = make_input(body, "text/plain");
        let output = rule.scan(&input);
        assert!(output.matches.len() >= 3);
        assert_eq!(output.action, Action::Flag);
    }

    #[test]
    fn empty_body_passes() {
        let rule = RegexPiiRule::new();
        let input = make_input(b"", "application/json");
        let output = rule.scan(&input);
        assert!(output.matches.is_empty());
        assert_eq!(output.action, Action::Pass);
    }

    // -- Luhn tests --

    #[test]
    fn luhn_valid_numbers() {
        assert!(luhn_check("4111111111111111")); // Visa test
        assert!(luhn_check("5500000000000004")); // MC test
        assert!(luhn_check("378282246310005")); // Amex test
    }

    #[test]
    fn luhn_invalid_numbers() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890123456"));
    }

    #[test]
    fn luhn_strips_separators() {
        assert!(luhn_check("4111-1111-1111-1111"));
        assert!(luhn_check("4111 1111 1111 1111"));
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn_check("123"));
    }

    // -- Config parsing tests --

    #[test]
    fn parse_config_sync_egress() {
        let val = regorus::Value::from_json_str(
            r#"{"egress_mode": "sync", "egress_enforcement": "audit"}"#,
        )
        .unwrap();
        let config = parse_content_inspection_config(&val).unwrap();
        assert_eq!(config.egress_mode, InspectionMode::Sync);
        assert_eq!(config.egress_enforcement, EgressEnforcement::Audit);
        assert_eq!(config.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    }

    #[test]
    fn parse_config_enforce_mode() {
        let val = regorus::Value::from_json_str(
            r#"{"egress_mode": "sync", "egress_enforcement": "enforce", "max_body_bytes": 2048}"#,
        )
        .unwrap();
        let config = parse_content_inspection_config(&val).unwrap();
        assert_eq!(config.egress_enforcement, EgressEnforcement::Enforce);
        assert_eq!(config.max_body_bytes, 2048);
    }

    #[test]
    fn parse_config_noop_returns_none() {
        let val =
            regorus::Value::from_json_str(r#"{"egress_mode": "noop", "ingress_mode": "noop"}"#)
                .unwrap();
        assert!(parse_content_inspection_config(&val).is_none());
    }

    #[test]
    fn parse_config_missing_fields_defaults() {
        let val = regorus::Value::from_json_str(r#"{"egress_mode": "sync"}"#).unwrap();
        let config = parse_content_inspection_config(&val).unwrap();
        assert_eq!(config.ingress_mode, InspectionMode::Noop);
        assert_eq!(config.egress_enforcement, EgressEnforcement::Audit);
        assert_eq!(config.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert!(config.enabled_rules.is_empty());
    }

    #[test]
    fn parse_config_with_enabled_rules() {
        let val = regorus::Value::from_json_str(
            r#"{"egress_mode": "sync", "enabled_rules": ["pii-regex", "custom-rule"]}"#,
        )
        .unwrap();
        let config = parse_content_inspection_config(&val).unwrap();
        assert_eq!(config.enabled_rules, vec!["pii-regex", "custom-rule"]);
    }

    // -- is_binary_content_type tests --

    #[test]
    fn binary_content_types() {
        assert!(is_binary_content_type("image/png"));
        assert!(is_binary_content_type("application/octet-stream"));
        assert!(is_binary_content_type("application/grpc"));
        assert!(!is_binary_content_type("application/json"));
        assert!(!is_binary_content_type("text/plain"));
        assert!(!is_binary_content_type("text/html"));
    }
}
