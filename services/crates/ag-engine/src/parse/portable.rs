//! PortableRule/RulePack JSON adapter.
//! Backward-compatible with existing import format from ag-intent/import.rs.
//!
//! Format:
//! ```json
//! {
//!   "name": "lakera-pack",
//!   "version": "1.0",
//!   "provider": "lakera",
//!   "rules": [
//!     {
//!       "id": "LAKERA-001",
//!       "name": "block-prompt-injection-v2",
//!       "risk_score": 0.92,
//!       "action": "block",
//!       "priority": 5,
//!       "labels": ["prompt_injection"],
//!       "patterns": [{"field": null, "regex": "..."}],
//!       "exemptable": false
//!     }
//!   ],
//!   "keywords": []
//! }
//! ```

use serde::Deserialize;

use super::{ParseError, ParsedPattern, ParsedRule, RuleParser};
use crate::compile::RuleAction;
use crate::taxonomy::TaxonomyMapping;

/// Parser for the PortableRule/RulePack JSON format.
pub struct PortableRuleParser;

// ── Serde types (matching existing format exactly) ────────────────

#[derive(Deserialize)]
struct RulePack {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    provider: String,
    #[serde(default)]
    rules: Vec<PortableRule>,
    // Keywords are handled separately - not part of RuleParser trait
}

#[derive(Deserialize)]
struct PortableRule {
    id: String,
    name: String,
    risk_score: f64,
    action: String,
    #[serde(default = "default_priority")]
    priority: u8,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    tool_pattern: Option<String>,
    patterns: Vec<PortablePattern>,
    #[serde(default)]
    exempt_agents: Vec<String>,
    #[serde(default)]
    exemptable: bool,
    #[serde(default)]
    risk_above: Option<f64>,
    #[serde(default)]
    scope_pattern: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    references: Vec<String>,
}

fn default_priority() -> u8 {
    5 // Custom rules default to priority 5
}

#[derive(Deserialize)]
struct PortablePattern {
    #[serde(default)]
    field: Option<String>,
    regex: String,
}

// ── Implementation ────────────────────────────────────────────────

impl RuleParser for PortableRuleParser {
    fn format_name(&self) -> &str {
        "portable_json"
    }

    fn parse(&self, input: &str) -> Result<Vec<ParsedRule>, ParseError> {
        // Try as RulePack first, then as bare array of rules
        let rules_raw: Vec<PortableRule> = if input.trim_start().starts_with('{') {
            let pack: RulePack = serde_json::from_str(input).map_err(|e| {
                ParseError::InvalidFormat(format!("Invalid RulePack JSON: {}", e))
            })?;
            pack.rules
        } else {
            serde_json::from_str(input).map_err(|e| {
                ParseError::InvalidFormat(format!("Invalid rules JSON: {}", e))
            })?
        };

        let mut parsed = Vec::with_capacity(rules_raw.len());

        for pr in rules_raw {
            // Validate risk_score
            if pr.risk_score < 0.0 || pr.risk_score > 1.0 {
                return Err(ParseError::InvalidRiskScore(pr.risk_score));
            }

            // Validate action
            let action = match pr.action.as_str() {
                "block" => RuleAction::Block,
                "flag" => RuleAction::Flag,
                "pass" => RuleAction::Pass,
                other => {
                    return Err(ParseError::InvalidFormat(format!(
                        "Invalid action '{}' in rule '{}': must be 'block', 'flag', or 'pass'",
                        other, pr.id
                    )));
                }
            };

            let patterns: Vec<ParsedPattern> = pr
                .patterns
                .into_iter()
                .map(|p| ParsedPattern {
                    field: p.field,
                    regex: p.regex,
                })
                .collect();

            parsed.push(ParsedRule {
                id: pr.id,
                name: pr.name,
                risk_score: pr.risk_score,
                action,
                priority: pr.priority,
                labels: pr.labels,
                tool_pattern: pr.tool_pattern,
                scope_pattern: pr.scope_pattern.map(|s| vec![s]).unwrap_or_default(),
                patterns,
                exempt_agents: pr.exempt_agents,
                exemptable: pr.exemptable,
                risk_above: pr.risk_above,
                taxonomy: TaxonomyMapping::default(),
            });
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rulepack_json() {
        let json = r#"{
            "name": "test-pack",
            "version": "1.0",
            "provider": "test",
            "rules": [
                {
                    "id": "CUSTOM-001",
                    "name": "block-test",
                    "risk_score": 0.90,
                    "action": "block",
                    "labels": ["test"],
                    "patterns": [{"regex": "(?i)test_pattern"}]
                }
            ]
        }"#;

        let parser = PortableRuleParser;
        let rules = parser.parse(json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CUSTOM-001");
        assert_eq!(rules[0].priority, 5); // custom default
        assert!(!rules[0].exemptable); // safe default
    }

    #[test]
    fn parse_bare_rules_array() {
        let json = r#"[
            {
                "id": "BARE-001",
                "name": "bare-rule",
                "risk_score": 0.50,
                "action": "flag",
                "patterns": [{"regex": "test"}]
            }
        ]"#;

        let parser = PortableRuleParser;
        let rules = parser.parse(json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "BARE-001");
    }

    #[test]
    fn parse_portable_with_field_pattern() {
        let json = r#"{
            "name": "field-test",
            "version": "1.0",
            "rules": [
                {
                    "id": "FP-001",
                    "name": "field-pattern",
                    "risk_score": 0.80,
                    "action": "block",
                    "patterns": [{"field": "query", "regex": "(?i)DROP"}]
                }
            ]
        }"#;

        let parser = PortableRuleParser;
        let rules = parser.parse(json).unwrap();
        assert_eq!(rules[0].patterns[0].field.as_deref(), Some("query"));
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let parser = PortableRuleParser;
        assert!(parser.parse("not json").is_err());
    }

    #[test]
    fn parse_invalid_risk_score_returns_error() {
        let json = r#"{"name":"bad","version":"1","rules":[
            {"id":"BAD","name":"bad","risk_score":2.0,"action":"block","patterns":[{"regex":"x"}]}
        ]}"#;
        let parser = PortableRuleParser;
        assert!(parser.parse(json).is_err());
    }

    #[test]
    fn parser_format_name() {
        assert_eq!(PortableRuleParser.format_name(), "portable_json");
    }
}
