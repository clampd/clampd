//! Native TOML format parser.
//! This is the primary rule format for Clampd.
//!
//! Format:
//! ```toml
//! [[rule]]
//! id = "R001"
//! name = "block-destructive-sql"
//! risk_score = 0.95
//! action = "block"          # "block", "flag", or "pass"
//! priority = 10             # 0=override, 5=custom, 10=builtin (default)
//! labels = ["destructive_sql"]
//! tool_pattern = "database.*"
//! exemptable = true         # default: false
//! exempt_agents = ["admin"]
//! risk_above = 0.5
//!
//! [rule.taxonomy]
//! atlas = ["AML.T0051"]
//! owasp_llm = ["LLM07"]
//! regulations = ["PCI-DSS"]
//!
//! [[rule.pattern]]
//! field = "query"           # optional: null = match all fields
//! regex = '(?i)DROP\s+TABLE'
//! ```

use serde::Deserialize;

use super::{ParseError, ParsedPattern, ParsedRule, RuleParser};
use crate::compile::RuleAction;
use crate::taxonomy::TaxonomyMapping;

/// Parser for Clampd's native TOML rule format.
pub struct NativeParser;

// ── Serde intermediate types ──────────────────────────────────────

#[derive(Deserialize)]
struct TomlFile {
    rule: Vec<TomlRule>,
}

#[derive(Deserialize)]
struct TomlRule {
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
    #[serde(default, deserialize_with = "crate::parse::deserialize_scope_pattern")]
    scope_pattern: Vec<String>,
    #[serde(default)]
    pattern: Vec<TomlPattern>,
    #[serde(default)]
    exemptable: bool,
    #[serde(default)]
    exempt_agents: Vec<String>,
    #[serde(default)]
    risk_above: Option<f64>,
    #[serde(default)]
    taxonomy: TaxonomyMapping,
}

fn default_priority() -> u8 {
    10
}

#[derive(Deserialize)]
struct TomlPattern {
    #[serde(default)]
    field: Option<String>,
    regex: String,
}

// ── Implementation ────────────────────────────────────────────────

impl RuleParser for NativeParser {
    fn format_name(&self) -> &str {
        "toml"
    }

    fn parse(&self, input: &str) -> Result<Vec<ParsedRule>, ParseError> {
        let file: TomlFile = toml::from_str(input).map_err(|e| {
            ParseError::InvalidFormat(format!("TOML parse error: {}", e))
        })?;

        let mut rules = Vec::with_capacity(file.rule.len());

        for tr in file.rule {
            // Validate risk_score
            if tr.risk_score < 0.0 || tr.risk_score > 1.0 {
                return Err(ParseError::InvalidRiskScore(tr.risk_score));
            }

            // Validate action
            let action = match tr.action.as_str() {
                "block" => RuleAction::Block,
                "flag" => RuleAction::Flag,
                "pass" => RuleAction::Pass,
                other => {
                    return Err(ParseError::InvalidFormat(format!(
                        "Invalid action '{}': must be 'block', 'flag', or 'pass'",
                        other
                    )));
                }
            };

            // Convert patterns
            let patterns: Vec<ParsedPattern> = tr
                .pattern
                .into_iter()
                .map(|p| ParsedPattern {
                    field: p.field,
                    regex: p.regex,
                })
                .collect();

            rules.push(ParsedRule {
                id: tr.id,
                name: tr.name,
                risk_score: tr.risk_score,
                action,
                priority: tr.priority,
                labels: tr.labels,
                tool_pattern: tr.tool_pattern,
                scope_pattern: tr.scope_pattern,
                patterns,
                exempt_agents: tr.exempt_agents,
                exemptable: tr.exemptable,
                risk_above: tr.risk_above,
                taxonomy: tr.taxonomy,
            });
        }

        Ok(rules)
    }
}
