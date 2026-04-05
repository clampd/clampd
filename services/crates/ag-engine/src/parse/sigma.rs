//! Sigma YAML adapter - converts Sigma rules to Clampd ParsedRule.
//!
//! Registers `agent_tool_call` as a logsource category.
//! Supports modifiers: contains, startswith, endswith, re.
//! Level mapping: critical/high → Block, medium/low → Flag, informational → Pass.

use serde_yaml::Value;

use super::{ParseError, ParsedPattern, ParsedRule, RuleParser};
use crate::compile::RuleAction;
use crate::taxonomy::TaxonomyMapping;

/// Sigma YAML adapter for Clampd.
pub struct SigmaAdapter;

impl RuleParser for SigmaAdapter {
    fn format_name(&self) -> &str {
        "sigma"
    }

    fn parse(&self, input: &str) -> Result<Vec<ParsedRule>, ParseError> {
        let doc: Value = serde_yaml::from_str(input)
            .map_err(|e| ParseError::InvalidFormat(format!("Invalid Sigma YAML: {}", e)))?;

        // Check logsource
        let logsource = &doc["logsource"];
        let product = logsource["product"].as_str().unwrap_or("");
        let category = logsource["category"].as_str().unwrap_or("");

        // Only process clampd/agent_tool_call rules
        if product != "clampd" && category != "agent_tool_call" {
            return Ok(Vec::new());
        }

        let id = doc["id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let title = doc["title"]
            .as_str()
            .unwrap_or("Untitled Sigma Rule")
            .to_string();
        let level = doc["level"].as_str().unwrap_or("medium");

        let (action, risk_score) = map_level(level);

        // Parse detection
        let detection = &doc["detection"];
        let patterns = parse_detection(detection)?;

        // Parse tags → taxonomy
        let taxonomy = parse_tags(&doc["tags"]);

        Ok(vec![ParsedRule {
            id,
            name: title,
            risk_score,
            action,
            priority: 5, // Imported rules = priority 5
            labels: vec!["sigma_import".to_string()],
            tool_pattern: None,
            scope_pattern: None,
            patterns,
            exempt_agents: vec![],
            exemptable: false,
            risk_above: None,
            taxonomy,
        }])
    }
}

/// Map Sigma level to Clampd action + risk score.
fn map_level(level: &str) -> (RuleAction, f64) {
    match level {
        "critical" => (RuleAction::Block, 0.95),
        "high" => (RuleAction::Block, 0.85),
        "medium" => (RuleAction::Flag, 0.60),
        "low" => (RuleAction::Flag, 0.40),
        "informational" => (RuleAction::Pass, 0.20),
        _ => (RuleAction::Flag, 0.50),
    }
}

/// Parse Sigma detection block into patterns.
fn parse_detection(detection: &Value) -> Result<Vec<ParsedPattern>, ParseError> {
    let mut patterns = Vec::new();

    // Find the selection (referenced by condition)
    // Support: condition: selection (most common)
    let condition = detection["condition"].as_str().unwrap_or("selection");

    // Get the selection mapping
    let selection = &detection[condition];
    if selection.is_null() {
        return Ok(patterns);
    }

    if let Value::Mapping(map) = selection {
        for (key, value) in map {
            let key_str = key.as_str().unwrap_or("");
            let (field_name, modifier) = parse_field_modifier(key_str);
            let field = if field_name.is_empty() || field_name == "tool.args" {
                None
            } else {
                Some(field_name.to_string())
            };

            match value {
                Value::String(s) => {
                    let regex = modifier_to_regex(&modifier, s);
                    patterns.push(ParsedPattern { field, regex });
                }
                Value::Sequence(seq) => {
                    // List of values → OR (any match)
                    let alternatives: Vec<String> = seq
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| modifier_to_regex(&modifier, s))
                        .collect();
                    if !alternatives.is_empty() {
                        let combined = if alternatives.len() == 1 {
                            alternatives.into_iter().next().unwrap()
                        } else {
                            format!("({})", alternatives.join("|"))
                        };
                        patterns.push(ParsedPattern {
                            field,
                            regex: combined,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    Ok(patterns)
}

/// Parse field name and modifier from "tool.args|contains" format.
fn parse_field_modifier(key: &str) -> (&str, String) {
    if let Some(idx) = key.find('|') {
        (&key[..idx], key[idx + 1..].to_string())
    } else {
        (key, String::new())
    }
}

/// Convert a Sigma modifier + value into a regex pattern.
fn modifier_to_regex(modifier: &str, value: &str) -> String {
    match modifier {
        "contains" => regex::escape(value),
        "startswith" => format!("^{}", regex::escape(value)),
        "endswith" => format!("{}$", regex::escape(value)),
        "re" => value.to_string(), // Pass through raw regex
        "" => {
            // Exact match
            format!("^{}$", regex::escape(value))
        }
        _ => regex::escape(value), // Unknown modifier → treat as contains
    }
}

/// Parse Sigma tags into TaxonomyMapping.
fn parse_tags(tags: &Value) -> TaxonomyMapping {
    let mut taxonomy = TaxonomyMapping::default();

    if let Value::Sequence(seq) = tags {
        for tag in seq {
            if let Some(s) = tag.as_str() {
                // MITRE ATT&CK tags: attack.tXXXX
                if s.starts_with("attack.t") {
                    let technique = s.strip_prefix("attack.").unwrap_or(s);
                    taxonomy.atlas.push(technique.to_uppercase());
                } else if s.starts_with("attack.") {
                    // Tactic name (e.g., attack.credential_access)
                    let tactic = s.strip_prefix("attack.").unwrap_or(s);
                    taxonomy.owasp_llm.push(tactic.to_string());
                }
            }
        }
    }

    taxonomy
}
