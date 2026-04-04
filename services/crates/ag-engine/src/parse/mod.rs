//! Multi-format rule parsing: TOML (native), Sigma YAML, PortableRule JSON.
//!
//! All formats produce Vec<ParsedRule> which feeds into compile::CompiledRuleset.

pub mod native;
pub mod portable;
#[cfg(feature = "sigma")]
pub mod sigma;

use crate::compile::{Condition, RuleAction};
use crate::taxonomy::TaxonomyMapping;

/// A parsed (but not yet compiled) rule.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedRule {
    pub id: String,
    pub name: String,
    pub risk_score: f64,
    pub action: RuleAction,
    #[serde(default = "default_priority")]
    pub priority: u8,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub tool_pattern: Option<String>,
    /// Scope patterns this rule applies to.
    /// Supports single string `"db:*"` or array `["db:*", "exec:*"]` in TOML/JSON.
    /// `["*"]` or `"*"` means fire on all scopes.
    /// Empty vec means no scope filter (falls through to tool_pattern).
    /// Multiple scopes enable cross-category detection (e.g., shell rule that
    /// also fires on file-read tools).
    #[serde(default, deserialize_with = "deserialize_scope_pattern")]
    pub scope_pattern: Vec<String>,
    pub patterns: Vec<ParsedPattern>,
    #[serde(default)]
    pub exempt_agents: Vec<String>,
    #[serde(default)]
    pub exemptable: bool,
    #[serde(default)]
    pub risk_above: Option<f64>,
    #[serde(default)]
    pub taxonomy: TaxonomyMapping,
}

/// Deserialize scope_pattern from either a single string or array of strings.
/// Supports: `scope_pattern = "*"`, `scope_pattern = "db:*"`, `scope_pattern = ["db:*", "exec:*"]`
fn deserialize_scope_pattern<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct ScopePatternVisitor;

    impl<'de> de::Visitor<'de> for ScopePatternVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Vec<String>, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut v = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                v.push(s);
            }
            Ok(v)
        }

        fn visit_none<E: de::Error>(self) -> Result<Vec<String>, E> {
            Ok(Vec::new())
        }

        fn visit_unit<E: de::Error>(self) -> Result<Vec<String>, E> {
            Ok(Vec::new())
        }
    }

    deserializer.deserialize_any(ScopePatternVisitor)
}

fn default_priority() -> u8 {
    10
}

/// A regex pattern associated with a parsed rule.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedPattern {
    #[serde(default)]
    pub field: Option<String>,
    pub regex: String,
}

/// Trait for rule format parsers.
pub trait RuleParser: Send + Sync {
    fn format_name(&self) -> &str;
    fn parse(&self, input: &str) -> Result<Vec<ParsedRule>, ParseError>;
}

/// Error during rule parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Invalid regex '{pattern}': {reason}")]
    InvalidRegex { pattern: String, reason: String },
    #[error("Potential ReDoS in pattern '{pattern}': {reason}")]
    ReDoS { pattern: String, reason: String },
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid risk score {0}: must be 0.0-1.0")]
    InvalidRiskScore(f64),
}
