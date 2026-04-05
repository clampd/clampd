//! Condition types and closure compilation.
//!
//! Each Condition variant compiles to a Box<dyn Fn(&ExecutionContext) -> bool>.
//! Closures capture compiled regex, field indices, and match values.

use crate::scheme::FieldId;
use serde::{Deserialize, Serialize};

/// A match pattern for string fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum MatchPattern {
    Exact(String),
    Contains(String),
    Glob(String),
    Regex(String),
    ContainsAny(Vec<String>),
}

/// A condition in a detection rule.
/// Compiled to closures at load time — never interpreted at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Condition {
    // Tool identity
    ToolNameIn { values: Vec<String> },
    ToolNameMatch { pattern: MatchPattern },

    // Argument inspection
    FieldMatches {
        field: String,
        pattern: MatchPattern,
    },
    FieldContains {
        field: String,
        pattern: String,
    },
    FieldEquals {
        field: String,
        value: String,
    },
    FieldGt {
        field: String,
        threshold: f64,
    },

    // Payload-level
    PayloadContains { pattern: MatchPattern },
    PayloadSizeExceeds { bytes: usize },

    // Composition
    All { conditions: Vec<Condition> },
    Any { conditions: Vec<Condition> },
    Not { condition: Box<Condition> },
}
