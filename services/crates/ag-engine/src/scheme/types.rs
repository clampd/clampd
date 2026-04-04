//! Field types and values for the Scheme.

use std::sync::Arc;

/// The type of a field in the scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    String,
    StringList,
    Float,
    Int,
    Bool,
    Json,
    Bytes,
}

/// A concrete value for a field in an ExecutionContext.
#[derive(Debug, Clone)]
pub enum FieldValue {
    String(Arc<str>),
    StringList(Arc<[Arc<str>]>),
    Float(f64),
    Int(i64),
    Bool(bool),
    Json(Arc<serde_json::Value>),
    Bytes(Arc<[u8]>),
    Absent,
}

impl FieldValue {
    /// Returns true if this value is Absent.
    pub fn is_absent(&self) -> bool {
        matches!(self, FieldValue::Absent)
    }

    /// Try to get as string reference. Returns empty string for Absent.
    pub fn as_str(&self) -> &str {
        match self {
            FieldValue::String(s) => s,
            _ => "",
        }
    }

    /// Try to get as f64. Returns 0.0 for Absent or type mismatch.
    pub fn as_float(&self) -> f64 {
        match self {
            FieldValue::Float(f) => *f,
            _ => 0.0,
        }
    }

    /// Try to get as i64. Returns 0 for Absent or type mismatch.
    pub fn as_int(&self) -> i64 {
        match self {
            FieldValue::Int(i) => *i,
            _ => 0,
        }
    }

    /// Try to get as bool. Returns false for Absent or type mismatch.
    pub fn as_bool(&self) -> bool {
        match self {
            FieldValue::Bool(b) => *b,
            _ => false,
        }
    }
}

impl PartialEq for FieldValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FieldValue::String(a), FieldValue::String(b)) => a == b,
            (FieldValue::Float(a), FieldValue::Float(b)) => (a - b).abs() < f64::EPSILON,
            (FieldValue::Int(a), FieldValue::Int(b)) => a == b,
            (FieldValue::Bool(a), FieldValue::Bool(b)) => a == b,
            (FieldValue::Absent, FieldValue::Absent) => true,
            _ => false,
        }
    }
}
