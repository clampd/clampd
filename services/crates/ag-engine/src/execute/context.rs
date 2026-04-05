//! ExecutionContext: fixed-size array of field values, indexed by FieldId.
//!
//! Constructed once per request from the ClassifyRequest.
//! All SDK adapters (Python, TS, MCP proxy) populate the same interface.

use crate::scheme::{FieldId, FieldValue, Scheme};
use std::sync::Arc;

/// The execution context for a single tool call evaluation.
/// Fields are stored in a fixed-size Vec indexed by FieldId — O(1) access.
pub struct ExecutionContext {
    values: Vec<FieldValue>,
    /// Pre-computed: all strings from tool.args joined with spaces.
    all_text: Arc<str>,
    /// Pre-computed: normalized variants of the input.
    normalized_variants: Arc<[String]>,
    /// Decoded binary content (if L0 funnel produced any).
    binary_content: Option<Arc<[u8]>>,
}

impl ExecutionContext {
    /// Create a new context with all fields set to Absent.
    pub fn new(scheme: &Scheme) -> Self {
        Self {
            values: vec![FieldValue::Absent; scheme.len()],
            all_text: Arc::from(""),
            normalized_variants: Arc::from(vec![]),
            binary_content: None,
        }
    }

    /// Set a field value by FieldId.
    pub fn set(&mut self, id: FieldId, value: FieldValue) {
        if (id.0 as usize) < self.values.len() {
            self.values[id.0 as usize] = value;
        }
    }

    /// Get a field value by FieldId. Returns Absent if out of bounds.
    #[inline]
    pub fn get(&self, id: FieldId) -> &FieldValue {
        self.values
            .get(id.0 as usize)
            .unwrap_or(&FieldValue::Absent)
    }

    /// Get field as string. Returns empty string for missing/wrong type.
    #[inline]
    pub fn get_str(&self, id: FieldId) -> &str {
        self.get(id).as_str()
    }

    /// Get field as f64. Returns 0.0 for missing/wrong type.
    #[inline]
    pub fn get_float(&self, id: FieldId) -> f64 {
        self.get(id).as_float()
    }

    /// Get field as i64. Returns 0 for missing/wrong type.
    #[inline]
    pub fn get_int(&self, id: FieldId) -> i64 {
        self.get(id).as_int()
    }

    /// Get the pre-computed all_text (all strings from tool.args joined).
    pub fn all_text(&self) -> &str {
        &self.all_text
    }

    /// Set the pre-computed all_text.
    pub fn set_all_text(&mut self, text: Arc<str>) {
        self.all_text = text;
    }

    /// Get normalized variants.
    pub fn normalized_variants(&self) -> &[String] {
        &self.normalized_variants
    }

    /// Set normalized variants.
    pub fn set_normalized_variants(&mut self, variants: Arc<[String]>) {
        self.normalized_variants = variants;
    }

    /// Get binary content (from L0 funnel).
    pub fn binary_content(&self) -> Option<&[u8]> {
        self.binary_content.as_deref()
    }

    /// Set binary content.
    pub fn set_binary_content(&mut self, content: Arc<[u8]>) {
        self.binary_content = Some(content);
    }
}

impl std::fmt::Debug for ExecutionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionContext")
            .field("field_count", &self.values.len())
            .field("all_text_len", &self.all_text.len())
            .field("variant_count", &self.normalized_variants.len())
            .field("has_binary", &self.binary_content.is_some())
            .finish()
    }
}
