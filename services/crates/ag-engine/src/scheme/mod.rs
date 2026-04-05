//! Typed field registry (Scheme) for the rule engine.
//!
//! Fields resolve to FieldId(u16) at parse time — array index, not hash lookup.
//! ExecutionContext uses Vec<FieldValue> indexed by FieldId for O(1) access.

mod types;

pub use types::{FieldType, FieldValue};

use indexmap::IndexMap;
use std::sync::Arc;

/// Array index into ExecutionContext.values — not a string key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldId(pub u16);

/// Definition of a single field in the scheme.
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,
    pub id: FieldId,
}

/// Typed field registry. Fields are registered at startup; rules reference fields by FieldId.
/// Uses IndexMap to preserve insertion order and enable O(1) index-based access.
#[derive(Debug, Clone)]
pub struct Scheme {
    fields: IndexMap<String, FieldDef>,
}

impl Scheme {
    /// Create an empty scheme.
    pub fn new() -> Self {
        Self {
            fields: IndexMap::new(),
        }
    }

    /// Register a field. Returns its FieldId (position in the IndexMap).
    /// Panics if field name already registered.
    pub fn register(&mut self, name: &str, field_type: FieldType) -> FieldId {
        assert!(
            !self.fields.contains_key(name),
            "Field '{}' already registered",
            name
        );
        let id = FieldId(self.fields.len() as u16);
        self.fields.insert(
            name.to_string(),
            FieldDef {
                name: name.to_string(),
                field_type,
                id,
            },
        );
        id
    }

    /// Look up a field by name. Returns None if not registered.
    pub fn get(&self, name: &str) -> Option<&FieldDef> {
        self.fields.get(name)
    }

    /// Look up a field by FieldId. Returns None if out of bounds.
    pub fn get_by_id(&self, id: FieldId) -> Option<&FieldDef> {
        self.fields.get_index(id.0 as usize).map(|(_, def)| def)
    }

    /// Number of registered fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the scheme has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Iterate over all fields in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &FieldDef> {
        self.fields.values()
    }
}

impl Default for Scheme {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the default Clampd scheme with all 22 fields.
pub fn clampd_scheme() -> Scheme {
    let mut s = Scheme::new();
    // WHO/WHAT/HOW fields (0-13)
    s.register("tool.name", FieldType::String);           // 0
    s.register("tool.action", FieldType::String);          // 1
    s.register("tool.args", FieldType::Json);              // 2
    s.register("tool.args_normalized", FieldType::Json);   // 3
    s.register("tool.args_text", FieldType::String);       // 4
    s.register("agent.id", FieldType::String);             // 5
    s.register("agent.risk_score", FieldType::Float);      // 6
    s.register("delegation.depth", FieldType::Int);        // 7
    s.register("encodings.detected", FieldType::StringList); // 8
    s.register("tool.descriptor_hash", FieldType::String); // 9
    s.register("tool.category", FieldType::String);        // 10
    s.register("transport.type", FieldType::String);       // 11
    s.register("session.flags", FieldType::StringList);    // 12
    s.register("session.risk_factor", FieldType::Float);   // 13
    // L0 decode funnel fields (14-21)
    s.register("content.magic_type", FieldType::String);   // 14
    s.register("content.entropy", FieldType::Float);       // 15
    s.register("content.has_shebang", FieldType::Bool);    // 16
    s.register("content.yara_matches", FieldType::StringList); // 17
    s.register("content.size_bytes", FieldType::Int);      // 18
    s.register("decode.depth", FieldType::Int);            // 19
    s.register("decode.encodings", FieldType::StringList); // 20
    s.register("decode.timed_out", FieldType::Bool);       // 21
    // Unified scope field (22)
    s.register("tool.scope", FieldType::String);             // 22
    s
}
