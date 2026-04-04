//! ag-engine: Runtime rule engine for Clampd
//!
//! 5-layer detection pipeline:
//! - L0: Decode funnel + binary inspection (yara-x, entropy, magic bytes)
//! - L4: Text normalization (13-step recursive decode)
//! - L1: Regex rules (per-field RegexSet + closure evaluation)
//! - L2: Aho-Corasick dictionary (keyword scan)
//! - L3: Compound signals (micro-signal scoring)
//!
//! Architecture inspired by Cloudflare's wirefilter:
//! - Typed Scheme with IndexMap field registry
//! - Parse → Compile → Execute pipeline
//! - Closure-based compilation (no JIT)
//! - Fixed-size ExecutionContext indexed by FieldId

pub mod scheme;
pub mod compile;
pub mod execute;
pub mod parse;
pub mod normalize;
pub mod dictionary;
pub mod signals;
pub mod taxonomy;
pub mod compliance;
pub mod builtins;
pub mod funnel;
pub mod storage;
pub mod versioning;
pub mod testing;

// Re-exports for public API
pub use scheme::{FieldId, FieldType, FieldValue, Scheme};
pub use compile::{CompiledRule, CompiledRuleset, Condition, RuleAction};
pub use execute::{ExecutionContext, EvalResult, RuleMatch};
pub use parse::{ParsedRule, RuleParser, ParseError};
pub use taxonomy::TaxonomyMapping;
