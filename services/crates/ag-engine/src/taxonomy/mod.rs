//! MITRE ATLAS + OWASP LLM Top 10 + regulation taxonomy mapping.

use serde::{Deserialize, Serialize};

/// Taxonomy mapping for a rule - maps to industry-standard categories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaxonomyMapping {
    /// MITRE ATLAS technique IDs (e.g., "AML.T0051", "AML.T0054")
    #[serde(default)]
    pub atlas: Vec<String>,
    /// OWASP LLM Top 10 categories (e.g., "LLM01", "LLM07")
    #[serde(default)]
    pub owasp_llm: Vec<String>,
    /// Regulation identifiers (e.g., "HIPAA", "GDPR", "PCI-DSS")
    #[serde(default)]
    pub regulations: Vec<String>,
}

impl TaxonomyMapping {
    pub fn is_empty(&self) -> bool {
        self.atlas.is_empty() && self.owasp_llm.is_empty() && self.regulations.is_empty()
    }
}
