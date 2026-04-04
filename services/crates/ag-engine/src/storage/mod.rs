//! Ruleset storage backends.
//! Trait-based: filesystem, Redis, or custom.

pub mod filesystem;

/// Trait for ruleset storage backends.
pub trait RulesetStorage {
    /// Store a ruleset at a specific version.
    fn store_ruleset(&self, version: u64, content: &str, format: &str) -> Result<(), String>;

    /// Load a ruleset. If version is None, load the latest.
    /// Returns (content, version).
    fn load_ruleset(&self, version: Option<u64>) -> Result<(String, u64), String>;

    /// List all stored versions.
    fn list_versions(&self) -> Result<Vec<u64>, String>;

    /// Delete a specific version.
    fn delete_version(&self, version: u64) -> Result<(), String>;
}
