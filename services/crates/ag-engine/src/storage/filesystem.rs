//! Filesystem storage backend for rulesets.
//! Stores each version as a directory: {base_path}/v{version}/ruleset.toml

use std::fs;
use std::path::{Path, PathBuf};

use super::RulesetStorage;

/// Filesystem-based ruleset storage.
/// Structure: {base_path}/v001/ruleset.{format}
pub struct FilesystemStorage {
    base_path: PathBuf,
}

impl FilesystemStorage {
    pub fn new(base_path: &Path) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
        }
    }

    fn version_dir(&self, version: u64) -> PathBuf {
        self.base_path.join(format!("v{:03}", version))
    }

    fn ruleset_file(&self, version: u64) -> PathBuf {
        self.version_dir(version).join("ruleset.toml")
    }
}

impl RulesetStorage for FilesystemStorage {
    fn store_ruleset(&self, version: u64, content: &str, _format: &str) -> Result<(), String> {
        let dir = self.version_dir(version);
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create dir: {}", e))?;

        let file = self.ruleset_file(version);
        fs::write(&file, content).map_err(|e| format!("Failed to write ruleset: {}", e))?;

        Ok(())
    }

    fn load_ruleset(&self, version: Option<u64>) -> Result<(String, u64), String> {
        let ver = match version {
            Some(v) => v,
            None => {
                // Find the latest version
                let versions = self.list_versions()?;
                *versions
                    .iter()
                    .max()
                    .ok_or("No ruleset versions found")?
            }
        };

        let file = self.ruleset_file(ver);
        let content =
            fs::read_to_string(&file).map_err(|e| format!("Failed to read v{}: {}", ver, e))?;

        Ok((content, ver))
    }

    fn list_versions(&self) -> Result<Vec<u64>, String> {
        if !self.base_path.exists() {
            return Ok(Vec::new());
        }

        let mut versions = Vec::new();
        let entries =
            fs::read_dir(&self.base_path).map_err(|e| format!("Failed to read dir: {}", e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Parse "v001" → 1
            if let Some(stripped) = name_str.strip_prefix('v') {
                if let Ok(v) = stripped.parse::<u64>() {
                    versions.push(v);
                }
            }
        }

        versions.sort();
        Ok(versions)
    }

    fn delete_version(&self, version: u64) -> Result<(), String> {
        let dir = self.version_dir(version);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| format!("Failed to delete v{}: {}", version, e))?;
        }
        Ok(())
    }
}
