//! Ruleset versioning and deployment stages.
//! Draft → Testing → Canary → Production → Retired

use serde::{Deserialize, Serialize};

/// Deployment stage for a ruleset version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RulesetStage {
    Draft,
    Testing,
    Canary,
    Production,
    Retired,
}

impl RulesetStage {
    /// Returns the next valid promotion target, if any.
    fn next(self) -> Option<RulesetStage> {
        match self {
            RulesetStage::Draft => Some(RulesetStage::Testing),
            RulesetStage::Testing => Some(RulesetStage::Canary),
            RulesetStage::Canary => Some(RulesetStage::Production),
            RulesetStage::Production => Some(RulesetStage::Retired),
            RulesetStage::Retired => None,
        }
    }
}

/// A versioned ruleset entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesetVersion {
    pub version: u64,
    #[serde(with = "hex_array")]
    pub checksum: [u8; 32],
    pub stage: RulesetStage,
    pub rule_count: usize,
    pub source_format: String,
    pub created_at: String,
}

/// Manifest tracking all ruleset versions and their stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesetManifest {
    versions: Vec<RulesetVersion>,
}

impl RulesetManifest {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
        }
    }

    pub fn versions(&self) -> &[RulesetVersion] {
        &self.versions
    }

    pub fn add_version(&mut self, version: RulesetVersion) {
        self.versions.push(version);
    }

    /// Returns the version number of the latest Production ruleset.
    pub fn active_version(&self) -> Option<u64> {
        self.versions
            .iter()
            .filter(|v| v.stage == RulesetStage::Production)
            .map(|v| v.version)
            .max()
    }

    /// Promote a version to the next stage. Validates stage ordering.
    pub fn promote(&mut self, version: u64, target: RulesetStage) -> Result<(), String> {
        let entry = self
            .versions
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or_else(|| format!("Version {} not found", version))?;

        let expected_next = entry
            .stage
            .next()
            .ok_or_else(|| format!("Cannot promote from {:?}", entry.stage))?;

        if target != expected_next {
            return Err(format!(
                "Cannot promote from {:?} to {:?}; next valid stage is {:?}",
                entry.stage, target, expected_next
            ));
        }

        entry.stage = target;
        Ok(())
    }

    /// Retire a version (mark as no longer active).
    pub fn retire(&mut self, version: u64) -> Result<(), String> {
        let entry = self
            .versions
            .iter_mut()
            .find(|v| v.version == version)
            .ok_or_else(|| format!("Version {} not found", version))?;

        entry.stage = RulesetStage::Retired;
        Ok(())
    }

    /// Rollback: retire the current active version, making the previous Production active.
    pub fn rollback(&mut self) -> Result<(), String> {
        // Find all Production versions sorted by version number
        let mut prod_versions: Vec<u64> = self
            .versions
            .iter()
            .filter(|v| v.stage == RulesetStage::Production)
            .map(|v| v.version)
            .collect();
        prod_versions.sort();

        if prod_versions.len() < 2 {
            return Err("No previous Production version to rollback to".to_string());
        }

        // Retire the latest
        let latest = *prod_versions.last().unwrap();
        self.retire(latest)?;

        Ok(())
    }
}

impl Default for RulesetManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Serde helper for [u8; 32] as hex string.
mod hex_array {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        if bytes.len() == 32 {
            arr.copy_from_slice(&bytes);
        }
        Ok(arr)
    }
}
