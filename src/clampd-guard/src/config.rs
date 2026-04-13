/// Guard configuration with managed config support.
///
/// Load order (later overrides earlier):
///   1. User config:    ~/.clampd/guard.json
///   2. Managed config: /etc/clampd/guard.json (Linux) or
///                      /Library/Application Support/clampd/guard.json (macOS)
///
/// Managed config is pushed by security teams via Ansible/Jamf/Intune.
/// Any field set in managed config cannot be overridden by the user.
/// This lets security teams enforce fail_open: false, gateway_url, etc.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    pub gateway_url: String,
    pub api_key: String,
    pub agent_id: String,
    pub secret: String,
    #[serde(default)]
    pub skip_low_risk: bool,
    #[serde(default = "default_fail_open")]
    pub fail_open: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_fail_open() -> bool { true }
fn default_timeout_ms() -> u64 { 2000 }

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            gateway_url: "http://127.0.0.1:8080".into(),
            api_key: String::new(),
            agent_id: String::new(),
            secret: String::new(),
            skip_low_risk: false,
            fail_open: true,
            timeout_ms: 2000,
        }
    }
}

impl GuardConfig {
    pub fn config_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".clampd")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("guard.json")
    }

    /// System-level managed config path. Pushed by security team via MDM.
    /// Fields in managed config override user config and cannot be changed.
    fn managed_config_path() -> PathBuf {
        if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/clampd/guard.json")
        } else {
            PathBuf::from("/etc/clampd/guard.json")
        }
    }

    /// Load config: user config first, then managed config overrides.
    pub fn load() -> Result<Self> {
        let user_path = Self::config_path();
        let managed_path = Self::managed_config_path();

        // Try user config first
        let mut cfg = if user_path.exists() {
            let content = std::fs::read_to_string(&user_path)
                .with_context(|| format!("Failed to read {}", user_path.display()))?;
            serde_json::from_str::<Self>(&content)
                .with_context(|| format!("Failed to parse {}", user_path.display()))?
        } else if managed_path.exists() {
            // No user config but managed exists — use managed as base
            Self::default()
        } else {
            anyhow::bail!(
                "Guard config not found at {} or {}. Run: clampd-guard setup",
                user_path.display(),
                managed_path.display()
            );
        };

        // Apply managed config overrides (security team wins)
        if managed_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&managed_path) {
                if let Ok(managed) = serde_json::from_str::<serde_json::Value>(&content) {
                    cfg.apply_managed(&managed);
                }
            }
        }

        Ok(cfg)
    }

    /// Apply managed config overrides. Any field present in managed config
    /// replaces the user config value. Security team controls these.
    fn apply_managed(&mut self, managed: &serde_json::Value) {
        if let Some(v) = managed.get("gateway_url").and_then(|v| v.as_str()) {
            self.gateway_url = v.to_string();
        }
        if let Some(v) = managed.get("api_key").and_then(|v| v.as_str()) {
            self.api_key = v.to_string();
        }
        if let Some(v) = managed.get("agent_id").and_then(|v| v.as_str()) {
            self.agent_id = v.to_string();
        }
        if let Some(v) = managed.get("secret").and_then(|v| v.as_str()) {
            self.secret = v.to_string();
        }
        if let Some(v) = managed.get("skip_low_risk").and_then(|v| v.as_bool()) {
            self.skip_low_risk = v;
        }
        if let Some(v) = managed.get("fail_open").and_then(|v| v.as_bool()) {
            self.fail_open = v;
        }
        if let Some(v) = managed.get("timeout_ms").and_then(|v| v.as_u64()) {
            self.timeout_ms = v;
        }
    }

    pub fn save(&self) -> Result<PathBuf> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;

        let path = Self::config_path();
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let cfg = GuardConfig::default();
        assert!(cfg.fail_open);
        assert_eq!(cfg.timeout_ms, 2000);
        assert!(!cfg.skip_low_risk);
    }

    #[test]
    fn roundtrip() {
        let cfg = GuardConfig {
            gateway_url: "https://clampd.test".into(),
            api_key: "ag_test_key".into(),
            agent_id: "agent-123".into(),
            secret: "ags_test".into(),
            skip_low_risk: true,
            fail_open: false,
            timeout_ms: 500,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: GuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.gateway_url, "https://clampd.test");
        assert!(parsed.skip_low_risk);
        assert!(!parsed.fail_open);
    }

    #[test]
    fn managed_overrides_user() {
        let mut cfg = GuardConfig {
            gateway_url: "https://user-gateway.test".into(),
            api_key: "user_key".into(),
            agent_id: "user-agent".into(),
            secret: "user_secret".into(),
            skip_low_risk: false,
            fail_open: true,
            timeout_ms: 2000,
        };

        let managed = serde_json::json!({
            "gateway_url": "https://corp-gateway.internal",
            "fail_open": false,
            "timeout_ms": 5000
        });

        cfg.apply_managed(&managed);

        // Managed fields override
        assert_eq!(cfg.gateway_url, "https://corp-gateway.internal");
        assert!(!cfg.fail_open);
        assert_eq!(cfg.timeout_ms, 5000);

        // User fields preserved
        assert_eq!(cfg.api_key, "user_key");
        assert_eq!(cfg.agent_id, "user-agent");
        assert_eq!(cfg.secret, "user_secret");
        assert!(!cfg.skip_low_risk);
    }

    #[test]
    fn managed_empty_changes_nothing() {
        let mut cfg = GuardConfig {
            gateway_url: "https://user.test".into(),
            fail_open: true,
            ..Default::default()
        };

        let managed = serde_json::json!({});
        cfg.apply_managed(&managed);

        assert_eq!(cfg.gateway_url, "https://user.test");
        assert!(cfg.fail_open);
    }

    #[test]
    fn managed_full_override() {
        let mut cfg = GuardConfig::default();

        let managed = serde_json::json!({
            "gateway_url": "https://enforced.corp",
            "api_key": "corp_key",
            "agent_id": "corp-agent",
            "secret": "corp_secret",
            "skip_low_risk": false,
            "fail_open": false,
            "timeout_ms": 3000
        });

        cfg.apply_managed(&managed);

        assert_eq!(cfg.gateway_url, "https://enforced.corp");
        assert_eq!(cfg.api_key, "corp_key");
        assert_eq!(cfg.agent_id, "corp-agent");
        assert_eq!(cfg.secret, "corp_secret");
        assert!(!cfg.skip_low_risk);
        assert!(!cfg.fail_open);
        assert_eq!(cfg.timeout_ms, 3000);
    }
}
