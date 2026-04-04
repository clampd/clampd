use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Context (like kubeconfig context) ────────────────────

/// A named connection context, similar to kubectl contexts.
/// Each context points to a specific clampd control plane + org.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClampdContext {
    /// Unique name for this context (e.g. "local", "staging", "prod")
    pub name: String,
    /// Endpoint URL for the control plane.
    /// For now this is the Dashboard API URL (HTTP).
    /// In future phases, this will be ag-control gRPC endpoint.
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    /// Organization ID for this context
    #[serde(default)]
    pub org_id: String,
    /// API token for authentication
    #[serde(default)]
    pub api_token: String,
    /// Transport protocol: "http" (dashboard API) or "grpc" (ag-control direct)
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Optional: license token associated with this context
    #[serde(default)]
    pub license_token: String,
}

fn default_endpoint() -> String {
    "http://127.0.0.1:3001".into()
}
fn default_transport() -> String {
    "http".into()
}

impl Default for ClampdContext {
    fn default() -> Self {
        Self {
            name: "local".into(),
            endpoint: default_endpoint(),
            org_id: String::new(),
            api_token: String::new(),
            transport: default_transport(),
            license_token: String::new(),
        }
    }
}

// ── Config file ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Name of the active context
    #[serde(default = "default_current_context")]
    pub current_context: String,

    /// List of available contexts
    #[serde(default = "default_contexts")]
    pub contexts: Vec<ClampdContext>,

    /// Legacy fields kept for backward compat with existing config files.
    /// If present, they are migrated into a "local" context on load.
    #[serde(default, skip_serializing)]
    pub core: Option<LegacyCoreConfig>,
    #[serde(default, skip_serializing)]
    pub connections: Option<LegacyConnectionsConfig>,

    #[serde(default)]
    pub output: OutputConfig,

    /// Direct service URLs for fallback/TUI/demo modes
    #[serde(default)]
    pub services: ServiceUrls,
}

/// Legacy core config — migrated to context on load
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LegacyCoreConfig {
    #[serde(default)]
    pub org_id: String,
    #[serde(default)]
    pub license_token: String,
    #[serde(default = "default_compose_file")]
    pub compose_file: String,
}

/// Legacy connections config — migrated to context on load
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LegacyConnectionsConfig {
    #[serde(default)]
    pub dashboard_url: String,
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub database_url: String,
    #[serde(default)]
    pub redis_url: String,
    #[serde(default)]
    pub nats_url: String,
    #[serde(default)]
    pub clickhouse_url: String,
    #[serde(default)]
    pub gateway_url: String,
    #[serde(default)]
    pub registry_url: String,
    #[serde(default)]
    pub token_url: String,
    #[serde(default)]
    pub kill_url: String,
    #[serde(default)]
    pub risk_url: String,
    #[serde(default)]
    pub control_url: String,
}

/// Direct service URLs for local development, TUI, and demo modes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceUrls {
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    #[serde(default = "default_nats_url")]
    pub nats_url: String,
    #[serde(default = "default_clickhouse_url")]
    pub clickhouse_url: String,
    #[serde(default = "default_gateway_url")]
    pub gateway_url: String,
    #[serde(default = "default_registry_url")]
    pub registry_url: String,
    #[serde(default = "default_token_url")]
    pub token_url: String,
    #[serde(default = "default_kill_url")]
    pub kill_url: String,
    #[serde(default = "default_risk_url")]
    pub risk_url: String,
    #[serde(default = "default_control_url")]
    pub control_url: String,
    #[serde(default = "default_compose_file")]
    pub compose_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub no_color: bool,
}

fn default_current_context() -> String {
    "local".into()
}
fn default_contexts() -> Vec<ClampdContext> {
    vec![ClampdContext::default()]
}
fn default_compose_file() -> String {
    "docker-compose.yml".into()
}
fn default_database_url() -> String {
    "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd".into()
}
fn default_redis_url() -> String {
    "redis://127.0.0.1:6380".into()
}
fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".into()
}
fn default_clickhouse_url() -> String {
    "http://127.0.0.1:8123".into()
}
fn default_gateway_url() -> String {
    "http://127.0.0.1:8080".into()
}
fn default_registry_url() -> String {
    "http://127.0.0.1:50051".into()
}
fn default_token_url() -> String {
    "http://127.0.0.1:50054".into()
}
fn default_kill_url() -> String {
    "http://127.0.0.1:50055".into()
}
fn default_risk_url() -> String {
    "http://127.0.0.1:50056".into()
}
fn default_control_url() -> String {
    "http://127.0.0.1:50057".into()
}
fn default_format() -> String {
    "table".into()
}

impl Default for ServiceUrls {
    fn default() -> Self {
        Self {
            database_url: default_database_url(),
            redis_url: default_redis_url(),
            nats_url: default_nats_url(),
            clickhouse_url: default_clickhouse_url(),
            gateway_url: default_gateway_url(),
            registry_url: default_registry_url(),
            token_url: default_token_url(),
            kill_url: default_kill_url(),
            risk_url: default_risk_url(),
            control_url: default_control_url(),
            compose_file: default_compose_file(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            no_color: false,
        }
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            current_context: default_current_context(),
            contexts: default_contexts(),
            core: None,
            connections: None,
            output: OutputConfig::default(),
            services: ServiceUrls::default(),
        }
    }
}

impl CliConfig {
    pub fn config_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".clampd")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        Self::from_toml(&contents)
            .with_context(|| format!("Failed to parse {}", path.display()))
    }

    /// Parse config from a TOML string, handling legacy format migration.
    pub fn from_toml(contents: &str) -> Result<Self> {
        let mut cfg: Self = toml::from_str(contents)?;
        cfg.migrate_legacy();
        Ok(cfg)
    }

    /// Migrate legacy [core]/[connections] sections into a "local" context.
    fn migrate_legacy(&mut self) {
        let has_legacy = self.core.is_some() || self.connections.is_some();
        if !has_legacy {
            return;
        }

        let core = self.core.take().unwrap_or_default();
        let conn = self.connections.take().unwrap_or_default();

        // Build a context from legacy fields
        let legacy_ctx = ClampdContext {
            name: "local".into(),
            endpoint: if conn.dashboard_url.is_empty() {
                default_endpoint()
            } else {
                conn.dashboard_url.clone()
            },
            org_id: core.org_id,
            api_token: conn.api_token,
            transport: "http".into(),
            license_token: core.license_token,
        };

        // Merge legacy service URLs
        if !conn.database_url.is_empty() {
            self.services.database_url = conn.database_url;
        }
        if !conn.redis_url.is_empty() {
            self.services.redis_url = conn.redis_url;
        }
        if !conn.nats_url.is_empty() {
            self.services.nats_url = conn.nats_url;
        }
        if !conn.clickhouse_url.is_empty() {
            self.services.clickhouse_url = conn.clickhouse_url;
        }
        if !conn.gateway_url.is_empty() {
            self.services.gateway_url = conn.gateway_url;
        }
        if !conn.registry_url.is_empty() {
            self.services.registry_url = conn.registry_url;
        }
        if !conn.token_url.is_empty() {
            self.services.token_url = conn.token_url;
        }
        if !conn.kill_url.is_empty() {
            self.services.kill_url = conn.kill_url;
        }
        if !conn.risk_url.is_empty() {
            self.services.risk_url = conn.risk_url;
        }
        if !conn.control_url.is_empty() {
            self.services.control_url = conn.control_url;
        }
        if !core.compose_file.is_empty() {
            self.services.compose_file = core.compose_file;
        }

        // Replace or insert the "local" context
        if let Some(existing) = self.contexts.iter_mut().find(|c| c.name == "local") {
            *existing = legacy_ctx;
        } else {
            self.contexts.insert(0, legacy_ctx);
        }
        self.current_context = "local".into();
    }

    /// Apply environment variable overrides on top of file config.
    pub fn with_env_overrides(mut self) -> Self {
        // Override active context's fields from env
        if let Some(ctx) = self.active_context_mut() {
            if let Ok(v) = std::env::var("CLAMPD_ORG_ID") {
                ctx.org_id = v;
            }
            if let Ok(v) = std::env::var("CLAMPD_LICENSE_TOKEN") {
                ctx.license_token = v;
            }
            if let Ok(v) = std::env::var("CLAMPD_DASHBOARD_URL") {
                ctx.endpoint = v;
            }
            if let Ok(v) = std::env::var("CLAMPD_API_TOKEN") {
                ctx.api_token = v;
            }
        }

        // Service URL overrides
        if let Ok(v) = std::env::var("DATABASE_URL") {
            self.services.database_url = v;
        }
        if let Ok(v) = std::env::var("REDIS_URL") {
            self.services.redis_url = v;
        }
        if let Ok(v) = std::env::var("NATS_URL") {
            self.services.nats_url = v;
        }
        if let Ok(v) = std::env::var("CLICKHOUSE_URL") {
            self.services.clickhouse_url = v;
        }
        if let Ok(v) = std::env::var("GATEWAY_URL") {
            self.services.gateway_url = v;
        }
        if let Ok(v) = std::env::var("REGISTRY_URL") {
            self.services.registry_url = v;
        }
        if let Ok(v) = std::env::var("TOKEN_URL") {
            self.services.token_url = v;
        }
        if let Ok(v) = std::env::var("KILL_URL") {
            self.services.kill_url = v;
        }
        if let Ok(v) = std::env::var("RISK_URL") {
            self.services.risk_url = v;
        }
        if let Ok(v) = std::env::var("CONTROL_URL") {
            self.services.control_url = v;
        }
        self
    }

    // ── Context management ───────────────────────────────

    /// Get the active context (immutable).
    pub fn active_context(&self) -> Option<&ClampdContext> {
        self.contexts.iter().find(|c| c.name == self.current_context)
    }

    /// Get the active context (mutable).
    pub fn active_context_mut(&mut self) -> Option<&mut ClampdContext> {
        let name = self.current_context.clone();
        self.contexts.iter_mut().find(|c| c.name == name)
    }

    /// Get a context by name.
    pub fn get_context(&self, name: &str) -> Option<&ClampdContext> {
        self.contexts.iter().find(|c| c.name == name)
    }

    /// Switch the active context. Returns error if context doesn't exist.
    pub fn use_context(&mut self, name: &str) -> Result<()> {
        if !self.contexts.iter().any(|c| c.name == name) {
            anyhow::bail!(
                "Context '{}' not found. Available: {}",
                name,
                self.context_names().join(", ")
            );
        }
        self.current_context = name.to_string();
        Ok(())
    }

    /// Add a new context. Returns error if name already exists.
    pub fn add_context(&mut self, ctx: ClampdContext) -> Result<()> {
        if self.contexts.iter().any(|c| c.name == ctx.name) {
            anyhow::bail!("Context '{}' already exists. Use 'context set' to update it.", ctx.name);
        }
        self.contexts.push(ctx);
        Ok(())
    }

    /// Remove a context by name. Cannot remove the active context.
    pub fn remove_context(&mut self, name: &str) -> Result<()> {
        if name == self.current_context {
            anyhow::bail!("Cannot remove the active context '{}'. Switch to another context first.", name);
        }
        let before = self.contexts.len();
        self.contexts.retain(|c| c.name != name);
        if self.contexts.len() == before {
            anyhow::bail!("Context '{}' not found.", name);
        }
        Ok(())
    }

    /// Update fields on an existing context.
    pub fn set_context_field(&mut self, name: &str, field: &str, value: &str) -> Result<()> {
        let ctx = self.contexts.iter_mut().find(|c| c.name == name)
            .ok_or_else(|| anyhow::anyhow!("Context '{}' not found.", name))?;
        match field {
            "endpoint" => ctx.endpoint = value.to_string(),
            "org_id" | "org-id" => ctx.org_id = value.to_string(),
            "api_token" | "api-token" => ctx.api_token = value.to_string(),
            "transport" => {
                if value != "http" && value != "grpc" {
                    anyhow::bail!("Transport must be 'http' or 'grpc', got '{}'", value);
                }
                ctx.transport = value.to_string();
            }
            "license_token" | "license-token" => ctx.license_token = value.to_string(),
            _ => anyhow::bail!("Unknown field '{}'. Valid: endpoint, org_id, api_token, transport, license_token", field),
        }
        Ok(())
    }

    /// List all context names.
    pub fn context_names(&self) -> Vec<&str> {
        self.contexts.iter().map(|c| c.name.as_str()).collect()
    }

    // ── Convenience accessors using active context ──────

    /// Dashboard URL from the active context (or default).
    pub fn dashboard_url(&self) -> &str {
        self.active_context()
            .map(|c| c.endpoint.as_str())
            .unwrap_or("http://127.0.0.1:3001")
    }

    /// API token from the active context.
    pub fn api_token(&self) -> &str {
        self.active_context()
            .map(|c| c.api_token.as_str())
            .unwrap_or("")
    }

    /// Org ID from the active context.
    pub fn org_id(&self) -> &str {
        self.active_context()
            .map(|c| c.org_id.as_str())
            .unwrap_or("")
    }

    /// License token from the active context.
    pub fn license_token(&self) -> &str {
        self.active_context()
            .map(|c| c.license_token.as_str())
            .unwrap_or("")
    }

    // ── Persistence ─────────────────────────────────────

    pub fn write_default() -> Result<PathBuf> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
        let path = Self::config_path();
        let cfg = Self::default();
        let content = toml::to_string_pretty(&cfg)?;
        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(path)
    }

    pub fn save(&self) -> Result<PathBuf> {
        let dir = Self::config_dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
        let path = Self::config_path();
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(path)
    }
}

// ── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_local_context() {
        let cfg = CliConfig::default();
        assert_eq!(cfg.current_context, "local");
        assert_eq!(cfg.contexts.len(), 1);
        assert_eq!(cfg.contexts[0].name, "local");
        assert_eq!(cfg.contexts[0].endpoint, "http://127.0.0.1:3001");
        assert_eq!(cfg.contexts[0].transport, "http");
    }

    #[test]
    fn test_add_context() {
        let mut cfg = CliConfig::default();
        let ctx = ClampdContext {
            name: "prod".into(),
            endpoint: "https://api.clampd.dev".into(),
            org_id: "abc-123".into(),
            api_token: "token_prod".into(),
            transport: "grpc".into(),
            license_token: String::new(),
        };
        cfg.add_context(ctx).unwrap();
        assert_eq!(cfg.contexts.len(), 2);
        assert_eq!(cfg.get_context("prod").unwrap().endpoint, "https://api.clampd.dev");
    }

    #[test]
    fn test_add_duplicate_context_fails() {
        let mut cfg = CliConfig::default();
        let ctx = ClampdContext {
            name: "local".into(),
            ..Default::default()
        };
        let err = cfg.add_context(ctx).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_use_context() {
        let mut cfg = CliConfig::default();
        cfg.add_context(ClampdContext {
            name: "staging".into(),
            endpoint: "http://staging:3001".into(),
            ..Default::default()
        }).unwrap();

        cfg.use_context("staging").unwrap();
        assert_eq!(cfg.current_context, "staging");
        assert_eq!(cfg.dashboard_url(), "http://staging:3001");
    }

    #[test]
    fn test_use_nonexistent_context_fails() {
        let mut cfg = CliConfig::default();
        let err = cfg.use_context("doesnt-exist").unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(err.to_string().contains("local")); // suggests available contexts
    }

    #[test]
    fn test_remove_context() {
        let mut cfg = CliConfig::default();
        cfg.add_context(ClampdContext {
            name: "staging".into(),
            ..Default::default()
        }).unwrap();
        assert_eq!(cfg.contexts.len(), 2);

        cfg.remove_context("staging").unwrap();
        assert_eq!(cfg.contexts.len(), 1);
        assert!(cfg.get_context("staging").is_none());
    }

    #[test]
    fn test_cannot_remove_active_context() {
        let mut cfg = CliConfig::default();
        let err = cfg.remove_context("local").unwrap_err();
        assert!(err.to_string().contains("Cannot remove the active context"));
    }

    #[test]
    fn test_remove_nonexistent_context_fails() {
        let mut cfg = CliConfig::default();
        let err = cfg.remove_context("nope").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_set_context_field() {
        let mut cfg = CliConfig::default();
        cfg.set_context_field("local", "endpoint", "http://new:3001").unwrap();
        cfg.set_context_field("local", "org_id", "my-org-id").unwrap();
        cfg.set_context_field("local", "api_token", "tok123").unwrap();
        cfg.set_context_field("local", "transport", "grpc").unwrap();

        let ctx = cfg.get_context("local").unwrap();
        assert_eq!(ctx.endpoint, "http://new:3001");
        assert_eq!(ctx.org_id, "my-org-id");
        assert_eq!(ctx.api_token, "tok123");
        assert_eq!(ctx.transport, "grpc");
    }

    #[test]
    fn test_set_context_invalid_transport() {
        let mut cfg = CliConfig::default();
        let err = cfg.set_context_field("local", "transport", "websocket").unwrap_err();
        assert!(err.to_string().contains("must be 'http' or 'grpc'"));
    }

    #[test]
    fn test_set_context_unknown_field() {
        let mut cfg = CliConfig::default();
        let err = cfg.set_context_field("local", "banana", "yes").unwrap_err();
        assert!(err.to_string().contains("Unknown field"));
    }

    #[test]
    fn test_context_names() {
        let mut cfg = CliConfig::default();
        cfg.add_context(ClampdContext { name: "prod".into(), ..Default::default() }).unwrap();
        cfg.add_context(ClampdContext { name: "staging".into(), ..Default::default() }).unwrap();
        let names = cfg.context_names();
        assert_eq!(names, vec!["local", "prod", "staging"]);
    }

    #[test]
    fn test_active_context_accessors() {
        let mut cfg = CliConfig::default();
        cfg.set_context_field("local", "org_id", "org-abc").unwrap();
        cfg.set_context_field("local", "api_token", "tok-xyz").unwrap();

        assert_eq!(cfg.org_id(), "org-abc");
        assert_eq!(cfg.api_token(), "tok-xyz");
        assert_eq!(cfg.dashboard_url(), "http://127.0.0.1:3001");
    }

    #[test]
    fn test_legacy_migration() {
        let toml_str = r#"
[core]
org_id = "legacy-org-123"
license_token = "jwt_legacy"
compose_file = "custom-compose.yml"

[connections]
dashboard_url = "http://legacy:3001"
api_token = "legacy_token"
database_url = "postgres://user:pass@db:5432/mydb"
nats_url = "nats://nats:4222"

[output]
format = "json"
"#;
        let cfg = CliConfig::from_toml(toml_str).unwrap();

        // Legacy fields migrated into "local" context
        assert_eq!(cfg.current_context, "local");
        let ctx = cfg.get_context("local").unwrap();
        assert_eq!(ctx.org_id, "legacy-org-123");
        assert_eq!(ctx.license_token, "jwt_legacy");
        assert_eq!(ctx.endpoint, "http://legacy:3001");
        assert_eq!(ctx.api_token, "legacy_token");
        assert_eq!(ctx.transport, "http");

        // Service URLs migrated
        assert_eq!(cfg.services.database_url, "postgres://user:pass@db:5432/mydb");
        assert_eq!(cfg.services.nats_url, "nats://nats:4222");
        assert_eq!(cfg.services.compose_file, "custom-compose.yml");

        // Output preserved
        assert_eq!(cfg.output.format, "json");

        // Legacy sections consumed (skip_serializing)
        assert!(cfg.core.is_none());
        assert!(cfg.connections.is_none());
    }

    #[test]
    fn test_new_format_roundtrip() {
        let toml_str = r#"
current_context = "prod"

[[contexts]]
name = "local"
endpoint = "http://127.0.0.1:3001"
org_id = "local-org"
api_token = ""
transport = "http"
license_token = ""

[[contexts]]
name = "prod"
endpoint = "https://api.clampd.dev"
org_id = "prod-org-uuid"
api_token = "ag_live_xxx"
transport = "grpc"
license_token = "eyJhbGc..."

[output]
format = "table"
no_color = false
"#;
        let cfg = CliConfig::from_toml(toml_str).unwrap();
        assert_eq!(cfg.current_context, "prod");
        assert_eq!(cfg.contexts.len(), 2);

        let prod = cfg.get_context("prod").unwrap();
        assert_eq!(prod.endpoint, "https://api.clampd.dev");
        assert_eq!(prod.org_id, "prod-org-uuid");
        assert_eq!(prod.transport, "grpc");

        // Active context points to prod
        assert_eq!(cfg.dashboard_url(), "https://api.clampd.dev");
        assert_eq!(cfg.org_id(), "prod-org-uuid");
    }

    #[test]
    fn test_serialization_excludes_legacy() {
        let mut cfg = CliConfig::default();
        cfg.set_context_field("local", "org_id", "test-org").unwrap();
        let serialized = toml::to_string_pretty(&cfg).unwrap();

        // Should have new format, not legacy [core]/[connections]
        assert!(serialized.contains("current_context"));
        assert!(serialized.contains("[[contexts]]"));
        assert!(!serialized.contains("[core]"));
        assert!(!serialized.contains("[connections]"));
    }

    #[test]
    fn test_switch_context_changes_accessors() {
        let mut cfg = CliConfig::default();
        cfg.add_context(ClampdContext {
            name: "cloud".into(),
            endpoint: "https://cloud.clampd.dev".into(),
            org_id: "cloud-org".into(),
            api_token: "cloud-token".into(),
            transport: "grpc".into(),
            license_token: String::new(),
        }).unwrap();

        assert_eq!(cfg.dashboard_url(), "http://127.0.0.1:3001");
        assert_eq!(cfg.org_id(), "");

        cfg.use_context("cloud").unwrap();
        assert_eq!(cfg.dashboard_url(), "https://cloud.clampd.dev");
        assert_eq!(cfg.org_id(), "cloud-org");
        assert_eq!(cfg.api_token(), "cloud-token");
    }

    #[test]
    fn test_hyphenated_field_names() {
        let mut cfg = CliConfig::default();
        // Should accept both snake_case and kebab-case
        cfg.set_context_field("local", "org-id", "hyphen-org").unwrap();
        cfg.set_context_field("local", "api-token", "hyphen-tok").unwrap();
        cfg.set_context_field("local", "license-token", "hyphen-lic").unwrap();

        let ctx = cfg.get_context("local").unwrap();
        assert_eq!(ctx.org_id, "hyphen-org");
        assert_eq!(ctx.api_token, "hyphen-tok");
        assert_eq!(ctx.license_token, "hyphen-lic");
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    #[test]
    fn test_from_toml_empty_string() {
        // Empty TOML should still produce a valid config (with defaults)
        let result = CliConfig::from_toml("");
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_toml_minimal_new_format() {
        let toml = r#"
current_context = "prod"

[[contexts]]
name = "prod"
endpoint = "https://prod.clampd.dev"
org_id = "org-prod"
api_token = "tok-prod"
transport = "http"
license_token = ""
"#;
        let cfg = CliConfig::from_toml(toml).unwrap();
        assert_eq!(cfg.current_context, "prod");
        assert_eq!(cfg.contexts.len(), 1);
        assert_eq!(cfg.contexts[0].name, "prod");
        assert_eq!(cfg.contexts[0].endpoint, "https://prod.clampd.dev");
    }

    #[test]
    fn test_get_context_nonexistent() {
        let cfg = CliConfig::default();
        assert!(cfg.get_context("nonexistent").is_none());
    }

    #[test]
    fn test_set_context_field_nonexistent_context() {
        let mut cfg = CliConfig::default();
        let result = cfg.set_context_field("nonexistent", "endpoint", "http://x");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_contexts() {
        let mut cfg = CliConfig::default();
        cfg.add_context(ClampdContext {
            name: "staging".into(),
            endpoint: "https://staging.clampd.dev".into(),
            org_id: "org-stg".into(),
            api_token: "tok-stg".into(),
            transport: "http".into(),
            license_token: String::new(),
        }).unwrap();
        cfg.add_context(ClampdContext {
            name: "prod".into(),
            endpoint: "https://prod.clampd.dev".into(),
            org_id: "org-prod".into(),
            api_token: "tok-prod".into(),
            transport: "http".into(),
            license_token: String::new(),
        }).unwrap();
        let names = cfg.context_names();
        assert_eq!(names.len(), 3); // local + staging + prod
        assert!(names.contains(&"local"));
        assert!(names.contains(&"staging"));
        assert!(names.contains(&"prod"));
    }

    #[test]
    fn test_use_context_updates_accessors() {
        let mut cfg = CliConfig::default();
        cfg.add_context(ClampdContext {
            name: "other".into(),
            endpoint: "https://other.test".into(),
            org_id: "org-other".into(),
            api_token: "tok-other".into(),
            transport: "http".into(),
            license_token: "lic-other".into(),
        }).unwrap();
        cfg.use_context("other").unwrap();
        assert_eq!(cfg.dashboard_url(), "https://other.test");
        assert_eq!(cfg.org_id(), "org-other");
        assert_eq!(cfg.api_token(), "tok-other");
        assert_eq!(cfg.license_token(), "lic-other");
    }

    #[test]
    fn test_set_context_field_endpoint() {
        let mut cfg = CliConfig::default();
        cfg.set_context_field("local", "endpoint", "https://new.endpoint").unwrap();
        assert_eq!(cfg.get_context("local").unwrap().endpoint, "https://new.endpoint");
    }

    #[test]
    fn test_set_context_field_transport_grpc() {
        let mut cfg = CliConfig::default();
        cfg.set_context_field("local", "transport", "grpc").unwrap();
        assert_eq!(cfg.get_context("local").unwrap().transport, "grpc");
    }
}
