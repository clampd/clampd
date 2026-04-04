use crate::degradation::DegradationConfig;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_or_u16(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_or_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_or_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(default)
}

fn env_required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        // Panic at startup so misconfigured deployments fail fast rather than
        // silently polling with an empty token.
        panic!("required environment variable {} is not set", key)
    })
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub port: u16,
    pub metrics_port: u16,
    pub redis_url: String,
    pub nats_url: String,
    pub registry_url: String,
    pub intent_url: String,
    pub policy_url: String,
    pub token_url: String,
    pub jwt_secret: String,
    /// Risk score at or above which requests are blocked. Default: 0.70.
    pub risk_threshold: f64,
    pub degradation: DegradationConfig,
    pub model_escalation: ModelEscalationConfig,
    pub llm_judge: LlmJudgeConfig,
    /// Max tool calls per session before requests are rejected (0 = unlimited). Default: 50.
    pub max_calls_per_session: u64,
    /// Max new sessions per hour per agent. Default 50.
    pub max_sessions_per_hour: u32,
}

/// Configuration for hybrid model escalation.
///
/// When the rules engine returns a risk score in the "gray zone" (between
/// `low_threshold` and `high_threshold`), the gateway escalates to an ML model
/// for a second opinion. Scores below `low_threshold` are allowed instantly;
/// scores above `high_threshold` are blocked instantly. This gives sub-1ms
/// latency for ~80% of requests while improving accuracy for ambiguous cases.
#[derive(Debug, Clone)]
pub struct ModelEscalationConfig {
    /// Enable model escalation. When false, rules engine score is final.
    pub enabled: bool,
    /// Scores below this are ALLOW (rules confident). Default: 0.2.
    pub low_threshold: f64,
    /// Scores above this are BLOCK (rules confident). Default: 0.75.
    pub high_threshold: f64,
    /// Model backend: "onnx" for local ONNX Runtime, "http" for remote endpoint.
    pub backend: String,
    /// Path to ONNX model file (when backend="onnx").
    pub onnx_model_path: String,
    /// URL of remote classification endpoint (when backend="http").
    pub model_url: String,
    /// Timeout for model inference in milliseconds. Default: 200ms.
    pub timeout_ms: u64,
    /// If model call fails, use the rules engine score as-is (fail-open).
    pub fail_open: bool,
    /// Also escalate when NO rules matched (score=0.0) to catch novel attacks.
    /// When true, every unmatched request gets a model check. When false, only
    /// gray-zone scores (matched but ambiguous) trigger escalation. Default: false.
    pub check_unmatched: bool,
}

impl Default for ModelEscalationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            low_threshold: 0.2,
            high_threshold: 0.75,
            backend: "http".to_string(),
            onnx_model_path: String::new(),
            model_url: String::new(),
            timeout_ms: 200,
            fail_open: true,
            check_unmatched: false,
        }
    }
}

/// Configuration for LLM-as-judge secondary review.
///
/// When enabled, the gateway can escalate ambiguous or high-risk requests to an
/// LLM for a second opinion. Disabled by default — the rules engine and intent
/// classification pipeline handle all decisions without this.
#[derive(Debug, Clone)]
pub struct LlmJudgeConfig {
    /// Enable LLM judge. When false, no LLM calls are made.
    pub enabled: bool,
    /// LLM provider: "anthropic", "openai", etc.
    pub provider: String,
    /// Model identifier (e.g. "claude-haiku-4-5").
    pub model: String,
    /// API key for the LLM provider.
    pub api_key: String,
    /// Custom base URL for the LLM API (empty = provider default).
    pub base_url: String,
    /// Timeout for LLM judge calls in milliseconds.
    pub timeout_ms: u64,
    /// If LLM judge call fails, use rules engine score as-is (fail-open).
    /// When false (fail-closed), a failed LLM call blocks the request.
    pub fail_open: bool,
    /// Max LLM judge calls per minute. 0 = unlimited.
    /// When limit is hit, falls back to rules score (fail-open behavior).
    pub max_calls_per_minute: u32,
    /// Max consecutive failures before auto-disabling for cooldown_secs.
    pub max_consecutive_failures: u32,
    /// Cooldown period in seconds after max_consecutive_failures reached.
    pub cooldown_secs: u64,
}

impl Default for LlmJudgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "anthropic".to_string(),
            model: "claude-haiku-4-5".to_string(),
            api_key: String::new(),
            base_url: String::new(),
            timeout_ms: 2000,
            fail_open: true,
            max_calls_per_minute: 100,
            max_consecutive_failures: 5,
            cooldown_secs: 60,
        }
    }
}

impl GatewayConfig {
    pub fn from_env() -> Self {
        // -- REDIS HIGH AVAILABILITY ---------------------------------------------------
        //
        // Current: Single Redis instance (REDIS_URL=redis://:password@host:6379)
        //   Pro: Simple, fast
        //   Con: SPOF for all 9 services
        //
        // Planned (Tier 3): Redis Sentinel or Cluster
        //   Option A: Sentinel -- automatic failover, same client API
        //     REDIS_SENTINEL_URLS=redis-sentinel://host1:26379,host2:26379,host3:26379
        //     REDIS_SENTINEL_MASTER=mymaster
        //   Option B: Cluster -- sharded, higher throughput
        //     REDIS_CLUSTER_URLS=redis://node1:7000,redis://node2:7001,...
        //
        // Migration path:
        //   1. Switch bb8-redis to support sentinel/cluster connection managers
        //   2. Update docker-compose with 3-node sentinel setup
        //   3. Test failover under load (kill master, verify auto-promotion)
        //   4. Key namespace audit (ensure no cross-slot operations in cluster mode)
        //
        // Trigger: Implement when first customer reports Redis-related outage.
        // --------------------------------------------------------------------------
        Self {
            port: env_or_u16("AG_GATEWAY_PORT", 8080),
            metrics_port: env_or_u16("AG_GATEWAY_METRICS_PORT", 9090),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
            registry_url: env_or("REGISTRY_URL", "http://127.0.0.1:50051"),
            intent_url: env_or("INTENT_URL", "http://127.0.0.1:50052"),
            policy_url: env_or("POLICY_URL", "http://127.0.0.1:50053"),
            token_url: env_or("TOKEN_URL", "http://127.0.0.1:50054"),
            jwt_secret: env_or("JWT_SECRET", ""),
            risk_threshold: env_or("RISK_THRESHOLD", "0.70").parse().unwrap_or(0.70),
            degradation: DegradationConfig::default(),
            model_escalation: ModelEscalationConfig {
                enabled: env_or("MODEL_ESCALATION_ENABLED", "false") == "true",
                low_threshold: env_or("MODEL_ESCALATION_LOW", "0.2").parse().unwrap_or(0.2),
                high_threshold: env_or("MODEL_ESCALATION_HIGH", "0.75").parse().unwrap_or(0.75),
                backend: env_or("MODEL_ESCALATION_BACKEND", "http"),
                onnx_model_path: env_or("MODEL_ONNX_PATH", ""),
                model_url: env_or("MODEL_URL", ""),
                timeout_ms: env_or("MODEL_TIMEOUT_MS", "200").parse().unwrap_or(200),
                fail_open: env_or("MODEL_FAIL_OPEN", "true") == "true",
                check_unmatched: env_or("MODEL_CHECK_UNMATCHED", "false") == "true",
            },
            llm_judge: LlmJudgeConfig {
                enabled: env_or_bool("CLAMPD_LLM_JUDGE_ENABLED", false),
                provider: env_or("CLAMPD_LLM_JUDGE_PROVIDER", "anthropic"),
                model: env_or("CLAMPD_LLM_JUDGE_MODEL", "claude-haiku-4-5"),
                api_key: env_or("CLAMPD_LLM_JUDGE_API_KEY", ""),
                base_url: env_or("CLAMPD_LLM_JUDGE_BASE_URL", ""),
                timeout_ms: env_or_u64("CLAMPD_LLM_JUDGE_TIMEOUT_MS", 2000),
                fail_open: env_or_bool("CLAMPD_LLM_JUDGE_FAIL_OPEN", true),
                max_calls_per_minute: env_or("CLAMPD_LLM_JUDGE_MAX_RPM", "100").parse().unwrap_or(100),
                max_consecutive_failures: env_or("CLAMPD_LLM_JUDGE_MAX_FAILURES", "5").parse().unwrap_or(5),
                cooldown_secs: env_or_u64("CLAMPD_LLM_JUDGE_COOLDOWN_SECS", 60),
            },
            max_calls_per_session: env_or_u64("CLAMPD_MAX_CALLS_PER_SESSION", 50),
            max_sessions_per_hour: env_or("CLAMPD_MAX_SESSIONS_PER_HOUR", "50").parse().unwrap_or(50),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub nats_url: String,
}

impl RegistryConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_REGISTRY_PORT", 50051),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd",
            ),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntentConfig {
    pub port: u16,
    pub redis_url: String,
    pub nats_url: String,
}

impl IntentConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_INTENT_PORT", 50051),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub port: u16,
    pub opa_url: String,
    pub redis_url: String,
    pub nats_url: String,
}

impl PolicyConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_POLICY_PORT", 50051),
            opa_url: env_or("OPA_URL", "http://127.0.0.1:8181"),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub port: u16,
    pub redis_url: String,
    pub database_url: String,
    pub nats_url: String,
    pub micro_token_ttl_secs: u32,
    pub nonce_ttl_secs: u64,
    /// Max requests per agent per rate-limit window.
    pub rate_limit_max: u32,
    /// Rate limit window in seconds.
    pub rate_limit_window_secs: u64,
    /// Circuit breaker failure threshold before tripping open.
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker reset timeout in seconds.
    pub circuit_breaker_reset_secs: u64,
    /// IdP provider: "none", "keycloak", "okta", "azure_ad" (default: "none").
    pub idp_provider: String,
    /// IdP config source: "env" or "database" (default: "env").
    pub idp_config_source: String,
    /// Keycloak URL (when idp_provider=keycloak && idp_config_source=env).
    pub keycloak_url: Option<String>,
    /// Keycloak realm (when idp_provider=keycloak && idp_config_source=env).
    pub keycloak_realm: Option<String>,
    /// Keycloak client ID (when idp_provider=keycloak && idp_config_source=env).
    pub keycloak_client_id: Option<String>,
    /// Keycloak client secret (when idp_provider=keycloak && idp_config_source=env).
    pub keycloak_client_secret: Option<String>,
}

impl TokenConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_TOKEN_PORT", 50051),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd",
            ),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
            micro_token_ttl_secs: 30,
            nonce_ttl_secs: 90,
            rate_limit_max: 120,
            rate_limit_window_secs: 60,
            circuit_breaker_threshold: 3,
            circuit_breaker_reset_secs: 60,
            idp_provider: env_or("IDP_PROVIDER", "none"),
            idp_config_source: env_or("IDP_CONFIG_SOURCE", "env"),
            keycloak_url: std::env::var("KEYCLOAK_URL").ok(),
            keycloak_realm: std::env::var("KEYCLOAK_REALM").ok(),
            keycloak_client_id: std::env::var("KEYCLOAK_CLIENT_ID").ok(),
            keycloak_client_secret: std::env::var("KEYCLOAK_CLIENT_SECRET").ok(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShadowConfig {
    pub nats_url: String,
    pub clickhouse_url: String,
    pub clickhouse_user: Option<String>,
    pub clickhouse_password: Option<String>,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
    /// Enable NER-based PII detection (default: true).
    pub pii_ner_enabled: bool,
    /// Enable reversible PII tokenization via Redis vault (default: false).
    pub pii_tokenization_enabled: bool,
    /// AES-256-GCM encryption key for PII vault (64 hex chars). Required when tokenization enabled.
    pub pii_encryption_key: Option<String>,
    /// TTL for tokenized PII in Redis vault, in days (default: 30).
    pub pii_token_ttl_days: u64,
    /// Redis URL for PII tokenization vault.
    pub redis_url: String,
}

impl ShadowConfig {
    pub fn from_env() -> Self {
        Self {
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
            clickhouse_url: env_or("CLICKHOUSE_URL", "http://127.0.0.1:8123"),
            clickhouse_user: std::env::var("CLICKHOUSE_USER").ok(),
            clickhouse_password: std::env::var("CLICKHOUSE_PASSWORD").ok(),
            batch_size: 100,
            flush_interval_secs: 5,
            pii_ner_enabled: env_or("PII_NER_ENABLED", "true") == "true",
            pii_tokenization_enabled: env_or("PII_TOKENIZATION_ENABLED", "false") == "true",
            pii_encryption_key: std::env::var("PII_ENCRYPTION_KEY").ok(),
            pii_token_ttl_days: env_or_u64("PII_TOKEN_TTL_DAYS", 30),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KillConfig {
    pub port: u16,
    pub redis_url: String,
    pub nats_url: String,
    pub database_url: String,
    /// gRPC URL for ag-token (token revocation).
    pub token_url: String,
    /// gRPC URL for ag-registry (state transitions).
    pub registry_url: String,
    /// TTL for deny list entries in Redis (seconds).
    pub deny_ttl_secs: u64,
    /// Extended TTL if Layer 6 (registry state change) fails.
    pub deny_extended_ttl_secs: u64,
    /// Max retries for Layer 6 (registry state change).
    pub registry_retries: u32,
}

impl KillConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_KILL_PORT", 50055),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd",
            ),
            token_url: env_or("TOKEN_URL", "http://127.0.0.1:50054"),
            registry_url: env_or("REGISTRY_URL", "http://127.0.0.1:50051"),
            deny_ttl_secs: env_or_u64("AG_KILL_DENY_TTL_SECS", 86400), // 24h default — agent stays blocked until explicitly revived
            deny_extended_ttl_secs: env_or_u64("AG_KILL_DENY_EXTENDED_TTL_SECS", 604800), // 7 days extended TTL if registry fails
            registry_retries: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskConfig {
    pub port: u16,
    pub redis_url: String,
    pub nats_url: String,
    /// gRPC URL for ag-registry (risk score updates, baseline loading).
    pub registry_url: String,
    /// gRPC URL for ag-kill (auto-suspend at critical threshold).
    pub kill_url: String,
    /// WebSocket feed port for dashboard.
    pub ws_port: u16,
    /// EMA smoothing factor (alpha). Default: 0.3.
    pub ema_alpha: f64,
    /// Risk score threshold for auto-suspend.
    pub auto_suspend_threshold: f64,
    /// Risk decay interval in seconds.
    pub decay_interval_secs: u64,
    /// Persist in-memory scores to Redis every N seconds.
    pub persist_interval_secs: u64,
    /// Maximum WebSocket clients per pod.
    pub max_ws_clients: usize,
}

impl RiskConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_RISK_PORT", 50056),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
            registry_url: env_or("REGISTRY_URL", "http://127.0.0.1:50051"),
            kill_url: env_or("KILL_URL", "http://127.0.0.1:50055"),
            ws_port: env_or_u16("AG_RISK_WS_PORT", 8081),
            ema_alpha: 0.3,
            auto_suspend_threshold: 0.9,
            decay_interval_secs: 300,
            persist_interval_secs: 10,
            max_ws_clients: 100,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub port: u16,
    pub redis_url: String,
    pub nats_url: String,
    pub database_url: String,
    /// gRPC URL for ag-registry (baseline storage).
    pub registry_url: String,
    /// ClickHouse URL for baseline computation queries.
    pub clickhouse_url: String,
    pub clickhouse_user: Option<String>,
    pub clickhouse_password: Option<String>,
    /// Leader election TTL in seconds.
    pub leader_ttl_secs: u64,
    /// Leader renewal interval in seconds.
    pub leader_renew_secs: u64,
    /// License heartbeat interval in seconds.
    pub license_heartbeat_secs: u64,
    /// Policy bundle sync interval in seconds.
    pub policy_sync_secs: u64,
    /// Rules sync interval in seconds.
    pub rules_sync_secs: u64,
    /// Base URL of the Clampd SaaS API (env: CLAMPD_SAAS_URL).
    pub saas_url: String,
    /// License token used to authenticate with the SaaS API (env: CLAMPD_LICENSE_TOKEN).
    pub license_token: String,
    /// How often to poll the SaaS API for commands, in seconds (env: CLAMPD_POLL_INTERVAL).
    pub poll_interval_secs: u64,
    /// Enable the WebSocket command client (env: CLAMPD_WS_ENABLED, default: true).
    /// When enabled, ag-control opens an outbound WS connection to the Dashboard
    /// API for real-time command delivery. The HTTP poller backs off while the
    /// WS connection is active.
    pub ws_enabled: bool,
    /// Maximum backoff delay between WS reconnect attempts, in seconds
    /// (env: CLAMPD_WS_MAX_BACKOFF, default: 60).
    pub ws_max_backoff_secs: u64,
    /// OPA sidecar URL for delegation data sync (env: OPA_URL, default: http://127.0.0.1:8181).
    /// ag-control pushes delegation data documents to OPA so the delegation
    /// Rego policy can evaluate workflow boundaries and approved edges.
    pub opa_url: String,
    /// Delegation OPA data sync interval in seconds (env: CLAMPD_DELEGATION_OPA_SYNC_SECS, default: 30).
    pub delegation_opa_sync_secs: u64,
}

impl ControlConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or_u16("AG_CONTROL_PORT", 50057),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            nats_url: env_or("NATS_URL", "nats://127.0.0.1:4222"),
            database_url: env_or(
                "DATABASE_URL",
                "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd",
            ),
            registry_url: env_or("REGISTRY_URL", "http://127.0.0.1:50051"),
            clickhouse_url: env_or("CLICKHOUSE_URL", "http://127.0.0.1:8123"),
            clickhouse_user: std::env::var("CLICKHOUSE_USER").ok(),
            clickhouse_password: std::env::var("CLICKHOUSE_PASSWORD").ok(),
            leader_ttl_secs: 30,
            leader_renew_secs: 10,
            license_heartbeat_secs: 3600,
            policy_sync_secs: 30,
            rules_sync_secs: 10,
            saas_url: env_or("CLAMPD_SAAS_URL", "https://api.clampd.dev"),
            license_token: std::env::var("CLAMPD_LICENSE_TOKEN").unwrap_or_default(),
            poll_interval_secs: env_or_u64("CLAMPD_POLL_INTERVAL", 5),
            ws_enabled: env_or_bool("CLAMPD_WS_ENABLED", true),
            ws_max_backoff_secs: env_or_u64("CLAMPD_WS_MAX_BACKOFF", 60),
            opa_url: env_or("OPA_URL", "http://127.0.0.1:8181"),
            delegation_opa_sync_secs: env_or_u64("CLAMPD_DELEGATION_OPA_SYNC_SECS", 30),
        }
    }
}

/// Parse a NATS URL that may contain an auth token in userinfo position.
///
/// `async_nats::connect()` does NOT extract tokens from `nats://token@host:port`.
/// This helper splits the URL into `(server_addr, Option<token>)` so callers
/// can use `ConnectOptions::with_token(token).connect(addr)`.
///
/// Supported formats:
///   - `nats://host:port`           → `("host:port", None)`
///   - `nats://token@host:port`     → `("host:port", Some("token"))`
///   - `host:port`                  → `("host:port", None)`
/// Connect a tonic gRPC endpoint with retries (up to 30s, exponential backoff).
/// Logs each retry attempt. Fails hard if all retries are exhausted.
pub async fn grpc_connect_with_retry(
    endpoint: tonic::transport::Endpoint,
    label: &str,
) -> Result<tonic::transport::Channel, tonic::transport::Error> {
    let max_retries = 10u32;
    let mut delay = std::time::Duration::from_secs(1);
    for attempt in 1..=max_retries {
        match endpoint.connect().await {
            Ok(channel) => {
                tracing::info!(%label, attempt, "gRPC connected");
                return Ok(channel);
            }
            Err(e) => {
                if attempt == max_retries {
                    tracing::error!(%label, attempt, error = %e, "gRPC connect failed — giving up");
                    return Err(e);
                }
                tracing::warn!(%label, attempt, error = %e, retry_in_secs = delay.as_secs(), "gRPC connect failed — retrying");
                std::thread::sleep(delay);
                delay = std::cmp::min(delay * 2, std::time::Duration::from_secs(10));
            }
        }
    }
    unreachable!()
}

pub fn parse_nats_url(url: &str) -> (String, Option<String>) {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("nats://")
        .or_else(|| url.strip_prefix("tls://"))
        .unwrap_or(url);

    // Check for userinfo (token@host:port)
    if let Some(at_pos) = without_scheme.find('@') {
        let token = &without_scheme[..at_pos];
        let server = &without_scheme[at_pos + 1..];
        if token.is_empty() {
            (server.to_string(), None)
        } else {
            (server.to_string(), Some(token.to_string()))
        }
    } else {
        (without_scheme.to_string(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_config_defaults() {
        let cfg = GatewayConfig::from_env();
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.metrics_port, 9090);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(cfg.registry_url, "http://127.0.0.1:50051");
        assert_eq!(cfg.intent_url, "http://127.0.0.1:50052");
        assert_eq!(cfg.policy_url, "http://127.0.0.1:50053");
        assert_eq!(cfg.token_url, "http://127.0.0.1:50054");
        assert_eq!(cfg.jwt_secret, "");
    }

    #[test]
    fn test_registry_config_defaults() {
        let cfg = RegistryConfig::from_env();
        assert_eq!(cfg.port, 50051);
        assert_eq!(
            cfg.database_url,
            "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd"
        );
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
    }

    #[test]
    fn test_intent_config_defaults() {
        let cfg = IntentConfig::from_env();
        assert_eq!(cfg.port, 50051);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
    }

    #[test]
    fn test_policy_config_defaults() {
        let cfg = PolicyConfig::from_env();
        assert_eq!(cfg.port, 50051);
        assert_eq!(cfg.opa_url, "http://127.0.0.1:8181");
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
    }

    #[test]
    fn test_token_config_defaults() {
        let cfg = TokenConfig::from_env();
        assert_eq!(cfg.port, 50051);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(
            cfg.database_url,
            "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd"
        );
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(cfg.micro_token_ttl_secs, 30);
        assert_eq!(cfg.nonce_ttl_secs, 90);
        assert_eq!(cfg.rate_limit_max, 120);
        assert_eq!(cfg.rate_limit_window_secs, 60);
        assert_eq!(cfg.circuit_breaker_threshold, 3);
        assert_eq!(cfg.circuit_breaker_reset_secs, 60);
        assert_eq!(cfg.idp_provider, "none");
        assert_eq!(cfg.idp_config_source, "env");
        assert!(cfg.keycloak_url.is_none());
        assert!(cfg.keycloak_realm.is_none());
        assert!(cfg.keycloak_client_id.is_none());
        assert!(cfg.keycloak_client_secret.is_none());
    }

    #[test]
    fn test_shadow_config_defaults() {
        let cfg = ShadowConfig::from_env();
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(cfg.clickhouse_url, "http://127.0.0.1:8123");
        assert_eq!(cfg.batch_size, 100);
        assert_eq!(cfg.flush_interval_secs, 5);
        assert!(cfg.pii_ner_enabled);
        assert!(!cfg.pii_tokenization_enabled);
        assert!(cfg.pii_encryption_key.is_none());
        assert_eq!(cfg.pii_token_ttl_days, 30);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
    }

    #[test]
    fn test_kill_config_defaults() {
        let cfg = KillConfig::from_env();
        assert_eq!(cfg.port, 50055);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(
            cfg.database_url,
            "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd"
        );
        assert_eq!(cfg.token_url, "http://127.0.0.1:50054");
        assert_eq!(cfg.registry_url, "http://127.0.0.1:50051");
        assert_eq!(cfg.deny_ttl_secs, 86400);
        assert_eq!(cfg.deny_extended_ttl_secs, 604800);
        assert_eq!(cfg.registry_retries, 3);
    }

    #[test]
    fn test_risk_config_defaults() {
        let cfg = RiskConfig::from_env();
        assert_eq!(cfg.port, 50056);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(cfg.registry_url, "http://127.0.0.1:50051");
        assert_eq!(cfg.kill_url, "http://127.0.0.1:50055");
        assert_eq!(cfg.ws_port, 8081);
        assert!((cfg.ema_alpha - 0.3).abs() < f64::EPSILON);
        assert!((cfg.auto_suspend_threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(cfg.decay_interval_secs, 300);
        assert_eq!(cfg.persist_interval_secs, 10);
        assert_eq!(cfg.max_ws_clients, 100);
    }

    #[test]
    fn test_control_config_defaults() {
        // CLAMPD_LICENSE_TOKEN is required — set it for the test.
        std::env::set_var("CLAMPD_LICENSE_TOKEN", "test-token");
        let cfg = ControlConfig::from_env();
        std::env::remove_var("CLAMPD_LICENSE_TOKEN");

        assert_eq!(cfg.port, 50057);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6379");
        assert_eq!(cfg.nats_url, "nats://127.0.0.1:4222");
        assert_eq!(
            cfg.database_url,
            "postgres://clampd:clampd_dev@127.0.0.1:5432/clampd"
        );
        assert_eq!(cfg.registry_url, "http://127.0.0.1:50051");
        assert_eq!(cfg.clickhouse_url, "http://127.0.0.1:8123");
        assert_eq!(cfg.leader_ttl_secs, 30);
        assert_eq!(cfg.leader_renew_secs, 10);
        assert_eq!(cfg.license_heartbeat_secs, 3600);
        assert_eq!(cfg.policy_sync_secs, 30);
        assert_eq!(cfg.rules_sync_secs, 10);
        assert_eq!(cfg.saas_url, "https://api.clampd.dev");
        assert_eq!(cfg.license_token, "test-token");
        assert_eq!(cfg.poll_interval_secs, 5);
        assert!(cfg.ws_enabled);
        assert_eq!(cfg.ws_max_backoff_secs, 60);
        assert_eq!(cfg.opa_url, "http://127.0.0.1:8181");
        assert_eq!(cfg.delegation_opa_sync_secs, 30);
    }

    #[test]
    fn test_gateway_llm_judge_defaults() {
        let cfg = GatewayConfig::from_env();
        assert!(!cfg.llm_judge.enabled);
        assert_eq!(cfg.llm_judge.provider, "anthropic");
        assert_eq!(cfg.llm_judge.model, "claude-haiku-4-5");
        assert_eq!(cfg.llm_judge.api_key, "");
        assert_eq!(cfg.llm_judge.base_url, "");
        assert_eq!(cfg.llm_judge.timeout_ms, 2000);
        assert!(cfg.llm_judge.fail_open);
    }

    #[test]
    fn test_env_or_returns_env_value_when_set() {
        // Verify env_or helper picks up env vars when set.
        std::env::set_var("_AG_TEST_CONFIG_VAR", "custom-value");
        let val = env_or("_AG_TEST_CONFIG_VAR", "default-value");
        assert_eq!(val, "custom-value");
        std::env::remove_var("_AG_TEST_CONFIG_VAR");
    }

    #[test]
    fn test_env_or_u16_returns_default_on_invalid() {
        // Non-numeric env var should fall back to default.
        std::env::set_var("_AG_TEST_U16_INVALID", "not-a-number");
        let val = env_or_u16("_AG_TEST_U16_INVALID", 9999);
        assert_eq!(val, 9999);
        std::env::remove_var("_AG_TEST_U16_INVALID");
    }

    #[test]
    fn test_env_or_u16_parses_valid_value() {
        std::env::set_var("_AG_TEST_U16_VALID", "4242");
        let val = env_or_u16("_AG_TEST_U16_VALID", 1111);
        assert_eq!(val, 4242);
        std::env::remove_var("_AG_TEST_U16_VALID");
    }

    #[test]
    fn test_parse_nats_url_with_token() {
        let (addr, token) = parse_nats_url("nats://my_secret_token@nats:4222");
        assert_eq!(addr, "nats:4222");
        assert_eq!(token, Some("my_secret_token".to_string()));
    }

    #[test]
    fn test_parse_nats_url_without_token() {
        let (addr, token) = parse_nats_url("nats://127.0.0.1:4222");
        assert_eq!(addr, "127.0.0.1:4222");
        assert_eq!(token, None);
    }

    #[test]
    fn test_parse_nats_url_bare_host() {
        let (addr, token) = parse_nats_url("localhost:4222");
        assert_eq!(addr, "localhost:4222");
        assert_eq!(token, None);
    }

    #[test]
    fn test_parse_nats_url_empty_token() {
        let (addr, token) = parse_nats_url("nats://@nats:4222");
        assert_eq!(addr, "nats:4222");
        assert_eq!(token, None);
    }
}
