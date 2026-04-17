//! ag-gateway - the ONLY external entry point for SDK/agent traffic.
//!
//! Architecture boundaries:
//! - External: SDKs, agents, MCP clients connect HERE via REST API
//! - Internal: gateway calls ag-registry, ag-intent, ag-policy, ag-token via gRPC
//! - Events: publishes shadow events to NATS for ag-shadow and ag-risk
//! - State: reads Redis for API keys, sessions, deny set, baselines
//!
//! NO other service should accept external traffic directly.

use std::sync::Arc;
use std::time::Instant;

/// Minimum recommended length for JWT_SECRET (used for JWT auth, not scope tokens).
const JWT_SECRET_MIN_LEN: usize = 32;
/// Maximum number of idle connections in the Redis connection pool.
fn redis_pool_max_size() -> u32 {
    std::env::var("REDIS_POOL_MAX_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}
/// Maximum idle HTTP connections per downstream host.
const HTTP_POOL_MAX_IDLE_PER_HOST: usize = 32;
/// Default timeout for downstream HTTP requests (seconds).
const HTTP_TIMEOUT_SECS: u64 = 30;

use ag_common::config::{GatewayConfig, parse_nats_url, grpc_connect_with_retry};

async fn connect_nats(url: &str) -> Result<async_nats::Client, async_nats::ConnectError> {
    let (addr, token) = parse_nats_url(url);
    if let Some(tok) = token {
        async_nats::ConnectOptions::with_token(tok)
            .connect(&addr)
            .await
    } else {
        async_nats::connect(&addr).await
    }
}
use ag_common::degradation::DegradationConfig;
use ag_common::interceptor::ClientAuthInterceptor;
use ag_license::{PlanGuard, FeatureFlags};
use anyhow::Result;
use axum::{extract::State, http::StatusCode, middleware as axum_middleware, routing::get, routing::post, Router};
use tower_http::cors::{CorsLayer, Any};
use tokio::net::TcpListener;
use tonic::service::interceptor::InterceptedService;
use tracing::{error, info, warn};

mod ap2;
mod baseline_cache;
mod circuit_breaker;
mod decision;
mod delegation;
mod deny;
mod extractor;
mod kill_listener;
mod license_gate;
pub mod metrics;
mod middleware;
mod model_escalation;
mod normalize;
pub mod otel;
mod proxy;
mod rate_limiter;
mod response_inspector;
mod scan;
mod scope_token;
mod session;
mod shadow;
#[allow(dead_code)]
mod wal;
#[allow(dead_code)]
mod wal_file;
mod x402;


use circuit_breaker::CircuitBreakerManager;
use deny::DenySet;

/// Shared application state accessible by all handlers.
pub struct AppState {
    pub config: Arc<GatewayConfig>,
    pub registry: ag_proto::agentguard::registry::registry_service_client::RegistryServiceClient<
        InterceptedService<tonic::transport::Channel, ClientAuthInterceptor>,
    >,
    pub intent: ag_proto::agentguard::intent::intent_service_client::IntentServiceClient<
        InterceptedService<tonic::transport::Channel, ClientAuthInterceptor>,
    >,
    pub policy: ag_proto::agentguard::policy::policy_service_client::PolicyServiceClient<
        InterceptedService<tonic::transport::Channel, ClientAuthInterceptor>,
    >,
    pub token: ag_proto::agentguard::token::token_service_client::TokenServiceClient<
        InterceptedService<tonic::transport::Channel, ClientAuthInterceptor>,
    >,
    pub redis_pool: bb8::Pool<bb8_redis::RedisConnectionManager>,
    pub nats: async_nats::Client,
    pub http_client: reqwest::Client,
    pub deny_set: Arc<DenySet>,
    /// Per-upstream circuit breaker manager (registry, intent, policy, token).
    pub circuit_breakers: Arc<CircuitBreakerManager>,
    /// Degradation config: what to do when upstream services are unavailable.
    pub degradation: DegradationConfig,
    /// Write-ahead log for shadow event durability on NATS failure.
    pub wal: Option<Arc<crate::wal_file::FileWriteAheadLog>>,
    /// Read-through cache for agent behavioral baselines from ag-risk.
    pub baseline_cache: Arc<baseline_cache::BaselineCache>,
    /// License plan guard for feature gating and limit checks.
    pub plan_guard: Arc<PlanGuard>,
    /// Ed25519 signing key for scope token minting (private - never exposed).
    pub scope_signing_key: ed25519_dalek::SigningKey,
    /// Ed25519 verifying key for scope token verification (public - exposed via JWKS).
    pub scope_verifying_key: ed25519_dalek::VerifyingKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    let startup_start = Instant::now();

    // Initialize OpenTelemetry distributed tracing (OTLP exporter + tracing-subscriber).
    // Falls back to plain tracing-subscriber if OTel init fails (e.g. no collector).
    if let Err(e) = otel::init_tracer("ag-gateway") {
        // OTel is optional - fall back to plain structured logging.
        eprintln!("OpenTelemetry init failed (non-fatal, falling back to plain logging): {e}");
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .json()
            .init();
    }

    // License check: validate CLAMPD_LICENSE_KEY before any other initialization.
    // Each service independently verifies the license using embedded crypto.
    // No network call - pure offline RSA/HMAC verification.
    ag_common::license_guard::enforce_or_exit("ag-gateway");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license - refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    let config = GatewayConfig::from_env();
    let config = Arc::new(config);

    // JWT_SECRET is mandatory. Without it, ANY JWT would be accepted - unacceptable
    // for a security product. No decode-only mode, no bypass flags.
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_default();
    if jwt_secret.is_empty() {
        error!("============================================================");
        error!("FATAL: JWT_SECRET is not set.");
        error!("Without JWT_SECRET, the gateway cannot verify JWT signatures.");
        error!("This is required in all environments (dev, staging, production).");
        error!("");
        error!("To fix: set JWT_SECRET to a strong random string (32+ chars).");
        error!("  Generate with: openssl rand -hex 32");
        error!("============================================================");
        std::process::exit(1);
    } else if jwt_secret.len() < JWT_SECRET_MIN_LEN {
        error!("============================================================");
        error!("FATAL: JWT_SECRET must be at least {} characters (got {}).", JWT_SECRET_MIN_LEN, jwt_secret.len());
        error!("A short HMAC key is cryptographically weak and brute-forceable.");
        error!("");
        error!("To fix: generate a strong random secret:");
        error!("  openssl rand -hex 32");
        error!("============================================================");
        std::process::exit(1);
    } else if jwt_secret.contains("change-me") {
        error!("============================================================");
        error!("FATAL: JWT_SECRET contains a known default value.");
        error!("Default secrets are published in source control and documentation.");
        error!("Using them in any environment is a critical security vulnerability.");
        error!("");
        error!("To fix: generate a strong random secret:");
        error!("  openssl rand -hex 32");
        error!("============================================================");
        std::process::exit(1);
    }

    // Connect Redis
    let redis_manager = bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
    let redis_pool = bb8::Pool::builder()
        .max_size(redis_pool_max_size())
        .build(redis_manager)
        .await?;
    info!("Connected to Redis");

    // Initialize deny set
    let deny_set = Arc::new(DenySet::new());

    // Connect gRPC clients with internal HMAC auth interceptor.
    let grpc_client_tls = ag_common::tls::client_tls_config();

    let mut registry_endpoint = tonic::transport::Channel::from_shared(config.registry_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        registry_endpoint = registry_endpoint.tls_config(tls.clone())?;
    }
    let registry_channel = grpc_connect_with_retry(registry_endpoint, "ag-registry").await?;
    let registry =
        ag_proto::agentguard::registry::registry_service_client::RegistryServiceClient::with_interceptor(
            registry_channel,
            ClientAuthInterceptor,
        );

    let mut intent_endpoint = tonic::transport::Channel::from_shared(config.intent_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        intent_endpoint = intent_endpoint.tls_config(tls.clone())?;
    }
    let intent_channel = grpc_connect_with_retry(intent_endpoint, "ag-intent").await?;
    let intent =
        ag_proto::agentguard::intent::intent_service_client::IntentServiceClient::with_interceptor(
            intent_channel,
            ClientAuthInterceptor,
        );

    let mut policy_endpoint = tonic::transport::Channel::from_shared(config.policy_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        policy_endpoint = policy_endpoint.tls_config(tls.clone())?;
    }
    let policy_channel = grpc_connect_with_retry(policy_endpoint, "ag-policy").await?;
    let policy =
        ag_proto::agentguard::policy::policy_service_client::PolicyServiceClient::with_interceptor(
            policy_channel,
            ClientAuthInterceptor,
        );

    let mut token_endpoint = tonic::transport::Channel::from_shared(config.token_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        token_endpoint = token_endpoint.tls_config(tls.clone())?;
    }
    let token_channel = grpc_connect_with_retry(token_endpoint, "ag-token").await?;
    let token =
        ag_proto::agentguard::token::token_service_client::TokenServiceClient::with_interceptor(
            token_channel,
            ClientAuthInterceptor,
        );
    info!("All gRPC clients connected");

    // Connect NATS
    let nats = connect_nats(&config.nats_url).await?;
    info!("Connected to NATS");

    // HTTP client for downstream forwarding
    let http_client = reqwest::Client::builder()
        .pool_max_idle_per_host(HTTP_POOL_MAX_IDLE_PER_HOST)
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()?;

    // Spawn NATS listener for kill/revive broadcasts
    kill_listener::spawn_kill_listener(nats.clone(), deny_set.clone(), redis_pool.clone()).await;
    info!("Kill listener started (NATS)");

    // Spawn periodic deny set sweep (every 60s)
    let sweep_deny = deny_set.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            sweep_deny.sweep_expired();
        }
    });

    // Replay active deny entries from Redis (agents killed while this pod was down)
    {
        let mut conn = redis_pool.get().await?;
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("ag:deny:*")
                .arg("COUNT")
                .arg(100u64)
                .query_async(&mut *conn)
                .await
                .unwrap_or((0, vec![]));
            for key in &keys {
                if let Some(agent_id) = key.strip_prefix("ag:deny:") {
                    deny_set.insert(agent_id.to_string());
                }
            }
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        info!("Replayed {} deny entries from Redis", deny_set.len());
    }

    // Initialize WAL for shadow event durability
    let wal_config = crate::wal_file::WalConfig::new(std::path::PathBuf::from("/tmp/ag-gateway-wal/shadow.wal"));
    let wal = match crate::wal_file::FileWriteAheadLog::new(wal_config) {
        Ok(w) => {
            info!("WAL initialized at /tmp/ag-gateway-wal");
            let wal = Arc::new(w);

            // Replay undelivered WAL entries from previous run (if any).
            // This recovers shadow events that were written to disk when NATS
            // was unavailable during the last gateway lifecycle.
            {
                let replay_wal = wal.clone();
                let replay_nats = nats.clone();
                tokio::spawn(async move {
                    match replay_wal.replay().await {
                        Ok(entries) if !entries.is_empty() => {
                            let count = entries.len();
                            let mut replayed = 0u32;
                            for payload in entries {
                                match replay_nats
                                    .publish("agentguard.events", payload.into_bytes().into())
                                    .await
                                {
                                    Ok(_) => replayed += 1,
                                    Err(e) => {
                                        warn!("WAL replay publish failed: {} - stopping replay", e);
                                        break;
                                    }
                                }
                            }
                            info!(total = count, replayed, "WAL replay completed on startup");
                        }
                        Ok(_) => {} // No entries to replay
                        Err(e) => warn!("WAL replay failed: {}", e),
                    }
                });
            }

            Some(wal)
        }
        Err(e) => {
            warn!("Failed to initialize WAL: {} - shadow events may be lost on NATS failure", e);
            None
        }
    };

    // Initialize circuit breakers for upstream gRPC services
    let circuit_breakers = Arc::new(CircuitBreakerManager::new());
    info!("Circuit breakers initialized for registry, intent, policy, token");

    // Initialize baseline cache (reads ag-risk baselines from Redis with 60s local TTL)
    let baseline_cache = Arc::new(baseline_cache::BaselineCache::new(redis_pool.clone()));

    // Generate or restore Ed25519 keypair for scope token signing.
    // Persists the seed in Redis so all gateway pods share the same key,
    // and the key survives restarts.
    let scope_signing_key = {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let mut conn = redis_pool.get().await?;
        let existing: Option<String> = redis::cmd("GET")
            .arg("ag:gateway:scope_key_seed")
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);

        match existing {
            Some(seed_hex) => {
                let seed_bytes = hex::decode(&seed_hex).expect("invalid scope key seed in Redis");
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                info!("Restored Ed25519 scope signing key from Redis");
                SigningKey::from_bytes(&seed)
            }
            None => {
                let key = SigningKey::generate(&mut OsRng);
                let seed_hex = hex::encode(key.to_bytes());
                let _: () = redis::cmd("SET")
                    .arg("ag:gateway:scope_key_seed")
                    .arg(&seed_hex)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or(());
                info!("Generated new Ed25519 scope signing key");
                key
            }
        }
    };
    let scope_verifying_key = scope_signing_key.verifying_key();

    let state = Arc::new(AppState {
        config: config.clone(),
        registry,
        intent,
        policy,
        token,
        redis_pool,
        nats,
        http_client,
        deny_set,
        circuit_breakers,
        degradation: config.degradation.clone(),
        wal,
        baseline_cache,
        plan_guard,
        scope_signing_key,
        scope_verifying_key,
    });

    // ── Connection warmup ──────────────────────────────────────────────
    // Establish real connections before accepting traffic so the first
    // request doesn't pay cold-start latency.
    info!("Starting connection warmup...");
    let warmup_start = Instant::now();

    // 1. Redis warmup - establish a pooled connection and verify reachability.
    match state.redis_pool.get().await {
        Ok(mut conn) => {
            let ping_result: Result<String, _> = redis::cmd("PING").query_async(&mut *conn).await;
            match ping_result {
                Ok(_) => info!("Redis connection warmed up"),
                Err(e) => warn!("Redis PING failed (non-fatal): {}", e),
            }
        }
        Err(e) => warn!("Redis warmup failed (non-fatal): {}", e),
    }

    // 2. gRPC channel warmup - send health checks to each upstream service
    //    to force tonic's lazy HTTP/2 connection establishment.
    {
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::pb::HealthCheckRequest;

        let warmup_services: &[(&str, &str)] = &[
            ("ag-registry", config.registry_url.as_str()),
            ("ag-intent", config.intent_url.as_str()),
            ("ag-policy", config.policy_url.as_str()),
            ("ag-token", config.token_url.as_str()),
        ];

        let warmup_tls = ag_common::tls::client_tls_config();
        for (name, url) in warmup_services {
            match tonic::transport::Channel::from_shared(url.to_string()) {
                Ok(endpoint) => {
                    let endpoint = if let Some(ref tls) = warmup_tls {
                        match endpoint.tls_config(tls.clone()) {
                            Ok(e) => e,
                            Err(e) => {
                                warn!(service = name, error = %e, "gRPC warmup TLS config failed (non-fatal)");
                                continue;
                            }
                        }
                    } else {
                        endpoint
                    };
                    match endpoint.connect().await {
                    Ok(channel) => {
                        let mut health = HealthClient::with_interceptor(channel, ClientAuthInterceptor);
                        match health
                            .check(HealthCheckRequest {
                                service: String::new(),
                            })
                            .await
                        {
                            Ok(resp) => {
                                let status = resp.into_inner().status;
                                info!(service = name, status = status, "gRPC health check OK");
                            }
                            Err(e) => {
                                warn!(
                                    service = name,
                                    error = %e,
                                    "gRPC health check failed (non-fatal) - channel connected but service may not be ready"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(service = name, error = %e, "gRPC warmup connect failed (non-fatal)");
                    }
                }
                },
                Err(e) => {
                    warn!(service = name, error = %e, "gRPC warmup endpoint failed (non-fatal)");
                }
            }
        }
    }

    // 3. NATS warmup - flush to verify the connection round-trips to the server.
    match state.nats.flush().await {
        Ok(_) => info!("NATS connection verified (flush OK)"),
        Err(e) => warn!("NATS flush failed (non-fatal): {}", e),
    }

    info!(
        elapsed_ms = warmup_start.elapsed().as_millis() as u64,
        "Connection warmup complete"
    );

    // Build router
    let app = Router::new()
        .route("/v1/proxy", post(proxy::handle_proxy))
        .route("/v1/verify", post(proxy::handle_verify))
        .route("/v1/inspect", post(proxy::handle_inspect))
        .route("/v1/scan-input", post(scan::handle_scan_input))
        .route("/v1/scan-output", post(scan::handle_scan_output))
        .layer(axum_middleware::from_fn(middleware::size_limit))
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any))
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        // JWKS endpoint - Ed25519 public key for scope token verification
        .route("/.well-known/jwks.json", get(handle_jwks))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr).await?;
    info!("ag-gateway listening on {}", addr);

    // ── Compliance: TLS enforcement check ────────────────────────────
    // HIPAA §164.312(e) and PCI-DSS Requirement 4 require encryption in transit.
    let is_production = std::env::var("CLAMPD_ENV").unwrap_or_default() == "production";
    let tls_configured = std::env::var("CLAMPD_TLS_CERT").is_ok()
        && std::env::var("CLAMPD_TLS_KEY").is_ok();
    if is_production && !tls_configured {
        error!(
            "COMPLIANCE WARNING: TLS not configured in production mode. \
             HIPAA §164.312(e) and PCI-DSS Requirement 4 require encryption in transit. \
             Set CLAMPD_TLS_CERT and CLAMPD_TLS_KEY environment variables."
        );
    } else if !tls_configured {
        warn!(
            "TLS not configured - acceptable for development. \
             Set CLAMPD_TLS_CERT and CLAMPD_TLS_KEY for production compliance."
        );
    }

    info!(
        startup_ms = startup_start.elapsed().as_millis() as u64,
        "ag-gateway started, 9-stage pipeline ready (total startup: {}ms)",
        startup_start.elapsed().as_millis()
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Flush any pending OpenTelemetry spans before exit.
    otel::shutdown_tracer();

    info!("ag-gateway shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "Failed to install Ctrl+C handler, shutdown may not work");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => { sig.recv().await; },
            Err(e) => {
                error!(error = %e, "Failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received Ctrl+C, initiating graceful shutdown"); },
        _ = terminate => { info!("Received SIGTERM, initiating graceful shutdown"); },
    }
}

async fn health(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, &'static str) {
    match state.redis_pool.get().await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "redis_unavailable"),
    }
}

async fn metrics_handler() -> String {
    metrics::render_prometheus()
}

/// JWKS endpoint - exposes the Ed25519 public key for scope token verification.
/// Tool-side SDKs fetch this to verify scope tokens without needing a shared secret.
async fn handle_jwks(
    State(state): State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let pub_key_bytes = state.scope_verifying_key.to_bytes();
    let x = URL_SAFE_NO_PAD.encode(pub_key_bytes);

    axum::Json(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "scope-v1",
            "x": x,
        }]
    }))
}
