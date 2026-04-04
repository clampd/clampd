use std::sync::Arc;

use ag_common::config::{PolicyConfig, parse_nats_url};

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
use ag_common::interceptor::server_auth_interceptor;
use ag_license::PlanGuard;
use anyhow::Result;
use bb8_redis::RedisConnectionManager;
use tonic::transport::Server;
use tracing::{info, warn};

mod boundary;
mod cache;
mod cedar;
mod decision;
mod delegation_workflow;
mod engine;
mod scope_exemption;
mod service;
mod thresholds;

use cache::DecisionCache;
use cedar::{CedarEvaluator, CedarPolicyEntry};
use service::PolicyServiceImpl;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // License check: every service validates independently.
    ag_common::license_guard::enforce_or_exit("ag-policy");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license — refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    let config = PolicyConfig::from_env();

    // Connect Redis (for delegation checks + decision cache)
    let redis_manager = RedisConnectionManager::new(config.redis_url.as_str())?;
    let redis_pool = bb8::Pool::builder()
        .max_size(
            std::env::var("AG_POLICY_REDIS_POOL_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(32u32),
        )
        .build(redis_manager)
        .await?;
    info!("Redis pool connected (pool sized via AG_POLICY_REDIS_POOL_SIZE)");

    // Connect NATS (for config change notifications)
    let _nats_client = match connect_nats(&config.nats_url).await {
        Ok(nc) => {
            info!("Connected to NATS at {}", config.nats_url);

            // Subscribe to config changes for cache invalidation
            let subscriber = nc.subscribe("agentguard.config_changed").await?;
            let nats_cache = Arc::new(DecisionCache::from_env());
            nats_cache.spawn_pruner();
            let cache_for_nats = nats_cache.clone();
            tokio::spawn(async move {
                handle_config_changes(subscriber, cache_for_nats).await;
            });
            info!("Subscribed to agentguard.config_changed for cache invalidation");

            // Use this cache instance for the service
            let decision_cache = nats_cache;
            Some((nc, decision_cache))
        }
        Err(e) => {
            warn!("Failed to connect to NATS: {} — config hot-reload disabled", e);
            None
        }
    };

    // Decision cache: use NATS-connected one if available, or create standalone
    let decision_cache = match &_nats_client {
        Some((_, cache)) => cache.clone(),
        None => {
            let cache = Arc::new(DecisionCache::from_env());
            cache.spawn_pruner();
            cache
        }
    };

    // ── Cedar custom policy evaluator (Layer 5) ──
    // Load initial policies from Redis (cold start recovery)
    let cedar_evaluator = Arc::new(CedarEvaluator::new_empty());
    {
        let pool = &decision_cache; // reuse reference scope
        match load_cedar_policies_from_redis(&redis_pool).await {
            Ok(entries) if !entries.is_empty() => {
                match cedar_evaluator.reload_all(&entries) {
                    Ok(()) => info!(count = entries.len(), "Cedar policies loaded from Redis"),
                    Err(e) => warn!(error = %e, "Failed to load Cedar policies — starting empty"),
                }
            }
            Ok(_) => info!("No Cedar policies in Redis — starting with empty PolicySet"),
            Err(e) => warn!(error = %e, "Redis unavailable for Cedar load — starting empty"),
        }
    }

    // Subscribe to NATS for Cedar policy hot-reload
    if let Some((ref nc, _)) = _nats_client {
        let policies_sub = nc.subscribe("agentguard.policies").await?;
        let cedar_for_nats = cedar_evaluator.clone();
        let cache_for_cedar = decision_cache.clone();
        tokio::spawn(async move {
            handle_cedar_policy_updates(policies_sub, cedar_for_nats, cache_for_cedar).await;
        });
        info!("Subscribed to agentguard.policies for Cedar hot-reload");
    }

    info!(
        "ag-policy starting — Rust engine L1-L4 + Rust scope exemptions + Cedar L5 (custom policies). \
         No OPA sidecar required."
    );

    let svc = PolicyServiceImpl::new(plan_guard, redis_pool, decision_cache, cedar_evaluator);

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ag_proto::agentguard::policy::policy_service_server::PolicyServiceServer<PolicyServiceImpl>>()
        .await;

    let addr = format!("0.0.0.0:{}", config.port).parse()?;
    info!("ag-policy listening on {}", addr);

    let mut builder = Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            ag_proto::agentguard::policy::policy_service_server::PolicyServiceServer::new(svc),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("ag-policy shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => { tracing::info!("Received Ctrl+C, shutting down"); }
        _ = sigterm.recv() => { tracing::info!("Received SIGTERM, shutting down"); }
    }
}

/// Handle config change notifications — invalidate decision cache.
async fn handle_config_changes(
    mut subscriber: async_nats::Subscriber,
    decision_cache: Arc<DecisionCache>,
) {
    use futures_util::StreamExt;
    while let Some(msg) = subscriber.next().await {
        let source = std::str::from_utf8(&msg.payload).unwrap_or("unknown");
        info!(source = %source, "Config changed — invalidating decision cache");
        decision_cache.clear();
    }
    warn!("Config change subscriber disconnected");
}

/// Handle Cedar policy updates from dashboard via NATS.
///
/// ag-control publishes to `agentguard.policies` when custom policies are
/// created, updated, or deleted. This handler hot-reloads the Cedar PolicySet.
///
/// Expected payload:
/// ```json
/// {
///   "action": "upsert" | "delete",
///   "policy_id": "uuid",
///   "name": "policy name",
///   "mode": "cedar" | "dsl",
///   "compiled": "Cedar policy text",
///   "priority": 100,
///   "cedar_action": "deny" | "remove_scope",
///   "cedar_reason": "reason string",
///   "cedar_scope": "scope to remove (for remove_scope)"
/// }
/// ```
async fn handle_cedar_policy_updates(
    mut subscriber: async_nats::Subscriber,
    cedar: Arc<CedarEvaluator>,
    cache: Arc<DecisionCache>,
) {
    use futures_util::StreamExt;
    while let Some(msg) = subscriber.next().await {
        let payload: serde_json::Value = match serde_json::from_slice(&msg.payload) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Failed to parse policy update payload");
                continue;
            }
        };

        let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("upsert");
        let policy_id = payload.get("policy_id").and_then(|v| v.as_str()).unwrap_or("unknown");

        info!(action = %action, policy_id = %policy_id, "Received policy update");

        match action {
            "delete" => {
                if let Err(e) = cedar.remove_policy(policy_id) {
                    warn!(error = %e, policy_id, "Failed to remove Cedar policy");
                }
            }
            "upsert" | _ => {
                // Extract Cedar policy text from compiled field
                let cedar_source = payload.get("compiled")
                    .and_then(|v| v.as_str())
                    .or_else(|| payload.get("source").and_then(|v| v.as_str()));

                if let Some(source) = cedar_source {
                    let entry = CedarPolicyEntry {
                        id: policy_id.to_string(),
                        source: source.to_string(),
                        priority: payload.get("priority").and_then(|v| v.as_i64()).unwrap_or(100) as i32,
                        action: payload.get("cedar_action").and_then(|v| v.as_str()).unwrap_or("deny").to_string(),
                        reason: payload.get("cedar_reason").and_then(|v| v.as_str()).unwrap_or("Custom policy").to_string(),
                        scope: payload.get("cedar_scope").and_then(|v| v.as_str()).map(String::from),
                    };

                    if let Err(e) = cedar.add_or_replace_policy(&entry) {
                        warn!(error = %e, policy_id, "Failed to add/replace Cedar policy");
                    }
                } else {
                    warn!(policy_id, "No Cedar source in policy payload — skipping");
                }
            }
        }

        // Invalidate all cached decisions — policies changed
        cache.clear();
    }
    warn!("Cedar policy update subscriber disconnected");
}

/// Load Cedar policies from Redis for cold start recovery.
///
/// Key: `ag:cedar:policies` (JSON array of CedarPolicyEntry)
async fn load_cedar_policies_from_redis(
    pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> Result<Vec<CedarPolicyEntry>, String> {
    let mut conn = pool.get().await.map_err(|e| format!("Redis pool: {}", e))?;
    let json: Option<String> = redis::cmd("GET")
        .arg("ag:cedar:policies")
        .query_async(&mut *conn)
        .await
        .map_err(|e| format!("Redis GET: {}", e))?;

    match json {
        Some(s) => serde_json::from_str(&s).map_err(|e| format!("JSON parse: {}", e)),
        None => Ok(Vec::new()),
    }
}
