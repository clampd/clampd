use std::sync::Arc;

use ag_common::config::{IntentConfig, parse_nats_url};

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
use ag_engine::builtins::compile_builtins;
use ag_engine::compile::CompiledRuleset;
use ag_license::PlanGuard;
use anyhow::Result;
use arc_swap::ArcSwap;
use tonic::transport::Server;
use tracing::{info, warn};

mod encoding;
mod loader;
mod rules;
mod session;
mod service;

use service::IntentServiceImpl;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // License check: every service validates independently.
    ag_common::license_guard::enforce_or_exit("ag-intent");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license — refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    let config = IntentConfig::from_env();

    // 1. Initialize ag-engine with built-in rules (110 rules from TOML)
    let ruleset = compile_builtins();
    info!(rule_count = ruleset.rule_count(), "ag-engine initialized with builtins");

    // 2. Wrap in ArcSwap for lock-free hot-reload
    let ruleset = Arc::new(ArcSwap::from_pointee(ruleset));

    // 3. Connect to Redis (for descriptor hash lookups)
    let redis_pool = match connect_redis(&config.redis_url).await {
        Ok(pool) => {
            info!("Connected to Redis");
            Some(pool)
        }
        Err(e) => {
            warn!(error = %e, "Failed to connect to Redis — descriptor lookups disabled");
            None
        }
    };

    // Hot-reload: custom rules from Redis + NATS notifications
    if let Some(ref pool) = redis_pool {
        let rules_loader = Arc::new(loader::RulesLoader::new(ruleset.clone(), pool.clone()));

        // Initial load from Redis
        if let Err(e) = rules_loader.reload().await {
            warn!(error = %e, "Initial rules load from Redis failed — using builtins only");
        }
        info!(
            rule_count = rules_loader.rule_count(),
            version = rules_loader.current_version(),
            "Rules loaded"
        );

        // Subscribe to NATS + fallback polling
        let nats_url = config.nats_url.clone();
        let loader_clone = rules_loader.clone();
        tokio::spawn(async move {
            match connect_nats(&nats_url).await {
                Ok(nats) => {
                    info!(url = %nats_url, "Connected to NATS for rules hot-reload");
                    loader_clone.subscribe_and_poll(nats).await;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to connect to NATS — Redis polling active");
                }
            }
        });
    }

    // 4. Create gRPC service
    let svc = IntentServiceImpl::new(ruleset.clone(), plan_guard, redis_pool.clone());

    // 5. Load threshold overrides + scope exemptions from Redis
    svc.load_thresholds_from_redis().await;
    svc.load_exemptions_from_redis().await;

    // Hot-reload thresholds + exemptions on NATS notifications
    if let Some(ref pool) = redis_pool {
        let threshold_handle = svc.threshold_overrides();
        let exemption_handle = svc.scope_exemptions();
        let redis_pool_clone = pool.clone();
        let nats_url = config.nats_url.clone();
        tokio::spawn(async move {
            let nats = match connect_nats(&nats_url).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(error = %e, "Failed to connect NATS for config hot-reload");
                    return;
                }
            };
            let mut sub = match nats.subscribe("agentguard.config.>").await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "Failed to subscribe to config updates");
                    return;
                }
            };
            use futures::StreamExt;
            while let Some(msg) = sub.next().await {
                let subject = msg.subject.as_str();
                if subject.contains("thresholds") {
                    if let Ok(mut conn) = redis_pool_clone.get().await {
                        let json: Result<String, _> = bb8_redis::redis::cmd("GET")
                            .arg("ag:config:thresholds")
                            .query_async(&mut *conn)
                            .await;
                        if let Ok(json) = json {
                            let overrides = ag_policy::thresholds::parse_threshold_overrides(&json);
                            info!(count = overrides.len(), "Hot-reloaded threshold overrides");
                            threshold_handle.store(Arc::new(overrides));
                        }
                    }
                } else if subject.contains("exemptions") {
                    if let Ok(mut conn) = redis_pool_clone.get().await {
                        let json: Result<String, _> = bb8_redis::redis::cmd("GET")
                            .arg("ag:config:exemptions")
                            .query_async(&mut *conn)
                            .await;
                        if let Ok(json) = json {
                            if let Ok(exemptions) = serde_json::from_str::<Vec<ag_policy::thresholds::ScopeExemption>>(&json) {
                                info!(count = exemptions.len(), "Hot-reloaded scope exemptions");
                                exemption_handle.store(Arc::new(exemptions));
                            }
                        }
                    }
                }
            }
        });
    }

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ag_proto::agentguard::intent::intent_service_server::IntentServiceServer<IntentServiceImpl>>()
        .await;

    let addr = format!("0.0.0.0:{}", config.port).parse()?;
    info!("ag-intent listening on {}", addr);

    let mut builder = Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            ag_proto::agentguard::intent::intent_service_server::IntentServiceServer::new(svc),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("ag-intent shut down gracefully");
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

/// Connect to Redis via bb8 connection pool.
async fn connect_redis(
    redis_url: &str,
) -> Result<bb8::Pool<bb8_redis::RedisConnectionManager>> {
    let manager = bb8_redis::RedisConnectionManager::new(redis_url)?;
    let pool = bb8::Pool::builder()
        .max_size(
            std::env::var("REDIS_POOL_MAX_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
        )
        .build(manager)
        .await?;
    Ok(pool)
}
