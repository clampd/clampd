use std::sync::Arc;

use ag_common::config::{RegistryConfig, parse_nats_url};

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
use tonic::transport::Server;
use tracing::{info, warn};

mod audit;
mod baselines;
mod cache;
mod lifecycle;
pub mod relationships;
mod repository;
mod risk;
mod service;

use audit::AuditLogger;
use service::RegistryServiceImpl;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // License check: every service validates independently.
    ag_common::license_guard::enforce_or_exit("ag-registry");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license - refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    let config = RegistryConfig::from_env();

    // Connect to PostgreSQL
    let db_pool = sqlx::PgPool::connect(&config.database_url).await?;
    info!("Connected to PostgreSQL");

    // Ensure A2A relationship table exists (idempotent CREATE IF NOT EXISTS)
    if let Err(e) = relationships::ensure_table(&db_pool).await {
        warn!(error = %e, "Failed to create agent_relationships table - A2A features may be unavailable");
    } else {
        info!("agent_relationships table ready");
    }

    // Connect to Redis
    let redis_manager = bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
    let redis_pool = bb8::Pool::builder()
        .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16))
        .build(redis_manager)
        .await?;
    info!("Connected to Redis");

    // Connect to NATS (optional - audit logging degrades gracefully)
    let audit_logger = match connect_nats(&config.nats_url).await {
        Ok(nats_client) => {
            info!("Connected to NATS for audit logging");
            AuditLogger::new(nats_client)
        }
        Err(e) => {
            warn!(error = %e, "Failed to connect to NATS - audit logging will use tracing only");
            AuditLogger::noop()
        }
    };

    let repo = Arc::new(repository::AgentRepository::new(db_pool.clone()));
    let svc = RegistryServiceImpl::new(repo, redis_pool.clone(), audit_logger, plan_guard);

    // Spawn supervised background touch flusher (every 60s).
    // If the inner task panics, it restarts after a 5s delay.
    let flush_pool = db_pool.clone();
    let flush_redis = redis_pool.clone();
    tokio::spawn(async move {
        loop {
            let pool = flush_pool.clone();
            let redis = flush_redis.clone();
            let result = tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    if let Err(e) = flush_touches(&pool, &redis).await {
                        tracing::warn!("Touch flusher error: {}", e);
                    }
                }
            }).await;

            match result {
                Ok(_) => break, // Normal exit (shouldn't happen with infinite loop)
                Err(e) => {
                    tracing::error!("Touch flusher panicked: {} - restarting in 5s", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        }
    });
    tracing::info!("Touch flusher background task started (supervised)");

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ag_proto::agentguard::registry::registry_service_server::RegistryServiceServer<RegistryServiceImpl>>()
        .await;

    let addr = format!("0.0.0.0:{}", config.port).parse()?;
    info!("ag-registry listening on {}", addr);

    let mut builder = Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            ag_proto::agentguard::registry::registry_service_server::RegistryServiceServer::new(
                svc,
            ),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("ag-registry shut down gracefully");
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

async fn flush_touches(
    pool: &sqlx::PgPool,
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> anyhow::Result<()> {
    let mut conn = redis_pool.get().await?;
    let mut cursor: u64 = 0;
    let mut agent_ids = Vec::new();

    loop {
        let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("ag:touch:*")
            .arg("COUNT")
            .arg(100u64)
            .query_async(&mut *conn)
            .await?;

        for key in &keys {
            if let Some(agent_id) = key.strip_prefix("ag:touch:") {
                agent_ids.push(agent_id.to_string());
            }
        }
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    if agent_ids.is_empty() {
        return Ok(());
    }

    let now = chrono::Utc::now();
    for agent_id in &agent_ids {
        // Update DB
        let _ = sqlx::query("UPDATE agents SET updated_at = $1 WHERE id = $2::uuid")
            .bind(now)
            .bind(agent_id)
            .execute(pool)
            .await;
        // Delete Redis key
        let key = format!("ag:touch:{}", agent_id);
        if let Err(e) = redis::cmd("DEL")
            .arg(&key)
            .query_async::<()>(&mut *conn)
            .await
        {
            warn!(error = %e, key = %key, "Failed to DEL touch key from Redis");
        }
    }

    tracing::debug!("Flushed {} touch entries to database", agent_ids.len());
    Ok(())
}
