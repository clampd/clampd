mod cascade;
mod service;

use std::sync::Arc;

use ag_common::config::{KillConfig, parse_nats_url, grpc_connect_with_retry};

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
use ag_common::interceptor::{ClientAuthInterceptor, server_auth_interceptor};
use ag_license::PlanGuard;
use ag_proto::agentguard::{
    kill::kill_service_server::KillServiceServer,
    registry::registry_service_client::RegistryServiceClient,
    token::token_service_client::TokenServiceClient,
};
use cascade::CascadeDeps;
use service::KillServiceImpl;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // License check: every service validates independently.
    ag_common::license_guard::enforce_or_exit("ag-kill");

    // Validate license JWT and extract plan guard.
    // Kill switch is a core feature available on ALL plans — no feature gating needed.
    let _plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license — refusing to start"),
    );
    info!(plan = %_plan_guard.plan, org_id = %_plan_guard.org_id, "Plan guard initialized (kill switch: all plans)");

    let config = KillConfig::from_env();
    info!(port = config.port, "ag-kill starting");

    // Connect Redis (connection pool).
    let redis_manager = bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
    let redis = bb8::Pool::builder()
        .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16))
        .build(redis_manager)
        .await?;
    info!("Redis connected");

    // Connect PostgreSQL.
    let db = sqlx::PgPool::connect(&config.database_url).await?;
    info!("PostgreSQL connected");

    // Connect NATS.
    let nats = connect_nats(&config.nats_url).await?;
    info!("NATS connected");

    // Connect gRPC clients with internal auth.
    let grpc_client_tls = ag_common::tls::client_tls_config();

    let mut token_endpoint = tonic::transport::Channel::from_shared(config.token_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        token_endpoint = token_endpoint.tls_config(tls.clone())?;
    }
    let token_channel = grpc_connect_with_retry(token_endpoint, "ag-token").await?;
    let token_client = TokenServiceClient::with_interceptor(token_channel, ClientAuthInterceptor);

    let mut registry_endpoint = tonic::transport::Channel::from_shared(config.registry_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        registry_endpoint = registry_endpoint.tls_config(tls.clone())?;
    }
    let registry_channel = grpc_connect_with_retry(registry_endpoint, "ag-registry").await?;
    let registry_client = RegistryServiceClient::with_interceptor(registry_channel, ClientAuthInterceptor);

    // Replay audit fallback entries from previous crashes
    replay_audit_fallback(&db).await;

    // Build cascade dependencies.
    let deps = Arc::new(CascadeDeps {
        redis: redis.clone(),
        nats,
        token_client,
        registry_client,
        db,
    });

    // Build gRPC service.
    let svc = KillServiceImpl::new(
        deps,
        config.deny_ttl_secs,
        config.deny_extended_ttl_secs,
        config.registry_retries,
    );

    // Health check.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<KillServiceServer<KillServiceImpl>>()
        .await;

    let addr = format!("0.0.0.0:{}", config.port).parse()?;
    info!(%addr, "ag-kill gRPC server listening");

    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            KillServiceServer::new(svc),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("ag-kill shut down gracefully");
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

async fn replay_audit_fallback(pool: &sqlx::PgPool) {
    let pod_name = std::env::var("POD_NAME").unwrap_or_else(|_| "default".to_string());
    let path = format!("/tmp/ag-kill-audit-fallback-{}.jsonl", pod_name);
    let content = match tokio::fs::read_to_string(&path).await {
        Ok(c) => c,
        Err(_) => return, // No fallback file, nothing to replay
    };

    let mut replayed = 0;
    for line in content.lines() {
        if line.trim().is_empty() { continue; }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let agent_id = entry.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
            let reason = entry.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            let initiated_by = entry.get("initiated_by").and_then(|v| v.as_str()).unwrap_or("");

            let result = sqlx::query(
                "INSERT INTO kill_audit (id, agent_id, reason, initiated_by, success, layers_succeeded, layers_failed, total_latency_ms, created_at) VALUES ($1, $2, $3, $4, true, 0, 0, 0, NOW()) ON CONFLICT DO NOTHING"
            )
            .bind(uuid::Uuid::new_v4())
            .bind(agent_id)
            .bind(reason)
            .bind(initiated_by)
            .execute(pool)
            .await;

            if result.is_ok() {
                replayed += 1;
            }
        }
    }

    if replayed > 0 {
        tracing::info!("Replayed {} audit entries from fallback file", replayed);
        // Truncate the file after successful replay
        let _ = tokio::fs::write(&path, "").await;
    }
}
