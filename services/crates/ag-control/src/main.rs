// ── ARCHITECTURAL NOTE ──────────────────────────────────────────────
// ag-control is the CONTROL PLANE BRIDGE between the Dashboard and the
// runtime service cluster. It is the ONLY service authorized to make
// direct gRPC calls to runtime services on behalf of the Dashboard.
//
// The Dashboard NEVER calls runtime services directly. Instead:
//   Dashboard → (WS/HTTP command) → ag-control → (gRPC) → ag-kill/ag-registry
//
// This is by design: ag-control centralizes authentication, rate limiting,
// leader election, and audit logging for all control plane operations.
// ─────────────────────────────────────────────────────────────────────

mod agent_cred_sync;
mod agent_sync;
mod apikey_sync;
mod audit_upload;
mod command_executor;
mod commands;
mod dashboard_auth;
mod engine_metadata;
mod delegation_redis_sync;
mod delegation_sync;
mod health;
mod key_rotation;
mod kill_listener;
mod leader;
mod license_heartbeat;
mod local_sync;
mod poller;
mod policy_sync;
mod rules_sync;
mod service;
mod tool_descriptor_sync;
mod agent_tool_grant_sync;
mod ws_client;

use std::sync::{
    atomic::AtomicU32,
    Arc,
};

use ag_common::config::{ControlConfig, parse_nats_url};

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
use ag_common::license::LicenseValidator;
use ag_license::{PlanGuard, FeatureFlags};
use ag_proto::agentguard::control::control_service_server::ControlServiceServer;
use leader::LeaderElection;
use service::ControlServiceImpl;
use tokio::sync::{RwLock, watch};
use tracing::{error, info, warn};

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
    ag_common::license_guard::enforce_or_exit("ag-control");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license — refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    // Log gated features for operational visibility.
    if plan_guard.is_enabled(FeatureFlags::RBAC) {
        info!("RBAC feature enabled");
    }
    if plan_guard.is_enabled(FeatureFlags::WEBHOOKS) {
        info!("Webhooks feature enabled");
    }
    if plan_guard.is_enabled(FeatureFlags::COMPLIANCE_EXPORT) {
        info!("Compliance export feature enabled");
    }

    let mut config = ControlConfig::from_env();
    info!(port = config.port, "ag-control starting");

    // ── Dashboard auth: auto-generate JWT if CLAMPD_LICENSE_TOKEN is not set ──
    // This replaces the old "dev-license-token" magic string with a proper JWT
    // signed using JWT_SECRET (shared with the Dashboard API).
    {
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_default();
        let generated = dashboard_auth::generate_dashboard_token(
            &config.license_token,
            &jwt_secret,
            &plan_guard.org_id,
        );
        if config.license_token.is_empty() && !generated.is_empty() {
            config.license_token = generated;
        } else if !config.license_token.is_empty() && config.license_token != "dev-license-token" {
            // Manual override — keep as-is.
        } else if config.license_token == "dev-license-token" && !generated.is_empty() {
            // Replace the old magic string with a proper JWT.
            info!("Replacing dev-license-token with signed JWT");
            config.license_token = generated;
        }
    }

    // Generate a unique pod ID.
    let pod_id = std::env::var("POD_NAME")
        .unwrap_or_else(|_| format!("ag-control-{}", uuid::Uuid::new_v4().as_simple()));
    info!(pod_id = %pod_id, "Pod identity");

    // Connect Redis.
    let redis_manager = bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
    let redis = bb8::Pool::builder()
        .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16))
        .build(redis_manager)
        .await?;
    info!("Redis connected");

    // Connect Postgres (for API key sync).
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&config.database_url)
        .await?;
    info!("Postgres connected");

    // Auto-migrate: create tables if they don't exist.
    sqlx::migrate!("./migrations")
        .run(&pg)
        .await
        .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
    info!("Database migrations applied");

    // Seed license claims into Redis from Postgres so policy_sync has org_id immediately.
    {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT org_id::text FROM licenses WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
        )
        .fetch_optional(&pg)
        .await?;
        if let Some((org_id,)) = row {
            if let Ok(mut conn) = redis.get().await {
                let claims = serde_json::json!({ "org_id": org_id });
                if let Err(e) = redis::cmd("SET")
                    .arg("ag:license:claims")
                    .arg(claims.to_string())
                    .query_async::<()>(&mut *conn)
                    .await
                {
                    error!(error = %e, "Failed to seed ag:license:claims in Redis");
                }
                info!(org_id = %org_id, "Seeded ag:license:claims from Postgres");
            }
        }
    }

    // SECURITY: NATS connection requires token auth (NATS_TOKEN embedded in NATS_URL).
    // All publications to agentguard.* topics are authenticated via this token.
    // See docker-compose.yml: nats --auth ${NATS_TOKEN}
    // The connect_nats() helper extracts the token from the URL and passes it
    // via ConnectOptions::with_token() so credentials are not logged.
    let nats = connect_nats(&config.nats_url).await?;
    info!("NATS connected");

    // Store engine metadata in Redis on startup so the dashboard can read it
    // immediately.  This is a best-effort operation — startup continues even if
    // it fails (metadata will be built on-demand via get_engine_metadata).
    match engine_metadata::store_metadata_in_redis(&redis).await {
        Ok(()) => {
            info!("Engine metadata stored in Redis on startup");
        }
        Err(e) => warn!(error = %e, "Failed to store engine metadata in Redis on startup — will be built on-demand"),
    }

    // Initialize license validator.
    let license_validator = Arc::new(RwLock::new(LicenseValidator::new()));
    info!("License validator initialized");

    // ── Graceful shutdown channel ──────────────────────────────────────────
    // A watch channel used to signal background loops to stop cleanly.
    // The sender is held in the shutdown handler; receivers are cloned into
    // each critical background task.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Initialize leader election.
    let leader = Arc::new(LeaderElection::new(
        redis.clone(),
        pod_id.clone(),
        config.leader_ttl_secs,
        config.leader_renew_secs,
    ));
    let is_leader = leader.is_leader_handle();

    // Spawn leader election loop.
    let leader_loop = leader.clone();
    tokio::spawn(async move {
        leader_loop.run_loop().await;
    });

    // Spawn periodic health check (every 30s, leader only).
    let health_redis = redis.clone();
    let health_nats = nats.clone();
    let health_license = license_validator.clone();
    let health_is_leader = is_leader.clone();
    let mut health_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = health_shutdown_rx.changed() => {
                    info!("Health check loop: shutdown signal received");
                    break;
                }
            }
            if !health_is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                continue; // Only leader runs health checks.
            }
            let license = health_license.read().await;
            let license_status = match license.status() {
                ag_common::license::LicenseStatus::Valid(_) => "valid",
                ag_common::license::LicenseStatus::NoLicense => "community",
                _ => "degraded",
            };
            health::run_health_check(&health_redis, &health_nats, license_status, 0).await;
        }
    });

    // Shared atomic counters for rules and policy versions.
    let rules_version = Arc::new(AtomicU32::new(0));
    let policy_version = Arc::new(AtomicU32::new(0));


    // Shared notify handle for rules_sync. Created early so both the command
    // executor (push_rules) and the config change listener can wake the rules
    // sync loop immediately, eliminating up to 10s of polling latency.
    let rules_sync_notify = Arc::new(tokio::sync::Notify::new());

    // Shared DB mode — SaaS poller, WS client, license heartbeat, policy sync
    // are not needed (proxy reads the same Postgres).
    {
        info!("Shared DB mode — SaaS poller, WS client, license heartbeat, and policy sync disabled (not needed)");

        // Spawn local command poller — reads runtime_commands from shared Postgres directly.
        // This handles kill/revive/push_policy commands from the Dashboard UI.
        let kill_url = std::env::var("KILL_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:50055".to_string());
        let local_executor = Arc::new(command_executor::ExecutorConfig {
            kill_url,
            registry_url: config.registry_url.clone(),
            nats_client: Some(nats.clone()),
            redis_pool: Some(redis.clone()),
            pg_pool: Some(pg.clone()),
            saas_url: None,
            license_token: None,
            rules_sync_notify: Some(rules_sync_notify.clone()),
        });
        // Command poller: Postgres runtime_commands → execute
        local_sync::spawn_command_poller(
            pg.clone(),
            local_executor,
            is_leader.clone(),
            config.poll_interval_secs,
        );
        info!(poll_interval_secs = config.poll_interval_secs, "Local command poller started");

        // Delegation observations: Redis → Postgres (every 15s)
        local_sync::spawn_delegation_sync(pg.clone(), redis.clone(), is_leader.clone());
        info!("Local delegation sync started");

        // Audit events: NATS → Postgres (buffered, flush every 30s)
        local_sync::spawn_audit_sync(pg.clone(), nats.clone());
        info!("Local audit sync started");

        // Workflow auto-discovery: agent_relationships → workflows (every 5 min)
        local_sync::spawn_workflow_discovery(pg.clone(), is_leader.clone());
        info!("Workflow auto-discovery started (every 5 min)");

        info!("Use clampd-cli or Redis rules_sync for configuration");
    }

    // ── Config change notifiers ─────────────────────────────────────────────
    // Create Notify handles that allow the config change listener to wake
    // individual sync loops immediately instead of waiting for their interval.
    let mut config_notifiers = local_sync::ConfigChangeNotifiers::new();
    // Use the same rules_sync Notify handle that was given to the command
    // executors, so both push_rules completion AND config_changed NATS events
    // wake the same sync loop.
    config_notifiers.rules_sync = rules_sync_notify.clone();

    // Spawn rules sync loop (leader-gated, every 10s).
    {
        let mut sync = rules_sync::RulesSync::new(
            redis.clone(),
            nats.clone(),
            is_leader.clone(),
            rules_version.clone(),
        );
        sync.set_force_sync(config_notifiers.rules_sync.clone());
        let interval = std::time::Duration::from_secs(config.rules_sync_secs);
        let rules_shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            sync.run_sync_loop_with_shutdown(interval, Some(rules_shutdown_rx)).await;
        });
        info!(
            interval_secs = config.rules_sync_secs,
            "Rules sync loop started"
        );
    }

    // Key rotation check (leader only, every 5 minutes)
    let kr_redis = redis.clone();
    let kr_nats = nats.clone();
    let kr_leader = is_leader.clone();
    let mut kr_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = kr_shutdown_rx.changed() => {
                    info!("Key rotation loop: shutdown signal received");
                    break;
                }
            }
            if kr_leader.load(std::sync::atomic::Ordering::Relaxed) {
                if let Err(e) = key_rotation::check_and_rotate_if_needed(&kr_redis, &kr_nats).await
                {
                    tracing::warn!("Key rotation check failed: {}", e);
                }
            }
        }
    });

    // ── Postgres→Redis sync loops ──────────────────────────────────────────

    // Delegation Redis sync — syncs approved edges + enforcement mode
    // from Postgres → Redis so ag-gateway/ag-policy can check them at request time.
    {
        let mut sync = delegation_redis_sync::DelegationRedisSync::new(
            pg.clone(),
            redis.clone(),
            is_leader.clone(),
        );
        sync.set_force_sync(config_notifiers.delegation_redis_sync.clone());
        let interval = std::time::Duration::from_secs(15);
        tokio::spawn(async move {
            sync.run_sync_loop(interval).await;
        });
        info!("Delegation Redis sync loop started (every 15s)");
    }

    // API key sync (leader-gated, every 30s).
    {
        let sync = apikey_sync::ApiKeySync::new(
            pg.clone(),
            redis.clone(),
            is_leader.clone(),
        );
        tokio::spawn(async move {
            sync.run_sync_loop(tokio::time::Duration::from_secs(30)).await;
        });
        info!("API key sync loop started (every 30s)");
    }

    // Agent credential sync (leader-gated, every 10s).
    {
        let mut sync = agent_cred_sync::AgentCredSync::new(
            pg.clone(),
            redis.clone(),
            is_leader.clone(),
        );
        sync.set_force_sync(config_notifiers.agent_cred_sync.clone());
        tokio::spawn(async move {
            sync.run_sync_loop(tokio::time::Duration::from_secs(10)).await;
        });
        info!("Agent credential sync loop started (every 10s)");
    }

    // Agent + org sync — no-op in shared DB mode (proxy reads the same DB).
    {
        let sync = agent_sync::AgentSync::new(
            pg.clone(),
            is_leader.clone(),
        );
        tokio::spawn(async move {
            sync.run_sync_loop(tokio::time::Duration::from_secs(30)).await;
        });
        info!("Agent sync loop started (every 30s)");
    }

    // Tool descriptor approval sync to Redis (leader-gated, every 30s).
    // Reads from local Postgres, writes to Redis: ag:tool:approved:{tool_name}:{hash}.
    {
        let mut sync = tool_descriptor_sync::ToolDescriptorSync::new(
            pg.clone(),
            redis.clone(),
            is_leader.clone(),
        );
        sync.set_force_sync(config_notifiers.tool_descriptor_sync.clone());
        tokio::spawn(async move {
            sync.run_sync_loop(tokio::time::Duration::from_secs(30)).await;
        });
        info!("Tool descriptor approval sync loop started (every 30s)");
    }

    // Agent tool grant sync to Redis (leader-gated, every 30s).
    // Writes: ag:agent:tool:{agent_id}:{tool_name} → {scopes, permission, descriptor_hash}
    {
        let sync = agent_tool_grant_sync::AgentToolGrantSync::new(
            pg.clone(),
            redis.clone(),
            is_leader.clone(),
        );
        tokio::spawn(async move {
            sync.run_sync_loop(tokio::time::Duration::from_secs(30)).await;
        });
        info!("Agent tool grant sync loop started (every 30s)");
    }

    // ── Config change listener (NATS → immediate sync) ───────────────────────
    // Subscribes to `agentguard.config_changed` and wakes the appropriate sync
    // loop immediately when a configuration change is published.
    local_sync::spawn_config_change_listener(
        nats.clone(),
        is_leader.clone(),
        config_notifiers,
    );
    info!("Config change listener started (NATS: {})", local_sync::NATS_CONFIG_CHANGED);

    // Build gRPC service.
    let svc = ControlServiceImpl {
        leader: leader.clone(),
        is_leader,
        license_validator,
        redis,
        nats,
        rules_version,
        policy_version,
        started_at: std::time::Instant::now(),
        plan_guard,
    };

    // Health check.
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ControlServiceServer<ControlServiceImpl>>()
        .await;

    let addr = format!("0.0.0.0:{}", config.port).parse()?;
    info!(%addr, "ag-control gRPC server listening");

    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            ControlServiceServer::new(svc),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal(shutdown_tx))
        .await?;

    info!("ag-control shut down gracefully — background tasks will be cancelled");
    Ok(())
}

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => { tracing::info!("Received Ctrl+C, shutting down"); }
        _ = sigterm.recv() => { tracing::info!("Received SIGTERM, shutting down"); }
    }
    // Signal all background loops holding a shutdown_rx to stop gracefully.
    let _ = shutdown_tx.send(true);
}
