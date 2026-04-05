mod alert_dedup;
mod anomaly;
mod auto_suspend;
mod baseline;
mod chains;
mod consumer;
mod correlation;
mod cross_correlation;
mod leader;
mod persistence;
mod role;
mod score_reader;
mod scorer;
mod service;
mod ws;
mod ws_feed;

use std::sync::Arc;

use futures_util::StreamExt;

use ag_common::config::{RiskConfig, parse_nats_url, grpc_connect_with_retry};

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
use ag_license::{PlanGuard, FeatureFlags};
use ag_proto::agentguard::{
    kill::kill_service_client::KillServiceClient,
    registry::registry_service_client::RegistryServiceClient,
    risk::risk_service_server::RiskServiceServer,
};
use correlation::{CorrelationConfig, CorrelationEngine};
use persistence::RiskPersistence;
use score_reader::ScoreProvider;
use scorer::RiskScorer;
use service::RiskServiceImpl;
use tracing::info;
use ws::{WsBroadcaster, WsState};

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
    ag_common::license_guard::enforce_or_exit("ag-risk");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license - refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    // A2A cross-agent correlation is gated by the A2A feature flag.
    let a2a_enabled = plan_guard.is_enabled(FeatureFlags::A2A);
    if a2a_enabled {
        info!("A2A feature enabled - cross-agent correlation active");
    } else {
        info!("A2A feature not enabled - cross-agent correlation will be skipped");
    }

    let config = RiskConfig::from_env();
    info!(port = config.port, ws_port = config.ws_port, "ag-risk starting");

    // Feature flag: enable leader/follower mode for multi-pod scaling.
    let leader_follower_enabled = std::env::var("AG_RISK_LEADER_FOLLOWER")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    info!(leader_follower = leader_follower_enabled, "Mode selected");

    if std::env::var("JWT_SECRET").unwrap_or_default().is_empty() {
        tracing::warn!("JWT_SECRET not set - WebSocket risk feed will accept unauthenticated connections");
    }

    // Connect Redis.
    let redis_manager = bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
    let redis_pool = bb8::Pool::builder()
        .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16))
        .build(redis_manager)
        .await?;
    info!("Redis connected");

    // Clone Redis pool for leader election before moving into persistence.
    let leader_redis = redis_pool.clone();

    // Initialize persistence layer.
    let persistence = Arc::new(RiskPersistence::new(redis_pool));

    // Connect NATS (plain subscription - no JetStream needed for risk scoring).
    let nats = connect_nats(&config.nats_url).await?;
    info!("NATS connected");

    // Connect ag-kill client (for auto-suspend) with internal auth.
    let grpc_client_tls = ag_common::tls::client_tls_config();

    let mut kill_endpoint = tonic::transport::Channel::from_shared(config.kill_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        kill_endpoint = kill_endpoint.tls_config(tls.clone())?;
    }
    let kill_channel = grpc_connect_with_retry(kill_endpoint, "ag-kill").await?;
    let kill_client = KillServiceClient::with_interceptor(kill_channel, ClientAuthInterceptor);

    // Connect ag-registry client (fallback for auto-suspend) with internal auth.
    let mut registry_endpoint = tonic::transport::Channel::from_shared(config.registry_url.clone())?;
    if let Some(ref tls) = grpc_client_tls {
        registry_endpoint = registry_endpoint.tls_config(tls.clone())?;
    }
    let registry_channel = grpc_connect_with_retry(registry_endpoint, "ag-registry").await?;
    let registry_client = RegistryServiceClient::with_interceptor(registry_channel, ClientAuthInterceptor);

    // Initialize scorer.
    let scorer = Arc::new(RiskScorer::new(
        config.ema_alpha,
        config.auto_suspend_threshold,
    ));
    info!(
        alpha = config.ema_alpha,
        threshold = config.auto_suspend_threshold,
        "Risk scorer initialized"
    );

    // Initialize auto-suspend enhancer (cooldown + escalation to permanent kill).
    let auto_suspend_enhancer = Arc::new(auto_suspend::AutoSuspendEnhancer::new(
        auto_suspend::AutoSuspendConfig::default(),
    ));
    info!("Auto-suspend enhancer initialized (3 suspends in 24h → permanent kill)");

    // Initialize correlation engine.
    let correlation = Arc::new(CorrelationEngine::new(CorrelationConfig::default()));
    info!("Correlation engine initialized");

    // Initialize WebSocket broadcaster.
    let broadcaster = Arc::new(WsBroadcaster::new(1024));

    // Initialize anomaly detector.
    let anomaly_detector = Arc::new(anomaly::AnomalyDetector::default());
    info!("Anomaly detector initialized");

    // Initialize baseline accumulator for enriched behavioral baselines.
    let baseline_accumulator = Arc::new(baseline::BaselineAccumulator::new());
    info!("Baseline accumulator initialized");

    // Initialize Redis-backed leader election.
    let pod_id = std::env::var("POD_NAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let leader_election = Arc::new(leader::LeaderElection::new(
        leader_redis,
        pod_id.clone(),
        30, // TTL seconds
        10, // Renew interval seconds
    ));
    let is_leader = leader_election.is_leader_handle();
    info!(pod_id = %pod_id, "Leader election initialized (Redis-backed)");

    // Spawn leader election loop (acquire/renew every 10s via Redis).
    let leader_clone = leader_election.clone();
    tokio::spawn(async move {
        leader_clone.run_loop().await;
    });

    if leader_follower_enabled {
        // ── Option E: Leader Scores, Followers Serve ──
        //
        // Leader pod: consumer + decay + persistence + correlation (via RoleManager)
        // Follower pods: serve gRPC reads from Redis-cached scores
        // Transition is automatic via RoleManager's transition loop.

        info!("Leader/follower mode: RoleManager will manage consumer and background tasks");

        // Restore scores from Redis so the scorer starts with existing state.
        // In leader mode, RoleManager will also restore on leadership acquisition.
        let restored = persistence.restore_scores().await;
        if !restored.is_empty() {
            info!(count = restored.len(), "Restoring risk scores from Redis");
            scorer.restore_scores(restored);
        }

        // Create the ScoreProvider for gRPC reads.
        let provider = Arc::new(ScoreProvider::new(
            is_leader.clone(),
            scorer.clone(),
            persistence.clone(),
        ));

        // Create the RoleManager that handles leader/follower transitions.
        let role_manager = Arc::new(role::RoleManager::new(
            pod_id.clone(),
            is_leader.clone(),
            scorer.clone(),
            persistence.clone(),
            config.nats_url.clone(),
            kill_client.clone(),
            registry_client.clone(),
            broadcaster.clone(),
            correlation.clone(),
            anomaly_detector.clone(),
            baseline_accumulator.clone(),
            config.decay_interval_secs,
            a2a_enabled,
            auto_suspend_enhancer.clone(),
        ));

        // Spawn the RoleManager transition loop.
        let rm = role_manager.clone();
        tokio::spawn(async move {
            rm.run_transition_loop().await;
        });

        // Spawn revive listener (runs on ALL pods - broadcast via NATS plain subscribe).
        spawn_revive_listener(
            &config.nats_url,
            scorer.clone(),
            persistence.clone(),
            Some(provider.clone()),
        )
        .await?;

        // Create shutdown channel for coordinated shutdown of gRPC + WebSocket.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn WebSocket server.
        spawn_ws_server(&broadcaster, &config, shutdown_rx).await?;

        // gRPC service with ScoreProvider (leader reads from scorer, follower from cache).
        let svc = RiskServiceImpl::new(provider);
        serve_grpc(svc, config.port, shutdown_tx).await?;
    } else {
        // ── Legacy single-pod mode (no leader/follower) ──
        //
        // All tasks run unconditionally on every pod (original behavior).

        info!("Single-pod mode: all tasks run on this pod");

        // Restore scores from Redis.
        let restored = persistence.restore_scores().await;
        if !restored.is_empty() {
            info!(count = restored.len(), "Restoring risk scores from Redis");
            scorer.restore_scores(restored);
        }

        // Spawn decay timer.
        let decay_scorer = scorer.clone();
        let decay_interval = config.decay_interval_secs;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(decay_interval));
            loop {
                interval.tick().await;
                decay_scorer.apply_decay();
            }
        });

        // Spawn periodic score persistence + baseline computation timer (every 30 s).
        let persist_scorer = scorer.clone();
        let persist_persistence = persistence.clone();
        let persist_accumulator = baseline_accumulator.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            let mut baseline_tick = 0u32;
            loop {
                interval.tick().await;
                let snapshot = persist_scorer.snapshot();
                persist_persistence.save_scores(&snapshot).await;

                // Compute baselines every 10 minutes (20 ticks × 30s = 600s).
                baseline_tick += 1;
                if baseline_tick >= 20 {
                    baseline_tick = 0;
                    persist_persistence
                        .compute_baselines_from_scores(&snapshot, &persist_accumulator)
                        .await;
                }
            }
        });

        // Spawn correlation cleanup timer (every 60 s).
        let cleanup_correlation = correlation.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                cleanup_correlation.cleanup();
            }
        });

        // Spawn NATS consumer (plain subscription, no JetStream).
        let consumer_nats = connect_nats(&config.nats_url).await?;
        let consumer_scorer = scorer.clone();
        let consumer_broadcaster = broadcaster.clone();
        let consumer_correlation = correlation.clone();
        let consumer_persistence = persistence.clone();
        let consumer_anomaly = anomaly_detector.clone();
        let consumer_accumulator = baseline_accumulator.clone();
        let consumer_a2a = a2a_enabled;
        let consumer_enhancer = auto_suspend_enhancer.clone();
        tokio::spawn(async move {
            if let Err(e) = consumer::run_consumer(
                consumer_nats,
                consumer_scorer,
                kill_client,
                registry_client,
                consumer_broadcaster,
                consumer_correlation,
                consumer_persistence,
                consumer_anomaly,
                consumer_accumulator,
                consumer_a2a,
                consumer_enhancer,
            )
            .await
            {
                tracing::error!(error = %e, "NATS consumer failed");
            }
        });

        // Spawn revive listener.
        spawn_revive_listener(&config.nats_url, scorer.clone(), persistence.clone(), None).await?;

        // Create shutdown channel for coordinated shutdown of gRPC + WebSocket.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        // Spawn WebSocket server.
        spawn_ws_server(&broadcaster, &config, shutdown_rx).await?;

        // gRPC service with ScoreProvider (always-leader in single-pod mode).
        let always_leader = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let provider = Arc::new(ScoreProvider::new(always_leader, scorer, persistence));
        let svc = RiskServiceImpl::new(provider);
        serve_grpc(svc, config.port, shutdown_tx).await?;
    }

    Ok(())
}

/// Spawn the NATS revive listener (runs on ALL pods - broadcast via plain subscribe).
async fn spawn_revive_listener(
    nats_url: &str,
    scorer: Arc<RiskScorer>,
    persistence: Arc<RiskPersistence>,
    provider: Option<Arc<ScoreProvider>>,
) -> anyhow::Result<()> {
    let revive_nats = connect_nats(nats_url).await?;
    let mut revive_sub = revive_nats.subscribe("agentguard.revive").await?;
    info!("Listening for agentguard.revive events (EMA reset)");
    tokio::spawn(async move {
        while let Some(msg) = revive_sub.next().await {
            let raw = String::from_utf8_lossy(&msg.payload).trim().to_string();
            if raw.is_empty() {
                continue;
            }
            // Try JSON first: {"agent_id": "..."}, then fall back to raw string
            let agent_id = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| v.get("agent_id").and_then(|a| a.as_str()).map(String::from))
                .unwrap_or(raw);
            if agent_id.is_empty() {
                continue;
            }
            info!(agent_id = %agent_id, "Agent revived - resetting EMA score to 0");
            scorer.reset_score(&agent_id);
            persistence.clear_agent_score(&agent_id).await;
            persistence.clear_suspicion_score(&agent_id).await;

            // Clear follower cache so next read picks up the reset from Redis.
            if let Some(ref p) = provider {
                p.clear_agent_cache(&agent_id);
            }
        }
    });
    Ok(())
}

/// Spawn the WebSocket server for real-time risk feed with graceful shutdown.
async fn spawn_ws_server(
    broadcaster: &Arc<WsBroadcaster>,
    config: &RiskConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let ws_state = WsState {
        broadcaster: broadcaster.clone(),
        max_clients: config.max_ws_clients,
    };
    let ws_router = ws::ws_router(ws_state);
    let ws_addr = format!("0.0.0.0:{}", config.ws_port);
    let ws_listener = tokio::net::TcpListener::bind(&ws_addr).await?;
    info!(addr = %ws_addr, "WebSocket server listening");
    tokio::spawn(async move {
        let graceful = axum::serve(ws_listener, ws_router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.wait_for(|&v| v).await;
                tracing::info!("WebSocket server shutting down");
            });
        if let Err(e) = graceful.await {
            tracing::error!(error = %e, "WebSocket server failed");
        }
    });
    Ok(())
}

/// Start the gRPC server with graceful shutdown.
async fn serve_grpc(svc: RiskServiceImpl, port: u16, shutdown_tx: tokio::sync::watch::Sender<bool>) -> anyhow::Result<()> {
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<RiskServiceServer<RiskServiceImpl>>()
        .await;

    let addr = format!("0.0.0.0:{}", port).parse()?;
    info!(%addr, "ag-risk gRPC server listening");

    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            RiskServiceServer::new(svc),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    // Signal the WebSocket server to shut down too.
    let _ = shutdown_tx.send(true);
    info!("ag-risk shut down gracefully");
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
