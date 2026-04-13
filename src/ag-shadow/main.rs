use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ag_common::config::{ShadowConfig, parse_nats_url};

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
use ag_license::{PlanGuard, FeatureFlags};
use anyhow::Result;
use tracing::{info, warn};

mod consumer;
mod enricher;

/// Ensure ClickHouse tables exist (idempotent, runs on every startup).
async fn ensure_clickhouse_tables(client: &clickhouse::Client) -> Result<()> {
    client.query(
        "CREATE TABLE IF NOT EXISTS shadow_logs (
            id String,
            trace_id String,
            timestamp UInt64,
            org_id String,
            agent_id String,
            agent_name String,
            user_id String,
            session_id String,
            tool_name String,
            tool_action String,
            params_hash String,
            prompt_hash String,
            assessed_risk Float32,
            session_risk_factor Float32,
            intent_classification String,
            policy_action String,
            policy_reason String,
            scope_requested String,
            scope_granted String,
            blocked UInt8,
            denial_reason String,
            latency_ms UInt16,
            masked_fields Array(String),
            pii_tokens Array(String),
            encodings_detected Array(String),
            encoding_risk_bonus Float32,
            intent_labels Array(String),
            matched_rules Array(String),
            boundary_violation String,
            session_flags Array(String),
            response_status_code UInt16,
            response_body_size UInt64,
            response_records_count UInt32,
            response_pii_detected UInt8,
            degraded_stages Array(String),
            params_summary String,
            response_hash String,
            derived_flags Array(String),
            caller_agent_id String,
            delegation_chain Array(String),
            delegation_trace_id String,
            delegation_depth UInt8,
            a2a_event_type LowCardinality(String) DEFAULT ''
        ) ENGINE = MergeTree()
        ORDER BY (org_id, agent_id, timestamp)
        PARTITION BY toYYYYMM(toDateTime(timestamp / 1000))"
    ).execute().await.map_err(|e| anyhow::anyhow!("Failed to create shadow_logs table: {}", e))?;

    // Migration: add a2a_event_type column to existing tables
    let _ = client.query("ALTER TABLE shadow_logs ADD COLUMN IF NOT EXISTS a2a_event_type LowCardinality(String) DEFAULT ''")
        .execute().await;

    client.query(
        "CREATE TABLE IF NOT EXISTS shadow_quarantine (
            id String,
            timestamp UInt64,
            org_id String,
            agent_id String,
            raw_event String,
            quarantine_reason String,
            quarantined_at UInt64
        ) ENGINE = MergeTree()
        ORDER BY (org_id, timestamp)"
    ).execute().await.map_err(|e| anyhow::anyhow!("Failed to create shadow_quarantine table: {}", e))?;

    Ok(())
}
mod lag_detector;
mod leader;
mod ner;
mod pii_masker;
mod quarantine;
mod retry;
mod tokenizer;
mod writer;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // License check: every service validates independently.
    ag_common::license_guard::enforce_or_exit("ag-shadow");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license — refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    // Log audit retention from license limits.
    info!(audit_retention_days = plan_guard.limits.audit_retention_days, "Audit retention from license");

    // PII quarantine feature check.
    if plan_guard.is_enabled(FeatureFlags::PII_QUARANTINE) {
        info!("PII quarantine feature enabled");
    } else {
        info!("PII quarantine feature not enabled — quarantine writes will be skipped");
    }

    let config = ShadowConfig::from_env();

    // Feature flag: enable leader/follower mode for multi-pod scaling.
    let leader_follower_enabled = std::env::var("AG_SHADOW_LEADER_FOLLOWER")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");
    info!(leader_follower = leader_follower_enabled, "ag-shadow starting");

    if leader_follower_enabled {
        // ── Leader/Follower mode ──
        //
        // Only the leader pod runs the JetStream consumer. Follower pods
        // wait and take over on failover (< 30s).

        // Initialize Redis pool for leader election.
        let leader_redis_manager =
            bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
        let leader_redis = bb8::Pool::builder()
            .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(4))
            .build(leader_redis_manager)
            .await?;

        let pod_id =
            std::env::var("POD_NAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
        let leader_election = Arc::new(leader::LeaderElection::new(
            leader_redis,
            pod_id.clone(),
            30, // TTL seconds
            10, // Renew interval seconds
        ));
        let is_leader = leader_election.is_leader_handle();
        info!(pod_id = %pod_id, "Shadow leader election initialized (Redis-backed)");

        // Spawn leader election loop.
        let le = leader_election.clone();
        tokio::spawn(async move {
            le.run_loop().await;
        });

        // Stable consumer name so the durable consumer survives restarts.
        let consumer_name = "ag-shadow-consumer".to_string();

        info!("Leader/follower mode: waiting for leadership before starting consumer");

        // Transition loop: start/stop consumer based on leadership.
        run_leader_consumer_loop(is_leader, config, consumer_name).await?;
    } else {
        // ── Legacy single-pod mode ──
        let (jetstream, nats_client, pii_masker, quarantine_writer, lag_detector, retry_policy, batch_writer) =
            init_consumer_deps(&config).await?;

        info!("Single-pod mode: consumer group ag-shadow-group");
        consumer::run_consumer(
            jetstream,
            nats_client,
            batch_writer,
            pii_masker,
            quarantine_writer,
            lag_detector,
            retry_policy,
        )
        .await?;
    }

    Ok(())
}

/// Initialize all consumer dependencies from config. Used by both legacy and
/// leader/follower modes to avoid duplicating setup code.
async fn init_consumer_deps(
    config: &ShadowConfig,
) -> Result<(
    async_nats::jetstream::Context,
    async_nats::Client,
    pii_masker::PiiMasker,
    quarantine::QuarantineWriter,
    lag_detector::LagDetector,
    retry::RetryPolicy,
    writer::BatchWriter,
)> {
    // Connect to NATS JetStream
    let nats = connect_nats(&config.nats_url).await?;
    let nats_client = nats.clone();
    let jetstream = async_nats::jetstream::new(nats);
    info!("Connected to NATS JetStream");

    // Connect to ClickHouse
    let mut ch_client = clickhouse::Client::default().with_url(&config.clickhouse_url);
    if let Some(user) = &config.clickhouse_user {
        ch_client = ch_client.with_user(user);
    }
    if let Some(password) = &config.clickhouse_password {
        ch_client = ch_client.with_password(password);
    }

    // Auto-create tables on startup (idempotent).
    ensure_clickhouse_tables(&ch_client).await?;
    info!("Connected to ClickHouse (tables verified)");

    // Initialize Redis pool for PII tokenization vault (if enabled)
    let pii_tokenizer = if config.pii_tokenization_enabled {
        match &config.pii_encryption_key {
            Some(key_hex) => {
                let key_bytes = hex::decode(key_hex)
                    .map_err(|e| anyhow::anyhow!("Invalid PII_ENCRYPTION_KEY hex: {}", e))?;
                if key_bytes.len() != 32 {
                    anyhow::bail!(
                        "PII_ENCRYPTION_KEY must be 64 hex chars (32 bytes), got {} bytes",
                        key_bytes.len()
                    );
                }
                let mut encryption_key = [0u8; 32];
                encryption_key.copy_from_slice(&key_bytes);

                let redis_manager =
                    bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
                let redis_pool = bb8::Pool::builder()
                    .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(8))
                    .build(redis_manager)
                    .await?;
                info!("PII tokenization Redis pool initialized");

                Arc::new(tokenizer::PiiTokenizer::new(
                    redis_pool,
                    config.pii_token_ttl_days,
                    encryption_key,
                ))
            }
            None => {
                anyhow::bail!(
                    "PII_TOKENIZATION_ENABLED=true but PII_ENCRYPTION_KEY is not set"
                );
            }
        }
    } else {
        info!("PII tokenization disabled, using irreversible masking");
        Arc::new(tokenizer::PiiTokenizer::noop())
    };

    // Initialize PII masker with NER and tokenizer
    let pii_masker = pii_masker::PiiMasker::new_with_ner(
        config.pii_ner_enabled,
        Some(pii_tokenizer),
    );
    info!(
        ner_enabled = config.pii_ner_enabled,
        tokenization_enabled = config.pii_tokenization_enabled,
        "PII masker initialized"
    );

    // Initialize quarantine writer
    let mut quarantine_ch = clickhouse::Client::default().with_url(&config.clickhouse_url);
    if let Some(user) = &config.clickhouse_user {
        quarantine_ch = quarantine_ch.with_user(user);
    }
    if let Some(password) = &config.clickhouse_password {
        quarantine_ch = quarantine_ch.with_password(password);
    }
    let quarantine_writer = quarantine::QuarantineWriter::new(quarantine_ch);
    info!("Quarantine writer initialized");

    let lag_detector = lag_detector::LagDetector::new();
    info!("Lag detector initialized");

    let retry_policy = retry::RetryPolicy::default();
    info!(
        max_retries = retry_policy.max_retries,
        initial_delay_ms = retry_policy.initial_delay.as_millis() as u64,
        "Retry policy initialized"
    );

    let batch_writer =
        writer::BatchWriter::new(ch_client, config.batch_size, config.flush_interval_secs);

    Ok((jetstream, nats_client, pii_masker, quarantine_writer, lag_detector, retry_policy, batch_writer))
}

/// Run the consumer only when this pod is leader. On leadership loss, the
/// consumer task is aborted. On re-acquisition, a new consumer is spawned
/// with fresh connections.
async fn run_leader_consumer_loop(
    is_leader: Arc<AtomicBool>,
    config: ShadowConfig,
    consumer_name: String,
) -> Result<()> {
    let mut was_leader = false;
    let mut consumer_handle: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let is_now_leader = is_leader.load(Ordering::Relaxed);

        if is_now_leader && !was_leader {
            // Became leader — spawn consumer with fresh connections.
            info!("Became shadow leader — starting consumer");

            let cfg = config.clone();
            let cn = consumer_name.clone();

            consumer_handle = Some(tokio::spawn(async move {
                // Initialize all deps fresh for this leader term.
                let deps = match init_consumer_deps(&cfg).await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to init consumer deps for leader term");
                        return;
                    }
                };

                let (jetstream, nats_client, pii_masker, quarantine_writer, lag_detector, retry_policy, batch_writer) = deps;

                if let Err(e) = consumer::run_consumer_named(
                    jetstream,
                    nats_client,
                    batch_writer,
                    pii_masker,
                    quarantine_writer,
                    lag_detector,
                    retry_policy,
                    &cn,
                )
                .await
                {
                    tracing::error!(error = %e, "Shadow leader consumer exited with error");
                }
            }));
        } else if !is_now_leader && was_leader {
            // Lost leadership — abort consumer.
            warn!("Lost shadow leadership — stopping consumer");
            if let Some(handle) = consumer_handle.take() {
                handle.abort();
            }
        }

        was_leader = is_now_leader;
    }
}
