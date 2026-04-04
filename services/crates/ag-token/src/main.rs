use std::sync::Arc;

use ag_common::config::{TokenConfig, parse_nats_url};

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
use ag_token::{
    connectors::{IdpConfig, IdpProvider},
    idp_mode::IdpMode,
    idp_store,
    signing,
};
use anyhow::Result;
use arc_swap::ArcSwap;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;
use tracing::{info, warn};

use ag_token::service::TokenServiceImpl;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // License check: every service validates independently.
    ag_common::license_guard::enforce_or_exit("ag-token");

    // Validate license JWT and extract plan guard for feature gating.
    let plan_guard = Arc::new(
        PlanGuard::from_license_jwt(
            &std::env::var("CLAMPD_LICENSE_KEY").expect("CLAMPD_LICENSE_KEY required"),
        )
        .expect("Invalid or tampered license — refusing to start"),
    );
    info!(plan = %plan_guard.plan, org_id = %plan_guard.org_id, "Plan guard initialized");

    let config = TokenConfig::from_env();

    // Connect to Redis (required — refuse to start if unreachable)
    let redis_manager = bb8_redis::RedisConnectionManager::new(config.redis_url.clone())?;
    let redis_pool = bb8::Pool::builder()
        .max_size(std::env::var("REDIS_POOL_MAX_SIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(16))
        .build(redis_manager)
        .await?;
    info!("Connected to Redis");

    // Determine IdP mode from config
    let idp_mode = match config.idp_provider.as_str() {
        "none" => {
            info!("IDP_PROVIDER=none — IdP exchange disabled, micro-token-only mode");
            IdpMode::Disabled
        }
        provider @ ("keycloak" | "okta" | "azure_ad") => {
            if config.idp_config_source == "database" {
                // Database-backed: connect to PostgreSQL, load configs, start hot-reload
                let pg_pool = PgPoolOptions::new()
                    .max_connections(8)
                    .connect(&config.database_url)
                    .await?;
                info!("Connected to PostgreSQL (for IdP config)");

                sqlx::migrate!("./migrations")
                    .run(&pg_pool)
                    .await
                    .map_err(|e| anyhow::anyhow!("Migration failed: {}", e))?;
                info!("Database migrations applied");

                let store = Arc::new(
                    idp_store::IdpStore::new(pg_pool.clone())
                        .await
                        .map_err(|e| anyhow::anyhow!("IdP store init failed: {}", e))?,
                );

                store
                    .clone()
                    .spawn_reload_listener(config.nats_url.clone());

                info!(provider, config_source = "database", "IdP enabled via database");
                IdpMode::DatabaseBacked(store)
            } else {
                // Env-backed: build IdpConfig from environment variables
                let idp_config = build_idp_config_from_env(provider, &config)?;
                info!(provider, config_source = "env", "IdP enabled via environment");
                IdpMode::EnvBacked(idp_config)
            }
        }
        other => {
            anyhow::bail!("Unknown IDP_PROVIDER: {}. Valid: none, keycloak, okta, azure_ad", other);
        }
    };

    // Load or generate signing key — persisted to Redis for pod-restart survival.
    // Seed is encrypted with AG_TOKEN_ENCRYPTION_KEY before storage (P2-13 fix).
    // If encryption key is not set, stores with PLAIN: prefix and logs a warning.
    let encryption_key = std::env::var("AG_TOKEN_ENCRYPTION_KEY").unwrap_or_default();
    if encryption_key.is_empty() {
        warn!("AG_TOKEN_ENCRYPTION_KEY not set — signing key stored unencrypted in Redis. \
               Set this env var in production for defense-in-depth.");
    }

    let signing_key = {
        let mut conn = redis_pool.get().await?;

        let active_kid: Option<String> = redis::cmd("GET")
            .arg("ag:signing:active_kid")
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);

        if let Some(kid) = active_kid {
            let seed_key = format!("ag:signing:key:{}", kid);
            let stored: Option<String> = redis::cmd("GET")
                .arg(&seed_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or(None);

            if let Some(stored_seed) = stored {
                match signing::SigningKeyManager::decrypt_seed_from_storage(&stored_seed, &encryption_key) {
                    Ok(seed_arr) => {
                        let manager = signing::SigningKeyManager::from_seed(&seed_arr, kid.clone());
                        info!("Restored signing key from Redis: kid={}", kid);
                        manager
                    }
                    Err(e) => {
                        warn!("Failed to decrypt signing key seed: {} — generating new key", e);
                        let manager = signing::SigningKeyManager::generate();
                        let encrypted = manager.encrypt_seed_for_storage(&encryption_key);
                        let _: () = redis::cmd("SET").arg("ag:signing:active_kid").arg(manager.active_kid()).query_async(&mut *conn).await.unwrap_or(());
                        let _: () = redis::cmd("SET").arg(format!("ag:signing:key:{}", manager.active_kid())).arg(&encrypted).query_async(&mut *conn).await.unwrap_or(());
                        manager
                    }
                }
            } else {
                let manager = signing::SigningKeyManager::generate();
                let encrypted = manager.encrypt_seed_for_storage(&encryption_key);
                let _: () = redis::cmd("SET").arg("ag:signing:active_kid").arg(manager.active_kid()).query_async(&mut *conn).await.unwrap_or(());
                let _: () = redis::cmd("SET").arg(format!("ag:signing:key:{}", manager.active_kid())).arg(&encrypted).query_async(&mut *conn).await.unwrap_or(());
                info!("Generated new signing key (no seed in Redis): kid={}", manager.active_kid());
                manager
            }
        } else {
            let manager = signing::SigningKeyManager::generate();
            let encrypted = manager.encrypt_seed_for_storage(&encryption_key);
            let _: () = redis::cmd("SET").arg("ag:signing:active_kid").arg(manager.active_kid()).query_async(&mut *conn).await.unwrap_or(());
            let _: () = redis::cmd("SET").arg(format!("ag:signing:key:{}", manager.active_kid())).arg(&encrypted).query_async(&mut *conn).await.unwrap_or(());
            info!("Generated new signing key: kid={}", manager.active_kid());
            manager
        }
    };

    let key_manager = Arc::new(signing_key);
    info!(kid = %key_manager.active_kid(), "Ed25519 signing key initialized");

    // Wrap in ArcSwap for hot-rotation
    let key_swap: Arc<ArcSwap<signing::SigningKeyManager>> =
        Arc::new(ArcSwap::from(key_manager.clone()));
    info!(kid = %key_swap.load().active_kid(), "Key rotation enabled via ArcSwap");

    // Subscribe to key rotation events via NATS
    let key_swap_clone = key_swap.clone();
    let nats_url = config.nats_url.clone();
    tokio::spawn(async move {
        match connect_nats(&nats_url).await {
            Ok(client) => {
                let mut sub = match client.subscribe("agentguard.keys.rotated").await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to subscribe to key rotation: {}", e);
                        return;
                    }
                };
                info!("Listening for key rotation events on NATS");
                while let Some(msg) = futures::StreamExt::next(&mut sub).await {
                    if let Ok(payload) =
                        serde_json::from_slice::<serde_json::Value>(&msg.payload)
                    {
                        if let (Some(seed_hex), Some(kid)) =
                            (payload["seed_hex"].as_str(), payload["kid"].as_str())
                        {
                            if let Ok(seed_bytes) = hex::decode(seed_hex) {
                                if seed_bytes.len() == 32 {
                                    let mut seed = [0u8; 32];
                                    seed.copy_from_slice(&seed_bytes);
                                    let new_km = signing::SigningKeyManager::from_seed(
                                        &seed,
                                        kid.to_string(),
                                    );
                                    key_swap_clone.store(Arc::new(new_km));
                                    info!(kid = kid, "Signing key rotated via NATS");
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!("NATS connection failed for key rotation: {}", e);
            }
        }
    });

    let port = config.port;
    let svc = TokenServiceImpl::new(redis_pool, key_manager, config, idp_mode, plan_guard);

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ag_proto::agentguard::token::token_service_server::TokenServiceServer<TokenServiceImpl>>()
        .await;

    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    info!("ag-token listening on {}", addr);

    let mut builder = Server::builder();
    if let Some(tls) = ag_common::tls::server_tls_config() {
        builder = builder.tls_config(tls)?;
    }
    builder
        .add_service(health_service)
        .add_service(tonic::service::interceptor::InterceptedService::new(
            ag_proto::agentguard::token::token_service_server::TokenServiceServer::new(svc),
            server_auth_interceptor,
        ))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("ag-token shut down gracefully");
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

/// Build an IdpConfig from environment variables (env-backed mode).
fn build_idp_config_from_env(provider: &str, config: &TokenConfig) -> Result<IdpConfig> {
    let idp_provider = match provider {
        "keycloak" => IdpProvider::Keycloak,
        "okta" => IdpProvider::Okta,
        "azure_ad" => IdpProvider::AzureAd,
        _ => anyhow::bail!("Unknown provider: {}", provider),
    };

    // Build token endpoint from provider-specific env vars
    let token_endpoint = match provider {
        "keycloak" => {
            let url = config.keycloak_url.as_deref()
                .ok_or_else(|| anyhow::anyhow!("KEYCLOAK_URL required when IDP_PROVIDER=keycloak"))?;
            let realm = config.keycloak_realm.as_deref()
                .ok_or_else(|| anyhow::anyhow!("KEYCLOAK_REALM required when IDP_PROVIDER=keycloak"))?;
            format!("{}/realms/{}/protocol/openid-connect/token", url, realm)
        }
        _ => {
            // For okta/azure_ad, expect a generic token endpoint env var
            std::env::var("IDP_TOKEN_ENDPOINT")
                .map_err(|_| anyhow::anyhow!("IDP_TOKEN_ENDPOINT required for {}", provider))?
        }
    };

    let client_id = match provider {
        "keycloak" => config.keycloak_client_id.clone()
            .ok_or_else(|| anyhow::anyhow!("KEYCLOAK_CLIENT_ID required"))?,
        _ => std::env::var("IDP_CLIENT_ID")
            .map_err(|_| anyhow::anyhow!("IDP_CLIENT_ID required for {}", provider))?,
    };

    let client_secret = match provider {
        "keycloak" => config.keycloak_client_secret.clone()
            .ok_or_else(|| anyhow::anyhow!("KEYCLOAK_CLIENT_SECRET required"))?,
        _ => std::env::var("IDP_CLIENT_SECRET")
            .map_err(|_| anyhow::anyhow!("IDP_CLIENT_SECRET required for {}", provider))?,
    };

    Ok(IdpConfig {
        id: format!("env-{}", provider),
        provider: idp_provider,
        token_endpoint,
        client_id,
        client_secret,
        audience: std::env::var("IDP_AUDIENCE").ok(),
        extra_scopes: Vec::new(),
        timeout_ms: 5000,
        enabled: true,
    })
}
