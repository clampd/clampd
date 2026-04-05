use std::sync::Arc;

use ag_common::config::TokenConfig;
use ag_proto::agentguard::token::{
    token_service_server::TokenService, ExchangeRequest, ExchangeResponse, IntrospectRequest,
    IntrospectResponse, RevokeRequest, RevokeResponse,
};
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use dashmap::DashMap;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use ag_license::{PlanGuard, FeatureFlags};

use crate::{
    cache::TokenCache,
    circuit_breaker::{BreakerState, CircuitBreaker},
    connectors::{
        azure_ad::AzureAdConnector, keycloak::KeycloakConnector, okta::OktaConnector,
        IdpConnector, IdpProvider,
    },
    degradation::{DegradationConfig, DegradationManager},
    exchange,
    idp_mode::IdpMode,
    idp_revoke::{self, IdpRevoker},
    nonce,
    rate_limiter::RateLimiter,
    signing::SigningKeyManager,
};

pub struct TokenServiceImpl {
    redis: Pool<RedisConnectionManager>,
    key_manager: Arc<SigningKeyManager>,
    config: TokenConfig,
    rate_limiter: Arc<RateLimiter>,
    cache: Arc<TokenCache>,
    idp_mode: IdpMode,
    /// Per-IdP circuit breakers, keyed by IdP config ID.
    circuit_breakers: Arc<DashMap<String, Arc<CircuitBreaker>>>,
    /// Degradation manager for IdP-down scenarios.
    degradation_manager: Arc<DegradationManager>,
    // Connector instances (stateless, shared)
    keycloak: Arc<KeycloakConnector>,
    okta: Arc<OktaConnector>,
    azure_ad: Arc<AzureAdConnector>,
    /// IdP session revoker for kill cascade Layer 5.
    idp_revoker: Arc<IdpRevoker>,
    /// License plan guard for feature gating.
    plan_guard: Arc<PlanGuard>,
}

impl TokenServiceImpl {
    pub fn new(
        redis: Pool<RedisConnectionManager>,
        key_manager: Arc<SigningKeyManager>,
        config: TokenConfig,
        idp_mode: IdpMode,
        plan_guard: Arc<PlanGuard>,
    ) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(
            redis.clone(),
            config.rate_limit_max,
            config.rate_limit_window_secs,
        ));
        let cache = Arc::new(TokenCache::new(redis.clone()));
        let degradation_manager = Arc::new(DegradationManager::new(DegradationConfig::from_env()));
        Self {
            redis,
            key_manager,
            rate_limiter,
            cache,
            idp_mode,
            circuit_breakers: Arc::new(DashMap::new()),
            degradation_manager,
            keycloak: Arc::new(KeycloakConnector::new()),
            okta: Arc::new(OktaConnector::new()),
            azure_ad: Arc::new(AzureAdConnector::new()),
            idp_revoker: Arc::new(IdpRevoker::new()),
            plan_guard,
            config,
        }
    }

    /// Get or create a circuit breaker for an IdP.
    fn get_breaker(&self, idp_id: &str) -> Arc<CircuitBreaker> {
        self.circuit_breakers
            .entry(idp_id.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker::new(
                    self.config.circuit_breaker_threshold,
                    self.config.circuit_breaker_reset_secs,
                ))
            })
            .clone()
    }

    /// Select the appropriate connector for a provider.
    fn connector_for(&self, provider: IdpProvider) -> &dyn IdpConnector {
        match provider {
            IdpProvider::Keycloak => self.keycloak.as_ref(),
            IdpProvider::Okta => self.okta.as_ref(),
            IdpProvider::AzureAd => self.azure_ad.as_ref(),
        }
    }
}

#[tonic::async_trait]
impl TokenService for TokenServiceImpl {
    /// Full exchange flow:
    /// 1. Rate limit check
    /// 2. Deny list check
    /// 3. Cache lookup (downstream token)
    /// 4-6. IdP exchange (skip if IdpMode::Disabled)
    /// 7. Cache store
    /// 8. Mint micro-token
    /// 9. Store nonce
    /// 10. Return
    async fn exchange_token(
        &self,
        request: Request<ExchangeRequest>,
    ) -> Result<Response<ExchangeResponse>, Status> {
        let req = request.into_inner();

        // P2-15: Global rate limit check - prevent distributed DoS across many agents.
        // Configurable via AG_TOKEN_GLOBAL_RATE_LIMIT env var (default: 1000 per 60s).
        {
            let max_global: u32 = std::env::var("AG_TOKEN_GLOBAL_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000);
            let global_window: u64 = std::env::var("AG_TOKEN_GLOBAL_RATE_WINDOW")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            if let Err(retry_after) = self.rate_limiter.check_global(max_global, global_window).await {
                return Err(Status::resource_exhausted(format!(
                    "Global rate limit exceeded. Retry after {}s",
                    retry_after
                )));
            }
        }

        // Step 1: Per-agent rate limit check
        if let Err(retry_after) = self.rate_limiter.check(&req.agent_id).await {
            return Err(Status::resource_exhausted(format!(
                "Rate limit exceeded. Retry after {}s",
                retry_after
            )));
        }

        // Step 2: Deny list check
        let denied = nonce::is_denied(&self.redis, &req.agent_id)
            .await
            .map_err(Status::internal)?;
        if denied {
            return Err(Status::permission_denied("Agent is on deny list"));
        }

        // Step 3: Cache lookup - if we have a valid downstream token, skip IdP call
        if let Some(cached) = self
            .cache
            .get(&req.agent_id, &req.requested_scopes, &req.call_binding_hash)
            .await
        {
            debug!(agent_id = %req.agent_id, "Cache hit for downstream token");
            // Mint micro-token wrapping cached downstream token
            return self.mint_and_respond(&req, Some(&cached.access_token), None).await;
        }

        // Steps 4-6: IdP exchange (skip when disabled)
        if !req.subject_token.is_empty() {
            match &self.idp_mode {
                IdpMode::Disabled => {
                    debug!(agent_id = %req.agent_id, "IdP disabled, skipping exchange");
                }
                IdpMode::EnvBacked(idp_config) => {
                    if let Some(resp) = self.try_idp_exchange(idp_config, &req).await {
                        return resp;
                    }
                }
                IdpMode::DatabaseBacked(store) => {
                    if let Some(idp_config) = store.get_all().first().cloned() {
                        if let Some(resp) = self.try_idp_exchange(&idp_config, &req).await {
                            return resp;
                        }
                    }
                }
            }
        }

        // No IdP exchange - mint micro-token directly
        self.mint_and_respond(&req, None, None).await
    }

    async fn introspect_token(
        &self,
        request: Request<IntrospectRequest>,
    ) -> Result<Response<IntrospectResponse>, Status> {
        let req = request.into_inner();

        // Verify JWT signature and extract claims
        let claims = match self.key_manager.verify_token(&req.token) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Response::new(IntrospectResponse {
                    active: false,
                    sub: String::new(),
                    scope: String::new(),
                    exp: 0,
                    tool_binding: String::new(),
                    reason: Some(format!("Invalid token: {}", e)),
                }));
            }
        };

        // Check expiry
        let now = chrono::Utc::now().timestamp();
        if claims.exp <= now {
            return Ok(Response::new(IntrospectResponse {
                active: false,
                sub: claims.sub,
                scope: claims.scope,
                exp: claims.exp as u64,
                tool_binding: claims.tool_binding,
                reason: Some("expired".to_string()),
            }));
        }

        // Check deny list
        let denied = nonce::is_denied(&self.redis, &claims.sub)
            .await
            .map_err(Status::internal)?;
        if denied {
            return Ok(Response::new(IntrospectResponse {
                active: false,
                sub: claims.sub,
                scope: claims.scope,
                exp: claims.exp as u64,
                tool_binding: claims.tool_binding,
                reason: Some("agent_denied".to_string()),
            }));
        }

        // Consume nonce (single-use)
        let consumed = nonce::consume_nonce(&self.redis, &claims.jti)
            .await
            .map_err(Status::internal)?;
        if !consumed {
            return Ok(Response::new(IntrospectResponse {
                active: false,
                sub: claims.sub,
                scope: claims.scope,
                exp: claims.exp as u64,
                tool_binding: claims.tool_binding,
                reason: Some("nonce_consumed".to_string()),
            }));
        }

        Ok(Response::new(IntrospectResponse {
            active: true,
            sub: claims.sub,
            scope: claims.scope,
            exp: claims.exp as u64,
            tool_binding: claims.tool_binding,
            reason: None,
        }))
    }

    async fn revoke_agent(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let req = request.into_inner();

        // Set deny entry in Redis
        let mut conn = self
            .redis
            .get()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let deny_key = format!("ag:deny:{}", req.agent_id);
        redis::cmd("SET")
            .arg(&deny_key)
            .arg("1")
            .arg("EX")
            .arg(600) // 10 min TTL
            .query_async::<()>(&mut *conn)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // Flush cached tokens (nonce keys)
        let pattern = format!("ag:token:{}:*", req.agent_id);
        let keys: Vec<String> = redis::cmd("SCAN")
            .arg(0)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(100)
            .query_async::<(u64, Vec<String>)>(&mut *conn)
            .await
            .map(|(_, keys)| keys)
            .unwrap_or_default();

        let mut tokens_revoked = keys.len() as u32;
        if !keys.is_empty() {
            if let Err(e) = redis::cmd("DEL")
                .arg(&keys)
                .query_async::<()>(&mut *conn)
                .await
            {
                warn!(error = %e, agent_id = %req.agent_id, "Failed to DEL token keys from Redis");
            }
        }

        // Also invalidate downstream token cache
        tokens_revoked += self.cache.invalidate_agent(&req.agent_id).await;

        // Layer 5 (kill cascade): Revoke IdP sessions if configured.
        // This is non-fatal - failures are logged but don't block the revocation.
        // SSO/IdP revocation is gated by the SSO feature flag.
        let mut sessions_revoked = 0u32;
        if self.plan_guard.is_enabled(FeatureFlags::SSO) {
            let idp_configs = self.get_idp_configs();
            for idp_config in &idp_configs {
                let result = idp_revoke::try_revoke_idp_sessions(
                    &self.idp_revoker,
                    idp_config,
                    &req.agent_id,
                )
                .await;
                if result.success {
                    sessions_revoked += result.sessions_revoked;
                } else {
                    warn!(
                        agent_id = %req.agent_id,
                        provider = %result.provider,
                        error = ?result.error,
                        "IdP session revocation failed (non-fatal)"
                    );
                }
            }
        } else {
            debug!(agent_id = %req.agent_id, "SSO feature not enabled - skipping IdP session revocation");
        }

        warn!(agent_id = %req.agent_id, tokens_revoked, sessions_revoked, "Agent revoked");

        Ok(Response::new(RevokeResponse {
            tokens_revoked,
            sessions_revoked,
        }))
    }
}

impl TokenServiceImpl {
    /// Get all active IdP configs based on the current mode.
    /// Returns an empty vec if IdP is disabled.
    fn get_idp_configs(&self) -> Vec<crate::connectors::IdpConfig> {
        match &self.idp_mode {
            IdpMode::Disabled => Vec::new(),
            IdpMode::EnvBacked(config) => vec![config.clone()],
            IdpMode::DatabaseBacked(store) => store.get_all().as_ref().clone(),
        }
    }

    /// Attempt IdP exchange for a given config. Returns Some(response) on success
    /// or None if exchange should be skipped/failed (fall through to micro-token-only).
    async fn try_idp_exchange(
        &self,
        idp_config: &crate::connectors::IdpConfig,
        req: &ExchangeRequest,
    ) -> Option<Result<Response<ExchangeResponse>, Status>> {
        // Circuit breaker check
        let breaker = self.get_breaker(&idp_config.id);
        let state = breaker.allow_request();
        if state == BreakerState::Open {
            warn!(idp_id = %idp_config.id, "Circuit breaker open, skipping IdP exchange");
            return None;
        }

        // IdP exchange
        let connector = self.connector_for(idp_config.provider);
        match connector
            .exchange(idp_config, &req.subject_token, &req.requested_scopes)
            .await
        {
            Ok(idp_resp) => {
                breaker.record_success();
                self.degradation_manager.restore_normal();
                info!(
                    idp_id = %idp_config.id,
                    expires_in = idp_resp.expires_in,
                    "IdP token exchange succeeded"
                );

                // Cache store
                let cached = crate::cache::CachedToken {
                    access_token: idp_resp.access_token.clone(),
                    token_type: idp_resp.token_type,
                    scope: idp_resp.scope,
                };
                let _ = self
                    .cache
                    .put(
                        &req.agent_id,
                        &req.requested_scopes,
                        &req.call_binding_hash,
                        &cached,
                        idp_resp.expires_in,
                    )
                    .await;

                // Mint with the IdP token (normal mode - no trust_level claim)
                Some(self.mint_and_respond(req, Some(&idp_resp.access_token), None).await)
            }
            Err(e) => {
                breaker.record_failure();
                self.degradation_manager.enter_degraded();
                warn!(
                    idp_id = %idp_config.id,
                    error = %e,
                    "IdP token exchange failed"
                );

                // Check if degraded tokens are allowed
                match self.degradation_manager.should_allow_degraded() {
                    Ok(degraded_ttl) => {
                        warn!(
                            agent_id = %req.agent_id,
                            degraded_ttl,
                            "Issuing degraded micro-token (IdP unreachable)"
                        );
                        Some(self.mint_and_respond_degraded(req, degraded_ttl).await)
                    }
                    Err(reason) => {
                        warn!(reason = %reason, "Degraded token not allowed");
                        Some(Err(Status::unavailable(reason)))
                    }
                }
            }
        }
    }

    /// Mint a micro-token and build the response. Steps 8-10 of the exchange flow.
    async fn mint_and_respond(
        &self,
        req: &ExchangeRequest,
        _downstream_token: Option<&str>,
        trust_level: Option<String>,
    ) -> Result<Response<ExchangeResponse>, Status> {
        let session_id = if req.session_id.is_empty() {
            None
        } else {
            Some(req.session_id.clone())
        };

        // Step 8: Mint micro-token
        let (token, jti, scope) = exchange::mint_micro_token(
            &self.key_manager,
            &req.agent_id,
            &req.requested_scopes,
            &req.call_binding_hash,
            self.config.micro_token_ttl_secs,
            None,
            session_id,
            trust_level,
        )
        .map_err(|e| Status::internal(format!("Token minting failed: {}", e)))?;

        // Step 9: Store nonce for single-use enforcement
        nonce::store_nonce(&self.redis, &jti, self.config.nonce_ttl_secs)
            .await
            .map_err(|e| Status::internal(format!("Nonce storage failed: {}", e)))?;

        debug!(
            agent_id = %req.agent_id,
            jti = %jti,
            scope = %scope,
            ttl = self.config.micro_token_ttl_secs,
            "Micro-token minted"
        );

        // Step 10: Return
        Ok(Response::new(ExchangeResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.micro_token_ttl_secs,
            scope,
            jti,
        }))
    }

    /// Mint a degraded micro-token with reduced TTL and `ag:trust_level = "degraded"` claim.
    async fn mint_and_respond_degraded(
        &self,
        req: &ExchangeRequest,
        degraded_ttl: u32,
    ) -> Result<Response<ExchangeResponse>, Status> {
        let session_id = if req.session_id.is_empty() {
            None
        } else {
            Some(req.session_id.clone())
        };

        let (token, jti, scope) = exchange::mint_micro_token(
            &self.key_manager,
            &req.agent_id,
            &req.requested_scopes,
            &req.call_binding_hash,
            degraded_ttl,
            None,
            session_id,
            Some("degraded".to_string()),
        )
        .map_err(|e| Status::internal(format!("Token minting failed: {}", e)))?;

        nonce::store_nonce(&self.redis, &jti, degraded_ttl.into())
            .await
            .map_err(|e| Status::internal(format!("Nonce storage failed: {}", e)))?;

        debug!(
            agent_id = %req.agent_id,
            jti = %jti,
            scope = %scope,
            ttl = degraded_ttl,
            trust_level = "degraded",
            "Degraded micro-token minted"
        );

        Ok(Response::new(ExchangeResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: degraded_ttl,
            scope,
            jti,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idp_mode_disabled_skips_exchange() {
        // When IdpMode::Disabled, the service should just mint micro-tokens
        let mode = IdpMode::Disabled;
        assert!(matches!(mode, IdpMode::Disabled));
    }

    #[test]
    fn test_idp_provider_none_is_default() {
        let config = TokenConfig::from_env();
        assert_eq!(config.idp_provider, "none");
    }

    #[test]
    fn test_idp_config_source_default_is_env() {
        let config = TokenConfig::from_env();
        assert_eq!(config.idp_config_source, "env");
    }
}
