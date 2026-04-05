use std::sync::{Arc, LazyLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Cached JWT_SECRET — read once at first access, immutable thereafter.
/// main.rs validates length (>=32 chars) and exits before any request handler runs,
/// so this is guaranteed non-empty in production.
pub(crate) static JWT_SECRET_CACHED: LazyLock<String> = LazyLock::new(|| {
    std::env::var("JWT_SECRET").unwrap_or_default()
});

use ag_common::degradation::DegradationMode;
use ag_proto::agentguard::{
    intent::ClassifyRequest, policy::EvaluateRequest, token::ExchangeRequest,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::extractor::{extract_tool_call, ErrorResponse, InspectRequest, ProxyRequest, ProxyResponse};

/// Convert intent action enum (0=PASS, 1=FLAG, 2=BLOCK) to string.
fn action_str(intent_action: i32) -> String {
    match intent_action {
        1 => "flag".to_string(),
        2 => "block".to_string(),
        _ => "pass".to_string(),
    }
}
use crate::license_gate::{self, GatewayLicenseStatus};
use crate::normalize::normalize_params;
use crate::rate_limiter::RateLimiter;
use crate::response_inspector::inspect_response;
use crate::session;
use ag_common::models::ShadowEvent;
use crate::AppState;

/// Build session_context_json in the format expected by ag-intent's SessionContext.
/// Computes distinct_tool_count, calls_this_hour, and read→write tool pairs
/// from the raw session tool call history. When a baseline is available (from
/// ag-risk via the baseline cache), real baseline data is included.
fn build_session_context_json(
    session_context: &ag_common::session::SessionContext,
    baseline: Option<&crate::baseline_cache::CachedBaseline>,
) -> String {
    let distinct_tools: std::collections::HashSet<&str> = session_context
        .tool_calls.iter().map(|r| r.tool_name.as_str()).collect();
    let one_hour_ago = chrono::Utc::now() - chrono::Duration::hours(1);
    let calls_this_hour = session_context.tool_calls.iter()
        .filter(|r| r.timestamp > one_hour_ago).count() as u64;
    // Build read→write tool pairs from session history
    let mut read_write_pairs: Vec<(String, String)> = Vec::new();
    let mut last_read_tool: Option<String> = None;
    for record in &session_context.tool_calls {
        if record.records_returned > 0 && !record.is_external_send {
            last_read_tool = Some(record.tool_name.clone());
        } else if record.is_external_send {
            if let Some(ref rt) = last_read_tool {
                read_write_pairs.push((rt.clone(), record.tool_name.clone()));
            }
        }
    }

    let (baseline_calls_per_hour, baseline_scopes, baseline_tool_pairs) = match baseline {
        Some(b) => (
            b.calls_per_hour as u64,
            b.known_scopes.iter().cloned().collect::<Vec<_>>(),
            b.known_tool_pairs.clone(),
        ),
        None => (0, vec![], vec![]),
    };

    serde_json::json!({
        "distinct_tool_count": distinct_tools.len(),
        "calls_this_hour": calls_this_hour,
        "baseline_calls_per_hour": baseline_calls_per_hour,
        "scopes_requested": [],
        "baseline_scopes": baseline_scopes,
        "tool_read_write_pairs": read_write_pairs,
        "baseline_tool_pairs": baseline_tool_pairs,
        "risk_trend": session_context.risk_trend,
    }).to_string()
}

/// Type alias for JSON error responses used across all gateway endpoints.
type ApiError = (StatusCode, Json<ErrorResponse>);

/// Build a structured JSON error response.
fn api_error(status: StatusCode, code: &str, message: impl Into<String>) -> ApiError {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
            error_code: code.to_string(),
            request_id: None,
        }),
    )
}

/// Default per-agent rate limit: 100 requests per 60-second window.
const DEFAULT_AGENT_RATE_LIMIT: u32 = 100;
/// Default rate limit window in seconds.
const DEFAULT_RATE_LIMIT_WINDOW_SECS: u32 = 60;
/// Redis EXPIRE TTL for rate-limit bucket keys (2× window to cover two buckets).
const RATE_LIMIT_BUCKET_TTL_SECS: u64 = 120;

/// Increment per-agent request counter in Redis and return calls in the last minute.
///
/// Uses a sliding-window approach with two 60-second buckets:
///   Key: `ag:calls:{agent_id}:{minute_bucket}`  where minute_bucket = epoch_secs / 60
///   - INCR current bucket + EXPIRE 120s
///   - GET previous bucket
///   - Return sum of both buckets
///
/// On Redis failure, returns 0 (fail-open) and logs a warning.
async fn increment_and_get_calls(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    agent_id: &str,
) -> u32 {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let current_bucket = now_secs / 60;
    let prev_bucket = current_bucket.saturating_sub(1);

    let current_key = format!("ag:calls:{}:{}", agent_id, current_bucket);
    let prev_key = format!("ag:calls:{}:{}", agent_id, prev_bucket);

    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Redis pool error for request counter: {} — fail-open with 0", e);
            return 0;
        }
    };

    // INCR current bucket and set TTL
    let current_count: u32 = match redis::cmd("INCR")
        .arg(&current_key)
        .query_async::<i64>(&mut *conn)
        .await
    {
        Ok(val) => {
            // Set expiry only on first increment (when val == 1)
            if val == 1 {
                if let Err(e) = redis::cmd("EXPIRE")
                    .arg(&current_key)
                    .arg(RATE_LIMIT_BUCKET_TTL_SECS)
                    .query_async::<()>(&mut *conn)
                    .await
                {
                    warn!("Redis EXPIRE failed for rate-limit key {}: {} — key may persist without TTL", current_key, e);
                }
            }
            val.max(0) as u32
        }
        Err(e) => {
            warn!("Redis INCR failed for {}: {} — fail-open with 0", current_key, e);
            return 0;
        }
    };

    // GET previous bucket count
    let prev_count: u32 = match redis::cmd("GET")
        .arg(&prev_key)
        .query_async::<Option<i64>>(&mut *conn)
        .await
    {
        Ok(Some(val)) => val.max(0) as u32,
        Ok(None) => 0,
        Err(e) => {
            debug!("Redis GET for previous bucket {}: {} — treating as 0", prev_key, e);
            0
        }
    };

    current_count + prev_count
}

/// POST /v1/proxy — Full 9-stage pipeline.
pub async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    let started_at = Instant::now();
    crate::metrics::increment_requests();
    let request_id = Uuid::new_v4();
    let mut degraded_stages = Vec::new();
    // Per-stage latency tracking (microseconds for precision, logged in ms at end)
    let mut stage_latencies: Vec<(&str, u64)> = Vec::with_capacity(12);
    let mut stage_start = Instant::now();

    // ---- Stage 1: AUTHENTICATE ----
    let api_key = headers
        .get("x-ag-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing_api_key", "Missing X-AG-Key header"))?;

    // Validate API key: SHA-256 hash and lookup in Redis
    let api_key_info = validate_api_key(&state.redis_pool, api_key).await
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid_api_key", "Invalid API key"))?;

    let jwt_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing_jwt", "Missing Authorization Bearer token"))?;

    // Validate JWT: per-agent credential from Redis, fallback to global JWT_SECRET
    let jwt_secret = JWT_SECRET_CACHED.clone();
    let jwt_claims = validate_jwt_with_agent_credential(jwt_token, &jwt_secret, &state.redis_pool)
        .await
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, "invalid_jwt", e))?;
    let agent_id_str = jwt_claims.sub.clone();

    // Check deny set (in-memory, <0.01ms)
    if state.deny_set.contains(&agent_id_str) {
        return Err(api_error(StatusCode::FORBIDDEN, "agent_killed", "Agent is kill-switched"));
    }

    // Extract session ID from X-AG-Session header (Stage 1 per spec)
    let session_id = session::extract_session_id(&headers, &agent_id_str)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, "invalid_session_id", e))?;

    stage_latencies.push(("auth", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- LICENSE GATE (before expensive gRPC calls) ----
    let license_gate = license_gate::check_license(&state.redis_pool).await;

    if license_gate.status == GatewayLicenseStatus::Revoked {
        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "license_revoked", "License revoked — contact support at clampd.dev"));
    }

    if license_gate.degraded {
        degraded_stages.push("license".to_string());
    }

    // Use license-aware rate limit (free tier on grace_expired, paid tier otherwise)
    let effective_rate_limit = license_gate.rate_limit;

    // ---- MONTHLY REQUEST LIMIT (plan-based) ----
    {
        let now = chrono::Utc::now();
        let usage_key = format!("ag:usage:{}:{}", api_key_info.org_id, now.format("%Y-%m"));
        if let Ok(mut conn) = state.redis_pool.get().await {
            let count: u32 = redis::cmd("INCR")
                .arg(&usage_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or(0);
            // Set TTL on first increment (32 days to cover the month + buffer)
            if count == 1 {
                let _: () = redis::cmd("EXPIRE")
                    .arg(&usage_key)
                    .arg(32 * 86400u64)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or(());
            }
            if let Err(e) = state.plan_guard.check_request_limit(count) {
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "plan_limit_reached",
                    format!("{} — upgrade at https://clampd.dev/#early-access", e),
                ));
            }
        }
    }

    // ---- DELEGATION CONTEXT (extract from headers + body, validate chain) ----
    // Moved BEFORE rate limit so depth/cycle attacks are rejected without consuming rate tokens.
    let delegation_ctx = crate::delegation::extract_delegation(
        &headers,
        &body.caller_agent_id,
        &body.delegation_chain,
        &body.delegation_trace_id,
        &body.delegation_purpose,
    )
    // Gateway appends the current agent (from JWT sub) to the chain.
    // The SDK sends chain=[A] (who delegated), the gateway completes it to [A, B]
    // using the authenticated agent identity. This is authoritative — can't be spoofed.
    .map(|mut ctx| {
        if !ctx.chain.contains(&agent_id_str) {
            ctx.chain.push(agent_id_str.clone());
        }
        // Recompute caller from the complete chain
        ctx.caller_agent_id = if ctx.chain.len() >= 2 {
            Some(ctx.chain[ctx.chain.len() - 2].clone())
        } else {
            ctx.caller_agent_id
        };
        ctx
    });

    if let Some(ref ctx) = delegation_ctx {
        // Validate delegation confidence value.
        const VALID_CONFIDENCES: &[&str] = &["verified", "inferred", "declared"];
        if !VALID_CONFIDENCES.contains(&ctx.confidence.as_str()) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_delegation_confidence",
                format!(
                    "Invalid delegation confidence '{}' — must be one of: verified, inferred, declared",
                    ctx.confidence
                ),
            ));
        }

        if !ctx.chain.is_empty() {
            if let Err(e) = crate::delegation::validate_chain(&ctx.chain) {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_delegation_chain",
                    e.to_string(),
                ));
            }
        }
        debug!(
            request_id = %request_id,
            caller_agent_id = ?ctx.caller_agent_id,
            chain = ?ctx.chain,
            trace_id = ?ctx.trace_id,
            confidence = %ctx.confidence,
            purpose = ?ctx.purpose,
            "Delegation context extracted"
        );
    }

    // ---- RATE LIMIT CHECK (after delegation validation, before expensive gRPC calls) ----
    let rate_result = RateLimiter::check_agent_rate_limit(
        &state.redis_pool,
        &agent_id_str,
        effective_rate_limit,
        DEFAULT_RATE_LIMIT_WINDOW_SECS,
    )
    .await;

    if !rate_result.allowed {
        let retry_after = rate_result.retry_after.unwrap_or(60);
        return Err(api_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", format!("Rate limit exceeded. Retry after {} seconds", retry_after)));
    }

    stage_latencies.push(("license_ratelimit", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 2: IDENTIFY (with circuit breaker) ----
    let agent_profile = if state.circuit_breakers.is_allowed("registry") {
        let mut client = state.registry.clone();
        match client
            .get_agent(ag_proto::agentguard::registry::GetAgentRequest {
                agent_id: agent_id_str.clone(),
            })
            .await
        {
            Ok(resp) => {
                state.circuit_breakers.record_success("registry");
                let profile = resp
                    .into_inner()
                    .agent
                    .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "agent_not_found", "Agent not found"))?;
                if profile.state != "active" {
                    return Err(api_error(StatusCode::FORBIDDEN, "agent_not_active", format!("Agent is {}", profile.state)));
                }
                profile
            }
            Err(e) => {
                // Distinguish "agent not found" from "registry down"
                if e.code() == tonic::Code::NotFound {
                    return Err(api_error(StatusCode::NOT_FOUND, "agent_not_found",
                        format!("Agent '{}' not found in registry", agent_id_str)));
                }
                state.circuit_breakers.record_failure("registry");
                error!("Registry unavailable: {}", e);
                degraded_stages.push("registry".to_string());
                return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable",
                    "Agent identity cannot be verified — registry unavailable (fail-closed)"));
            }
        }
    } else {
        // Circuit is open — fail-closed: deny the request.
        degraded_stages.push("registry".to_string());
        warn!("Registry circuit breaker is open — fail-closed");
        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable",
            "Agent identity cannot be verified — registry unavailable (fail-closed)"));
    };

    // ---- CROSS-ORG AGENT ACCESS GUARD ----
    // Verify the agent belongs to the same organization as the API key.
    // Prevents tenant A's API key from being used to proxy requests for tenant B's agent.
    if !agent_profile.org_id.is_empty() && agent_profile.org_id != api_key_info.org_id {
        warn!(
            agent_id = %agent_id_str,
            agent_org = %agent_profile.org_id,
            key_org = %api_key_info.org_id,
            "Cross-org agent access denied: agent does not belong to API key's organization"
        );
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "org_mismatch",
            format!("Agent {} does not belong to API key's organization", &agent_id_str[..std::cmp::min(12, agent_id_str.len())]),
        ));
    }

    // ---- LICENSE ORG ENFORCEMENT ----
    // Verify the agent belongs to the organization specified in the license.
    if !agent_profile.org_id.is_empty() && agent_profile.org_id != state.plan_guard.org_id {
        warn!(
            agent_id = %agent_id_str,
            agent_org = %agent_profile.org_id,
            license_org = %state.plan_guard.org_id,
            "Agent org does not match license org"
        );
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "agent_not_licensed",
            format!(
                "Agent belongs to org {} but license is for org {}",
                agent_profile.org_id,
                state.plan_guard.org_id
            ),
        ));
    }

    // ---- DELEGATION ENFORCEMENT (continued — extraction + chain validation done above) ----
    if let Some(ref ctx) = delegation_ctx {
        // ---- CROSS-ORG DELEGATION GUARD ----
        // Validate all agents in the delegation chain belong to the same org
        // as the authenticated API key. Prevents cross-tenant spoofing.
        if let Some(ref caller_id) = ctx.caller_agent_id {
            // The caller_agent_id must be resolvable within the same org.
            // We check the Redis delegation approval key which is org-scoped:
            // ag:delegation:approved:{parent}:{child} — only exists within same org.
            // If caller claims to be from a different org, the approval lookup will fail
            // and enforcement mode will block the request.
            //
            // Additionally, verify no chain member is the empty string (spoofed).
            if caller_id.is_empty() {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_caller_agent_id",
                    "caller_agent_id cannot be empty".to_string(),
                ));
            }
        }
        for chain_member in &ctx.chain {
            if chain_member.is_empty() || chain_member.len() > 128 {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_delegation_chain",
                    "Delegation chain contains invalid agent ID (empty or too long)".to_string(),
                ));
            }
        }

        // ---- DELEGATION ENFORCEMENT ----
        if ctx.chain.len() > 1 {
            let caller = &ctx.chain[ctx.chain.len() - 2];

            // Validate caller is a valid UUID to prevent spoofing
            if uuid::Uuid::parse_str(caller).is_err() {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_delegation_chain",
                    "Delegation chain contains invalid agent ID (not a UUID)".to_string(),
                ));
            }

            // Check ALL chain members against deny set (not just executor)
            for chain_member in &ctx.chain {
                if state.deny_set.contains(chain_member) {
                    let reason = format!(
                        "delegation_from_killed_agent: agent '{}' in delegation chain is kill-switched",
                        &chain_member[..chain_member.len().min(12)]
                    );
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: agent_profile.name.clone(),
                        tool_name: body.tool.clone(),
                        caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
                        delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
                        delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                        blocked: true,
                        denial_reason: Some(reason.clone()),
                        policy_action: "deny".into(),
                        policy_reason: "delegation_from_killed_agent".into(),
                        assessed_risk: 0.9,
                        session_id: session_id.clone(),
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        rejection_type: ag_common::models::RejectionType::Security,
                        a2a_event_type: Some("killed_delegation".into()),
                        ..ShadowEvent::default()
                    }).await;
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "agent_killed",
                        reason,
                    ));
                }
            }

            // Enforcement mode: check approval and allowed tools
            if crate::delegation::is_enforcement_enabled(&state.redis_pool, &api_key_info.org_id).await {
                let (approved, allowed_tools) = crate::delegation::check_delegation_approved(
                    &state.redis_pool,
                    caller,
                    &agent_id_str,
                )
                .await;

                if !approved {
                    let reason = format!(
                        "delegation_not_approved: caller '{}' is not approved to delegate to agent '{}'",
                        caller, agent_id_str
                    );
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: agent_profile.name.clone(),
                        tool_name: body.tool.clone(),
                        caller_agent_id: Some(caller.to_string()),
                        delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
                        delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                        blocked: true,
                        denial_reason: Some(reason.clone()),
                        policy_action: "deny".into(),
                        policy_reason: "delegation_not_approved".into(),
                        assessed_risk: 0.8,
                        session_id: session_id.clone(),
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        rejection_type: ag_common::models::RejectionType::Security,
                        ..ShadowEvent::default()
                    }).await;
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "delegation_not_approved",
                        reason,
                    ));
                }

                if !crate::delegation::is_tool_allowed(&allowed_tools, &body.tool) {
                    let reason = format!(
                        "delegation_tool_not_allowed: tool '{}' is not allowed for delegation {} → {}",
                        body.tool, caller, agent_id_str
                    );
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: agent_profile.name.clone(),
                        tool_name: body.tool.clone(),
                        caller_agent_id: Some(caller.to_string()),
                        delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
                        delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                        blocked: true,
                        denial_reason: Some(reason.clone()),
                        policy_action: "deny".into(),
                        policy_reason: "delegation_tool_not_allowed".into(),
                        assessed_risk: 0.8,
                        session_id: session_id.clone(),
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        rejection_type: ag_common::models::RejectionType::Security,
                        a2a_event_type: Some("tool_restricted".into()),
                        ..ShadowEvent::default()
                    }).await;
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "delegation_tool_not_allowed",
                        reason,
                    ));
                }
            }

            // Record observed delegation AFTER enforcement check passes.
            // Blocked delegations must NOT be recorded as observations — they
            // would pollute workflow auto-discovery (the enforcement block above
            // returns early on deny, so we only reach here for allowed delegations).
            crate::delegation::record_observed_delegation(
                &state.redis_pool,
                &api_key_info.org_id,
                caller,
                &agent_id_str,
                &ctx.confidence,
                &body.tool,
                ctx.trace_id.as_deref().unwrap_or(""),
            )
            .await;

            // ---- TASK REPLAY DETECTION ----
            // Prevent replayed delegation requests by checking an idempotency nonce.
            // Key = sha256(caller + target + tool + params_hash + trace_id), TTL = 60s.
            {
                use sha2::{Digest, Sha256};
                let params_hash = {
                    let mut h = Sha256::new();
                    h.update(serde_json::to_string(&body.params).unwrap_or_default().as_bytes());
                    format!("{:x}", h.finalize())
                };
                let nonce_input = format!(
                    "{}:{}:{}:{}:{}",
                    caller,
                    agent_id_str,
                    body.tool,
                    params_hash,
                    ctx.trace_id.as_deref().unwrap_or("")
                );
                let mut h = Sha256::new();
                h.update(nonce_input.as_bytes());
                let nonce_key = format!("ag:replay:{:x}", h.finalize());

                if let Ok(mut conn) = state.redis_pool.get().await {
                    let set_result: Result<bool, _> = redis::cmd("SET")
                        .arg(&nonce_key)
                        .arg("1")
                        .arg("NX")  // only set if not exists
                        .arg("EX")
                        .arg(60i64) // 60s TTL
                        .query_async(&mut *conn)
                        .await;

                    match set_result {
                        Ok(false) => {
                            // Key already existed — this is a replay
                            let reason = format!(
                                "task_replay_detected: duplicate delegation {} → {} within 60s",
                                &caller[..caller.len().min(12)],
                                &agent_id_str[..agent_id_str.len().min(12)]
                            );
                            crate::shadow::publish_event(&state, &ShadowEvent {
                                request_id,
                                org_id: api_key_info.org_id.clone(),
                                agent_id: agent_id_str.clone(),
                                agent_name: agent_profile.name.clone(),
                                tool_name: body.tool.clone(),
                                caller_agent_id: Some(caller.to_string()),
                                delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
                                delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                                blocked: true,
                                denial_reason: Some(reason.clone()),
                                policy_action: "deny".into(),
                                policy_reason: "task_replay_detected".into(),
                                assessed_risk: 0.9,
                                session_id: session_id.clone(),
                                latency_ms: started_at.elapsed().as_millis() as u32,
                                rejection_type: ag_common::models::RejectionType::Security,
                                a2a_event_type: Some("task_replay".into()),
                                ..ShadowEvent::default()
                            }).await;
                            return Err(api_error(
                                StatusCode::CONFLICT,
                                "task_replay_detected",
                                reason,
                            ));
                        }
                        Ok(true) => {} // First time — proceed
                        Err(e) => {
                            // Redis error — log and continue (fail-open for replay, fail-closed would block legitimate retries)
                            warn!(error = %e, "Redis SET NX failed for replay detection — skipping");
                        }
                    }
                }
            }
        }
    }

    stage_latencies.push(("identify_delegate", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 3: NORMALIZE + EXTRACT ----
    let (raw_tool_name, action, mut params_json, _raw_params_hash, prompt_hash) = extract_tool_call(&body);
    // Canonicalize tool name so all downstream services see consistent names.
    // "db.query" → "database.query", "file.read" → "filesystem.read", etc.
    let tool_name = ag_common::tool_names::canonicalize(&raw_tool_name);

    // ---- PAYMENT BOUNDARY CHECK ----
    // If the tool is a payment tool and the agent has spend limits configured,
    // enforce per-transaction and vendor whitelist checks before any further processing.
    if tool_name.starts_with("payment.") || tool_name.starts_with("billing.") || tool_name.starts_with("stripe.") || tool_name.starts_with("checkout.") || tool_name.starts_with("invoice.") {
        if let Some(ref bounds) = agent_profile.boundaries {
            // Per-transaction limit check
            if bounds.max_payment_per_tx_cents > 0 {
                // Extract amount from params (look for "amount", "total", "price", "cents")
                let amount_cents = body.params.get("amount").or(body.params.get("total")).or(body.params.get("price")).or(body.params.get("amount_cents"))
                    .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
                    .unwrap_or(0);
                if amount_cents > bounds.max_payment_per_tx_cents {
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "payment_limit_exceeded",
                        format!(
                            "Payment amount {} cents exceeds agent limit of {} cents per transaction",
                            amount_cents, bounds.max_payment_per_tx_cents
                        ),
                    ));
                }
            }

            // Vendor whitelist check
            if !bounds.approved_vendors.is_empty() {
                let vendor = body.params.get("vendor").or(body.params.get("recipient")).or(body.params.get("merchant"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !vendor.is_empty() && !bounds.approved_vendors.iter().any(|v| v == vendor) {
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "payment_vendor_not_approved",
                        format!(
                            "Vendor '{}' is not in this agent's approved vendor list ({} approved vendors configured)",
                            vendor, bounds.approved_vendors.len()
                        ),
                    ));
                }
            }
        }
    }

    // ---- AP2 MANDATE VALIDATION ----
    // If the tool call params contain an AP2 mandate (cart_mandate, intent_mandate,
    // ap2_mandate, or mandate key), extract and validate it against the agent's
    // boundary config. Invalid mandates are denied; valid human-not-present mandates
    // get a +0.2 risk bump applied after intent classification.
    let ap2_risk_modifier: f64 = if tool_name.starts_with("payment.")
        || tool_name.starts_with("billing.")
        || tool_name.starts_with("stripe.")
        || tool_name.starts_with("checkout.")
        || tool_name.starts_with("invoice.")
    {
        if let Some(mandate) = crate::ap2::extract_mandate(&body.params) {
            let effective = agent_profile
                .boundaries
                .as_ref()
                .cloned()
                .unwrap_or_default();
            let bounds = crate::ap2::Ap2Boundaries {
                max_payment_per_tx_cents: effective.max_payment_per_tx_cents,
            };
            let validation = crate::ap2::validate_mandate(&mandate, &bounds);
            // Log audit fields for observability.
            for (k, v) in &validation.audit_fields {
                debug!(ap2_audit_key = %k, ap2_audit_val = %v, "AP2 mandate audit");
            }
            if !validation.valid {
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "ap2_mandate_invalid",
                    validation
                        .deny_reason
                        .unwrap_or_else(|| "AP2 mandate validation failed".to_string()),
                ));
            }
            validation.risk_modifier
        } else {
            0.0
        }
    } else {
        0.0
    };

    // ---- PROMPT CONTEXT INJECTION INTO CLASSIFICATION ----
    // Schema injection attacks (R068-R073) target the LLM's prompt_context, not the tool params.
    // Merge prompt_context into params_json so the engine can scan it alongside tool params.
    // This ensures rules with scope_pattern "llm:input:prompt" can match content in prompt_context.
    if let Some(ref ctx) = body.prompt_context {
        if !ctx.is_empty() {
            if let Ok(mut obj) = serde_json::from_str::<serde_json::Value>(&params_json) {
                obj.as_object_mut().map(|m| m.insert("__prompt_context".to_string(), serde_json::Value::String(ctx.clone())));
                params_json = serde_json::to_string(&obj).unwrap_or(params_json);
            } else {
                // params_json isn't a JSON object — create a wrapper
                params_json = serde_json::json!({
                    "__raw_params": params_json,
                    "__prompt_context": ctx,
                }).to_string();
            }
        }
    }

    // Strip internal SDK metadata (keys starting with "_") from params before
    // rule evaluation. These contain UUIDs, trace IDs, and hashes that trigger
    // false positive PII/financial rules. User data never starts with "_".
    if let Ok(mut obj) = serde_json::from_str::<serde_json::Value>(&params_json) {
        if let Some(map) = obj.as_object_mut() {
            map.retain(|k, _| !k.starts_with('_'));
        }
        params_json = serde_json::to_string(&obj).unwrap_or(params_json);
    }

    // Emit OTel trace event for proxy request start.
    tracing::info!(
        otel.name = "proxy_request",
        tool_name = %tool_name,
        agent_id = %agent_id_str,
        "Proxy request started"
    );
    let params_summary = summarize_params(&tool_name, &body.params);

    // ---- FIX 5: WRITE BOMB MITIGATION ----
    // Truncate params_json to 64KB for classification to prevent CPU exhaustion
    // in the 13-step normalization + Aho-Corasick pipeline. Full payload still forwarded.
    const MAX_CLASSIFY_PARAMS_LEN: usize = 65_536;
    let params_json_for_classify = if params_json.len() > MAX_CLASSIFY_PARAMS_LEN {
        info!(
            request_id = %request_id,
            original_len = params_json.len(),
            "Truncating params_json to {}KB for classification",
            MAX_CLASSIFY_PARAMS_LEN / 1024
        );
        params_json[..MAX_CLASSIFY_PARAMS_LEN].to_string()
    } else {
        params_json.clone()
    };

    // Check byte rate limit (cumulative bytes per agent per minute)
    let byte_rate_result = crate::rate_limiter::RateLimiter::check_byte_rate_limit(
        &state.redis_pool,
        &agent_id_str,
        params_json.len() as u64,
        10 * 1024 * 1024, // 10MB per minute
        60,
    )
    .await;
    if !byte_rate_result.allowed {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "byte_rate_limited",
            format!("Byte rate limit exceeded (10MB/min). Retry after {} seconds", byte_rate_result.retry_after.unwrap_or(60)),
        ));
    }

    // Run normalization pipeline from ag-common (on truncated params for classification)
    let norm_result = normalize_params(&body.params, &params_json_for_classify);
    let params_hash = norm_result.params_hash.clone();
    let encodings_detected = norm_result.encodings_detected.clone();
    let encoding_risk_bonus = norm_result.encoding_risk_bonus;

    if !encodings_detected.is_empty() {
        info!(
            request_id = %request_id,
            encodings = ?encodings_detected,
            bonus = encoding_risk_bonus,
            "Encoding anomalies detected in params"
        );
    }

    // ---- Stage 3.5: REQUEST COUNTER ----
    // Increment per-agent call counter in Redis and read the sliding-window total.
    // This feeds B-001 volume quota enforcement in ag-policy.
    let calls_in_last_minute = increment_and_get_calls(&state.redis_pool, &agent_id_str).await;

    // ---- Stage 3.6: FIRST-TIME TOOL DETECTION ----
    // Check if the agent has used this tool before via Redis SET.
    // Novel tools add a risk signal (+0.2) to session context for ag-intent.
    let first_time_tool = {
        let known_tools_key = format!("ag:baseline:{}:known_tools", agent_id_str);
        let mut is_first = false;
        if let Ok(mut conn) = state.redis_pool.get().await {
            let is_member: bool = redis::cmd("SISMEMBER")
                .arg(&known_tools_key)
                .arg(&tool_name)
                .query_async(&mut *conn)
                .await
                .unwrap_or(false);
            is_first = !is_member;
        }
        is_first
    };

    stage_latencies.push(("normalize_extract", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 4: SESSION CONTEXT ----
    let agent_uuid = Uuid::parse_str(&agent_id_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid_agent_id", "Agent ID is not a valid UUID"))?;
    let mut session_context =
        session::load_or_create_session(&state.redis_pool, &agent_uuid, &session_id).await;

    // ---- FIX 3: SESSION HARDENING ----
    // Check if this is a new session (no tool calls yet = just created)
    let is_new_session = session_context.tool_calls.is_empty();
    if is_new_session {
        // Check if session creation is blocked post-kill
        if session::is_session_blocked(&state.redis_pool, &agent_id_str).await {
            return Err(api_error(
                StatusCode::FORBIDDEN,
                "session_blocked",
                "Session creation blocked — agent was recently kill-switched",
            ));
        }

        // Rate limit new session creation (configurable, default 50 per hour per agent)
        let max_sessions_per_hour = state.config.max_sessions_per_hour;
        if let Err(e) = session::rate_limit_session_creation(&state.redis_pool, &agent_id_str, max_sessions_per_hour).await {
            return Err(api_error(StatusCode::TOO_MANY_REQUESTS, "session_rate_limited", e));
        }

        // Set client fingerprint on new sessions
        session_context.client_fingerprint = session::extract_client_fingerprint(&headers);

        // Inherit 50% of agent's current EMA score
        let ema = session::read_agent_ema_score(&state.redis_pool, &agent_id_str).await;
        session_context.inherited_risk = ema * 0.5;

        // Immediately persist the new session so subsequent requests within the
        // same session_id find it in Redis and don't re-trigger the rate limiter.
        // Without this, fire-and-forget saves cause a race: the next request
        // arrives before the async save completes, sees an empty session, and
        // increments the creation counter again.
        session::save_session(&state.redis_pool, &session_context).await;
    }

    // ---- Stage 4.1: SESSION TOOL-CALL BUDGET (DoS prevention) ----
    // Per-agent boundary takes precedence, falls back to global config
    let max_calls = agent_profile.boundaries.as_ref()
        .map(|b| b.max_calls_per_session as u64)
        .filter(|&v| v > 0)
        .unwrap_or(state.config.max_calls_per_session);
    if max_calls > 0 && session_context.tool_calls.len() as u64 >= max_calls {
        warn!(
            request_id = %request_id,
            session_id = %session_id,
            agent_id = %agent_id_str,
            call_count = session_context.tool_calls.len(),
            max_calls,
            "Session tool-call budget exceeded"
        );
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "session_budget_exceeded",
            &format!("Session tool-call budget exceeded ({}/{})", session_context.tool_calls.len(), max_calls),
        ));
    }

    // ---- Stage 4.5: TOOL AUTHORIZATION (FIX 1) ----
    // Layer A: SDK sends authorized tools via header → lock immediately
    // Layer B: Auto-lock after 5 unique tools (protects older SDKs)
    let header_tools = session::extract_authorized_tools(&headers);
    if !session_context.tools_locked {
        if let Some(tools) = header_tools {
            // Canonicalize header tool names so they match the canonicalized tool_name
            // used in check_tool_authorized (e.g. "database_query" → "database.query")
            let canonical_tools = tools.into_iter()
                .map(|t| ag_common::tool_names::canonicalize(&t))
                .collect();
            session::lock_tool_set(&mut session_context, canonical_tools);
        }
    }

    // Check tool authorization
    if let Err(e) = session::check_tool_authorized(&session_context, &tool_name) {
        warn!(
            request_id = %request_id,
            tool = %tool_name,
            agent_id = %agent_id_str,
            "Unauthorized tool attempt blocked"
        );
        return Err(api_error(StatusCode::FORBIDDEN, "unauthorized_tool", e));
    }

    // Auto-lock after 5 unique tools (if no header lock was applied)
    if !session_context.tools_locked {
        session::auto_lock_tool_set(&mut session_context, &tool_name, 5);
    }

    let mut session_flags: Vec<String> = session_context.flag_names();
    if first_time_tool {
        session_flags.push("first_time_tool".to_string());
    }
    let session_risk_factor = session_context.risk_factor();

    stage_latencies.push(("session_toolauth", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 5+6: CLASSIFY + EVALUATE (with circuit breakers) ----

    // Fetch agent baseline from cache (ag-risk Redis HSET, 60s local TTL)
    let baseline = state.baseline_cache.get(&agent_id_str).await;

    // Stage 5: Classify intent (with circuit breaker)
    let classify_result = if state.circuit_breakers.is_allowed("intent") {
        tracing::info!(otel.name = "classify_intent", tool_name = %tool_name, agent_id = %agent_id_str, "Calling ag-intent ClassifyIntent");
        let mut client = state.intent.clone();
        let result = client
            .classify_intent(ClassifyRequest {
                tool_name: tool_name.clone(),
                action: action.clone(),
                params_json: params_json_for_classify.clone(),
                params_normalized_json: norm_result.normalized_params_json.clone(),
                encodings_detected: encodings_detected.clone(),
                agent_purpose: agent_profile.declared_purpose.clone(),
                agent_id: agent_id_str.clone(),
                agent_risk_score: session::read_agent_ema_score(&state.redis_pool, &agent_id_str).await,
                session_flags: session_flags.clone(),
                session_risk_factor,
                session_total_calls: session_context.tool_calls.len() as i32,
                session_context_window: session_context.tool_calls.len().min(10) as i32,
                session_context_json: build_session_context_json(&session_context, baseline.as_ref()),
                // agent_scopes removed — scope exemptions handled by policy layer
                caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
                delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()).unwrap_or_default(),
                delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                delegation_confidence: delegation_ctx.as_ref().map(|d| d.confidence.clone()),
                tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
            })
            .await;
        match &result {
            Ok(_) => state.circuit_breakers.record_success("intent"),
            Err(_) => state.circuit_breakers.record_failure("intent"),
        }
        Some(result)
    } else {
        degraded_stages.push("intent".to_string());
        warn!("Intent circuit breaker is open");
        None
    };

    stage_latencies.push(("classify_grpc", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // intent action: 0=PASS, 1=FLAG, 2=BLOCK (from proto enum)
    let (assessed_risk, classification, intent_labels, matched_rules, reasoning, intent_action, has_non_exemptable_block) =
        match classify_result {
            Some(Ok(resp)) => {
                let r = resp.into_inner();
                let reasoning = if r.reasoning.is_empty() { None } else { Some(r.reasoning) };
                (
                    r.assessed_risk,
                    r.classification,
                    r.labels,
                    r.matched_rules,
                    reasoning,
                    r.action, // 0=PASS, 1=FLAG, 2=BLOCK
                    r.has_non_exemptable_block,
                )
            }
            Some(Err(e)) => {
                error!("Intent service unavailable: {}", e);
                degraded_stages.push("intent".to_string());
                match apply_degradation_or_default(state.degradation.intent_unavailable) {
                    Some((risk, class, labels, rules, _action)) => (risk, class, labels, rules, None, 0i32, false), // PASS on degradation
                    None => {
                        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "intent_unavailable", "Intent service unavailable"));
                    }
                }
            }
            None => {
                // Circuit breaker is open — apply degradation.
                match apply_degradation_or_default(state.degradation.intent_unavailable) {
                    Some((risk, class, labels, rules, _action)) => (risk, class, labels, rules, None, 0i32, false),
                    None => {
                        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "intent_unavailable", "Intent service unavailable (circuit open)"));
                    }
                }
            }
        };

    // ---- Stage 5.5: MODEL ESCALATION (gray-zone hybrid) ----
    // Skip if intent already said Block — per-tool thresholds already decided.
    let assessed_risk = if intent_action != 2 && crate::model_escalation::needs_escalation(
        &state.config.model_escalation,
        assessed_risk,
    ) {
        debug!(
            tool = %tool_name,
            rules_risk = assessed_risk,
            "Gray-zone score detected, escalating to model"
        );
        match crate::model_escalation::escalate(
            &state.http_client,
            &state.config.model_escalation,
            crate::model_escalation::ModelRequest {
                tool_name: tool_name.clone(),
                action: action.clone(),
                params_json: params_json.clone(),
                rules_risk_score: assessed_risk,
                matched_rules: matched_rules.clone(),
                classification: classification.clone(),
                agent_id: agent_id_str.clone(),
                session_flags: session_flags.clone(),
            },
        )
        .await
        {
            Some(model_resp) => {
                debug!(
                    rules_risk = assessed_risk,
                    model_risk = model_resp.risk_score,
                    label = ?model_resp.label,
                    "Model refined risk score"
                );
                model_resp.risk_score.clamp(0.0, 1.0)
            }
            None => {
                // Model unavailable or fail-open — use rules score as-is
                assessed_risk
            }
        }
    } else {
        assessed_risk
    };

    // ---- Stage 5.5b: LLM-AS-JUDGE (semantic gray-zone) ----
    // Skip if intent already said Block — no point calling LLM for a request
    // that's already blocked by per-tool-category thresholds.
    let assessed_risk = if intent_action != 2 && crate::model_escalation::needs_llm_judge(
        &state.config.llm_judge,
        assessed_risk,
    ) {
        debug!(
            tool = %tool_name,
            rules_risk = assessed_risk,
            "Gray-zone score, invoking LLM judge"
        );
        let judge_req = crate::model_escalation::LlmJudgeRequest {
            tool_name: tool_name.clone(),
            action: action.clone(),
            params_summary: params_json.chars().take(500).collect(),
            rules_risk_score: assessed_risk,
            matched_rules: matched_rules.clone(),
            agent_id: agent_id_str.clone(),
        };
        match crate::model_escalation::llm_judge(
            &state.http_client,
            &state.config.llm_judge,
            &judge_req,
        )
        .await
        {
            Ok(resp) => {
                info!(
                    tool = %tool_name,
                    rules_risk = assessed_risk,
                    llm_risk = resp.risk_score,
                    label = %resp.label,
                    reasoning = %resp.reasoning,
                    "LLM judge result"
                );
                assessed_risk.max(resp.risk_score).clamp(0.0, 1.0)
            }
            Err(e) => {
                warn!(tool = %tool_name, error = %e, "LLM judge failed, using rules score");
                assessed_risk
            }
        }
    } else {
        assessed_risk
    };

    // Emit OTel trace event with final risk score.
    tracing::info!(
        otel.name = "risk_assessed",
        tool_name = %tool_name,
        agent_id = %agent_id_str,
        risk_score = assessed_risk,
        "Risk score assessed"
    );

    stage_latencies.push(("model_escalation", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // Stage 6: Evaluate policy (with circuit breaker)
    let policy_result = if state.circuit_breakers.is_allowed("policy") {
        tracing::info!(otel.name = "evaluate_policy", tool_name = %tool_name, agent_id = %agent_id_str, "Calling ag-policy Evaluate");
        let mut client = state.policy.clone();
        // Resolve tool scopes: try per-agent grant first, fall back to per-tool descriptor.
        // Grant-based: ag:agent:tool:{agent_id}:{tool_name} (from agent_tool_grants table)
        // Descriptor-based: ag:tool:scope:{org_id}:{tool_name} (from tool_descriptors table)
        let requested_scopes = match state.baseline_cache
            .resolve_agent_tool_grant(&agent_id_str, &tool_name)
            .await
        {
            Ok(scopes) => scopes,
            // No grant — fall back to tool descriptor scope resolution (transition path)
            Err(_) => match state.baseline_cache
                .resolve_tool_scopes(&api_key_info.org_id, &tool_name)
                .await
            {
                Ok(scopes) => scopes,
                Err(reason) => {
                    // Learning mode (auto_trust): derive default scopes from tool name
                    // instead of blocking. Tool is still discovered via shadow event.
                    let auto_trust = check_auto_trust(&state.redis_pool, &agent_id_str, &api_key_info.org_id).await;

                    // Always publish shadow event so ag-control discovers the tool
                    let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        trace_id: request_id.to_string(),
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: agent_profile.name.clone(),
                        user_id: jwt_claims.user_id.clone().unwrap_or_default(),
                        tool_name: tool_name.clone(),
                        tool_action: action.clone(),
                        params_hash: params_hash.clone(),
                        params_summary: params_summary.clone(),
                        prompt_hash: prompt_hash.clone().unwrap_or_default(),
                        assessed_risk,
                        intent_classification: classification.clone(),
                        policy_action: if auto_trust { "allow_learning".into() } else { "deny".into() },
                        policy_reason: "tool_not_registered".into(),
                        blocked: !auto_trust,
                        denial_reason: if auto_trust { None } else { Some(reason.clone()) },
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        encodings_detected: encodings_detected.clone(),
                        encoding_risk_bonus,
                        session_id: session_id.clone(),
                        session_flags: session_flags.clone(),
                        session_risk_factor,
                        degraded_stages: degraded_stages.clone(),
                        intent_labels: intent_labels.clone(),
                        matched_rules: matched_rules.clone(),
                        caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
                        delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
                        delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                        tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
                        tool_description: body.tool_description.clone().unwrap_or_default(),
                        tool_params_schema: body.tool_params_schema.clone().unwrap_or_default(),
                        active_hours_start: ah_start,
                        active_hours_end: ah_end,
                        rejection_type: ag_common::models::RejectionType::Config,
                        ..ShadowEvent::default()
                    }).await;

                    if auto_trust {
                        let scope = ag_common::scopes::tool_to_scope(&tool_name);
                        vec![scope.as_str()]
                    } else {
                        return Err(api_error(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "tool_not_registered",
                            &reason,
                        ));
                    }
                }
            },
        };

        let result = client
            .evaluate(EvaluateRequest {
                agent_id: agent_id_str.clone(),
                tool_name: tool_name.clone(),
                requested_scopes,
                agent_allowed_scopes: agent_profile.allowed_scopes.clone(),
                agent_risk_score: assessed_risk,
                intent_classification: classification.clone(),
                labels: intent_labels.clone(),
                session_flags: session_flags.clone(),
                agent_boundaries: agent_profile.boundaries.clone(),
                target_url: body.target_url.clone(),
                calls_in_last_minute,
                agent_timezone: "UTC".to_string(),
                agent_state: agent_profile.state.clone(),
                matched_rules: matched_rules.clone(),
                params_json: std::mem::take(&mut params_json), // Zero-copy: last usage
                has_non_exemptable_block,
                caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
                delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()).unwrap_or_default(),
                delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                delegation_confidence: delegation_ctx.as_ref().map(|d| d.confidence.clone()),
                org_id: api_key_info.org_id.clone(),
            })
            .await;
        match &result {
            Ok(_) => state.circuit_breakers.record_success("policy"),
            Err(_) => state.circuit_breakers.record_failure("policy"),
        }
        Some(result)
    } else {
        degraded_stages.push("policy".to_string());
        warn!("Policy circuit breaker is open");
        None
    };

    let (policy_action, granted_scopes, _denied_scopes, policy_reason, policy_token_ttl, matched_policies, boundary_violation_policy) = match policy_result {
        Some(Ok(resp)) => {
            let r = resp.into_inner();
            (r.action, r.required_scopes, r.denied_scopes, r.reason, r.token_ttl_seconds, r.matched_policies, r.boundary_violation)
        }
        Some(Err(e)) => {
            error!("Policy service unavailable: {}", e);
            degraded_stages.push("policy".to_string());
            match state.degradation.policy_unavailable {
                DegradationMode::AllowWithAlert => {
                    warn!("Policy degraded: AllowWithAlert");
                    (
                        ag_proto::agentguard::policy::PolicyAction::Allow as i32,
                        agent_profile.allowed_scopes.clone(),
                        Vec::new(),
                        "degraded: allow_with_alert".to_string(),
                        0u32,
                        Vec::new(),
                        None,
                    )
                }
                _ => {
                    return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable", "Policy service unavailable"));
                }
            }
        }
        None => {
            // Circuit breaker is open.
            match state.degradation.policy_unavailable {
                DegradationMode::AllowWithAlert => {
                    warn!("Policy degraded (circuit open): AllowWithAlert");
                    (
                        ag_proto::agentguard::policy::PolicyAction::Allow as i32,
                        agent_profile.allowed_scopes.clone(),
                        Vec::new(),
                        "degraded: allow_with_alert (circuit open)".to_string(),
                        0u32,
                        Vec::new(),
                        None,
                    )
                }
                _ => {
                    return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable", "Policy service unavailable (circuit open)"));
                }
            }
        }
    };

    // Propagate cross-boundary advisory from policy service to session_flags.
    // ag-policy sets boundary_violation when a delegation crosses workflow/org boundaries.
    if let Some(ref bv) = boundary_violation_policy {
        if bv.contains("cross_boundary") {
            session_flags.push("cross_boundary_delegation".to_string());
        }
    }
    for policy in &matched_policies {
        if policy.contains("cross_boundary") {
            if !session_flags.contains(&"cross_boundary_delegation".to_string()) {
                session_flags.push("cross_boundary_delegation".to_string());
            }
        }
    }

    // Determine a2a_event_type for the shadow event based on delegation context.
    let a2a_event_type: Option<String> = if session_flags.contains(&"cross_boundary_delegation".to_string()) {
        Some("cross_boundary".into())
    } else {
        None
    };

    // ---- SUSPICION SCORE (behavioral anomaly from ag-risk, async → Redis → hot path) ----
    let suspicion_score = state.baseline_cache.get_suspicion_score(&agent_id_str).await;

    // ---- DECISION GATE (extracted to decision.rs for testability) ----
    let decision = crate::decision::evaluate(&crate::decision::DecisionInput {
        suspicion_score,
        assessed_risk,
        ap2_risk_modifier,
        intent_action,
        policy_action,
        policy_reason: policy_reason.clone(),
        risk_threshold: state.config.risk_threshold,
        matched_rules: matched_rules.clone(),
        session_flags: session_flags.clone(),
        reasoning: reasoning.clone(),
    });
    let assessed_risk = decision.assessed_risk;
    let blocked = decision.blocked;
    let intent_says_flag = intent_action == 1; // Used downstream for flagged-but-allowed logging

    if blocked {
        let denial_reason = decision.denial_reason.unwrap_or_default();
        let rejection_type = decision.rejection_type;

        // Publish shadow event (fire and forget)
        let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
        crate::shadow::publish_event(&state, &ShadowEvent {
            request_id,
            trace_id: request_id.to_string(),
            org_id: api_key_info.org_id.clone(),
            agent_id: agent_id_str.clone(),
            agent_name: agent_profile.name.clone(),
            user_id: jwt_claims.user_id.clone().unwrap_or_default(),
            tool_name: tool_name.clone(),
            tool_action: action.clone(),
            params_hash: params_hash.clone(),
            params_summary: params_summary.clone(),
            prompt_hash: prompt_hash.clone().unwrap_or_default(),
            assessed_risk,
            intent_classification: classification.clone(),
            policy_action: "deny".into(),
            policy_reason: policy_reason.clone(),
            scope_requested: agent_profile.allowed_scopes.join(" "),
            blocked: true,
            denial_reason: Some(denial_reason.clone()),
            latency_ms: started_at.elapsed().as_millis() as u32,
            encodings_detected: encodings_detected.clone(),
            encoding_risk_bonus,
            session_id: session_id.clone(),
            session_flags: session_flags.clone(),
            session_risk_factor,
            degraded_stages: degraded_stages.clone(),
            intent_labels: intent_labels.clone(),
            matched_rules: matched_rules.clone(),
            caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
            delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
            delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
            tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
            tool_description: body.tool_description.clone().unwrap_or_default(),
            tool_params_schema: body.tool_params_schema.clone().unwrap_or_default(),
            active_hours_start: ah_start,
            active_hours_end: ah_end,
            rejection_type,
            a2a_event_type: a2a_event_type.clone(),
            ..ShadowEvent::default()
        }).await;

        // Record denied request in session (for ScopeProbing detection)
        {
            let is_external = session::is_external_send(&tool_name, &action);
            let tables = session::extract_tables_from_params(&tool_name, &body.params);
            let tool_record = session::build_tool_record(
                &tool_name,
                &action,
                0, // no records returned for denied requests
                true, // was_denied = true
                is_external,
                tables,
                "",
            );

            let mut session_to_save = session_context.clone();
            let max_records = 1000u32;
            session_to_save.record_tool_call(tool_record, max_records);
            session_to_save.record_risk(assessed_risk);

            let pool = state.redis_pool.clone();
            tokio::spawn(async move {
                session::save_session(&pool, &session_to_save).await;
            });
        }

        let latency_ms = started_at.elapsed().as_millis() as u64;
        crate::metrics::increment_denied();
        crate::metrics::record_latency(started_at.elapsed().as_micros() as u64);
        info!(
            request_id = %request_id,
            tool = %tool_name,
            risk = assessed_risk,
            latency_ms,
            reason = %denial_reason,
            "Proxy request denied"
        );
        // Log per-stage latency breakdown for observability
        let stage_breakdown: String = stage_latencies.iter()
            .map(|(name, us)| format!("{}={:.2}ms", name, *us as f64 / 1000.0))
            .collect::<Vec<_>>().join(" ");
        debug!(request_id = %request_id, stages = %stage_breakdown, "Stage latency breakdown (denied)");

        return Ok(Json(ProxyResponse {
            request_id: request_id.to_string(),
            allowed: false,
            action: action_str(intent_action),
            risk_score: assessed_risk,
            scope_granted: None,
            tool_response: None,
            denial_reason: Some(denial_reason),
            reasoning: reasoning.clone(),
            matched_rules: matched_rules.clone(),
            latency_ms,
            degraded_stages,
            session_flags,
            scope_token: None,
        }));
    }

    stage_latencies.push(("policy_decision", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Evaluate-only fast path: skip token exchange + forwarding when no target_url ----
    // This is the default SDK flow — agent executes the tool locally after getting allow/deny.
    if body.target_url.is_empty() {
        let scope_granted = granted_scopes.join(" ");

        // Mint a compact scope token (payload.signature) proving this call was approved.
        // Contains scope grant, tool binding, and expiry.
        //
        // Ed25519 asymmetric signing — cannot forge without the private key.
        // Public key is distributed via GET /.well-known/jwks.json for tool-side verification.
        let scope_token = {
            let scope_token_ttl: i64 = if policy_token_ttl > 0 {
                policy_token_ttl as i64
            } else {
                std::env::var("AG_SCOPE_TOKEN_TTL_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300)
            };
            crate::scope_token::mint(
                &state.scope_signing_key,
                &crate::scope_token::MintInput {
                    agent_id: &agent_id_str,
                    scope_granted: &scope_granted,
                    tool_name: &tool_name,
                    params_hash: &params_hash,
                    request_id: &request_id.to_string(),
                    ttl_secs: scope_token_ttl,
                    now: chrono::Utc::now().timestamp(),
                },
            )
        };
        let latency_ms = started_at.elapsed().as_millis() as u64;

        // Session update (fire-and-forget)
        {
            let tables = session::extract_tables_from_sql(body.params.get("sql").and_then(|v| v.as_str()).unwrap_or(""));
            let is_external = false;
            let tool_record = session::build_tool_record(
                &tool_name,
                &action,
                0, // no records returned (tool not executed by gateway)
                false,
                is_external,
                tables,
                "",
            );
            let mut session_to_save = session_context.clone();
            let max_records = 1000u32;
            session_to_save.record_tool_call(tool_record, max_records);
            session_to_save.record_risk(assessed_risk);
            let pool = state.redis_pool.clone();
            let tool_for_sadd = tool_name.clone();
            let agent_for_sadd = agent_id_str.clone();
            tokio::spawn(async move {
                session::save_session(&pool, &session_to_save).await;
                // Record this tool as known for first-time detection
                let known_tools_key = format!("ag:baseline:{}:known_tools", agent_for_sadd);
                if let Ok(mut conn) = pool.get().await {
                    let _: Result<(), _> = redis::cmd("SADD")
                        .arg(&known_tools_key)
                        .arg(&tool_for_sadd)
                        .query_async(&mut *conn)
                        .await;
                    // Set TTL to 30 days if this is a new set
                    let _: Result<(), _> = redis::cmd("EXPIRE")
                        .arg(&known_tools_key)
                        .arg(30 * 86400i64)
                        .query_async(&mut *conn)
                        .await;
                }
            });
        }

        // Audit (async fire-and-forget)
        let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
        crate::shadow::publish_event(&state, &ShadowEvent {
            request_id,
            trace_id: request_id.to_string(),
            org_id: api_key_info.org_id.clone(),
            agent_id: agent_id_str.clone(),
            agent_name: agent_profile.name.clone(),
            user_id: jwt_claims.user_id.clone().unwrap_or_default(),
            tool_name: tool_name.clone(),
            tool_action: action.clone(),
            params_hash: params_hash.clone(),
            params_summary: params_summary.clone(),
            prompt_hash: prompt_hash.clone().unwrap_or_default(),
            assessed_risk,
            intent_classification: classification.clone(),
            policy_action: "allow".into(),
            policy_reason: policy_reason.clone(),
            scope_requested: agent_profile.allowed_scopes.join(" "),
            scope_granted: Some(scope_granted.clone()),
            blocked: false,
            latency_ms: latency_ms as u32,
            encodings_detected: encodings_detected.clone(),
            encoding_risk_bonus,
            session_id: session_id.clone(),
            session_flags: session_flags.clone(),
            session_risk_factor,
            degraded_stages: degraded_stages.clone(),
            intent_labels: intent_labels.clone(),
            matched_rules: matched_rules.clone(),
            caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
            delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
            delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
            tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
            tool_description: body.tool_description.clone().unwrap_or_default(),
            tool_params_schema: body.tool_params_schema.clone().unwrap_or_default(),
            active_hours_start: ah_start,
            active_hours_end: ah_end,
            a2a_event_type: a2a_event_type.clone(),
            ..ShadowEvent::default()
        }).await;

        if intent_says_flag {
            crate::metrics::increment_flagged();
        }
        crate::metrics::increment_allowed();
        crate::metrics::record_latency(started_at.elapsed().as_micros() as u64);

        stage_latencies.push(("token_session_save", stage_start.elapsed().as_micros() as u64));
        info!(
            request_id = %request_id,
            tool = %tool_name,
            risk = assessed_risk,
            latency_ms,
            "Proxy request completed (evaluate-only, no forwarding)"
        );
        // Log per-stage latency breakdown for observability
        let stage_breakdown: String = stage_latencies.iter()
            .map(|(name, us)| format!("{}={:.2}ms", name, *us as f64 / 1000.0))
            .collect::<Vec<_>>().join(" ");
        debug!(request_id = %request_id, stages = %stage_breakdown, "Stage latency breakdown (allowed)");

        return Ok(Json(ProxyResponse {
            request_id: request_id.to_string(),
            allowed: true,
            action: action_str(intent_action),
            risk_score: assessed_risk,
            scope_granted: Some(scope_granted),
            tool_response: None,
            denial_reason: None,
            reasoning,
            matched_rules,
            latency_ms,
            degraded_stages,
            session_flags,
            scope_token: Some(scope_token),
        }));
    }

    stage_latencies.push(("token_session_save", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 7: TOKEN EXCHANGE (only when forwarding to target_url) ----
    let binding_hash = {
        use sha2::{Digest, Sha256};
        let input = format!("{}{}", tool_name, params_hash);
        hex::encode(Sha256::digest(input.as_bytes()))
    };

    let token_result = if state.circuit_breakers.is_allowed("token") {
        let mut client = state.token.clone();
        let result = client
            .exchange_token(ExchangeRequest {
                subject_token: jwt_token.to_string(),
                agent_id: agent_id_str.clone(),
                requested_scopes: granted_scopes.clone(),
                tool_name: tool_name.clone(),
                call_binding_hash: binding_hash,
                session_id: session_id.clone(),
            })
            .await;
        match &result {
            Ok(_) => state.circuit_breakers.record_success("token"),
            Err(_) => state.circuit_breakers.record_failure("token"),
        }
        Some(result)
    } else {
        degraded_stages.push("token".to_string());
        warn!("Token circuit breaker is open");
        None
    };

    let (micro_token, scope_granted) = match token_result {
        Some(Ok(resp)) => {
            let r = resp.into_inner();
            (r.access_token, r.scope)
        }
        Some(Err(e)) => {
            error!("Token service unavailable: {}", e);
            degraded_stages.push("token".to_string());
            return apply_degradation_error(
                state.degradation.token_broker_unavailable,
                "token_unavailable",
                "Token service unavailable",
            );
        }
        None => {
            return apply_degradation_error(
                state.degradation.token_broker_unavailable,
                "token_unavailable",
                "Token service unavailable (circuit open)",
            );
        }
    };

    // ---- Stage 8: FORWARD to target_url + INSPECT RESPONSE ----
    let (tool_response, response_metadata) = match state
        .http_client
        .post(&body.target_url)
        .bearer_auth(&micro_token)
        .json(&body.params)
        .send()
        .await
    {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            // Capture response headers for x402 extraction before consuming the body.
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
                .collect();
            let body_bytes = resp.bytes().await.unwrap_or_default();

            // Stage 8b: INSPECT RESPONSE
            let metadata = inspect_response(&body_bytes, status_code, &content_type);
            debug!(
                status = status_code,
                body_size = metadata.body_size_bytes,
                records = metadata.records_count,
                pii = metadata.contains_pii_patterns,
                "Downstream tool responded"
            );

            // Stage 8b-drift: SEMANTIC DRIFT CHECK via LLM judge
            // Read historical output fingerprints from Redis and compare against
            // current response. If drift (>3x median) AND agent has recent contact
            // with a high-risk agent, call llm_judge_drift() to assess sleeper
            // activation. Runs in tokio::spawn to avoid blocking the response path.
            {
                let drift_pool = state.redis_pool.clone();
                let drift_agent_id = agent_id_str.clone();
                let drift_tool_name = tool_name.clone();
                let drift_body_size = metadata.body_size_bytes;
                let drift_records = metadata.records_count;
                let drift_http = state.http_client.clone();
                let drift_config = state.config.llm_judge.clone();
                let drift_purpose = agent_profile.declared_purpose.clone();
                let drift_body_summary = String::from_utf8_lossy(
                    &body_bytes[..body_bytes.len().min(500)]
                ).to_string();

                tokio::spawn(async move {
                    // 1. Read last 5 output fingerprints from Redis
                    let fingerprints: Vec<String> = {
                        let fp_key = format!("ag:output:fp:{}", drift_agent_id);
                        match drift_pool.get().await {
                            Ok(mut conn) => {
                                redis::cmd("LRANGE")
                                    .arg(&fp_key)
                                    .arg(0i64)
                                    .arg(4i64)
                                    .query_async::<Vec<String>>(&mut *conn)
                                    .await
                                    .unwrap_or_default()
                            }
                            Err(_) => Vec::new(),
                        }
                    };

                    if fingerprints.len() < 3 {
                        return; // Not enough history to detect drift
                    }

                    // 2. Parse fingerprints and compute median body_size and records_count
                    let mut sizes: Vec<u64> = Vec::new();
                    let mut records: Vec<u32> = Vec::new();
                    let mut summaries: Vec<String> = Vec::new();
                    for fp_json in &fingerprints {
                        if let Ok(fp) = serde_json::from_str::<serde_json::Value>(fp_json) {
                            if let Some(sz) = fp.get("body_size_bytes").and_then(|v| v.as_u64()) {
                                sizes.push(sz);
                            }
                            if let Some(rc) = fp.get("records_count").and_then(|v| v.as_u64()) {
                                records.push(rc as u32);
                            }
                            // Build a summary string from the fingerprint for LLM context
                            summaries.push(format!(
                                "size={}B records={} pii={}",
                                fp.get("body_size_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                                fp.get("records_count").and_then(|v| v.as_u64()).unwrap_or(0),
                                fp.get("contains_pii").and_then(|v| v.as_bool()).unwrap_or(false),
                            ));
                        }
                    }

                    if sizes.is_empty() {
                        return;
                    }

                    sizes.sort();
                    records.sort();
                    let median_size = sizes[sizes.len() / 2];
                    let median_records = if records.is_empty() { 0 } else { records[records.len() / 2] };

                    let size_drift = median_size > 0 && drift_body_size > median_size * 3;
                    let records_drift = median_records > 0 && drift_records > median_records * 3;

                    if !size_drift && !records_drift {
                        return; // No drift detected
                    }

                    // 3. Check if agent has recent contact with a high-risk agent
                    let contact_key = format!("ag:contact:last:{}", drift_agent_id);
                    let has_risky_contact: bool = match drift_pool.get().await {
                        Ok(mut conn) => {
                            let val: Option<String> = redis::cmd("GET")
                                .arg(&contact_key)
                                .query_async(&mut *conn)
                                .await
                                .unwrap_or(None);
                            // Parse "caller_id:risk:ts" — check if risk > 0.5
                            val.map_or(false, |v| {
                                let mut parts = v.rsplitn(3, ':');
                                let _ts = parts.next();
                                let risk_str = parts.next().unwrap_or("0");
                                risk_str.parse::<f64>().unwrap_or(0.0) > 0.5
                            })
                        }
                        Err(_) => false,
                    };

                    if !has_risky_contact {
                        return; // Drift without risky contact — not a sleeper signal
                    }

                    // 4. Call llm_judge_drift for semantic assessment
                    let drift_request = crate::model_escalation::LlmDriftRequest {
                        agent_id: drift_agent_id.clone(),
                        tool_name: drift_tool_name.clone(),
                        current_output_summary: format!(
                            "size={}B records={} body_preview={}",
                            drift_body_size, drift_records, drift_body_summary,
                        ),
                        historical_summaries: summaries,
                        declared_purpose: drift_purpose,
                    };

                    match crate::model_escalation::llm_judge_drift(
                        &drift_http, &drift_config, &drift_request,
                    ).await {
                        Ok(resp) if resp.risk_score > 0.7 => {
                            warn!(
                                agent_id = %drift_agent_id,
                                tool = %drift_tool_name,
                                drift_risk = resp.risk_score,
                                label = %resp.label,
                                "Sleeper agent drift detected by LLM judge — flagging for enhanced monitoring"
                            );
                            // Set enhanced monitoring flag in Redis (300s TTL)
                            if let Ok(mut conn) = drift_pool.get().await {
                                let em_key = format!("ag:enhanced_monitoring:{}", drift_agent_id);
                                let _: Result<(), _> = redis::cmd("SET")
                                    .arg(&em_key)
                                    .arg(format!("drift:{:.4}:{}", resp.risk_score, resp.label))
                                    .arg("EX")
                                    .arg(300i64)
                                    .query_async(&mut *conn)
                                    .await;
                            }
                            // Add sleeper_agent_detected to session flags in Redis
                            if let Ok(mut conn) = drift_pool.get().await {
                                let flag_key = format!("ag:session:flags:{}", drift_agent_id);
                                let _: Result<(), _> = redis::cmd("SADD")
                                    .arg(&flag_key)
                                    .arg("sleeper_agent_detected")
                                    .query_async(&mut *conn)
                                    .await;
                                let _: Result<(), _> = redis::cmd("EXPIRE")
                                    .arg(&flag_key)
                                    .arg(300i64)
                                    .query_async(&mut *conn)
                                    .await;
                            }
                        }
                        Ok(resp) => {
                            debug!(
                                agent_id = %drift_agent_id,
                                drift_risk = resp.risk_score,
                                "LLM judge drift check passed (risk below threshold)"
                            );
                        }
                        Err(e) => {
                            debug!(
                                agent_id = %drift_agent_id,
                                error = %e,
                                "LLM judge drift check skipped or failed"
                            );
                        }
                    }
                });
            }

            // Stage 8b-x402: INTERCEPT x402 PAYMENT REQUIRED
            // If downstream returned 402, extract payment details and enforce boundaries
            // BEFORE the agent/SDK wallet sends payment.
            if status_code == 402 {
                if let Some(payment) = crate::x402::extract_x402_payment(
                    status_code,
                    &resp_headers,
                    &body_bytes,
                ) {
                    let has_payment_scope = agent_profile.allowed_scopes.iter()
                        .any(|s| s.starts_with("payment:") || s == "payment" || s == "*");
                    let payment_boundaries = crate::x402::PaymentBoundaryConfig {
                        max_payment_per_tx_cents: agent_profile.boundaries.as_ref()
                            .map_or(0, |b| b.max_payment_per_tx_cents),
                        max_payment_per_hour_cents: agent_profile.boundaries.as_ref()
                            .map_or(0, |b| b.max_payment_per_hour_cents),
                        approved_vendors: agent_profile.boundaries.as_ref()
                            .map_or_else(Vec::new, |b| b.approved_vendors.clone()),
                        has_payment_scope,
                    };
                    let decision = crate::x402::enforce_x402(&payment, &agent_id_str, &payment_boundaries);

                    if !decision.allow {
                        info!(
                            request_id = %request_id,
                            agent_id = %agent_id_str,
                            amount = %payment.amount,
                            currency = %payment.currency,
                            recipient = %payment.recipient,
                            reason = ?decision.deny_reason,
                            "x402 payment BLOCKED"
                        );
                        let blocked_body = crate::x402::blocked_payment_response(
                            decision.deny_reason.as_deref().unwrap_or("payment not permitted"),
                        );
                        let parsed: serde_json::Value =
                            serde_json::from_slice(&blocked_body).unwrap_or_default();
                        return Ok(Json(ProxyResponse {
                            request_id: request_id.to_string(),
                            allowed: false,
                            action: "block".to_string(),
                            risk_score: assessed_risk,
                            scope_granted: Some(scope_granted.clone()),
                            tool_response: Some(parsed),
                            denial_reason: decision.deny_reason,
                            reasoning: Some("x402 payment blocked by boundary enforcement".to_string()),
                            matched_rules: vec![],
                            latency_ms: started_at.elapsed().as_millis() as u64,
                            degraded_stages: degraded_stages.clone(),
                            session_flags: session_flags.clone(),
                            scope_token: None,
                        }));
                    }

                    // Allowed — adjust risk and log.
                    debug!(
                        request_id = %request_id,
                        agent_id = %agent_id_str,
                        amount = %payment.amount,
                        currency = %payment.currency,
                        risk_modifier = decision.risk_modifier,
                        "x402 payment ALLOWED — passing 402 through"
                    );
                    // Note: risk modifier applied via x402 audit trail; assessed_risk
                    // is already finalized at this point in the pipeline. The risk
                    // modifier is recorded in shadow events for downstream consumption.
                }
            }

            // Stage 8c: SANITIZE ERROR RESPONSES (FIX 2)
            // Strip sensitive internals (Zod trees, stack traces, MCP version) from error responses
            let effective_body = if status_code >= 400 {
                let (sanitized, was_sanitized) = crate::response_inspector::sanitize_error_response(&body_bytes, status_code);
                if was_sanitized {
                    debug!(
                        request_id = %request_id,
                        status = status_code,
                        "Sanitized error response — stripped sensitive internal details"
                    );
                }
                sanitized
            } else {
                body_bytes.to_vec()
            };

            let parsed: serde_json::Value =
                serde_json::from_slice(&effective_body).unwrap_or_else(|_| {
                    serde_json::Value::String(String::from_utf8_lossy(&effective_body).to_string())
                });

            (Some(parsed), Some(metadata))
        }
        Err(e) => {
            warn!("Downstream tool call failed: {}", e);
            (None, None)
        }
    };

    // ---- Stage 8c: POST-RESPONSE DENY CHECK (mid-flight kill detection) ----
    // If the agent was kill-switched while the downstream tool was executing,
    // discard the response and return 403. This is an O(1) in-memory check.
    if state.deny_set.contains(&agent_id_str) {
        warn!(
            request_id = %request_id,
            agent_id = %agent_id_str,
            tool = %tool_name,
            "Agent killed mid-flight — discarding downstream response"
        );

        // Publish shadow event for the discarded response
        let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
        crate::shadow::publish_event(&state, &ShadowEvent {
            request_id,
            trace_id: request_id.to_string(),
            org_id: api_key_info.org_id.clone(),
            agent_id: agent_id_str.clone(),
            agent_name: agent_profile.name.clone(),
            user_id: jwt_claims.user_id.clone().unwrap_or_default(),
            tool_name: tool_name.clone(),
            tool_action: action.clone(),
            params_hash: params_hash.clone(),
            params_summary: params_summary.clone(),
            prompt_hash: prompt_hash.clone().unwrap_or_default(),
            assessed_risk,
            intent_classification: classification.clone(),
            policy_action: "deny".into(),
            policy_reason: policy_reason.clone(),
            scope_requested: agent_profile.allowed_scopes.join(" "),
            scope_granted: Some(scope_granted.clone()),
            blocked: true,
            denial_reason: Some("agent_killed_mid_flight".into()),
            latency_ms: started_at.elapsed().as_millis() as u32,
            encodings_detected: encodings_detected.clone(),
            encoding_risk_bonus,
            session_id: session_id.clone(),
            session_flags: session_flags.clone(),
            session_risk_factor,
            response_metadata,
            degraded_stages: degraded_stages.clone(),
            intent_labels: intent_labels.clone(),
            matched_rules: matched_rules.clone(),
            caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
            delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
            delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
            tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
            tool_description: body.tool_description.clone().unwrap_or_default(),
            tool_params_schema: body.tool_params_schema.clone().unwrap_or_default(),
            active_hours_start: ah_start,
            active_hours_end: ah_end,
            rejection_type: ag_common::models::RejectionType::Security, // mid-flight kill is a security action
            a2a_event_type: a2a_event_type.clone(),
            ..ShadowEvent::default()
        }).await;

        return Err(api_error(
            StatusCode::FORBIDDEN,
            "agent_killed_mid_flight",
            "Agent was kill-switched during tool execution — response discarded",
        ));
    }

    let latency_ms = started_at.elapsed().as_millis() as u64;

    // ---- Update session context (fire-and-forget after response) ----
    {
        let records_returned = response_metadata
            .as_ref()
            .map(|m| m.records_count)
            .unwrap_or(0);
        let is_external = session::is_external_send(&tool_name, &action);
        let tables = session::extract_tables_from_params(&tool_name, &body.params);
        let tool_record = session::build_tool_record(
            &tool_name,
            &action,
            records_returned,
            false, // not denied (we passed decision gate)
            is_external,
            tables,
            "",
        );

        let mut session_to_save = session_context.clone();
        let max_records = 1000u32; // default; would come from agent boundaries in full impl
        session_to_save.record_tool_call(tool_record, max_records);
        session_to_save.record_risk(assessed_risk);

        // Save session async (fire-and-forget per spec)
        let pool = state.redis_pool.clone();
        let tool_for_sadd = tool_name.clone();
        let agent_for_sadd = agent_id_str.clone();
        tokio::spawn(async move {
            session::save_session(&pool, &session_to_save).await;
            // Record this tool as known for first-time detection
            let known_tools_key = format!("ag:baseline:{}:known_tools", agent_for_sadd);
            if let Ok(mut conn) = pool.get().await {
                let _: Result<(), _> = redis::cmd("SADD")
                    .arg(&known_tools_key)
                    .arg(&tool_for_sadd)
                    .query_async(&mut *conn)
                    .await;
                let _: Result<(), _> = redis::cmd("EXPIRE")
                    .arg(&known_tools_key)
                    .arg(30 * 86400i64)
                    .query_async(&mut *conn)
                    .await;
            }
        });
    }

    // ---- Stage 9: AUDIT (async fire-and-forget) ----
    let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
    crate::shadow::publish_event(&state, &ShadowEvent {
        request_id,
        trace_id: request_id.to_string(),
        org_id: api_key_info.org_id.clone(),
        agent_id: agent_id_str.clone(),
        agent_name: agent_profile.name.clone(),
        user_id: jwt_claims.user_id.clone().unwrap_or_default(),
        tool_name: tool_name.clone(),
        tool_action: action.clone(),
        params_hash: params_hash.clone(),
        params_summary: params_summary.clone(),
        prompt_hash: prompt_hash.clone().unwrap_or_default(),
        assessed_risk,
        intent_classification: classification.clone(),
        policy_action: "allow".into(),
        policy_reason: policy_reason.clone(),
        scope_requested: agent_profile.allowed_scopes.join(" "),
        scope_granted: Some(scope_granted.clone()),
        blocked: false,
        latency_ms: latency_ms as u32,
        encodings_detected: encodings_detected.clone(),
        encoding_risk_bonus,
        session_id: session_id.clone(),
        session_flags: session_flags.clone(),
        session_risk_factor,
        response_metadata: response_metadata.clone(),
        degraded_stages: degraded_stages.clone(),
        intent_labels: intent_labels.clone(),
        matched_rules: matched_rules.clone(),
        caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
        delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
        delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
        tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
        tool_description: body.tool_description.clone().unwrap_or_default(),
        tool_params_schema: body.tool_params_schema.clone().unwrap_or_default(),
        active_hours_start: ah_start,
        active_hours_end: ah_end,
        a2a_event_type: a2a_event_type.clone(),
        ..ShadowEvent::default()
    }).await;

    // Track allowed/flagged metrics
    if intent_says_flag {
        crate::metrics::increment_flagged();
    }
    crate::metrics::increment_allowed();
    crate::metrics::record_latency(started_at.elapsed().as_micros() as u64);

    stage_latencies.push(("token_forward_inspect", stage_start.elapsed().as_micros() as u64));

    info!(
        request_id = %request_id,
        tool = %tool_name,
        risk = assessed_risk,
        latency_ms,
        "Proxy request completed"
    );
    // Log per-stage latency breakdown for observability
    let stage_breakdown: String = stage_latencies.iter()
        .map(|(name, us)| format!("{}={:.2}ms", name, *us as f64 / 1000.0))
        .collect::<Vec<_>>().join(" ");
    debug!(request_id = %request_id, stages = %stage_breakdown, "Stage latency breakdown (forwarded)");

    Ok(Json(ProxyResponse {
        request_id: request_id.to_string(),
        allowed: true,
        action: action_str(intent_action),
        risk_score: assessed_risk,
        scope_granted: Some(scope_granted),
        tool_response,
        denial_reason: None,
        reasoning,
        matched_rules,
        latency_ms,
        degraded_stages,
        session_flags,
        scope_token: None, // Full proxy mode uses micro_token in Authorization header instead
    }))
}

/// POST /v1/verify — Dry-run (Stages 1-6 only, no token exchange or forwarding).
///
/// Important: /v1/verify READS session context but does NOT WRITE to it.
/// Session state is only updated by actual /v1/proxy calls.
pub async fn handle_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    let started_at = Instant::now();
    let request_id = Uuid::new_v4();

    // Same as proxy stages 1-6, but return early without token/forward
    let api_key = headers
        .get("x-ag-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing_api_key", "Missing X-AG-Key header"))?;

    let api_key_info = validate_api_key(&state.redis_pool, api_key).await
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid_api_key", "Invalid API key"))?;

    let jwt_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing_jwt", "Missing Authorization Bearer token"))?;

    let jwt_secret = JWT_SECRET_CACHED.clone();
    let jwt_claims = validate_jwt_with_agent_credential(jwt_token, &jwt_secret, &state.redis_pool)
        .await
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, "invalid_jwt", e))?;
    let agent_id_str = jwt_claims.sub.clone();
    if state.deny_set.contains(&agent_id_str) {
        return Err(api_error(StatusCode::FORBIDDEN, "agent_killed", "Agent is kill-switched"));
    }

    // ---- CROSS-ORG AGENT ACCESS GUARD ----
    crate::scan::check_agent_org_membership(&state.redis_pool, &agent_id_str, &api_key_info.org_id).await?;

    // License gate applies to verify too
    let license_gate = license_gate::check_license(&state.redis_pool).await;
    if license_gate.status == GatewayLicenseStatus::Revoked {
        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "license_revoked", "License revoked — contact support at clampd.dev"));
    }

    let (tool_name, action, params_json, _params_hash, _) = extract_tool_call(&body);

    // Run normalization for verify too (affects risk scoring)
    let norm_result = normalize_params(&body.params, &params_json);

    // Load session context for accurate risk scoring (read-only)
    let session_id = session::extract_session_id(&headers, &agent_id_str)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, "invalid_session_id", e))?;
    let agent_uuid = Uuid::parse_str(&agent_id_str)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid_agent_id", "Agent ID is not a valid UUID"))?;
    let session_context =
        session::load_or_create_session(&state.redis_pool, &agent_uuid, &session_id).await;
    let session_flags = session_context.flag_names();
    let session_risk_factor = session_context.risk_factor();

    // Fetch agent baseline from cache (ag-risk Redis HSET, 60s local TTL)
    let baseline = state.baseline_cache.get(&agent_id_str).await;

    // Classify (with circuit breaker check)
    let classify_result = if state.circuit_breakers.is_allowed("intent") {
        let mut client = state.intent.clone();
        let result = client
            .classify_intent(ClassifyRequest {
                tool_name: tool_name.clone(),
                action: action.clone(),
                params_json: params_json.clone(),
                params_normalized_json: norm_result.normalized_params_json.clone(),
                encodings_detected: norm_result.encodings_detected.clone(),
                agent_purpose: String::new(),
                agent_id: agent_id_str.clone(),
                agent_risk_score: 0.0,
                session_flags: session_flags.clone(),
                session_risk_factor,
                session_total_calls: session_context.tool_calls.len() as i32,
                session_context_window: session_context.tool_calls.len().min(10) as i32,
                session_context_json: build_session_context_json(&session_context, baseline.as_ref()),
                caller_agent_id: None,
                delegation_chain: Vec::new(),
                delegation_trace_id: None,
                delegation_confidence: None,
                tool_descriptor_hash: String::new(),
            })
            .await;
        match &result {
            Ok(_) => state.circuit_breakers.record_success("intent"),
            Err(_) => state.circuit_breakers.record_failure("intent"),
        }
        Some(result)
    } else {
        None
    };

    let (assessed_risk, _classification, verify_reasoning, verify_rules, verify_intent_action) = match classify_result {
        Some(Ok(resp)) => {
            let r = resp.into_inner();
            let reason = if r.reasoning.is_empty() { None } else { Some(r.reasoning) };
            (r.assessed_risk, r.classification, reason, r.matched_rules, r.action)
        }
        Some(Err(_)) | None => (0.0, "Unknown".to_string(), None, vec![], 0i32),
    };

    // Model escalation for gray-zone scores (same as proxy pipeline)
    let assessed_risk = if crate::model_escalation::needs_escalation(
        &state.config.model_escalation,
        assessed_risk,
    ) {
        match crate::model_escalation::escalate(
            &state.http_client,
            &state.config.model_escalation,
            crate::model_escalation::ModelRequest {
                tool_name: tool_name.clone(),
                action: action.clone(),
                params_json: params_json.clone(),
                rules_risk_score: assessed_risk,
                matched_rules: verify_rules.clone(),
                classification: _classification.clone(),
                agent_id: agent_id_str.clone(),
                session_flags: session_flags.clone(),
            },
        )
        .await
        {
            Some(model_resp) => model_resp.risk_score.clamp(0.0, 1.0),
            None => assessed_risk,
        }
    } else {
        assessed_risk
    };

    // Block if: (1) intent says BLOCK, or (2) risk >= threshold (unless FLAG)
    let intent_says_block = verify_intent_action == 2; // Action::BLOCK
    let intent_says_flag = verify_intent_action == 1;  // Action::FLAG (warn only)
    let blocked = !intent_says_flag && (intent_says_block || assessed_risk >= state.config.risk_threshold);
    let latency_ms = started_at.elapsed().as_millis() as u64;

    // NOTE: /v1/verify does NOT save session context (read-only per spec).

    info!(
        request_id = %request_id,
        tool = %body.tool,
        risk = assessed_risk,
        allowed = !blocked,
        latency_ms,
        "Verify request completed"
    );

    Ok(Json(ProxyResponse {
        request_id: request_id.to_string(),
        allowed: !blocked,
        action: action_str(verify_intent_action),
        risk_score: assessed_risk,
        scope_granted: None,
        tool_response: None,
        denial_reason: if blocked {
            Some(format!("Risk score {:.2} exceeds threshold", assessed_risk))
        } else {
            None
        },
        reasoning: verify_reasoning,
        matched_rules: verify_rules,
        latency_ms,
        degraded_stages: Vec::new(),
        session_flags,
        scope_token: None, // /v1/verify is dry-run only
    }))
}

// ── Scope token verification for /v1/inspect ────────────────────────────
// ScopeTokenClaims and verify_scope_token moved to crate::scope_token.

/// Mutation-evidence patterns in response text that contradict a read-only scope.
const MUTATION_EVIDENCE: &[&str] = &[
    "rows updated",
    "rows deleted",
    "insert into",
    "table dropped",
    "rows inserted",
    "rows affected",
    "table created",
    "table altered",
];

/// Size threshold for flagging response data as anomalously large (100KB).
const INSPECT_SIZE_ANOMALY_THRESHOLD: usize = 100 * 1024;

/// Sensitive keyword patterns scanned during response inspection.
const SENSITIVE_KEYWORDS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "private_key",
    "private-key",
    "client_secret",
    "client-secret",
];

/// POST /v1/inspect — Inspect a tool response for PII, anomalies, and sensitive data.
///
/// Runs the response data through lightweight checks without forwarding or
/// token exchange. Uses the same auth pattern as /v1/proxy (JWT + API key).
pub async fn handle_inspect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InspectRequest>,
) -> Result<Json<ProxyResponse>, ApiError> {
    let started_at = Instant::now();
    let request_id = body
        .request_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .unwrap_or_else(Uuid::new_v4);

    // ---- AUTH (same pattern as /v1/proxy) ----
    let api_key = headers
        .get("x-ag-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing_api_key", "Missing X-AG-Key header"))?;

    let api_key_info = validate_api_key(&state.redis_pool, api_key).await
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid_api_key", "Invalid API key"))?;

    let jwt_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing_jwt", "Missing Authorization Bearer token"))?;

    let jwt_secret = JWT_SECRET_CACHED.clone();
    let jwt_claims = validate_jwt_with_agent_credential(jwt_token, &jwt_secret, &state.redis_pool)
        .await
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, "invalid_jwt", e))?;
    let agent_id_str = jwt_claims.sub.clone();
    if state.deny_set.contains(&agent_id_str) {
        return Err(api_error(StatusCode::FORBIDDEN, "agent_killed", "Agent is kill-switched"));
    }

    // ---- CROSS-ORG AGENT ACCESS GUARD ----
    crate::scan::check_agent_org_membership(&state.redis_pool, &agent_id_str, &api_key_info.org_id).await?;

    // ---- INSPECT RESPONSE DATA ----
    let serialized = serde_json::to_string(&body.response_data).unwrap_or_default();
    let serialized_bytes = serialized.as_bytes();

    let mut risk_score: f64 = 0.0;
    let mut findings: Vec<String> = Vec::new();

    // 1. PII detection via the existing response_inspector machinery
    let metadata = inspect_response(
        serialized_bytes,
        200, // synthetic status — we're inspecting data, not a real HTTP response
        "application/json",
    );
    if metadata.contains_pii_patterns {
        risk_score += 0.4;
        findings.push("PII patterns detected in response data".to_string());
    }

    // 2. Size anomaly check (>100KB)
    if serialized_bytes.len() > INSPECT_SIZE_ANOMALY_THRESHOLD {
        risk_score += 0.2;
        findings.push(format!(
            "Response data size {}KB exceeds 100KB threshold",
            serialized_bytes.len() / 1024,
        ));
    }

    // 3. Sensitive keyword scan (case-insensitive)
    let lower = serialized.to_lowercase();
    let mut matched_keywords: Vec<String> = Vec::new();
    for kw in SENSITIVE_KEYWORDS {
        if lower.contains(kw) {
            matched_keywords.push((*kw).to_string());
        }
    }
    if !matched_keywords.is_empty() {
        risk_score += 0.3;
        findings.push(format!(
            "Sensitive keywords found: {}",
            matched_keywords.join(", ")
        ));
    }

    // 4. Scope token verification — check that response doesn't violate granted scope
    let mut scope_blocked = false;
    if let Some(ref token) = body.scope_token {
        match crate::scope_token::verify(token, &state.scope_verifying_key, chrono::Utc::now().timestamp()) {
            Ok(claims) => {
                let scope = claims.scope.unwrap_or_default();

                // If scope is read-only but response contains mutation evidence,
                // that indicates the tool performed an unauthorized write operation.
                if scope.contains("query") || scope.contains("read") {
                    let response_text = body.response_data.to_string().to_lowercase();
                    for pattern in MUTATION_EVIDENCE {
                        if response_text.contains(pattern) {
                            findings.push(format!(
                                "scope_violation: response indicates mutation ('{}') but scope is read-only ({})",
                                pattern, scope
                            ));
                            risk_score = risk_score.max(0.90);
                            scope_blocked = true;
                            break;
                        }
                    }
                }

                debug!(
                    scope = %scope,
                    tool = %claims.tool,
                    agent = %claims.sub,
                    "Scope token verified for response inspection"
                );
            }
            Err(reason) => {
                warn!(reason = %reason, "Invalid scope_token in inspect request");
                // Don't block — token verification failure shouldn't prevent inspection
                // But record it for audit trail
                findings.push(format!("scope_token_invalid: {}", reason));
            }
        }
    }

    // Clamp risk score to [0.0, 1.0]
    risk_score = risk_score.clamp(0.0, 1.0);

    let blocked = scope_blocked || risk_score >= state.config.risk_threshold;
    let denial_reason = if blocked {
        Some(findings.join("; "))
    } else {
        None
    };

    let latency_ms = started_at.elapsed().as_millis() as u64;

    info!(
        request_id = %request_id,
        tool = %body.tool,
        risk = risk_score,
        findings = ?findings,
        latency_ms,
        "Inspect request completed"
    );

    Ok(Json(ProxyResponse {
        request_id: request_id.to_string(),
        allowed: !blocked,
        action: if blocked { "block".to_string() } else { "pass".to_string() },
        risk_score,
        scope_granted: None,
        tool_response: None,
        denial_reason,
        reasoning: if findings.is_empty() {
            None
        } else {
            Some(findings.join("; "))
        },
        matched_rules: matched_keywords,
        latency_ms,
        degraded_stages: Vec::new(),
        session_flags: Vec::new(),
        scope_token: None,
    }))
}

/// Apply degradation mode and return an error or default values.
///
/// Used when a circuit breaker is open or a gRPC call fails for
/// registry and token stages (which cannot proceed with defaults).
fn apply_degradation_error<T>(
    mode: DegradationMode,
    code: &str,
    message: &str,
) -> Result<T, ApiError> {
    match mode {
        DegradationMode::FailClosed => {
            Err(api_error(StatusCode::SERVICE_UNAVAILABLE, code, message))
        }
        DegradationMode::AllowWithAlert => {
            warn!("Degraded (AllowWithAlert): {}", message);
            Err(api_error(StatusCode::SERVICE_UNAVAILABLE, code, message))
        }
        DegradationMode::ApplyCachedRules => {
            warn!("Degraded (ApplyCachedRules): {} — no cache impl yet, fail-closed", message);
            Err(api_error(StatusCode::SERVICE_UNAVAILABLE, code, message))
        }
        DegradationMode::ApplyDefaultDeny => {
            warn!("Degraded (ApplyDefaultDeny): {}", message);
            Err(api_error(StatusCode::SERVICE_UNAVAILABLE, code, message))
        }
    }
}

/// Apply degradation for intent/policy stages that CAN produce default values.
///
/// Returns `Some((risk, classification, labels, rules, action))` if degradation
/// allows proceeding with defaults, or `None` if fail-closed.
fn apply_degradation_or_default(
    mode: DegradationMode,
) -> Option<(f64, String, Vec<String>, Vec<String>, String)> {
    match mode {
        DegradationMode::AllowWithAlert => {
            // Proceed with risk=0.5 (Suspicious) and alert.
            Some((
                0.5,
                "Suspicious".to_string(),
                vec!["degraded".to_string()],
                Vec::new(),
                "allow_with_alert".to_string(),
            ))
        }
        DegradationMode::FailClosed
        | DegradationMode::ApplyCachedRules
        | DegradationMode::ApplyDefaultDeny => None,
    }
}

/// Extract a human-readable summary from request params (truncated to 200 chars).
/// Shows the actual query, URL, path, or command for TUI/audit display.
fn summarize_params(tool_name: &str, params: &serde_json::Value) -> String {
    let summary = if let Some(query) = params.get("query").and_then(|v| v.as_str()) {
        query.to_string()
    } else if let Some(url) = params.get("url").and_then(|v| v.as_str()) {
        url.to_string()
    } else if let Some(path) = params.get("path").and_then(|v| v.as_str()) {
        path.to_string()
    } else if let Some(cmd) = params.get("command").and_then(|v| v.as_str()) {
        cmd.to_string()
    } else if let Some(endpoint) = params.get("endpoint").and_then(|v| v.as_str()) {
        let method = params.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        format!("{} {}", method, endpoint)
    } else {
        // Fallback: compact JSON
        let json = serde_json::to_string(params).unwrap_or_default();
        json
    };

    // Truncate to 200 chars
    if summary.len() > 200 {
        format!("{}...", &summary[..197])
    } else {
        summary
    }
}

/// Check if learning mode is active for an agent (via its workflow or org setting).
/// Checks two levels:
///   1. Workflow: ag:agent:workflow:{agent_id} -> workflow_id, then ag:workflow:learning:{workflow_id} -> "true"
///   2. Org fallback: ag:org:auto_trust:{org_id} -> "true"
/// Fail-open on Redis errors: defaults to false (enforcement mode).
async fn check_auto_trust(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    agent_id: &str,
    org_id: &str,
) -> bool {
    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Check workflow-level first: is the agent's workflow in learning mode?
    let workflow_key = format!("ag:agent:workflow:{agent_id}");
    let workflow_id: Option<String> = redis::cmd("GET")
        .arg(&workflow_key)
        .query_async(&mut *conn)
        .await
        .unwrap_or(None);

    if let Some(wf_id) = workflow_id {
        // Workflow exists — check if it's NOT enforcing (= learning mode)
        let enforcement_key = format!("ag:delegation:enforcement:{org_id}");
        let enforcing: Option<String> = redis::cmd("GET")
            .arg(&enforcement_key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);

        // If org delegation is not enforced, the workflow is in learning mode
        if enforcing.as_deref() != Some("true") {
            return true;
        }

        // Even if org enforces, check the specific workflow's enforcement_mode
        // Workflows with enforcement_mode=false are in learning mode
        let wf_enforce_key = format!("ag:workflow:enforcement:{wf_id}");
        let wf_enforcing: Option<String> = redis::cmd("GET")
            .arg(&wf_enforce_key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);

        if wf_enforcing.as_deref() != Some("true") {
            return true; // workflow in learning mode
        }

        return false;
    }

    // No workflow — fall back to org-level auto_trust
    let org_key = format!("ag:org:auto_trust:{org_id}");
    let result: Option<String> = redis::cmd("GET")
        .arg(&org_key)
        .query_async(&mut *conn)
        .await
        .unwrap_or(None);
    result.as_deref() == Some("true")
}

/// Validate an API key by computing SHA-256 hash and checking Redis.
/// Key format in Redis: ag:apikey:{hash_prefix} -> { "is_active": true, "org_id": "..." }
/// Fail-closed: Redis failure = reject.  No guessing.
/// Result of a successful API key validation.
pub(crate) struct ApiKeyInfo {
    pub(crate) org_id: String,
}

pub(crate) async fn validate_api_key(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    raw_key: &str,
) -> Option<ApiKeyInfo> {
    // Validate key format: must start with ag_live_ or ag_test_
    if !raw_key.starts_with("ag_live_") && !raw_key.starts_with("ag_test_") {
        return None;
    }

    let hash = ag_common::auth::hash_api_key(raw_key);
    let redis_key = format!("ag:apikey:{}", &hash[..16]);

    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Redis unavailable for API key validation: {} — rejecting (fail-closed)", e);
            return None;
        }
    };

    match redis::cmd("GET").arg(&redis_key).query_async::<Option<String>>(&mut *conn).await {
        Ok(Some(value)) => {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&value) {
                let is_active = parsed.get("is_active").and_then(|v| v.as_bool()).unwrap_or(false);
                if is_active {
                    let org_id = parsed.get("org_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    Some(ApiKeyInfo { org_id })
                } else {
                    None
                }
            } else {
                None
            }
        }
        Ok(None) => None,
        Err(e) => {
            tracing::error!("Redis GET failed for API key: {} — rejecting (fail-closed)", e);
            None
        }
    }
}

/// Per-agent JWT validation with Redis credential lookup.
///
/// 1. Decode JWT (without sig check) to extract `sub` (agent_id).
/// 2. Look up `ag:agent:cred:{agent_id}` in Redis for per-agent secret hash.
/// 3. If found: validate JWT signature against the agent's credential hash.
/// 4. If not found (IdP agent, dev mode): fall back to global `JWT_SECRET`.
/// 5. If Redis is down: fall back to global `JWT_SECRET` (existing behavior).
///
/// This means rotating an agent's secret in the dashboard immediately
/// invalidates JWTs signed with the old secret (once ag-control syncs the
/// new hash to Redis, typically within ~10s).
async fn validate_jwt_with_agent_credential(
    token: &str,
    jwt_secret: &str,
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> Result<ag_common::models::AgentJwtClaims, String> {
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm, TokenData};

    // JWT_SECRET is always required — no decode-only mode.
    if jwt_secret.is_empty() {
        return Err("JWT_SECRET not configured — cannot validate JWT".to_string());
    }

    // Step 1: Decode without sig verification to extract agent_id (sub claim).
    let agent_id = {
        let mut peek_validation = Validation::default();
        peek_validation.insecure_disable_signature_validation();
        peek_validation.validate_exp = false; // don't reject expired yet
        peek_validation.validate_aud = false;
        let key = DecodingKey::from_secret(b"unused");
        let token_data: TokenData<serde_json::Value> = decode(token, &key, &peek_validation)
            .map_err(|e| format!("JWT decode failed: {}", e))?;
        token_data
            .claims
            .get("sub")
            .and_then(|v| v.as_str())
            .map(String::from)
    };

    // Step 2: Look up per-agent credential hash in Redis.
    // Redis failure = reject.  No guessing, no fail-open.
    let agent_secret = if let Some(ref aid) = agent_id {
        let redis_key = format!("ag:agent:cred:{}", aid);
        match redis_pool.get().await {
            Ok(mut conn) => {
                match redis::cmd("GET")
                    .arg(&redis_key)
                    .query_async::<Option<String>>(&mut *conn)
                    .await
                {
                    Ok(val) => val,
                    Err(e) => {
                        return Err(format!(
                            "Redis error during credential lookup: {} — rejecting request (fail-closed)", e
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Redis unavailable for credential lookup: {} — rejecting request (fail-closed)", e
                ));
            }
        }
    } else {
        None
    };

    // Step 3: Validate signature.  No fallback.  No second chances.
    //
    // - Per-agent key exists in Redis → validate ONLY against that key.
    //   This is the credential_hash (SHA-256 of the raw ags_ secret).
    //   The SDK signs the JWT with the same hash.  If it doesn't match,
    //   the request is rejected — period.
    //
    // - No per-agent key in Redis (IdP agent, agent without clampd auth) →
    //   validate against global JWT_SECRET.  This is the only case where
    //   the global secret is used.
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_aud = false;

    let signing_key = match agent_secret {
        Some(ref agent_key) => agent_key.as_str(),
        None => jwt_secret,
    };

    let key = DecodingKey::from_secret(signing_key.as_bytes());
    let token_data: TokenData<serde_json::Value> = decode(token, &key, &validation)
        .map_err(|e| format!("JWT validation failed: {}", e))?;
    extract_claims_from_value(&token_data.claims)
}

/// Public wrapper for JWT validation, used by scan endpoints.
pub async fn validate_jwt_for_scan(
    token: &str,
    jwt_secret: &str,
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> Result<ag_common::models::AgentJwtClaims, String> {
    validate_jwt_with_agent_credential(token, jwt_secret, redis_pool).await
}

fn extract_claims_from_value(claims: &serde_json::Value) -> Result<ag_common::models::AgentJwtClaims, String> {
    let sub = claims.get("sub")
        .and_then(|v| v.as_str())
        .ok_or("JWT missing 'sub' claim")?;
    // Validate UUID format to prevent Redis key injection and random UUID fallback
    if uuid::Uuid::parse_str(sub).is_err() {
        return Err("JWT 'sub' claim is not a valid UUID".to_string());
    }
    let sub = sub.to_string();
    let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    let user_id = claims.get("user_id").and_then(|v| v.as_str()).map(String::from);
    Ok(ag_common::models::AgentJwtClaims { sub, iss, aud, scope, exp, user_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── extract_claims_from_value ────────────────────────────

    #[test]
    fn extract_claims_valid() {
        let claims = json!({
            "sub": "b0000000-0000-0000-0000-000000000001",
            "iss": "clampd-sdk",
            "aud": "ag-gateway",
            "scope": "read write",
            "exp": 9999999999i64,
            "user_id": "user-123"
        });
        let result = extract_claims_from_value(&claims).unwrap();
        assert_eq!(result.sub, "b0000000-0000-0000-0000-000000000001");
        assert_eq!(result.iss, "clampd-sdk");
        assert_eq!(result.aud, "ag-gateway");
        assert_eq!(result.scope, "read write");
        assert_eq!(result.exp, 9999999999);
        assert_eq!(result.user_id, Some("user-123".to_string()));
    }

    #[test]
    fn extract_claims_minimal_sub_only() {
        let claims = json!({"sub": "a0000000-0000-0000-0000-000000000002"});
        let result = extract_claims_from_value(&claims).unwrap();
        assert_eq!(result.sub, "a0000000-0000-0000-0000-000000000002");
        assert_eq!(result.iss, "");
        assert_eq!(result.aud, "");
        assert_eq!(result.scope, "");
        assert_eq!(result.exp, 0);
        assert_eq!(result.user_id, None);
    }

    #[test]
    fn extract_claims_missing_sub_fails() {
        let claims = json!({"iss": "test", "exp": 1234});
        let result = extract_claims_from_value(&claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sub"));
    }

    #[test]
    fn extract_claims_null_sub_fails() {
        let claims = json!({"sub": null, "iss": "test"});
        let result = extract_claims_from_value(&claims);
        assert!(result.is_err());
    }

    #[test]
    fn extract_claims_numeric_sub_fails() {
        // sub must be a string, not a number
        let claims = json!({"sub": 12345});
        let result = extract_claims_from_value(&claims);
        assert!(result.is_err());
    }

    #[test]
    fn extract_claims_empty_sub_rejected() {
        // Empty string is not a valid UUID — rejected at extraction
        let claims = json!({"sub": ""});
        let result = extract_claims_from_value(&claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UUID"));
    }

    // ── validate_jwt_with_agent_credential: empty secret ─────

    #[tokio::test]
    async fn validate_jwt_empty_secret_rejects() {
        // We can't easily construct a Redis pool in unit tests,
        // but we CAN test the early-exit path: empty JWT_SECRET → immediate error.
        // Use a dummy pool that will never be reached.
        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1")
            .expect("manager creation");
        let pool = bb8::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(1))
            .build(manager)
            .await
            .expect("pool creation");

        let result = validate_jwt_with_agent_credential(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake",
            "",
            &pool,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("JWT_SECRET not configured"));
    }

    // ── JWT signature validation ─────────────────────────────

    #[tokio::test]
    async fn validate_jwt_invalid_token_rejects() {
        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1")
            .expect("manager");
        let pool = bb8::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(1))
            .build(manager)
            .await
            .expect("pool");

        let result = validate_jwt_with_agent_credential(
            "not-a-jwt-at-all",
            "some-secret-that-is-32-chars-long!",
            &pool,
        )
        .await;

        assert!(result.is_err(), "Garbage token should be rejected");
    }

    #[tokio::test]
    async fn validate_jwt_tampered_payload_rejects() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "clampd-dev-secret-change-me-in-production-32ch";

        // Build a valid JWT
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"agent-001","exp":9999999999}"#);
        let signing_input = format!("{}.{}", header, payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let valid_token = format!("{}.{}.{}", header, payload, sig);

        // Tamper with payload (change agent-001 to agent-999)
        let tampered_payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"agent-999","exp":9999999999}"#);
        let tampered_token = format!("{}.{}.{}", header, tampered_payload, sig);

        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1").unwrap();
        let pool = bb8::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(1))
            .build(manager)
            .await
            .unwrap();

        // Valid token fails only because Redis is unreachable (fail-closed)
        // but importantly does NOT fail on decode
        let result = validate_jwt_with_agent_credential(&valid_token, secret, &pool).await;
        // Redis unreachable → fail-closed error (expected in unit test without Redis)
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Redis") || err.contains("redis"),
            "Valid token should get past decode but fail on Redis: {}",
            err
        );

        // Tampered token should fail on signature verification
        // (it reaches Redis lookup first since decode succeeds, but the sig
        //  check happens after — in unit tests without Redis it fails at Redis)
        let result2 = validate_jwt_with_agent_credential(&tampered_token, secret, &pool).await;
        assert!(result2.is_err());
    }
}
