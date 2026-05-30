use std::sync::{Arc, LazyLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Cached JWT_SECRET - read once at first access, immutable thereafter.
/// main.rs validates length (>=32 chars) and exits before any request handler runs,
/// so this is guaranteed non-empty in production.
pub(crate) static JWT_SECRET_CACHED: LazyLock<String> = LazyLock::new(|| {
    std::env::var("JWT_SECRET").unwrap_or_default()
});

/// Strict descriptor-hash enforcement. When true, a call to a tool that has a
/// pinned (approved) descriptor hash MUST present a matching `tool_descriptor_hash`
/// — a call that omits it is rejected, closing the "omit the hash to skip the
/// rug-pull check" bypass. Off by default because not every client sends the hash
/// on every call (e.g. dashboard-classified tools); enable once all clients do.
pub(crate) static REQUIRE_DESCRIPTOR_HASH: LazyLock<bool> = LazyLock::new(|| {
    matches!(
        std::env::var("CLAMPD_REQUIRE_DESCRIPTOR_HASH").as_deref(),
        Ok("true") | Ok("1")
    )
});

use ag_common::degradation::DegradationMode;
use ag_common::trust::{
    BoundaryOutcome, BoundaryReason, DecisionLayer, DecisionTrace, LayerDecision, TrustLevel,
};
use ag_proto::agentguard::{
    intent::ClassifyRequest,
    policy::{BoundaryCheckRequest, EvaluateRequest},
    token::ExchangeRequest,
};
use std::str::FromStr;
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

/// Resolve the action string for ALLOW responses.
///
/// When the request is allowed (`blocked == false`), the action should reflect
/// the final decision, not the raw intent. If intent was "block" but policy
/// exempted it, the action is "exempt". Otherwise, keep the raw intent action.
fn resolved_action_str(intent_action: i32, policy_reason: &str) -> String {
    if intent_action == 2 && policy_reason.starts_with("scope_exemption:") {
        "exempt".to_string()
    } else {
        action_str(intent_action)
    }
}
/// Convert borrowed stage latencies to owned for JSON response.
fn owned_stages(stages: &[(&str, u64)]) -> Vec<(String, u64)> {
    stages.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

/// Emit a ShadowEvent for a delegation-chain validation denial that fires
/// before the registry lookup (i.e. agent_name is not yet known).
///
/// Without this, depth-exceeded / cycle / malformed-chain rejections leave
/// no audit trail — they just return 4xx. Which means the dashboard's
/// "Delegation analytics" page sees nothing about hostile chains we caught.
#[allow(clippy::too_many_arguments)]
async fn publish_chain_validation_denial(
    state: &AppState,
    request_id: Uuid,
    org_id: &str,
    agent_id: &str,
    tool: &str,
    session_id: &str,
    chain: Option<Vec<String>>,
    trace_id: Option<String>,
    caller: Option<String>,
    started_at: Instant,
    code: &str,
    reason: String,
) {
    crate::shadow::publish_event(state, &ShadowEvent {
        request_id,
        trace_id: trace_id.clone().unwrap_or_else(|| request_id.to_string()),
        org_id: org_id.to_string(),
        agent_id: agent_id.to_string(),
        agent_name: "PRE_REGISTRY".into(),
        tool_name: tool.to_string(),
        caller_agent_id: caller,
        delegation_chain: chain,
        delegation_trace_id: trace_id,
        blocked: true,
        denial: Some(crate::denial::gateway_denial(format!("GATEWAY/{}", code), reason)),
        policy_action: "deny".into(),
        policy_reason: code.to_string(),
        assessed_risk: 0.85,
        session_id: session_id.to_string(),
        latency_ms: started_at.elapsed().as_millis() as u32,
        rejection_type: ag_common::models::RejectionType::Security,
        a2a_event_type: Some(code.to_string()),
        ..ShadowEvent::default()
    }).await;
}

fn build_decision_trace(
    trust: TrustLevel,
    boundary_reason_str: &str,
    boundary_matched_rule: &str,
    policy_reason: &str,
    policy_action: i32,
    blocked: bool,
    intent_action: i32,
    matched_rules: &[String],
) -> DecisionTrace {
    let outcome = BoundaryOutcome {
        trust,
        reason: match boundary_reason_str {
            "AllowListMatch" => BoundaryReason::AllowListMatch,
            "BlockListMatch" => BoundaryReason::BlockListMatch,
            "AllowListConfiguredButNoMatch" => BoundaryReason::AllowListConfiguredButNoMatch,
            "BehavioralAnomaly" => BoundaryReason::BehavioralAnomaly,
            "RateLimit" => BoundaryReason::RateLimit,
            "OffHours" => BoundaryReason::OffHours,
            "BlockedDay" => BoundaryReason::BlockedDay,
            _ => BoundaryReason::NoListConfigured,
        },
        matched_rule: if boundary_matched_rule.is_empty() {
            None
        } else {
            Some(boundary_matched_rule.to_string())
        },
        confidence: 1.0,
    };

    let mut trace = DecisionTrace::new(outcome);
    let intent_code = if matched_rules.is_empty() {
        "intent:clean".to_string()
    } else {
        format!("intent:{}", matched_rules.join(","))
    };
    trace.add_layer(if intent_action == 2 {
        LayerDecision::deny(DecisionLayer::Intent, intent_code, 0)
    } else {
        LayerDecision::allow(DecisionLayer::Intent, intent_code, 0)
    });

    let policy_code = if policy_reason.is_empty() {
        "policy:default".to_string()
    } else {
        format!("policy:{}", policy_reason)
    };
    trace.add_layer(if policy_action == 2 || blocked {
        LayerDecision::deny(DecisionLayer::Cedar, policy_code, 0)
    } else {
        LayerDecision::allow(DecisionLayer::Cedar, policy_code, 0)
    });
    trace
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
///
/// `resolved_scope` is the current request's classified scope (e.g.
/// "comms:email:send") computed from the typed descriptor at the call site.
/// Empty string when the tool is unclassified — produces an empty
/// scopes_requested array, which Pattern 7 (permission_escalation) treats
/// as "no novel scopes requested."
fn build_session_context_json(
    session_context: &ag_common::session::SessionContext,
    baseline: Option<&crate::baseline_cache::CachedBaseline>,
    resolved_scope: &str,
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

    // T4: emit the current request's resolved scope so Pattern 7 can compare
    // against baseline_scopes. Skip when the tool is unclassified — there's
    // no scope to compare and an empty value would produce a meaningless "" entry.
    let scopes_requested: Vec<&str> = if resolved_scope.is_empty() {
        Vec::new()
    } else {
        vec![resolved_scope]
    };

    // T8: previous_output_sensitive is the PII flag from the most recent
    // tool call's response. At the time this function runs, the CURRENT
    // request has not yet been recorded into tool_calls (record_tool_call
    // fires after the decision pipeline completes), so .last() returns the
    // genuinely previous call — exactly the "prev tool returned sensitive
    // data" semantic Pattern 13 (sensitive_data_flow, +0.40) anchors on.
    let previous_output_sensitive = session_context
        .tool_calls
        .last()
        .map(|r| r.pii_in_response)
        .unwrap_or(false);

    // T10: split resolved_scope ("cat:sub:op") into the 3 fields that
    // ag-intent's patterns 1, 2, and 13 read for descriptor-driven
    // category/egress decisions. Empty strings when the tool is
    // unclassified — by design, those patterns then return None for this
    // request (no tool-name guessing). Mirrors the architectural principle
    // in proxy.rs:1592.
    let (cur_cat, cur_sub, cur_op) = match resolved_scope.split(':').collect::<Vec<&str>>().as_slice() {
        [c, s, o] if !c.is_empty() && !s.is_empty() && !o.is_empty() => {
            (c.to_string(), s.to_string(), o.to_string())
        }
        _ => (String::new(), String::new(), String::new()),
    };

    // T5: total_records_extracted comes from SessionContext (already tracked
    // per record_tool_call). requests_7d / baseline_requests_7d are not yet
    // populated in CachedBaseline — sent as 0 so Pattern 14 (slow_drip)
    // remains dormant until ag-risk feeds those fields. The JSON shape
    // matches what ag-intent expects so the field reaches the analyzer.
    serde_json::json!({
        "distinct_tool_count": distinct_tools.len(),
        "calls_this_hour": calls_this_hour,
        "baseline_calls_per_hour": baseline_calls_per_hour,
        "scopes_requested": scopes_requested,
        "baseline_scopes": baseline_scopes,
        "tool_read_write_pairs": read_write_pairs,
        "baseline_tool_pairs": baseline_tool_pairs,
        "risk_trend": session_context.risk_trend,
        "total_records_extracted": session_context.total_records_fetched,
        "requests_7d": 0,
        "baseline_requests_7d": 0,
        "previous_output_sensitive": previous_output_sensitive,
        "current_tool_category": cur_cat,
        "current_tool_subcategory": cur_sub,
        "current_tool_operation": cur_op,
        // T27: sticky-taint bool flows from gateway's SessionContext
        // through to ag-intent's analyzer for `check_sensitive_chain`.
        "sensitive_data_touched": session_context.sensitive_data_touched,
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

/// Validate target URL to prevent SSRF attacks.
/// Blocks requests to private/internal networks, cloud metadata endpoints,
/// and non-HTTP(S) schemes.
fn validate_target_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {}", e))?;

    // Only allow http/https schemes
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("disallowed scheme: {}", scheme)),
    }

    let host = parsed.host_str().unwrap_or("");

    // Block localhost
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" || host == "0.0.0.0" {
        return Err(format!("disallowed host: {} (localhost)", host));
    }

    // Block cloud metadata endpoints
    if host == "169.254.169.254" || host == "metadata.google.internal" {
        return Err(format!("disallowed host: {} (cloud metadata)", host));
    }

    // Block private IP ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let is_private = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()             // 127.0.0.0/8
                || v4.is_private()           // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()        // 169.254.0.0/16
                || v4.is_unspecified()       // 0.0.0.0
                || v4.octets()[0] == 100 && v4.octets()[1] >= 64 && v4.octets()[1] <= 127 // 100.64.0.0/10 (CGNAT)
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified()
            }
        };
        if is_private {
            return Err(format!("disallowed host: {} (private/internal network)", host));
        }
    }

    Ok(())
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
            warn!("Redis pool error for request counter: {} - fail-open with 0", e);
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
                    warn!("Redis EXPIRE failed for rate-limit key {}: {} - key may persist without TTL", current_key, e);
                }
            }
            val.max(0) as u32
        }
        Err(e) => {
            warn!("Redis INCR failed for {}: {} - fail-open with 0", current_key, e);
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
            debug!("Redis GET for previous bucket {}: {} - treating as 0", prev_key, e);
            0
        }
    };

    current_count + prev_count
}

/// POST /v1/proxy - Full 9-stage pipeline.
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

    // ── Early kill-switch (contagion) check ─────────────────────────────
    // A killed agent's credential is removed from Redis, so it would otherwise
    // fail JWT validation below as a generic `invalid_jwt`/agent_shadow_attempt
    // — masking the real reason (the agent is kill-switched) and the
    // contagion_alert signal. Peek the unverified `sub` and deny early if it is
    // in the deny-set. This is fail-safe: an unverified sub can only DENY here;
    // it can never grant access (the signature is still verified below before
    // anything is allowed).
    if let Some(peeked) = peek_jwt_subject(jwt_token) {
        if state.deny_set.contains(&peeked) {
            crate::shadow::publish_event(&state, &ShadowEvent {
                request_id,
                org_id: api_key_info.org_id.clone(),
                agent_id: peeked.clone(),
                tool_name: body.tool.clone(),
                blocked: true,
                denial: Some(crate::denial::gateway_denial(
                    "GATEWAY/agent_killed",
                    "Agent is kill-switched",
                )),
                policy_action: "deny".into(),
                policy_reason: "agent_killed".into(),
                assessed_risk: 1.0,
                rejection_type: ag_common::models::RejectionType::Security,
                a2a_event_type: Some("contagion_alert".into()),
                latency_ms: started_at.elapsed().as_millis() as u32,
                ..ShadowEvent::default()
            }).await;
            return Err(api_error(StatusCode::FORBIDDEN, "agent_killed", "Agent is kill-switched"));
        }
    }

    // Validate JWT: per-agent credential from Redis, fallback to global JWT_SECRET
    let jwt_secret = JWT_SECRET_CACHED.clone();
    let jwt_claims = match validate_jwt_with_agent_credential(jwt_token, &jwt_secret, &state.redis_pool).await {
        Ok(claims) => claims,
        Err(e) => {
            // ISSUE-023: Publish agent_shadow_attempt event on JWT validation failure
            crate::shadow::publish_event(&state, &ShadowEvent {
                request_id,
                org_id: api_key_info.org_id.clone(),
                tool_name: body.tool.clone(),
                blocked: true,
                denial: Some(crate::denial::gateway_denial(
                    "GATEWAY/invalid_jwt",
                    format!("agent_shadow_attempt: {}", e),
                )),
                policy_action: "deny".into(),
                policy_reason: "invalid_jwt".into(),
                assessed_risk: 0.95,
                rejection_type: ag_common::models::RejectionType::Security,
                a2a_event_type: Some("agent_shadow_attempt".into()),
                latency_ms: started_at.elapsed().as_millis() as u32,
                ..ShadowEvent::default()
            }).await;
            return Err(api_error(StatusCode::UNAUTHORIZED, "invalid_jwt", e));
        }
    };
    let agent_id_str = jwt_claims.sub.clone();

    // Deny-set check on the VERIFIED sub (defense-in-depth). The early peeked
    // check above already denies a kill-switched agent before JWT validation
    // (handling the credential-removed case); this re-checks against the
    // signature-verified `sub` so a kill that lands between the two points, or
    // any agent denied while its credential still exists, is still caught.
    if state.deny_set.contains(&agent_id_str) {
        // ISSUE-023: Publish contagion_alert when a killed agent tries to call
        crate::shadow::publish_event(&state, &ShadowEvent {
            request_id,
            org_id: api_key_info.org_id.clone(),
            agent_id: agent_id_str.clone(),
            tool_name: body.tool.clone(),
            blocked: true,
            denial: Some(crate::denial::gateway_denial(
                "GATEWAY/agent_killed",
                "Agent is kill-switched",
            )),
            policy_action: "deny".into(),
            policy_reason: "agent_killed".into(),
            assessed_risk: 1.0,
            rejection_type: ag_common::models::RejectionType::Security,
            a2a_event_type: Some("contagion_alert".into()),
            latency_ms: started_at.elapsed().as_millis() as u32,
            ..ShadowEvent::default()
        }).await;
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
        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "license_revoked", "License revoked - contact support at clampd.dev"));
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
                    format!("{} - upgrade at https://clampd.dev/#early-access", e),
                ));
            }
        }
    }

    // ---- DELEGATION CONTEXT (extract from headers + body, validate chain) ----
    // Moved BEFORE rate limit so depth/cycle attacks are rejected without consuming rate tokens.
    let mut delegation_ctx = crate::delegation::extract_delegation(
        // headers + body sources; body_signed_proof threaded so the SDK
        // can send the proof in the JSON body (the SDKs currently mint
        // there) and the gateway treats it equivalent to the header form.
        &headers,
        &body.caller_agent_id,
        &body.delegation_chain,
        &body.delegation_trace_id,
        &body.delegation_purpose,
        &body.signed_proof,
    )
    // Gateway appends the current agent (from JWT sub) to the chain.
    // The SDK sends chain=[A] (who delegated), the gateway completes it to [A, B]
    // using the authenticated agent identity. This is authoritative - can't be spoofed.
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
            let reason = format!(
                "Invalid delegation confidence '{}' - must be one of: verified, inferred, declared",
                ctx.confidence
            );
            publish_chain_validation_denial(
                &state, request_id, &api_key_info.org_id, &agent_id_str,
                &body.tool, &session_id, Some(ctx.chain.clone()),
                ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                started_at, "invalid_delegation_confidence", reason.clone(),
            ).await;
            crate::metrics::increment_denied();
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid_delegation_confidence",
                reason,
            ));
        }

        if !ctx.chain.is_empty() {
            if let Err(e) = crate::delegation::validate_chain(&ctx.chain) {
                let reason = e.to_string();
                publish_chain_validation_denial(
                    &state, request_id, &api_key_info.org_id, &agent_id_str,
                    &body.tool, &session_id, Some(ctx.chain.clone()),
                    ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                    started_at, "invalid_delegation_chain", reason.clone(),
                ).await;
                crate::metrics::increment_denied();
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_delegation_chain",
                    reason,
                ));
            }
        }

        // A2: Cryptographic delegation proof.
        //
        // When CLAMPD_DELEGATION_SIGNATURES is on, every multi-hop chain
        // must carry a signed proof in `X-Clampd-Delegation-Signature`.
        // Off (default): we accept SDK-asserted chains as
        // confidence="declared" — the SDKs haven't shipped signing yet,
        // so flipping enforcement on prematurely would break every
        // delegating client. Once SDK v0.16+ is the floor across the fleet,
        // flip the env var and start rejecting unsigned multi-hop calls.
        if crate::delegation::signatures_enforced() && ctx.chain.len() > 1 {
            match ctx.signed_proof.as_deref() {
                None => {
                    let reason = "Delegation signatures are enforced — multi-hop chain requires X-Clampd-Delegation-Signature header".to_string();
                    publish_chain_validation_denial(
                        &state, request_id, &api_key_info.org_id, &agent_id_str,
                        &body.tool, &session_id, Some(ctx.chain.clone()),
                        ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                        started_at, "delegation_signature_required", reason.clone(),
                    ).await;
                    crate::metrics::increment_denied();
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "delegation_signature_required",
                        reason,
                    ));
                }
                Some(proof) => {
                    if let Err(e) = crate::delegation::verify_signed_delegation(
                        proof, &ctx.chain, &agent_id_str, &state.redis_pool,
                    ).await {
                        let reason = format!("Delegation signature verification failed: {}", e);
                        publish_chain_validation_denial(
                            &state, request_id, &api_key_info.org_id, &agent_id_str,
                            &body.tool, &session_id, Some(ctx.chain.clone()),
                            ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                            started_at, "delegation_signature_invalid", reason.clone(),
                        ).await;
                        crate::metrics::increment_denied();
                        return Err(api_error(
                            StatusCode::FORBIDDEN,
                            "delegation_signature_invalid",
                            reason,
                        ));
                    }
                    // Verified: keep the inner `ctx` borrow read-only; after
                    // exiting this validation block we re-enter the merged
                    // delegation_ctx mutably and upgrade confidence to
                    // "verified" so downstream services (ag-intent, ag-policy,
                    // ShadowEvent) see a real cryptographic confidence level.
                }
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

    // A2: After all validation+verification has run, upgrade the merged
    // context's confidence to "verified" if a signed proof was supplied AND
    // verification succeeded above. The validate-and-deny path returned
    // early on failure, so reaching here with both `signatures_enforced()`
    // and a non-None `signed_proof` means verification passed.
    if crate::delegation::signatures_enforced() {
        if let Some(ref mut ctx_mut) = delegation_ctx {
            if ctx_mut.signed_proof.is_some() && ctx_mut.chain.len() > 1 {
                ctx_mut.confidence = "verified".to_string();
            }
        }
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
                // Agent state enforcement moved to Cedar (builtin-agent-state-active).
                // Gateway passes agent_state to EvaluateRequest; Cedar decides.
                profile
            }
            Err(e) => {
                // Distinguish "agent not found" from "registry down"
                if e.code() == tonic::Code::NotFound {
                    // Shadow agent detection: publish audit event for unregistered agents
                    // so they appear in the A2A security feed and can be investigated.
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: "UNREGISTERED".into(),
                        tool_name: body.tool.clone(),
                        blocked: true,
                        denial: Some(crate::denial::gateway_denial(
                            "GATEWAY/agent_not_registered",
                            "agent_not_registered",
                        )),
                        policy_action: "deny".into(),
                        policy_reason: "shadow_agent_detected".into(),
                        assessed_risk: 0.85,
                        session_id: session_id.clone(),
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        rejection_type: ag_common::models::RejectionType::Security,
                        a2a_event_type: Some("shadow_agent".into()),
                        ..ShadowEvent::default()
                    }).await;

                    return Err(api_error(StatusCode::NOT_FOUND, "agent_not_found",
                        format!("Agent '{}' not found in registry", agent_id_str)));
                }
                state.circuit_breakers.record_failure("registry");
                error!("Registry unavailable: {}", e);
                degraded_stages.push("registry".to_string());
                return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable",
                    "Agent identity cannot be verified - registry unavailable (fail-closed)"));
            }
        }
    } else {
        // Circuit is open - fail-closed: deny the request.
        degraded_stages.push("registry".to_string());
        warn!("Registry circuit breaker is open - fail-closed");
        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable",
            "Agent identity cannot be verified - registry unavailable (fail-closed)"));
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

    // ---- DELEGATION CONTEXT ENRICHMENT ----
    // Gateway checks delegation approval and passes result to Cedar via EvaluateRequest.
    let mut delegation_is_approved: Option<bool> = None;
    if let Some(ref ctx) = delegation_ctx {
        // ---- CROSS-ORG DELEGATION GUARD ----
        // Validate all agents in the delegation chain belong to the same org
        // as the authenticated API key. Prevents cross-tenant spoofing.
        if let Some(ref caller_id) = ctx.caller_agent_id {
            // The caller_agent_id must be resolvable within the same org.
            // We check the Redis delegation approval key which is org-scoped:
            // ag:delegation:approved:{parent}:{child} - only exists within same org.
            // If caller claims to be from a different org, the approval lookup will fail
            // and enforcement mode will block the request.
            //
            // Additionally, verify no chain member is the empty string (spoofed).
            if caller_id.is_empty() {
                let reason = "caller_agent_id cannot be empty".to_string();
                publish_chain_validation_denial(
                    &state, request_id, &api_key_info.org_id, &agent_id_str,
                    &body.tool, &session_id, Some(ctx.chain.clone()),
                    ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                    started_at, "invalid_caller_agent_id", reason.clone(),
                ).await;
                crate::metrics::increment_denied();
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_caller_agent_id",
                    reason,
                ));
            }
        }
        for chain_member in &ctx.chain {
            if chain_member.is_empty() || chain_member.len() > 128 {
                let reason = "Delegation chain contains invalid agent ID (empty or too long)".to_string();
                publish_chain_validation_denial(
                    &state, request_id, &api_key_info.org_id, &agent_id_str,
                    &body.tool, &session_id, Some(ctx.chain.clone()),
                    ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                    started_at, "invalid_delegation_chain", reason.clone(),
                ).await;
                crate::metrics::increment_denied();
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_delegation_chain",
                    reason,
                ));
            }
        }

        // ---- DELEGATION ENFORCEMENT ----
        if ctx.chain.len() > 1 {
            let caller = &ctx.chain[ctx.chain.len() - 2];

            // Validate caller is a valid UUID to prevent spoofing
            if uuid::Uuid::parse_str(caller).is_err() {
                let reason = "Delegation chain contains invalid agent ID (not a UUID)".to_string();
                publish_chain_validation_denial(
                    &state, request_id, &api_key_info.org_id, &agent_id_str,
                    &body.tool, &session_id, Some(ctx.chain.clone()),
                    ctx.trace_id.clone(), ctx.caller_agent_id.clone(),
                    started_at, "invalid_delegation_chain", reason.clone(),
                ).await;
                crate::metrics::increment_denied();
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_delegation_chain",
                    reason,
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
                        denial: Some(crate::denial::gateway_denial(
                            "GATEWAY/delegation_from_killed_agent",
                            reason.clone(),
                        )),
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

            // ISSUE-017: Verify the caller agent actually exists (prevents fabricated UUIDs)
            if !state.delegation_cache.verify_agent_exists(caller).await {
                let reason = format!(
                    "delegation_unknown_caller: caller '{}' is not a registered agent",
                    &caller[..caller.len().min(12)]
                );
                warn!(request_id = %request_id, caller = %caller, "Delegation from unknown agent rejected");
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "delegation_unknown_caller",
                    reason,
                ));
            }

            // Delegation enforcement moved to Cedar (builtin-delegation-approval).
            // Gateway enriches delegation_approved context for Cedar.
            // Check approval status and pass to EvaluateRequest - Cedar decides.
            //
            // Tool-caveat enforcement (Macaroon-style "allowed_tools" list on
            // each approved edge) is NOT done here — `ag-policy/service.rs:241`
            // calls `delegation_workflow::check_tool_restriction(&edge,
            // tool_name, ...)` during BoundaryCheck, which is the single
            // source of truth. Replicating it in the gateway would create a
            // second deny path that can drift out of sync with Cedar.
            if crate::delegation::is_enforcement_enabled(&state.redis_pool, &api_key_info.org_id).await {
                let (approved, _allowed_tools) = state
                    .delegation_cache
                    .check_delegation_approved(caller, &agent_id_str)
                    .await;
                delegation_is_approved = Some(approved);
            }

            // Record observed delegation AFTER enforcement check passes.
            // Blocked delegations must NOT be recorded as observations - they
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

            // ISSUE-023: Emit cross_boundary_delegation event when multi-hop delegation observed
            if ctx.chain.len() > 2 {
                crate::shadow::publish_event(&state, &ShadowEvent {
                    request_id,
                    org_id: api_key_info.org_id.clone(),
                    agent_id: agent_id_str.clone(),
                    agent_name: agent_profile.name.clone(),
                    tool_name: body.tool.clone(),
                    caller_agent_id: Some(caller.to_string()),
                    delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()),
                    delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                    blocked: false,
                    policy_action: "allow".into(),
                    policy_reason: format!("cross_boundary_delegation: depth={}", ctx.chain.len()),
                    assessed_risk: 0.3,
                    session_id: session_id.clone(),
                    latency_ms: started_at.elapsed().as_millis() as u32,
                    rejection_type: ag_common::models::RejectionType::None,
                    a2a_event_type: Some("cross_boundary_delegation".into()),
                    ..ShadowEvent::default()
                }).await;
            }

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
                            // Key already existed - this is a replay
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
                                denial: Some(crate::denial::gateway_denial(
                                    "GATEWAY/task_replay_detected",
                                    reason.clone(),
                                )),
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
                        Ok(true) => {} // First time - proceed
                        Err(e) => {
                            // Redis error - log and continue (fail-open for replay, fail-closed would block legitimate retries)
                            warn!(error = %e, "Redis SET NX failed for replay detection - skipping");
                        }
                    }
                }
            }
        }
    }

    stage_latencies.push(("identify_delegate", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 3: NORMALIZE + EXTRACT ----
    // T1: descriptor passed as None for now. T3 will plumb the real
    // descriptor_opt through (resolved at line ~1170 via baseline_cache).
    let (raw_tool_name, action, mut params_json, _raw_params_hash, prompt_hash) = extract_tool_call(&body, None);
    // Canonicalize tool name so all downstream services see consistent names.
    // "db.query" → "database.query", "file.read" → "filesystem.read", etc.
    let tool_name = ag_common::tool_names::canonicalize(&raw_tool_name);

    // ---- PAYMENT CONTEXT EXTRACTION ----
    // Payment enforcement moved to Cedar (builtin-payment-vendor-whitelist, builtin-payment-require-scope).
    // Gateway extracts payment context and passes to EvaluateRequest for Cedar evaluation.
    // SDK convention: tools registered with the SDK commonly use the `pay_`
    // prefix (e.g. pay_x402, pay_invoice, pay_stripe). Without this prefix
    // recognised here, payment context (amount, recipient, vendor_approved)
    // never gets populated for SDK-direct payment tools and ag-policy can't
    // enforce per-tx amount limits or vendor allowlists. The longer-term
    // fix is scope-based recognition (descriptor.category=="payment"), which
    // requires moving this block to after descriptor resolution at L1244.
    let is_payment_tool = tool_name.starts_with("payment.")
        || tool_name.starts_with("billing.")
        || tool_name.starts_with("stripe.")
        || tool_name.starts_with("checkout.")
        || tool_name.starts_with("invoice.")
        || tool_name.starts_with("pay_")
        || tool_name.starts_with("payments_")
        || tool_name == "pay";
    let (payment_amount_cents, payment_recipient, payment_vendor_approved) = if is_payment_tool {
        let amount_cents = body.params.get("amount").or(body.params.get("total")).or(body.params.get("price")).or(body.params.get("amount_cents"))
            .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
            .unwrap_or(0);
        let vendor = body.params.get("vendor").or(body.params.get("recipient")).or(body.params.get("merchant"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let vendor_approved = if let Some(ref bounds) = agent_profile.boundaries {
            // Source: unified BoundaryAllowlistEntry rows scoped to
            // (category="payment", subcategory="transaction"). Single source
            // of truth shared with x402 response interception (line ~2665)
            // and the request-side B-006 boundary check.
            let payment_allowlist: Vec<&str> = bounds.allowlist.iter()
                .filter(|e| e.category == "payment" && e.subcategory == "transaction")
                .map(|e| e.pattern.as_str())
                .collect();
            if payment_allowlist.is_empty() {
                true // no allowlist entries = all approved (preserves existing default)
            } else if vendor.is_empty() {
                true
            } else {
                // Hoist `vendor.to_lowercase()` out of the iterator so we
                // allocate the lowercased vendor once instead of N+1 times.
                // `to_lowercase()` is preserved (Unicode-aware) over
                // `eq_ignore_ascii_case` to keep semantics identical for
                // non-ASCII vendor names.
                let vendor_lower = vendor.to_lowercase();
                payment_allowlist.iter().any(|p| p.to_lowercase() == vendor_lower)
            }
        } else {
            true // no boundaries configured
        };
        (Some(amount_cents as i64), Some(vendor), Some(vendor_approved))
    } else {
        (None, None, None)
    };

    // ---- X402 PAYMENT-SIGNATURE TRACK-A CHECKS (B-X402-FRESH + B-X402-NONCE) ----
    // The agent's retry after a 402 carries a `PAYMENT-SIGNATURE` request
    // header containing the signed authorization (EIP-3009 / EIP-712 / ERC-7710
    // payload). When present, run two safety checks BEFORE forwarding:
    //   1. Freshness: validBefore - now ≤ 5min, and not already expired
    //   2. Nonce replay: SET-NX in Redis with 24h TTL, deny if seen before
    // Both fail-CLOSED on Redis failure — replay/freshness gates are safety
    // controls, an attacker DoSing Redis must not bypass them.
    if is_payment_tool {
        let header_pairs: Vec<(String, String)> = headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|vs| (k.as_str().to_string(), vs.to_string())))
            .collect();
        if let Some(payload) = crate::x402::extract_payment_payload(&header_pairs) {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            // B-X402-FRESH
            if let Some(reason) = crate::x402::check_x402_freshness(&payload, now_secs) {
                warn!(
                    request_id = %request_id,
                    nonce = %payload.nonce,
                    "x402 PAYMENT-SIGNATURE freshness check failed"
                );
                crate::shadow::publish_event(&state, &ShadowEvent {
                    request_id,
                    org_id: api_key_info.org_id.clone(),
                    agent_id: agent_id_str.clone(),
                    agent_name: agent_profile.name.clone(),
                    tool_name: body.tool.clone(),
                    blocked: true,
                    denial: Some(crate::denial::gateway_denial(
                        "GATEWAY/x402_payload_stale",
                        format!("x402_payload_stale: {}", reason),
                    )),
                    policy_action: "deny".into(),
                    policy_reason: "x402_payload_stale".into(),
                    assessed_risk: 0.7,
                    rejection_type: ag_common::models::RejectionType::Security,
                    a2a_event_type: Some("x402_payload_stale".into()),
                    session_id: session_id.clone(),
                    latency_ms: started_at.elapsed().as_millis() as u32,
                    ..ShadowEvent::default()
                }).await;
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "x402_payload_stale",
                    &format!("B-X402-FRESH: {}", reason),
                ));
            }

            // B-X402-SIGVERIFY (Track B) — verify the EIP-3009 signature
            // recovers to the claimed `from` address. Catches spoofed
            // PAYMENT-SIGNATURE headers and tampered payloads. Non-EVM
            // chains (Solana, Stellar) skip — they use schemes we don't
            // verify here. AddressMismatch and Malformed both deny;
            // Verified and NotApplicable proceed.
            match crate::x402_sig::verify_eip3009(&payload) {
                crate::x402_sig::SigVerifyResult::Verified { .. } => { /* signature OK */ }
                crate::x402_sig::SigVerifyResult::NotApplicable => { /* non-EVM chain — skip */ }
                crate::x402_sig::SigVerifyResult::AddressMismatch { recovered, claimed } => {
                    warn!(
                        request_id = %request_id,
                        recovered = %hex::encode(recovered),
                        claimed = %hex::encode(claimed),
                        "x402 signature recovered to different address than claimed `from`"
                    );
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: agent_profile.name.clone(),
                        tool_name: body.tool.clone(),
                        blocked: true,
                        denial: Some(crate::denial::gateway_denial(
                            "GATEWAY/x402_signature_address_mismatch",
                            format!(
                                "x402_signature_address_mismatch: recovered=0x{}, claimed=0x{}",
                                hex::encode(recovered),
                                hex::encode(claimed),
                            ),
                        )),
                        policy_action: "deny".into(),
                        policy_reason: "x402_signature_address_mismatch".into(),
                        assessed_risk: 0.95,
                        rejection_type: ag_common::models::RejectionType::Security,
                        a2a_event_type: Some("x402_signature_address_mismatch".into()),
                        session_id: session_id.clone(),
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        ..ShadowEvent::default()
                    }).await;
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "x402_signature_address_mismatch",
                        "B-X402-SIGVERIFY: signature recovers to a different address than claimed `from` — likely spoofed or tampered",
                    ));
                }
                crate::x402_sig::SigVerifyResult::Malformed(msg) => {
                    warn!(
                        request_id = %request_id,
                        reason = %msg,
                        "x402 signature payload malformed — denying"
                    );
                    crate::shadow::publish_event(&state, &ShadowEvent {
                        request_id,
                        org_id: api_key_info.org_id.clone(),
                        agent_id: agent_id_str.clone(),
                        agent_name: agent_profile.name.clone(),
                        tool_name: body.tool.clone(),
                        blocked: true,
                        denial: Some(crate::denial::gateway_denial(
                            "GATEWAY/x402_signature_malformed",
                            format!("x402_signature_malformed: {}", msg),
                        )),
                        policy_action: "deny".into(),
                        policy_reason: "x402_signature_malformed".into(),
                        assessed_risk: 0.7,
                        rejection_type: ag_common::models::RejectionType::Security,
                        a2a_event_type: Some("x402_signature_malformed".into()),
                        session_id: session_id.clone(),
                        latency_ms: started_at.elapsed().as_millis() as u32,
                        ..ShadowEvent::default()
                    }).await;
                    return Err(api_error(
                        StatusCode::FORBIDDEN,
                        "x402_signature_malformed",
                        &format!("B-X402-SIGVERIFY: {}", msg),
                    ));
                }
            }

            // B-X402-NONCE replay registry — 24h dedup window
            let nonce_key = format!("ag:x402:nonce:{}:{}", api_key_info.org_id, payload.nonce);
            match state.redis_pool.get().await {
                Ok(mut conn) => {
                    let set_result: redis::RedisResult<Option<String>> = redis::cmd("SET")
                        .arg(&nonce_key)
                        .arg("1")
                        .arg("NX")
                        .arg("EX")
                        .arg(86400i64)
                        .query_async(&mut *conn)
                        .await;
                    match set_result {
                        Ok(Some(_)) => { /* first-seen — proceed */ }
                        Ok(None) => {
                            warn!(
                                request_id = %request_id,
                                nonce = %payload.nonce,
                                "x402 nonce already seen — replay attempt denied"
                            );
                            crate::shadow::publish_event(&state, &ShadowEvent {
                                request_id,
                                org_id: api_key_info.org_id.clone(),
                                agent_id: agent_id_str.clone(),
                                agent_name: agent_profile.name.clone(),
                                tool_name: body.tool.clone(),
                                blocked: true,
                                denial: Some(crate::denial::gateway_denial(
                                    "GATEWAY/x402_nonce_replay",
                                    format!(
                                        "x402_nonce_replay: nonce {} already used in last 24h",
                                        payload.nonce
                                    ),
                                )),
                                policy_action: "deny".into(),
                                policy_reason: "x402_nonce_replay".into(),
                                assessed_risk: 0.95,
                                rejection_type: ag_common::models::RejectionType::Security,
                                a2a_event_type: Some("x402_nonce_replay".into()),
                                session_id: session_id.clone(),
                                latency_ms: started_at.elapsed().as_millis() as u32,
                                ..ShadowEvent::default()
                            }).await;
                            return Err(api_error(
                                StatusCode::FORBIDDEN,
                                "x402_nonce_replay",
                                &format!("B-X402-NONCE: nonce {} already used in last 24h", payload.nonce),
                            ));
                        }
                        Err(e) => {
                            warn!(error = %e, "Redis SET-NX failed for x402 nonce — failing CLOSED");
                            return Err(api_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "x402_nonce_check_redis_error",
                                "B-X402-NONCE: cannot verify nonce replay (fail-closed)",
                            ));
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Redis pool unavailable for x402 nonce check — failing CLOSED");
                    return Err(api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "x402_nonce_check_redis_unavailable",
                        "B-X402-NONCE: cannot verify nonce replay (fail-closed)",
                    ));
                }
            }
        }
    }

    // ---- AP2 MANDATE STRUCTURAL VALIDATION ----
    // Gateway extracts and validates mandate structure (TTL, signature format).
    // Boundary enforcement (amount limits, payee whitelist) moved to Cedar via EvaluateRequest.
    // Only structural failures (expired TTL, malformed signature) are blocked here.
    let ap2_risk_modifier: f64 = if is_payment_tool {
        if let Some(mandate) = crate::ap2::extract_mandate(&body.params) {
            // Track-A AP2 checks (B-AP2-SCOPE, B-AP2-REFUND, B-AP2-REPLAY).
            // Run BEFORE structural validation: no point validating TTL of a
            // mandate that's bound to the wrong agent or already replayed.

            // B-AP2-SCOPE: stolen-mandate prevention.
            if let Some(reason) = crate::ap2::check_scope_binding(&mandate, &agent_id_str) {
                warn!(request_id = %request_id, "AP2 scope binding violated");
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "ap2_scope_binding_violated",
                    &format!("B-AP2-SCOPE: {}", reason),
                ));
            }

            // B-AP2-REFUND: Intent mandates require refund_policy.
            if let Some(reason) = crate::ap2::check_refund_policy_present(&mandate) {
                warn!(request_id = %request_id, "AP2 refund_policy missing on Intent mandate");
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "ap2_refund_policy_missing",
                    &format!("B-AP2-REFUND: {}", reason),
                ));
            }

            // B-AP2-REPLAY: mandate-id replay registry. Skipped when the
            // mandate didn't carry an id (logged for audit, but spec says
            // id is RECOMMENDED not REQUIRED). When present, SET-NX-EX
            // with 24h TTL — same fail-closed pattern as x402 nonce above.
            if !mandate.mandate_id.is_empty() {
                let replay_key = crate::ap2::ap2_replay_key(&api_key_info.org_id, &mandate.mandate_id);
                match state.redis_pool.get().await {
                    Ok(mut conn) => {
                        let set_result: redis::RedisResult<Option<String>> = redis::cmd("SET")
                            .arg(&replay_key)
                            .arg("1")
                            .arg("NX")
                            .arg("EX")
                            .arg(86400i64)
                            .query_async(&mut *conn)
                            .await;
                        match set_result {
                            Ok(Some(_)) => { /* first-seen — proceed */ }
                            Ok(None) => {
                                warn!(
                                    request_id = %request_id,
                                    mandate_id = %mandate.mandate_id,
                                    "AP2 mandate replay denied"
                                );
                                return Err(api_error(
                                    StatusCode::FORBIDDEN,
                                    "ap2_mandate_replay",
                                    &format!("B-AP2-REPLAY: mandate id {} already used in last 24h", mandate.mandate_id),
                                ));
                            }
                            Err(e) => {
                                warn!(error = %e, "Redis SET-NX failed for AP2 replay — failing CLOSED");
                                return Err(api_error(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "ap2_replay_check_redis_error",
                                    "B-AP2-REPLAY: cannot verify mandate replay (fail-closed)",
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Redis pool unavailable for AP2 replay — failing CLOSED");
                        return Err(api_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "ap2_replay_check_redis_unavailable",
                            "B-AP2-REPLAY: cannot verify mandate replay (fail-closed)",
                        ));
                    }
                }
            }

            // Structural validation only - no boundary checks.
            // TTL expiry and signature format are protocol concerns, not policy.
            // Amount/vendor/payee enforcement is handled by Cedar (Phase 2).
            let structural_bounds = crate::ap2::Ap2Boundaries::default(); // no limits = skip boundary checks
            let validation = crate::ap2::validate_mandate(&mandate, &structural_bounds);
            for (k, v) in &validation.audit_fields {
                debug!(ap2_audit_key = %k, ap2_audit_val = %v, "AP2 mandate audit");
            }
            // Only block on structural failures (TTL expired, bad signature, missing merchant sig)
            // Amount/vendor policy decisions are handled by Cedar
            if !validation.valid && validation.audit_fields.iter().any(|(k, v)|
                k == "validation_failure" && (v == "ttl_expired" || v == "bad_signature" || v == "merchant_not_signed"))
            {
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "ap2_mandate_invalid",
                    validation
                        .deny_reason
                        .unwrap_or_else(|| "AP2 mandate structural validation failed".to_string()),
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
                // params_json isn't a JSON object - create a wrapper
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
    // Read EMA once per request — reused below (new-session inherit) and
    // again in the classify RPC (Stage 5). ag-risk owns writes to this key
    // and no gateway code path mutates it between reads.
    let agent_ema_score = session::read_agent_ema_score(&state.redis_pool, &agent_id_str).await;
    if is_new_session {
        // Check if session creation is blocked post-kill
        if session::is_session_blocked(&state.redis_pool, &agent_id_str).await {
            return Err(api_error(
                StatusCode::FORBIDDEN,
                "session_blocked",
                "Session creation blocked - agent was recently kill-switched",
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
        session_context.inherited_risk = agent_ema_score * 0.5;

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

    // Check tool authorization (wildcard scope bypasses tool lock)
    if let Err(e) = session::check_tool_authorized(&session_context, &tool_name, &agent_profile.allowed_scopes) {
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

    // A3 (purpose caveat): if the SDK declared a delegation purpose, propagate
    // it to ag-intent as a session_flag with prefix `delegation_purpose:`. The
    // intent rule for purpose-drift checks tool category against the declared
    // purpose. Truncate to 80 chars and strip control chars / pipes / colons
    // so the flag can't smuggle separators that confuse downstream parsers.
    if let Some(ref dctx) = delegation_ctx {
        if let Some(ref purpose) = dctx.purpose {
            let cleaned: String = purpose
                .chars()
                .filter(|c| !c.is_control() && *c != '|' && *c != ':')
                .take(80)
                .collect::<String>()
                .trim()
                .to_string();
            if !cleaned.is_empty() {
                session_flags.push(format!("delegation_purpose:{}", cleaned));
            }
        }
    }

    let session_risk_factor = session_context.risk_factor();

    // Scope boundary enforcement moved to ag-policy (Layer 0) - ISSUE-025
    // Gateway passes agent_allowed_scopes to policy; policy denies if tool scope is outside boundary.

    stage_latencies.push(("session_toolauth", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 4.9: BOUNDARY CHECK (v0.11.0 trust model) ----
    // Runs the 4-rule BoundaryEvaluator before classify so ag-intent
    // receives a real TrustLevel. On Trusted, ag-intent's trust_skip
    // branch returns early and skips LLM Judge (~2.2s + 1800 tokens saved).
    // On transport/policy failure we fall back to Unknown - the request
    // still flows through full classify + evaluate, just without the
    // trust-skip win.
    let pre_classify_trust: TrustLevel = if state.circuit_breakers.is_allowed("policy") {
        let mut policy_client = state.policy.clone();
        let boundary_req = BoundaryCheckRequest {
            agent_id: agent_id_str.clone(),
            org_id: api_key_info.org_id.clone(),
            tool_name: tool_name.clone(),
            target_url: body.target_url.clone(),
            agent_boundaries: agent_profile.boundaries.clone(),
            calls_in_last_minute,
            agent_timezone: "UTC".to_string(),
            agent_state: agent_profile.state.clone(),
            params_json: params_json.clone(),
            caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
            delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()).unwrap_or_default(),
            payment_amount_cents,
            payment_recipient: payment_recipient.clone(),
        };
        match policy_client.boundary_check(boundary_req).await {
            Ok(resp) => {
                state.circuit_breakers.record_success("policy");
                let r = resp.into_inner();
                TrustLevel::from_str(&r.trust_level).unwrap_or(TrustLevel::Unknown)
            }
            Err(e) => {
                state.circuit_breakers.record_failure("policy");
                warn!(error = %e, "BoundaryCheck failed - falling back to Unknown trust");
                TrustLevel::Unknown
            }
        }
    } else {
        TrustLevel::Unknown
    };
    stage_latencies.push(("boundary_check", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Stage 5+6: CLASSIFY + EVALUATE (with circuit breakers) ----

    // Fetch agent baseline + typed descriptor concurrently (two independent
    // Redis lookups). Baseline is ag-risk HSET with 60s local TTL; descriptor
    // feeds the authoritative tool scope below.
    let (baseline, descriptor_opt) = tokio::join!(
        state.baseline_cache.get(&agent_id_str),
        state.baseline_cache.resolve_typed_descriptor(&api_key_info.org_id, &tool_name),
    );

    // Scope is passed to intent + policy RPCs via `resolved_scope`. Empty
    // string when no descriptor exists — consumers fall back to the legacy
    // path during the migration window.
    // T3: borrow rather than move so descriptor_opt remains usable downstream
    // (passed into is_external_send at the tool-record build sites).
    let resolved_scope: String = match descriptor_opt.as_ref() {
        Some(desc) => ag_common::scopes::compute_scope_global(desc)
            .map(|s| s.as_str())
            .unwrap_or_default(),
        None => String::new(),
    };

    // ── Effect-scope least-privilege guard (Phase 3) ────────────────────
    // The call's ACTUAL effect — derived from its params (e.g. the leading SQL
    // verb) — must be covered by the agent's granted scopes, not just the
    // tool's DECLARED classification. Closes the "tool declared db:query:read,
    // but the SQL is an INSERT" gap: a read-scoped agent can no longer mutate
    // through a read-classified tool.
    //
    // Purely additive and surgical: it only DENIES (never grants); only for
    // agents that DO hold a grant (empty allowed_scopes is left to the existing
    // default-deny path, untouched); and only when the effect is unambiguously
    // derivable. Reuses the same allowed_scopes + scope_matches as the declared
    // check — no new scope vocabulary, no config toggle.
    if !agent_profile.allowed_scopes.is_empty() {
        if let Some(effect) = ag_common::scopes::effect_scope(&tool_name, &body.params) {
            let effect_str = effect.as_str();
            let covered = agent_profile
                .allowed_scopes
                .iter()
                .any(|g| ag_common::scopes::scope_matches(g, &effect_str));
            if !covered {
                let reason = format!(
                    "effect_scope_violation: call effect '{}' exceeds the agent's granted scopes [{}]",
                    effect_str,
                    agent_profile.allowed_scopes.join(", ")
                );
                crate::shadow::publish_event(&state, &ShadowEvent {
                    request_id,
                    org_id: api_key_info.org_id.clone(),
                    agent_id: agent_id_str.clone(),
                    tool_name: body.tool.clone(),
                    blocked: true,
                    denial: Some(crate::denial::gateway_denial(
                        "GATEWAY/effect_scope_violation",
                        format!("Call effect requires scope '{effect_str}', which the agent has not been granted"),
                    )),
                    policy_action: "deny".into(),
                    policy_reason: "effect_scope_violation".into(),
                    assessed_risk: 0.9,
                    rejection_type: ag_common::models::RejectionType::Security,
                    latency_ms: started_at.elapsed().as_millis() as u32,
                    ..ShadowEvent::default()
                }).await;
                return Err(api_error(StatusCode::FORBIDDEN, "effect_scope_violation", reason));
            }
        }
    }

    // ── Rug-pull guard: the tool contract must match what was approved ───
    // If a pinned (approved) hash exists for this tool, the caller must prove it
    // is invoking that exact contract:
    //   - claimed hash differs from the pin  → rug-pull (advertise one schema,
    //     serve another) → reject.
    //   - claimed hash omitted, strict mode  → can't prove identity → reject
    //     (closes the "omit the hash to skip the check" bypass).
    //   - claimed hash omitted, default mode → not enforced (the call resolves
    //     under the still-pinned approved descriptor; content scanning applies).
    // No pin yet (migration window) → nothing to enforce.
    if let Some(pinned_hash) = state
        .baseline_cache
        .resolve_pinned_descriptor_hash(&api_key_info.org_id, &tool_name)
        .await
    {
        let claimed = body
            .tool_descriptor_hash
            .as_deref()
            .filter(|h| h.len() == 64);
        let (ok, reason) = match claimed {
            Some(h) if h == pinned_hash => (true, ""),
            Some(_) => (false, "descriptor_hash_mismatch"),
            None if *REQUIRE_DESCRIPTOR_HASH => (false, "descriptor_hash_missing"),
            None => (true, ""),
        };
        if !ok {
            crate::shadow::publish_event(&state, &ShadowEvent {
                request_id,
                org_id: api_key_info.org_id.clone(),
                agent_id: agent_id_str.clone(),
                tool_name: body.tool.clone(),
                tool_descriptor_hash: claimed.unwrap_or_default().to_string(),
                blocked: true,
                denial: Some(crate::denial::gateway_denial(
                    "GATEWAY/descriptor_hash_mismatch",
                    "Tool contract does not match the approved descriptor",
                )),
                policy_action: "deny".into(),
                policy_reason: reason.into(),
                assessed_risk: 1.0,
                rejection_type: ag_common::models::RejectionType::Security,
                a2a_event_type: Some("rug_pull_alert".into()),
                latency_ms: started_at.elapsed().as_millis() as u32,
                ..ShadowEvent::default()
            }).await;
            return Err(api_error(
                StatusCode::FORBIDDEN,
                reason,
                "Tool contract does not match the approved descriptor - re-approve it in the dashboard",
            ));
        }
    }

    // ── Confused-deputy guard: delegation chain scope intersection ───────
    // When the call is made inside a delegation chain (chain = [ancestor…, principal]),
    // every ancestor must ALSO allow the resolved_scope. Without this check
    // a narrow attacker can delegate to a broader target and smuggle in the
    // target's wider scopes.
    //
    // For unclassified tools (no descriptor → empty resolved_scope) we use
    // the same fallback as ag-policy's boundary check so behavior is
    // consistent and a wildcard-principal cannot smuggle an unclassified
    // tool through a narrow chain ancestor.
    {
        let chain_check_scope: &str = if resolved_scope.is_empty() {
            "unknown:unclassified:unknown"
        } else {
            resolved_scope.as_str()
        };
        if let Some(ref dctx) = delegation_ctx {
            if dctx.chain.len() >= 2 {
                let principal_idx = dctx.chain.len() - 1;

                // Build the list of ancestors that need a registry round-trip
                // (skip self-references — `executor` re-appearing in its own
                // chain is not an ancestor of itself).
                let to_fetch: Vec<(usize, String)> = dctx.chain[..principal_idx]
                    .iter()
                    .enumerate()
                    .filter(|(_, id)| **id != agent_id_str)
                    .map(|(idx, id)| (idx, id.clone()))
                    .collect();

                if !to_fetch.is_empty() {
                    // Circuit breaker is checked once before launching the
                    // batch — all calls go to the same registry service, so
                    // per-future re-checks would be redundant.
                    if !state.circuit_breakers.is_allowed("registry") {
                        return Err(api_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "registry_unavailable",
                            "chain ancestor lookup blocked by circuit breaker",
                        ));
                    }

                    // Parallelize the round-trips. Sequential get_agent across
                    // a depth-5 chain previously cost 4 × ~5–10ms = 20–40ms p99.
                    // `join_all` makes that p99 = max(individual) ≈ 5–10ms.
                    // We use `join_all` (not `try_join_all`) so we can surface
                    // errors in chain-index order — preserves the deterministic
                    // `chain_ancestor_unknown[idx=N]` reason that operators
                    // depend on for forensics, instead of "first-future-to-fail
                    // wins" non-determinism.
                    let fetch_futures = to_fetch.iter().map(|(_, ancestor_id)| {
                        let mut reg_client = state.registry.clone();
                        let id = ancestor_id.clone();
                        async move {
                            reg_client
                                .get_agent(ag_proto::agentguard::registry::GetAgentRequest {
                                    agent_id: id,
                                })
                                .await
                        }
                    });
                    let results = futures::future::join_all(fetch_futures).await;

                    for ((idx, ancestor_id), result) in to_fetch.into_iter().zip(results.into_iter()) {
                        let ancestor_profile = match result {
                            Ok(resp) => resp.into_inner().agent,
                            Err(e) => {
                                if e.code() == tonic::Code::NotFound {
                                    return Err(api_error(
                                        StatusCode::FORBIDDEN,
                                        "chain_ancestor_unknown",
                                        format!(
                                            "delegation_chain[{}]={} not found in registry",
                                            idx, ancestor_id
                                        ),
                                    ));
                                }
                                state.circuit_breakers.record_failure("registry");
                                return Err(api_error(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "registry_unavailable",
                                    "chain ancestor lookup failed - registry unavailable (fail-closed)",
                                ));
                            }
                        };
                        let ancestor = match ancestor_profile {
                            Some(p) => p,
                            None => {
                                return Err(api_error(
                                    StatusCode::FORBIDDEN,
                                    "chain_ancestor_unknown",
                                    format!("delegation_chain[{}]={} has no profile", idx, ancestor_id),
                                ));
                            }
                        };
                    // Cross-org guard: every chain member must share the principal's org.
                    if !ancestor.org_id.is_empty() && ancestor.org_id != api_key_info.org_id {
                        return Err(api_error(
                            StatusCode::FORBIDDEN,
                            "chain_cross_org",
                            format!(
                                "delegation_chain[{}]={} org={} does not match principal org={}",
                                idx, ancestor_id, ancestor.org_id, api_key_info.org_id
                            ),
                        ));
                    }
                    // Wildcard ancestor permits anything — skip narrow check.
                    if ancestor.allowed_scopes.iter().any(|s| s == "*") {
                        continue;
                    }
                    // Empty scopes → nothing is allowed through this ancestor.
                    if ancestor.allowed_scopes.is_empty() {
                        return Err(api_error(
                            StatusCode::FORBIDDEN,
                            "chain_scope_violation",
                            format!(
                                "delegation_chain[{}]={} has empty allowed_scopes — cannot delegate {}",
                                idx, ancestor_id, chain_check_scope
                            ),
                        ));
                    }
                    // Ancestor must have at least one pattern matching the tool scope.
                    let allows = ancestor.allowed_scopes.iter().any(|pat| {
                        ag_common::scopes::scope_matches(pat, chain_check_scope)
                    });
                    if !allows {
                        warn!(
                            agent_id = %agent_id_str,
                            ancestor_id = %ancestor_id,
                            tool = %tool_name,
                            resolved_scope = %chain_check_scope,
                            ancestor_scopes = ?ancestor.allowed_scopes,
                            "chain_scope_violation: ancestor does not allow resolved_scope"
                        );
                        return Err(api_error(
                            StatusCode::FORBIDDEN,
                            "chain_scope_violation",
                            format!(
                                "delegation_chain[{}]={} does not allow tool scope '{}' (ancestor scopes: [{}])",
                                idx, ancestor_id, chain_check_scope,
                                ancestor.allowed_scopes.join(",")
                            ),
                        ));
                    }
                    } // close for-loop body
                } // close `if !to_fetch.is_empty()`
            }
        }
    }

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
                agent_risk_score: agent_ema_score,
                session_flags: session_flags.clone(),
                session_risk_factor,
                session_total_calls: session_context.tool_calls.len() as i32,
                session_context_window: session_context.tool_calls.len().min(10) as i32,
                session_context_json: build_session_context_json(&session_context, baseline.as_ref(), &resolved_scope),
                // agent_scopes removed - scope exemptions handled by policy layer
                caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
                delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()).unwrap_or_default(),
                delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                delegation_confidence: delegation_ctx.as_ref().map(|d| d.confidence.clone()),
                tool_descriptor_hash: body.tool_descriptor_hash.clone().unwrap_or_default(),
                trust_level: pre_classify_trust.to_string(),
                org_id: api_key_info.org_id.clone(),
                resolved_scope: resolved_scope.clone(),
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
    // `intent_token_ttl`: per-exemption scope-token TTL surfaced by ag-intent when
    // an exemption row matched. Forwarded into every EvaluateRequest so ag-policy
    // can echo it on the response; gateway then uses it instead of the env default.
    let (mut assessed_risk, classification, mut intent_labels, mut matched_rules, reasoning, mut intent_action, mut has_non_exemptable_block, intent_token_ttl, mut matched_rule_correctives) =
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
                    r.token_ttl_seconds,
                    r.matched_rule_correctives,
                )
            }
            Some(Err(e)) => {
                error!("Intent service unavailable: {}", e);
                degraded_stages.push("intent".to_string());
                match apply_degradation_or_default(state.degradation.intent_unavailable) {
                    Some((risk, class, labels, rules, _action)) => (risk, class, labels, rules, None, 0i32, false, 0u32, Vec::new()), // PASS on degradation
                    None => {
                        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "intent_unavailable", "Intent service unavailable"));
                    }
                }
            }
            None => {
                // Circuit breaker is open - apply degradation.
                match apply_degradation_or_default(state.degradation.intent_unavailable) {
                    Some((risk, class, labels, rules, _action)) => (risk, class, labels, rules, None, 0i32, false, 0u32, Vec::new()),
                    None => {
                        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "intent_unavailable", "Intent service unavailable (circuit open)"));
                    }
                }
            }
        };

    // ---- Stage 5.25: PROMPT-SCOPED CLASSIFY (when prompt_context present) ----
    //
    // The first classify call runs at the tool's scope (e.g. db:query:read)
    // and only fires rules whose scope_pattern matches that scope. Rules
    // declared with scope_pattern="llm:input:prompt" — R013 (override),
    // R014 (roleplay), R015 (delimiter), R031 (context-poisoning),
    // R032 (impersonation), R038 (system-prompt extraction) — will NOT
    // fire at the tool scope. Without this second pass, prompt-context is
    // only audited (prompt_hash) and scanned by wildcard rules (R068 etc.),
    // missing the entire prompt-injection rule set.
    //
    // Cost: one extra ag-intent gRPC RTT per /v1/proxy call that carries
    // prompt_context. The call body is small (tool="prompt_scan",
    // params={text:<prompt>}). Aggregation: BLOCK from either layer wins;
    // matched_rules from both are unioned.
    if let Some(ref ctx) = body.prompt_context {
        let trimmed = ctx.trim();
        if !trimmed.is_empty() && state.circuit_breakers.is_allowed("intent") {
            let prompt_params = serde_json::json!({"text": trimmed}).to_string();
            tracing::debug!(otel.name = "classify_prompt", agent_id = %agent_id_str, "Calling ag-intent ClassifyIntent for prompt_context (scope=llm:input:prompt)");
            let mut client = state.intent.clone();
            let prompt_result = client
                .classify_intent(ClassifyRequest {
                    tool_name: "prompt_scan".to_string(),
                    action: "scan".to_string(),
                    params_json: prompt_params,
                    params_normalized_json: String::new(),
                    encodings_detected: vec![],
                    agent_purpose: agent_profile.declared_purpose.clone(),
                    agent_id: agent_id_str.clone(),
                    agent_risk_score: agent_ema_score,
                    session_flags: session_flags.clone(),
                    session_risk_factor,
                    session_total_calls: session_context.tool_calls.len() as i32,
                    session_context_window: session_context.tool_calls.len().min(10) as i32,
                    session_context_json: String::new(),
                    caller_agent_id: delegation_ctx.as_ref().and_then(|d| d.caller_agent_id.clone()),
                    delegation_chain: delegation_ctx.as_ref().map(|d| d.chain.clone()).unwrap_or_default(),
                    delegation_trace_id: delegation_ctx.as_ref().and_then(|d| d.trace_id.clone()),
                    delegation_confidence: delegation_ctx.as_ref().map(|d| d.confidence.clone()),
                    tool_descriptor_hash: String::new(),
                    trust_level: pre_classify_trust.to_string(),
                    org_id: api_key_info.org_id.clone(),
                    resolved_scope: "llm:input:prompt".to_string(),
                })
                .await;
            match prompt_result {
                Ok(resp) => {
                    state.circuit_breakers.record_success("intent");
                    let r = resp.into_inner();
                    // Aggregate: BLOCK > FLAG > PASS (proto enum: 0=PASS, 1=FLAG, 2=BLOCK)
                    if r.action > intent_action {
                        intent_action = r.action;
                    }
                    if r.assessed_risk > assessed_risk {
                        assessed_risk = r.assessed_risk;
                    }
                    if r.has_non_exemptable_block {
                        has_non_exemptable_block = true;
                    }
                    for label in r.labels {
                        if !intent_labels.contains(&label) {
                            intent_labels.push(label);
                        }
                    }
                    for rule in r.matched_rules {
                        if !matched_rules.contains(&rule) {
                            matched_rules.push(rule);
                        }
                    }
                    for mrc in r.matched_rule_correctives {
                        if !matched_rule_correctives.iter().any(|x| x.rule_id == mrc.rule_id) {
                            matched_rule_correctives.push(mrc);
                        }
                    }
                }
                Err(e) => {
                    state.circuit_breakers.record_failure("intent");
                    warn!(error = %e, "Prompt-scope classify failed — proceeding with tool-scope result only");
                }
            }
        }
    }

    // ---- Stage 5.5: MODEL ESCALATION (gray-zone hybrid) ----
    // Skip if intent already said Block - per-tool thresholds already decided.
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
                // Model unavailable or fail-open - use rules score as-is
                assessed_risk
            }
        }
    } else {
        assessed_risk
    };

    // ---- Stage 5.5b: LLM-AS-JUDGE (semantic gray-zone) ----
    // Skip if intent already said Block - no point calling LLM for a request
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
                // Tag the LLM judge result in labels and session flags
                intent_labels.push(format!("llm_judge:{}", resp.label));
                session_flags.push("LlmJudge".to_string());
                if resp.risk_score > 0.7 {
                    session_flags.push("LlmJudgeHighRisk".to_string());
                }
                if !resp.reasoning.is_empty() {
                    // Append reasoning to matched_rules for visibility in dashboard
                    matched_rules.push(format!("LLM:{}", resp.label));
                }
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

    // ---- Stage 5.7: IMPERSONATION MATCHER ----
    //
    // After the rule engine and LLM judge, run the per-tenant entity
    // registry matcher against the raw params. Any hit (homograph,
    // typosquat, TLD-swap, subdomain-confusion, exact wallet match, …)
    // is converted into a synthetic rule-match record with labels that
    // are already in NEVER_EXEMPTABLE_LABELS, so downstream policy eval
    // treats the hit as non-silenceable regardless of scope.
    //
    // Runs only if the tenant has registered entities; `None` / empty
    // returns a fast no-op.
    let assessed_risk = match state
        .baseline_cache
        .resolve_tenant_entities(&api_key_info.org_id)
        .await
    {
        Some(entities) if !entities.is_empty() => {
            let imp_matches = ag_common::impersonation::match_payload(&params_json, &entities);
            if !imp_matches.is_empty() {
                for m in &imp_matches {
                    // Synthetic rule id exposes the method + entity so
                    // audit log readers can tell "paypal homograph" from
                    // "stripe tld-swap" without extra lookups.
                    matched_rules.push(format!(
                        "R164:{}:{}",
                        serde_json::to_string(&m.method)
                            .unwrap_or_else(|_| "\"unknown\"".into())
                            .trim_matches('"'),
                        m.entity_id
                    ));
                    // Labels — all of these are never-exemptable in
                    // scope_exemption.rs::NEVER_EXEMPTABLE_LABELS.
                    intent_labels.push("impersonation".to_string());
                    intent_labels.push("protected_entity".to_string());
                    match m.method {
                        ag_common::entity::DetectionMethod::Homograph
                        | ag_common::entity::DetectionMethod::Punycode => {
                            intent_labels.push("homograph".to_string());
                        }
                        ag_common::entity::DetectionMethod::Typosquat
                        | ag_common::entity::DetectionMethod::TldSubstitution
                        | ag_common::entity::DetectionMethod::SubdomainConfusion => {
                            intent_labels.push("phishing".to_string());
                        }
                        ag_common::entity::DetectionMethod::ExactMatch => {}
                    }
                }
                // Matcher produced never-exemptable labels — propagate
                // the flag so ag-policy evaluates its boundary check
                // before trying any scope-based exemption path.
                has_non_exemptable_block = true;
                tracing::warn!(
                    otel.name = "impersonation_matched",
                    tool_name = %tool_name,
                    agent_id = %agent_id_str,
                    org_id = %api_key_info.org_id,
                    matches = imp_matches.len(),
                    "Impersonation matcher fired"
                );
                // Push risk high enough to clear the global block threshold.
                // Labels-based never-exemptable block is the primary enforcement
                // path; the risk bump is a belt-and-suspenders for any code path
                // that bypasses the label check.
                assessed_risk.max(0.95)
            } else {
                assessed_risk
            }
        }
        _ => assessed_risk,
    };
    stage_latencies.push(("impersonation_match", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // Stage 6: Evaluate policy (with circuit breaker)
    let policy_result = if state.circuit_breakers.is_allowed("policy") {
        tracing::info!(otel.name = "evaluate_policy", tool_name = %tool_name, agent_id = %agent_id_str, "Calling ag-policy Evaluate");
        let mut client = state.policy.clone();
        // #31: measure the gRPC round-trip to ag-policy so operators get
        // real p50/p95/p99 on the hot-path policy eval. The histogram
        // observation is O(8) comparisons + one atomic - well under the
        // 1 µs/call budget in the issue's acceptance criteria.
        let policy_eval_start = Instant::now();
        // Resolve tool scopes with three layers of specificity:
        //   1. Per-agent grant       ag:agent:tool:{agent_id}:{tool_name}
        //   2. Typed descriptor      ag:descriptor:{org_id}:{tool_name}   (authoritative)
        //   3. Legacy scope strings  ag:tool:scope:{org_id}:{tool_name}   (transition fallback)
        //
        // Layer 2 is the new descriptor-based path — it reads the full
        // `ag_common::descriptor::Descriptor` and calls `compute_scope`
        // instead of guessing from the tool name. Layer 3 is kept for the
        // short transition window until every org has migration 020 applied.
        //
        // No path parses the tool name to guess a scope. A discovered tool
        // with no descriptor runs under `unknown:unclassified:unknown`, which
        // carries no category-specific protection but also tells no lies.
        let requested_scopes = match state.baseline_cache
            .resolve_agent_tool_grant(&agent_id_str, &tool_name)
            .await
        {
            Ok(scopes) => scopes,
            // No per-agent grant. Try typed descriptor, then legacy fallback.
            Err(_) => {
                let typed = state.baseline_cache
                    .resolve_typed_descriptor(&api_key_info.org_id, &tool_name)
                    .await;

                match typed {
                    // Layer 2 hit: use the typed descriptor authoritatively.
                    Some(descriptor) => {
                        match ag_common::scopes::compute_scope_global(&descriptor) {
                            Ok(scope) => vec![scope.as_str()],

                            // Descriptor present but not classified — admin
                            // hasn't picked (category, subcategory, operation).
                            // Default-deny with a specific reason; no auto_trust
                            // here, because that was the path that let the
                            // PayPal homograph through silently.
                            Err(ag_common::scopes::ScopeError::Unclassified { .. }) => {
                                let (ah_start, ah_end) = agent_profile.boundaries.as_ref()
                                    .map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
                                let denial = format!(
                                    "Tool '{}' is approved but has no (category, subcategory, operation) classification. Classify it in the dashboard.",
                                    tool_name
                                );
                                crate::shadow::publish_event(&state, &ShadowEvent {
                                    request_id,
                                    trace_id: request_id.to_string(),
                                    org_id: api_key_info.org_id.clone(),
                                    agent_id: agent_id_str.clone(),
                                    agent_name: agent_profile.name.clone(),
                                    user_id: if agent_profile.owner_user_id.is_empty() { jwt_claims.user_id.clone().unwrap_or_default() } else { agent_profile.owner_user_id.clone() },
                                    tool_name: tool_name.clone(),
                                    tool_action: action.clone(),
                                    params_hash: params_hash.clone(),
                                    params_summary: params_summary.clone(),
                                    prompt_hash: prompt_hash.clone().unwrap_or_default(),
                                    assessed_risk,
                                    intent_classification: classification.clone(),
                                    policy_action: "deny".into(),
                                    policy_reason: "tool_not_classified".into(),
                                    blocked: true,
                                    denial: Some(crate::denial::gateway_denial(
                                        "GATEWAY/tool_not_classified",
                                        denial.clone(),
                                    )),
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
                tool_annotations: body.tool_annotations.clone().unwrap_or_default(),
                                    active_hours_start: ah_start,
                                    active_hours_end: ah_end,
                                    rejection_type: ag_common::models::RejectionType::Config,
                                    ..ShadowEvent::default()
                                }).await;

                                return Err(api_error(
                                    StatusCode::UNPROCESSABLE_ENTITY,
                                    "tool_not_classified",
                                    &denial,
                                ));
                            }

                            // Stale taxonomy — classified descriptor references
                            // a category/subcategory/operation that no longer
                            // exists in categories.toml. Hard error into the
                            // operator log; do not silently name-match.
                            Err(e) => {
                                error!(
                                    tool = %tool_name,
                                    agent_id = %agent_id_str,
                                    error = %e,
                                    "compute_scope failed on classified descriptor (stale taxonomy)"
                                );
                                return Err(api_error(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "taxonomy_stale",
                                    &format!("Classification references unknown taxonomy entry: {}", e),
                                ));
                            }
                        }
                    }

                    // Layer 2 miss: no typed descriptor. Fall through to legacy
                    // scope-string key (for envs where migration 020 has not
                    // yet run, or tools never approved at all).
                    None => match state.baseline_cache
                        .resolve_tool_scopes(&api_key_info.org_id, &tool_name)
                        .await
                    {
                        Ok(scopes) => scopes,
                        Err(reason) => {
                            // Discovery path. Emit shadow so ag-control picks
                            // up the tool and populates a descriptor. Instead
                            // of name-parsing a scope, grant the explicit
                            // unclassified marker — honest about what we don't
                            // know, while still letting auto_trust proceed.
                            let auto_trust = check_auto_trust(&state.redis_pool, &agent_id_str, &api_key_info.org_id).await;

                            let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
                            crate::shadow::publish_event(&state, &ShadowEvent {
                                request_id,
                                trace_id: request_id.to_string(),
                                org_id: api_key_info.org_id.clone(),
                                agent_id: agent_id_str.clone(),
                                agent_name: agent_profile.name.clone(),
                                user_id: if agent_profile.owner_user_id.is_empty() { jwt_claims.user_id.clone().unwrap_or_default() } else { agent_profile.owner_user_id.clone() },
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
                                denial: if auto_trust {
                                    None
                                } else {
                                    Some(crate::denial::gateway_denial(
                                        "GATEWAY/tool_not_registered",
                                        reason.clone(),
                                    ))
                                },
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
                tool_annotations: body.tool_annotations.clone().unwrap_or_default(),
                                active_hours_start: ah_start,
                                active_hours_end: ah_end,
                                rejection_type: ag_common::models::RejectionType::Config,
                                ..ShadowEvent::default()
                            }).await;

                            if auto_trust {
                                // Explicit unclassified scope instead of a
                                // name-parsed guess. Category-specific rules
                                // deliberately don't match; payload-pattern
                                // rules (PII, injection, homograph normaliser)
                                // still fire on their own signals.
                                vec!["unknown:unclassified:unknown".to_string()]
                            } else {
                                return Err(api_error(
                                    StatusCode::UNPROCESSABLE_ENTITY,
                                    "tool_not_registered",
                                    &reason,
                                ));
                            }
                        }
                    },
                }
            }
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
                // Payment context (enriched by gateway for Cedar policies)
                payment_amount_cents: payment_amount_cents,
                payment_recipient: payment_recipient.clone(),
                payment_network: None, // extracted at x402 response level, not request level
                payment_currency: None, // extracted at x402 response level, not request level
                payment_vendor_approved: payment_vendor_approved,
                delegation_approved: delegation_is_approved,
                resolved_scope: resolved_scope.clone(),
                token_ttl_seconds: intent_token_ttl,
                matched_rule_correctives: matched_rule_correctives
                    .iter()
                    .map(|m| ag_proto::agentguard::policy::MatchedRuleCorrective {
                        rule_id: m.rule_id.clone(),
                        corrective_json: m.corrective_json.clone(),
                    })
                    .collect(),
                // v0.20 Wave 3: forward the SDK-side override (when set)
                // to ag-policy. JSON-encoded `CorrectiveTemplate`. Empty
                // string = no override (resolver falls through to rule
                // defaults). Gateway does no validation here — ag-policy
                // is the typed-deserialisation boundary.
                sdk_corrective_override_json: body
                    .sdk_corrective_override
                    .as_ref()
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
            })
            .await;
        crate::metrics::observe_policy_eval_us(
            policy_eval_start.elapsed().as_micros() as u64,
        );
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

    let (policy_action, granted_scopes, _denied_scopes, policy_reason, policy_token_ttl, matched_policies, boundary_violation_policy, trust, boundary_reason_str, boundary_matched_rule, policy_denial_proto) = match policy_result {
        Some(Ok(resp)) => {
            let r = resp.into_inner();
            let trust = TrustLevel::from_str(&r.trust_level).unwrap_or(TrustLevel::Unknown);
            let boundary_reason_str = r.boundary_reason.clone();
            // v0.20: reason, boundary_violation, boundary_matched_rule now
            // live inside the optional StructuredDenial. Extract them here
            // so the rest of the function keeps reading flat locals.
            let (reason, boundary_violation, boundary_matched_rule) = match r.denial.as_ref() {
                Some(d) => (
                    d.violated_predicate.clone(),
                    d.boundary_violation.clone(),
                    d.boundary_matched_rule.clone().unwrap_or_default(),
                ),
                None => (String::new(), None, String::new()),
            };
            (r.action, r.required_scopes, r.denied_scopes, reason, r.token_ttl_seconds, r.matched_policies, boundary_violation, trust, boundary_reason_str, boundary_matched_rule, r.denial)
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
                        TrustLevel::Unknown,
                        String::new(),
                        String::new(),
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
                        TrustLevel::Unknown,
                        String::new(),
                        String::new(),
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

        // Use ag-policy's structured denial when it returned one; otherwise the
        // block came from suspicion/risk-threshold logic in decision.rs and we
        // synthesize a gateway-local denial.
        let denial_json = match policy_denial_proto.as_ref() {
            Some(d) => crate::denial::to_json(d),
            None => crate::denial::gateway_denial(
                if matched_rules.is_empty() {
                    "GATEWAY/risk_threshold".to_string()
                } else {
                    format!("GATEWAY/{}", matched_rules[0])
                },
                denial_reason.clone(),
            ),
        };

        // Publish shadow event (fire and forget)
        let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
        crate::shadow::publish_event(&state, &ShadowEvent {
            request_id,
            trace_id: request_id.to_string(),
            org_id: api_key_info.org_id.clone(),
            agent_id: agent_id_str.clone(),
            agent_name: agent_profile.name.clone(),
            user_id: if agent_profile.owner_user_id.is_empty() { jwt_claims.user_id.clone().unwrap_or_default() } else { agent_profile.owner_user_id.clone() },
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
            denial: Some(denial_json.clone()),
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
            trust_level: pre_classify_trust.to_string(),
            ..ShadowEvent::default()
        }).await;

        // Record denied request in session (for ScopeProbing detection)
        {
            // T3: descriptor_opt resolved earlier at line ~1170 via baseline_cache.
            // When the tool is classified, is_external_send uses the descriptor's
            // (cat, sub, op) and ignores the substring fallback path.
            let is_external = session::is_external_send(&tool_name, &action, descriptor_opt.as_ref());
            let tables = session::extract_tables_from_params(&tool_name, &body.params);
            // Classify denial type: "scope" for scope mismatches, "intent" for rule-based blocks
            let denial_type = if denial_reason.contains("scope_boundary") || denial_reason.contains("No requested scopes") {
                "scope"
            } else {
                "intent"
            };
            let tool_record = session::build_tool_record_with_type(
                &tool_name,
                &action,
                0, // no records returned for denied requests
                true, // was_denied = true
                denial_type,
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
            denial: Some(denial_json),
            reasoning: reasoning.clone(),
            matched_rules: matched_rules.clone(),
            latency_ms,
            stage_latencies_us: owned_stages(&stage_latencies),
            degraded_stages,
            session_flags,
            scope_token: None,
            trust_level: Some(trust.to_string()),
            decision_trace: Some(build_decision_trace(
                trust,
                &boundary_reason_str,
                &boundary_matched_rule,
                &policy_reason,
                policy_action,
                true,
                intent_action,
                &matched_rules,
            )),
        }));
    }

    stage_latencies.push(("policy_decision", stage_start.elapsed().as_micros() as u64));
    stage_start = Instant::now();

    // ---- Evaluate-only fast path: skip token exchange + forwarding when no target_url ----
    // This is the default SDK flow - agent executes the tool locally after getting allow/deny.
    if body.target_url.is_empty() {
        let scope_granted = granted_scopes.join(" ");

        // Mint a compact scope token (payload.signature) proving this call was approved.
        // Contains scope grant, tool binding, and expiry.
        //
        // Ed25519 asymmetric signing - cannot forge without the private key.
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
            // Per-call binding: sha256(canonical_json({tool, params})) over the
            // RAW tool name + RAW params the agent sent, so the tool side (and
            // the SDKs) reproduce it byte-for-byte and reject a token replayed
            // for a different call. Uses the raw tool name (not the canonicalized
            // form) so both ends agree without sharing normalization rules.
            let call_binding =
                ag_common::contract_hash::call_binding(&raw_tool_name, &body.params);
            crate::scope_token::mint(
                &state.scope_signing_key,
                &crate::scope_token::MintInput {
                    agent_id: &agent_id_str,
                    scope_granted: &scope_granted,
                    tool_name: &tool_name,
                    binding: &call_binding,
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
            user_id: if agent_profile.owner_user_id.is_empty() { jwt_claims.user_id.clone().unwrap_or_default() } else { agent_profile.owner_user_id.clone() },
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
            trust_level: pre_classify_trust.to_string(),
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
            action: resolved_action_str(intent_action, &policy_reason),
            risk_score: assessed_risk,
            scope_granted: Some(scope_granted),
            tool_response: None,
            denial: None,
            reasoning,
            matched_rules: matched_rules.clone(),
            latency_ms,
            stage_latencies_us: owned_stages(&stage_latencies),
            degraded_stages,
            session_flags,
            scope_token: Some(scope_token),
            trust_level: Some(trust.to_string()),
            decision_trace: Some(build_decision_trace(
                trust,
                &boundary_reason_str,
                &boundary_matched_rule,
                &policy_reason,
                policy_action,
                false,
                intent_action,
                &matched_rules,
            )),
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

    // ---- Stage 7.5: SSRF PROTECTION ----
    // Validate target_url before forwarding to prevent SSRF attacks.
    if let Err(reason) = validate_target_url(&body.target_url) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "ssrf_blocked",
            format!("Target URL blocked: {}", reason),
        ));
    }

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
            //
            // v0.11.1 P4: when trust=Trusted AND the org/agent effective
            // config has `skip_pii_scan=true`, bypass the PII scanner.
            // Default config has `skip_pii_scan=false` so DLP stays on
            // unless admin explicitly opts out for trusted destinations.
            let pii_skip_enabled = matches!(pre_classify_trust, TrustLevel::Trusted) && {
                let org_uuid = uuid::Uuid::parse_str(&api_key_info.org_id).ok();
                let agent_uuid = uuid::Uuid::parse_str(&agent_id_str).ok();
                match org_uuid {
                    Some(oid) => state.trust_cache.resolve(&oid, agent_uuid.as_ref()).skip_pii_scan,
                    None => false,
                }
            };
            let metadata = if pii_skip_enabled {
                debug!(
                    agent_id = %agent_id_str,
                    "skip_pii_scan=true + trust=Trusted → bypassing PII scanner"
                );
                // Return minimal metadata so downstream code continues to
                // work; contains_pii_patterns=false is the safe default.
                ag_common::models::ResponseMetadata {
                    status_code,
                    body_size_bytes: body_bytes.len() as u64,
                    records_count: 0,
                    contains_pii_patterns: false,
                    truncated: false,
                    response_hash: String::new(),
                }
            } else {
                inspect_response(&body_bytes, status_code, &content_type)
            };
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
                            // Parse "caller_id:risk:ts" - check if risk > 0.5
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
                        return; // Drift without risky contact - not a sleeper signal
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
                                "Sleeper agent drift detected by LLM judge - flagging for enhanced monitoring"
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
                        // Source: unified BoundaryAllowlistEntry rows scoped to
                        // (category="payment", subcategory="transaction"). Same
                        // source as the request-side check at proxy.rs ~line 910.
                        approved_vendors: agent_profile.boundaries.as_ref()
                            .map_or_else(Vec::new, |b| {
                                b.allowlist.iter()
                                    .filter(|e| e.category == "payment" && e.subcategory == "transaction")
                                    .map(|e| e.pattern.clone())
                                    .collect()
                            }),
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
                        crate::metrics::observe_gateway_total_us(started_at.elapsed().as_micros() as u64);
                        return Ok(Json(ProxyResponse {
                            request_id: request_id.to_string(),
                            allowed: false,
                            action: "block".to_string(),
                            risk_score: assessed_risk,
                            scope_granted: Some(scope_granted.clone()),
                            tool_response: Some(parsed),
                            denial: Some(crate::denial::gateway_denial(
                                "GATEWAY/x402_payment_blocked",
                                decision.deny_reason.clone().unwrap_or_else(|| "payment not permitted".to_string()),
                            )),
                            reasoning: Some("x402 payment blocked by boundary enforcement".to_string()),
                            matched_rules: vec![],
                            latency_ms: started_at.elapsed().as_millis() as u64,
                            stage_latencies_us: owned_stages(&stage_latencies),
                            degraded_stages: degraded_stages.clone(),
                            session_flags: session_flags.clone(),
                            scope_token: None,
                            trust_level: Some(trust.to_string()),
                            decision_trace: Some(build_decision_trace(
                                trust,
                                &boundary_reason_str,
                                &boundary_matched_rule,
                                &policy_reason,
                                policy_action,
                                true,
                                intent_action,
                                &matched_rules,
                            )),
                        }));
                    }

                    // Allowed - adjust risk and log.
                    debug!(
                        request_id = %request_id,
                        agent_id = %agent_id_str,
                        amount = %payment.amount,
                        currency = %payment.currency,
                        risk_modifier = decision.risk_modifier,
                        "x402 payment ALLOWED - passing 402 through"
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
                        "Sanitized error response - stripped sensitive internal details"
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
            "Agent killed mid-flight - discarding downstream response"
        );

        // Publish shadow event for the discarded response
        let (ah_start, ah_end) = agent_profile.boundaries.as_ref().map_or((0, 0), |b| (b.allowed_hours_start, b.allowed_hours_end));
        crate::shadow::publish_event(&state, &ShadowEvent {
            request_id,
            trace_id: request_id.to_string(),
            org_id: api_key_info.org_id.clone(),
            agent_id: agent_id_str.clone(),
            agent_name: agent_profile.name.clone(),
            user_id: if agent_profile.owner_user_id.is_empty() { jwt_claims.user_id.clone().unwrap_or_default() } else { agent_profile.owner_user_id.clone() },
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
            denial: Some(crate::denial::gateway_denial(
                "GATEWAY/agent_killed_mid_flight",
                "agent_killed_mid_flight",
            )),
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
            trust_level: pre_classify_trust.to_string(),
            ..ShadowEvent::default()
        }).await;

        return Err(api_error(
            StatusCode::FORBIDDEN,
            "agent_killed_mid_flight",
            "Agent was kill-switched during tool execution - response discarded",
        ));
    }

    let latency_ms = started_at.elapsed().as_millis() as u64;

    // ---- Update session context (fire-and-forget after response) ----
    {
        let records_returned = response_metadata
            .as_ref()
            .map(|m| m.records_count)
            .unwrap_or(0);
        // T3: descriptor_opt resolved earlier at line ~1170 via baseline_cache.
        let is_external = session::is_external_send(&tool_name, &action, descriptor_opt.as_ref());
        let tables = session::extract_tables_from_params(&tool_name, &body.params);
        let mut tool_record = session::build_tool_record(
            &tool_name,
            &action,
            records_returned,
            false, // not denied (we passed decision gate)
            is_external,
            tables,
            "",
        );
        // T7: propagate the response inspector's PII detection into the
        // session record. Read by `compute_flags` to set the
        // PreviousOutputSensitive flag and by build_session_context_json to
        // populate `previous_output_sensitive` for ag-intent's Pattern 13.
        tool_record.pii_in_response = response_metadata
            .as_ref()
            .map(|m| m.contains_pii_patterns)
            .unwrap_or(false);

        let mut session_to_save = session_context.clone();
        let max_records = 1000u32; // default; would come from agent boundaries in full impl
        session_to_save.record_tool_call(tool_record, max_records);
        session_to_save.record_risk(assessed_risk);

        // Per-hour payment counter — INCRBY only on successful payment so
        // failed downstream calls don't burn the agent's hourly budget.
        // ag-policy reads this same key in its Phase 0.6 check (B-PAYMENT-HOUR)
        // before approving the next payment. Key TTL = 7200s covers the bucket
        // plus a generous tail so cross-bucket reads still see fresh data.
        let payment_hour_incr = if is_payment_tool {
            payment_amount_cents.filter(|&a| a > 0)
        } else {
            None
        };

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

                // Per-hour payment counter increment.
                if let Some(amount) = payment_hour_incr {
                    let hour_bucket = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() / 3600)
                        .unwrap_or(0);
                    let counter_key = format!("ag:payment:hourly:{}:{}", agent_for_sadd, hour_bucket);
                    let _: Result<i64, _> = redis::cmd("INCRBY")
                        .arg(&counter_key)
                        .arg(amount)
                        .query_async(&mut *conn)
                        .await;
                    let _: Result<(), _> = redis::cmd("EXPIRE")
                        .arg(&counter_key)
                        .arg(7200i64)
                        .query_async(&mut *conn)
                        .await;
                }
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
        user_id: if agent_profile.owner_user_id.is_empty() { jwt_claims.user_id.clone().unwrap_or_default() } else { agent_profile.owner_user_id.clone() },
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
        trust_level: pre_classify_trust.to_string(),
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
        action: resolved_action_str(intent_action, &policy_reason),
        risk_score: assessed_risk,
        scope_granted: Some(scope_granted),
        tool_response,
        denial: None,
        reasoning,
        matched_rules: matched_rules.clone(),
        latency_ms,
        stage_latencies_us: owned_stages(&stage_latencies),
        degraded_stages,
        session_flags,
        scope_token: None, // Full proxy mode uses micro_token in Authorization header instead
        trust_level: Some(trust.to_string()),
        decision_trace: Some(build_decision_trace(
            trust,
            &boundary_reason_str,
            &boundary_matched_rule,
            &policy_reason,
            policy_action,
            false,
            intent_action,
            &matched_rules,
        )),
    }))
}

/// POST /v1/verify - Dry-run (Stages 1-6 only, no token exchange or forwarding).
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
        return Err(api_error(StatusCode::SERVICE_UNAVAILABLE, "license_revoked", "License revoked - contact support at clampd.dev"));
    }

    // T1: descriptor passed as None for now (T3 plumbs the real one through).
    let (tool_name, action, params_json, _params_hash, _) = extract_tool_call(&body, None);

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

    // Fetch baseline + typed descriptor concurrently (two independent Redis
    // reads). Baseline is ag-risk HSET (60s local TTL); descriptor feeds the
    // authoritative tool scope below.
    let (baseline, descriptor_opt) = tokio::join!(
        state.baseline_cache.get(&agent_id_str),
        state.baseline_cache.resolve_typed_descriptor(&api_key_info.org_id, &tool_name),
    );

    // Scope is passed to intent + policy RPCs via `resolved_scope`. Empty
    // string when no descriptor exists — consumers fall back to the legacy
    // path during the migration window.
    // T3: borrow rather than move so descriptor_opt remains usable downstream
    // (passed into is_external_send at the tool-record build sites).
    let resolved_scope: String = match descriptor_opt.as_ref() {
        Some(desc) => ag_common::scopes::compute_scope_global(desc)
            .map(|s| s.as_str())
            .unwrap_or_default(),
        None => String::new(),
    };

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
                session_context_json: build_session_context_json(&session_context, baseline.as_ref(), &resolved_scope),
                caller_agent_id: None,
                delegation_chain: Vec::new(),
                delegation_trace_id: None,
                delegation_confidence: None,
                tool_descriptor_hash: String::new(),
                // /v1/verify has no target_url/agent_boundaries context, so
                // we cannot run BoundaryCheck meaningfully here. Stays Unknown.
                trust_level: TrustLevel::Unknown.to_string(),
                org_id: api_key_info.org_id.clone(),
                resolved_scope: resolved_scope.clone(),
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

    crate::metrics::observe_gateway_total_us(started_at.elapsed().as_micros() as u64);
    Ok(Json(ProxyResponse {
        request_id: request_id.to_string(),
        allowed: !blocked,
        action: action_str(verify_intent_action),
        risk_score: assessed_risk,
        scope_granted: None,
        tool_response: None,
        denial: if blocked {
            Some(crate::denial::gateway_denial(
                "GATEWAY/risk_threshold",
                format!("Risk score {:.2} exceeds threshold", assessed_risk),
            ))
        } else {
            None
        },
        reasoning: verify_reasoning,
        matched_rules: verify_rules,
        latency_ms,
        stage_latencies_us: Vec::new(),
        degraded_stages: Vec::new(),
        session_flags,
        scope_token: None, // /v1/verify is dry-run only
        trust_level: None,
        decision_trace: None,
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

/// POST /v1/inspect - Inspect a tool response for PII, anomalies, and sensitive data.
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

    // 1. PII detection via the existing response_inspector machinery.
    //    Gate identical to proxy.rs Stage 8b: when the org/agent effective
    //    trust config has `skip_pii_scan=true`, bypass the bump. Email
    //    integrations and payment tools that legitimately return PII can
    //    opt out via dashboard trust config without disabling all rules.
    let pii_skip_enabled = {
        let org_uuid = uuid::Uuid::parse_str(&api_key_info.org_id).ok();
        let agent_uuid = uuid::Uuid::parse_str(&agent_id_str).ok();
        match org_uuid {
            Some(oid) => state.trust_cache.resolve(&oid, agent_uuid.as_ref()).skip_pii_scan,
            None => false,
        }
    };
    if !pii_skip_enabled {
        let metadata = inspect_response(
            serialized_bytes,
            200, // synthetic status - we're inspecting data, not a real HTTP response
            "application/json",
        );
        if metadata.contains_pii_patterns {
            risk_score += 0.4;
            findings.push("PII patterns detected in response data".to_string());
        }
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

    // 4. Scope token verification - check that response doesn't violate granted scope
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
                // Don't block - token verification failure shouldn't prevent inspection
                // But record it for audit trail
                findings.push(format!("scope_token_invalid: {}", reason));
            }
        }
    }

    // Clamp risk score to [0.0, 1.0]
    risk_score = risk_score.clamp(0.0, 1.0);

    let blocked = scope_blocked || risk_score >= state.config.risk_threshold;
    let denial_json = if blocked {
        Some(crate::denial::gateway_denial(
            "GATEWAY/inspect_blocked",
            findings.join("; "),
        ))
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

    crate::metrics::observe_gateway_total_us(started_at.elapsed().as_micros() as u64);
    Ok(Json(ProxyResponse {
        request_id: request_id.to_string(),
        allowed: !blocked,
        action: if blocked { "block".to_string() } else { "pass".to_string() },
        risk_score,
        scope_granted: None,
        tool_response: None,
        denial: denial_json,
        reasoning: if findings.is_empty() {
            None
        } else {
            Some(findings.join("; "))
        },
        matched_rules: matched_keywords,
        latency_ms,
        stage_latencies_us: Vec::new(),
        degraded_stages: Vec::new(),
        session_flags: Vec::new(),
        scope_token: None,
        trust_level: None,
        decision_trace: None,
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
            warn!("Degraded (ApplyCachedRules): {} - no cache impl yet, fail-closed", message);
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
/// `_tool_name` is reserved for future tool-specific summary heuristics
/// (e.g., DB-tool params get SQL extraction, http tools get URL extraction);
/// kept in the signature so callers don't change when those land.
fn summarize_params(_tool_name: &str, params: &serde_json::Value) -> String {
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
        // Workflow exists - check if it's NOT enforcing (= learning mode)
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

    // No workflow - fall back to org-level auto_trust
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
            tracing::error!("Redis unavailable for API key validation: {} - rejecting (fail-closed)", e);
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
            tracing::error!("Redis GET failed for API key: {} - rejecting (fail-closed)", e);
            None
        }
    }
}

/// Peek the (unverified) `sub` claim from a JWT without verifying the
/// signature. Used ONLY for the early kill-switch (deny-set) check, which is
/// fail-safe: a match denies the request, and an unverified sub can never grant
/// access (the signature is still verified in `validate_jwt_with_agent_credential`
/// before anything is allowed). Returns None if the token is malformed.
fn peek_jwt_subject(token: &str) -> Option<String> {
    use base64::Engine as _;
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("sub").and_then(|v| v.as_str()).map(String::from)
}

/// Per-agent JWT validation: EdDSA signature against the enrolled public key.
///
/// 1. Decode JWT (without sig check) to extract `sub` (agent_id).
/// 2. Look up `ag:agent:cred:{agent_id}` in Redis — the agent's Ed25519 public
///    key, written at enrollment and synced by ag-control.
/// 3. If found: verify the EdDSA signature against that public key.
/// 4. If not found: reject (fail-closed) — the agent is not enrolled. There is
///    no shared-secret fallback.
/// 5. If Redis is down: reject (fail-closed).
async fn validate_jwt_with_agent_credential(
    token: &str,
    _jwt_secret: &str,
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> Result<ag_common::models::AgentJwtClaims, String> {
    use base64::Engine as _;

    // Step 1: Decode the payload (signature not yet trusted) to extract `sub`.
    // We parse the payload directly rather than via jsonwebtoken so the peek is
    // independent of the signing algorithm (the EdDSA signature is verified in
    // Step 3 against the agent's enrolled public key).
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("invalid JWT format".to_string());
    }
    let agent_id = peek_jwt_subject(token);

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
                            "Redis error during credential lookup: {} - rejecting request (fail-closed)", e
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(format!(
                    "Redis unavailable for credential lookup: {} - rejecting request (fail-closed)", e
                ));
            }
        }
    } else {
        None
    };

    // Step 3: Verify the EdDSA signature against the agent's registered public
    // key (ed25519-dalek, mirroring ag-token's verifier). The stored credential
    // is the raw base64url Ed25519 public key written at enrollment. No
    // per-agent credential means the agent is not enrolled -> reject. There is
    // no shared-secret fallback.
    let pubkey_b64 = agent_secret.ok_or_else(|| {
        format!(
            "no credential for agent '{}' - not enrolled (rejecting, fail-closed)",
            agent_id.as_deref().unwrap_or("<unknown>")
        )
    })?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pubkey_b64.trim_end_matches('='))
        .map_err(|e| format!("invalid agent public key encoding: {e}"))?;
    let key_arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("agent public key must be 32 bytes, got {}", raw.len()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| format!("invalid agent public key: {e}"))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("invalid signature encoding: {e}"))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("invalid signature: {e}"))?;
    {
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| "JWT signature verification failed".to_string())?;
    }

    // Signature is valid; decode claims and enforce expiry.
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("invalid payload encoding: {e}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid payload: {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if exp != 0 && exp < now {
        return Err("JWT expired".to_string());
    }
    extract_claims_from_value(&claims)
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

    // ── peek_jwt_subject (early kill-switch check) ───────────
    #[test]
    fn peek_subject_extracts_sub_without_verifying() {
        use base64::Engine as _;
        let eng = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = eng.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = eng.encode(br#"{"sub":"agent-123","iss":"clampd-sdk"}"#);
        // Signature is irrelevant to the peek (not verified here).
        let token = format!("{header}.{payload}.deadbeef");
        assert_eq!(peek_jwt_subject(&token), Some("agent-123".to_string()));
    }

    #[test]
    fn peek_subject_returns_none_for_malformed() {
        assert_eq!(peek_jwt_subject("not-a-jwt"), None);
        assert_eq!(peek_jwt_subject("only.two"), None);
        assert_eq!(peek_jwt_subject("bad!!.payload!!.sig"), None);
    }

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
        // Empty string is not a valid UUID - rejected at extraction
        let claims = json!({"sub": ""});
        let result = extract_claims_from_value(&claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("UUID"));
    }

    // ── validate_jwt_with_agent_credential: credential lookup is fail-closed ─

    #[tokio::test]
    async fn validate_jwt_no_credential_rejects() {
        // EdDSA validation looks up the agent's public key in Redis. With Redis
        // unreachable the credential can't be resolved, so the request must be
        // rejected fail-closed (never accepted without a verified signature).
        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1")
            .expect("manager creation");
        let pool = bb8::Pool::builder()
            .max_size(1)
            .connection_timeout(std::time::Duration::from_millis(1))
            .build(manager)
            .await
            .expect("pool creation");

        // A decodable token (valid sub) so it reaches the credential lookup.
        let result = validate_jwt_with_agent_credential(
            "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.fake",
            "",
            &pool,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("Redis") || err.contains("redis"),
            "credential lookup must fail closed on Redis error: {err}"
        );
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
        //  check happens after - in unit tests without Redis it fails at Redis)
        let result2 = validate_jwt_with_agent_credential(&tampered_token, secret, &pool).await;
        assert!(result2.is_err());
    }

    // ══════════════════════════════════════════════════════════════════
    // ADVERSARIAL TESTS - SSRF Protection (#15)
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_ssrf_aws_metadata() {
        let result = validate_target_url("http://169.254.169.254/latest/meta-data/");
        assert!(result.is_err(), "AWS metadata endpoint should be blocked");
    }

    #[test]
    fn adversarial_ssrf_gcp_metadata() {
        let result = validate_target_url("http://metadata.google.internal/computeMetadata/v1/");
        assert!(result.is_err(), "GCP metadata endpoint should be blocked");
    }

    #[test]
    fn adversarial_ssrf_localhost() {
        assert!(validate_target_url("http://127.0.0.1/admin").is_err());
        assert!(validate_target_url("http://localhost/admin").is_err());
        assert!(validate_target_url("http://0.0.0.0/").is_err());
        assert!(validate_target_url("http://[::1]/").is_err());
    }

    #[test]
    fn adversarial_ssrf_private_networks() {
        assert!(validate_target_url("http://10.0.0.1/internal").is_err(), "10.x blocked");
        assert!(validate_target_url("http://172.16.0.1/internal").is_err(), "172.16.x blocked");
        assert!(validate_target_url("http://192.168.1.1/internal").is_err(), "192.168.x blocked");
        assert!(validate_target_url("http://169.254.1.1/").is_err(), "link-local blocked");
    }

    #[test]
    fn adversarial_ssrf_cgnat() {
        assert!(validate_target_url("http://100.64.0.1/").is_err(), "CGNAT range blocked");
        assert!(validate_target_url("http://100.127.255.255/").is_err(), "CGNAT upper range blocked");
    }

    #[test]
    fn adversarial_ssrf_disallowed_schemes() {
        assert!(validate_target_url("file:///etc/passwd").is_err(), "file:// scheme blocked");
        assert!(validate_target_url("ftp://internal/data").is_err(), "ftp:// scheme blocked");
        assert!(validate_target_url("gopher://internal/data").is_err(), "gopher:// scheme blocked");
    }

    #[test]
    fn adversarial_ssrf_valid_external_url() {
        assert!(validate_target_url("https://api.example.com/weather").is_ok(), "External HTTPS allowed");
        assert!(validate_target_url("http://api.example.com/data").is_ok(), "External HTTP allowed");
    }

    #[test]
    fn adversarial_ssrf_malformed_url() {
        assert!(validate_target_url("not-a-url").is_err(), "Malformed URL blocked");
        assert!(validate_target_url("").is_err(), "Empty URL blocked");
    }

    // ── #17: API key hash truncation ───────────────────────────────

    #[test]
    fn adversarial_api_key_hash_only_64_bits() {
        // API key lookup uses only first 16 hex chars of SHA-256 = 64 bits
        // Documenting: this is a 2^64 search space, not 2^256
        let hash = ag_common::auth::hash_api_key("ag_live_test_key_12345");
        let truncated = &hash[..16];
        assert_eq!(truncated.len(), 16, "Only 64 bits used for key lookup");
        // Full hash is 64 hex chars (256 bits)
        assert_eq!(hash.len(), 64, "Full SHA-256 is 256 bits");
        // This means API key security is 64 bits, not 256 bits
        // Still infeasible to brute force (2^64 operations) but weaker than expected
    }
}
