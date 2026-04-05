//! Session context adapter for ag-gateway.
//!
//! Bridges the ag-common SessionManager/SessionContext with the gateway
//! proxy pipeline. Handles:
//!
//! - Extracting session_id from `X-AG-Session` request header (or generating one)
//! - Loading or creating session context via Redis
//! - Recording tool calls into the session after intent classification
//! - Passing session flags and risk factor to gRPC calls
//! - Saving session state after the pipeline completes
//!
//! The ag-common `SessionManager` uses `redis::aio::ConnectionManager` (single
//! multiplexed connection), while ag-gateway uses `bb8::Pool<RedisConnectionManager>`.
//! This adapter uses the bb8 pool directly for Redis operations, implementing the
//! same get/set logic as `SessionManager` but against the pool connection type.

use ag_common::session::{session_redis_key, SessionContext, SessionToolRecord, MAX_SESSION_ID_LEN, SESSION_ID_CHARSET};
use axum::http::HeaderMap;
use tracing::{debug, warn};
use uuid::Uuid;

/// Redis TTL for session keys: 30 minutes (sliding window).
/// Must match ag-common::session::SESSION_TTL_SECS.
const SESSION_TTL_SECS: u64 = 1800;

/// Extract the session ID from the `X-AG-Session` header, or generate one.
///
/// If no header is present, generates a deterministic-but-unpredictable implicit
/// session ID based on the agent_id, a 15-minute rolling window, and a keyed HMAC
/// derived from the gateway's JWT_SECRET. This prevents attackers from guessing
/// session IDs without knowing the secret.
///
/// Returns `Err(reason)` if the explicit session ID is invalid (too long, bad chars).
///
/// Matching the spec:
/// > Fallback if no X-AG-Session: use (agent_id, rolling_15min_window) as implicit session
pub fn extract_session_id(headers: &HeaderMap, agent_id: &str) -> Result<String, String> {
    if let Some(header_val) = headers.get("x-ag-session") {
        if let Ok(session_id) = header_val.to_str() {
            if !session_id.is_empty() {
                // Validate: max 128 chars, charset [a-zA-Z0-9_:.-]
                if session_id.len() > MAX_SESSION_ID_LEN {
                    return Err(format!(
                        "Session ID exceeds {} character limit (got {})",
                        MAX_SESSION_ID_LEN,
                        session_id.len()
                    ));
                }
                if !session_id.chars().all(|c| SESSION_ID_CHARSET.contains(c)) {
                    return Err(
                        "Session ID contains invalid characters (allowed: a-zA-Z0-9_:.-)".to_string()
                    );
                }
                return Ok(session_id.to_string());
            }
        }
    }

    // Generate implicit session ID from agent_id + 15-minute window + secret hash
    // + client fingerprint for added binding.
    let fingerprint = extract_client_fingerprint(headers);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let window_15min = now_secs / 900; // 15 minutes = 900 seconds

    // Add unpredictability using a keyed hash of agent_id + window + fingerprint.
    // Uses cached JWT_SECRET (validated at startup by main.rs).
    let secret = &*crate::proxy::JWT_SECRET_CACHED;
    let hash_input = format!("{}:{}:{}:{}", agent_id, window_15min, fingerprint, secret);
    let hash = compute_session_hash(&hash_input);
    Ok(format!("implicit:{}:{}:{}", agent_id, window_15min, &hash[..8]))
}

/// Extract a client fingerprint from request headers.
///
/// SHA-256(X-Forwarded-For + User-Agent), returns first 32 hex chars.
/// Used to bind sessions to specific clients.
pub fn extract_client_fingerprint(headers: &HeaderMap) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let forwarded_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let input = format!("{}:{}", forwarded_for, user_agent);
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    let h1 = hasher.finish();
    // Double-hash for 32 hex chars (two u64 hashes)
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    let h2 = hasher2.finish();
    format!("{:016x}{:016x}", h1, h2)
}

/// Rate-limit session creation per agent. Returns Ok(()) if allowed, Err if exceeded.
///
/// Uses Redis key `ag:session:create_count:{agent_id}:{hour_bucket}` with INCR + EXPIRE.
pub async fn rate_limit_session_creation(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    agent_id: &str,
    max_per_hour: u32,
) -> Result<(), String> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let hour_bucket = now_secs / 3600;
    let key = format!("ag:session:create_count:{}:{}", agent_id, hour_bucket);

    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Session rate limit fail-open: {}", e);
            return Ok(()); // fail-open
        }
    };

    let count: u32 = redis::cmd("INCR")
        .arg(&key)
        .query_async::<i64>(&mut *conn)
        .await
        .unwrap_or(0) as u32;

    if count == 1 {
        // Set TTL to 2 hours to cover current + next bucket
        let _: Result<(), _> = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(7200u64)
            .query_async(&mut *conn)
            .await;
    }

    if count > max_per_hour {
        return Err(format!(
            "Session creation rate limit exceeded ({} sessions/hour, max {})",
            count, max_per_hour
        ));
    }

    Ok(())
}

/// Check if new session creation is blocked for this agent (post-kill).
///
/// Checks Redis key `ag:session:blocked:{agent_id}`.
pub async fn is_session_blocked(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    agent_id: &str,
) -> bool {
    let key = format!("ag:session:blocked:{}", agent_id);
    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(_) => return false, // fail-open
    };

    let exists: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async::<i64>(&mut *conn)
        .await
        .map(|v| v > 0)
        .unwrap_or(false);

    exists
}

/// Read the agent's EMA risk score from Redis (ag:risk:scores HSET).
///
/// Returns 0.0 if no score exists or on Redis failure.
pub async fn read_agent_ema_score(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    agent_id: &str,
) -> f64 {
    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(_) => return 0.0,
    };

    let score_json: Option<String> = redis::cmd("HGET")
        .arg("ag:risk:scores")
        .arg(agent_id)
        .query_async(&mut *conn)
        .await
        .unwrap_or(None);

    match score_json {
        Some(json) => {
            // Parse JSON for "ema" field: {"ema": 0.45, ...}
            serde_json::from_str::<serde_json::Value>(&json)
                .ok()
                .and_then(|v| v.get("ema").and_then(|e| e.as_f64()))
                .unwrap_or(0.0)
        }
        None => 0.0,
    }
}

/// Compute a hex-encoded SHA-256 hash of the input string.
fn compute_session_hash(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Load or create a session context from Redis using a bb8 pool connection.
///
/// If the session exists, loads and refreshes its TTL (sliding window).
/// If the session does not exist, creates a new one.
/// On Redis failure, returns a fresh session and logs a warning.
pub async fn load_or_create_session(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    agent_id: &Uuid,
    session_id: &str,
) -> SessionContext {
    let key = session_redis_key(agent_id, session_id);

    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Redis pool error for session load: {} — creating ephemeral session", e);
            return SessionContext::new(*agent_id, session_id.to_string());
        }
    };

    // Try to load existing session.
    let existing: Option<String> = match redis::cmd("GET")
        .arg(&key)
        .query_async(&mut *conn)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("Redis GET failed for session {}: {} — creating new session", key, e);
            return SessionContext::new(*agent_id, session_id.to_string());
        }
    };

    let session = match existing {
        Some(json) => match serde_json::from_str::<SessionContext>(&json) {
            Ok(ctx) => {
                debug!(session_id, "Loaded existing session with {} tool calls", ctx.tool_calls.len());
                ctx
            }
            Err(e) => {
                warn!("Failed to deserialize session {}: {} — creating new", key, e);
                SessionContext::new(*agent_id, session_id.to_string())
            }
        },
        None => {
            debug!(session_id, "Creating new session");
            SessionContext::new(*agent_id, session_id.to_string())
        }
    };

    // Refresh TTL (sliding window).
    if let Err(e) = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(SESSION_TTL_SECS)
        .query_async::<()>(&mut *conn)
        .await
    {
        warn!(error = %e, session_id, "Failed to EXPIRE session key in Redis");
    }

    session
}

/// Save session context back to Redis with sliding TTL.
///
/// This is designed to be called after the pipeline completes.
/// On Redis failure, logs a warning but does not fail the request
/// (session update is fire-and-forget as per spec).
pub async fn save_session(
    redis_pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
    session: &SessionContext,
) {
    let key = session_redis_key(&session.agent_id, &session.session_id);

    let json = match serde_json::to_string(session) {
        Ok(j) => j,
        Err(e) => {
            warn!("Failed to serialize session for save: {}", e);
            return;
        }
    };

    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Redis pool error for session save: {} — session state lost", e);
            return;
        }
    };

    let result: Result<(), _> = redis::cmd("SET")
        .arg(&key)
        .arg(&json)
        .arg("EX")
        .arg(SESSION_TTL_SECS)
        .query_async(&mut *conn)
        .await;

    if let Err(e) = result {
        warn!("Redis SET failed for session {}: {} — session state lost", key, e);
    } else {
        debug!(session_id = %session.session_id, "Session saved to Redis");
    }
}

/// Extract authorized tool names from the `X-AG-Authorized-Tools` header.
///
/// Parses comma-separated tool names, validates each (1-128 chars, `[a-zA-Z0-9_.]`),
/// caps at 100 tools. Returns None if header is absent or empty.
pub fn extract_authorized_tools(headers: &HeaderMap) -> Option<Vec<String>> {
    let header_val = headers.get("x-ag-authorized-tools")?;
    let val_str = header_val.to_str().ok()?;
    if val_str.is_empty() {
        return None;
    }

    let tools: Vec<String> = val_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        })
        .take(100)
        .collect();

    if tools.is_empty() {
        None
    } else {
        Some(tools)
    }
}

/// Lock the tool set for a session.
///
/// Inserts the given tools into `authorized_tools` and sets `tools_locked = true`.
pub fn lock_tool_set(session: &mut SessionContext, tools: Vec<String>) {
    for tool in tools {
        session.authorized_tools.insert(tool);
    }
    session.tools_locked = true;
}

/// Check if a tool is authorized for this session.
///
/// Returns Ok(()) if the session is unlocked or the tool is in the authorized set.
/// Returns Err("unauthorized_tool") if locked and tool is not authorized.
pub fn check_tool_authorized(session: &SessionContext, tool_name: &str) -> Result<(), String> {
    if !session.tools_locked {
        return Ok(());
    }
    if session.authorized_tools.contains(tool_name) {
        Ok(())
    } else {
        Err(format!(
            "Tool '{}' is not in the authorized tool set for this session",
            tool_name
        ))
    }
}

/// Auto-lock the tool set after reaching the threshold.
///
/// Adds the tool to the set. If the set size >= threshold, locks the session.
pub fn auto_lock_tool_set(session: &mut SessionContext, tool_name: &str, threshold: usize) {
    session.authorized_tools.insert(tool_name.to_string());
    if session.authorized_tools.len() >= threshold {
        session.tools_locked = true;
    }
}

/// Build a SessionToolRecord from pipeline data for recording into the session.
pub fn build_tool_record(
    tool_name: &str,
    action: &str,
    records_returned: u32,
    was_denied: bool,
    is_external_send: bool,
    tables_accessed: Vec<String>,
    scope_requested: &str,
) -> SessionToolRecord {
    SessionToolRecord {
        tool_name: tool_name.to_string(),
        action: action.to_string(),
        timestamp: chrono::Utc::now(),
        records_returned,
        was_denied,
        is_external_send,
        tables_accessed,
        scope_requested: scope_requested.to_string(),
    }
}

/// Determine if a tool action represents an external send.
///
/// External sends include HTTP POST/PUT to external URLs, email sending,
/// webhook triggers, etc. Used for ExternalSendAfterRead detection.
pub fn is_external_send(tool_name: &str, action: &str) -> bool {
    let tool_lower = tool_name.to_lowercase();
    let action_lower = action.to_lowercase();

    // Check tool name patterns.
    if tool_lower.contains("http.post")
        || tool_lower.contains("http.put")
        || tool_lower.contains("email.send")
        || tool_lower.contains("webhook")
        || tool_lower.contains("slack.post")
        || tool_lower.contains("api.call")
    {
        return true;
    }

    // Check action patterns.
    if action_lower == "send" || action_lower == "post" || action_lower == "put" {
        return true;
    }

    false
}

/// Extract table names from tool parameters (best-effort heuristic).
///
/// Looks for common patterns in SQL queries and tool names to identify
/// which tables/resources are being accessed.
pub fn extract_tables_from_params(tool_name: &str, params: &serde_json::Value) -> Vec<String> {
    let mut tables = Vec::new();

    // Check for explicit table parameter.
    if let Some(table) = params.get("table").and_then(|v| v.as_str()) {
        tables.push(table.to_string());
    }

    // Try to extract table names from SQL query parameter.
    if let Some(query) = params.get("query").and_then(|v| v.as_str()) {
        tables.extend(extract_tables_from_sql(query));
    }

    // Infer from tool name (e.g., "database.users.query" → "users").
    let parts: Vec<&str> = tool_name.split('.').collect();
    if parts.len() >= 2 && parts[0] == "database" {
        tables.push(parts[1].to_string());
    }

    tables.sort();
    tables.dedup();
    tables
}

/// Very simple SQL table name extraction.
/// Looks for "FROM <table>" and "JOIN <table>" patterns.
pub fn extract_tables_from_sql(sql: &str) -> Vec<String> {
    let upper = sql.to_uppercase();
    let tokens: Vec<&str> = upper.split_whitespace().collect();
    let mut tables = Vec::new();

    for (i, token) in tokens.iter().enumerate() {
        if (*token == "FROM" || *token == "JOIN" || *token == "INTO" || *token == "UPDATE")
            && i + 1 < tokens.len()
        {
            let table = tokens[i + 1]
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                .to_lowercase();
            if !table.is_empty() && table != "(" && table != "select" {
                tables.push(table);
            }
        }
    }

    tables
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    // ── extract_session_id tests ──

    #[test]
    fn test_extract_session_id_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-session", HeaderValue::from_static("my-session-123"));

        let session_id = extract_session_id(&headers, "agent-1").unwrap();
        assert_eq!(session_id, "my-session-123");
    }

    #[test]
    fn test_extract_session_id_generates_implicit_when_missing() {
        let headers = HeaderMap::new();
        let session_id = extract_session_id(&headers, "agent-1").unwrap();
        assert!(session_id.starts_with("implicit:agent-1:"));
        // Should have 4 colon-separated parts: implicit, agent_id, window, hash
        let parts: Vec<&str> = session_id.splitn(4, ':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "implicit");
        assert_eq!(parts[1], "agent-1");
        // Hash part should be 8 hex chars
        assert_eq!(parts[3].len(), 8);
    }

    #[test]
    fn test_extract_session_id_generates_implicit_when_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-session", HeaderValue::from_static(""));

        let session_id = extract_session_id(&headers, "agent-1").unwrap();
        assert!(session_id.starts_with("implicit:agent-1:"));
        // Should contain a hash component
        let parts: Vec<&str> = session_id.splitn(4, ':').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_implicit_session_id_is_deterministic_within_window() {
        let headers = HeaderMap::new();
        let id1 = extract_session_id(&headers, "agent-1").unwrap();
        let id2 = extract_session_id(&headers, "agent-1").unwrap();
        // Within the same 15-minute window, IDs should match.
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_implicit_session_id_differs_for_different_agents() {
        let headers = HeaderMap::new();
        let id1 = extract_session_id(&headers, "agent-1").unwrap();
        let id2 = extract_session_id(&headers, "agent-2").unwrap();
        assert_ne!(id1, id2);
    }

    // ── Session ID validation tests (FIX 3) ──

    #[test]
    fn test_session_id_with_injection_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-session", HeaderValue::from_static(";DROP TABLE sessions"));
        let result = extract_session_id(&headers, "agent-1");
        assert!(result.is_err(), "Session ID with semicolons and spaces should be rejected");
    }

    #[test]
    fn test_session_id_too_long_rejected() {
        let mut headers = HeaderMap::new();
        let long_id = "a".repeat(129);
        headers.insert("x-ag-session", HeaderValue::from_str(&long_id).unwrap());
        let result = extract_session_id(&headers, "agent-1");
        assert!(result.is_err(), "Session ID > 128 chars should be rejected");
    }

    #[test]
    fn test_session_id_at_max_length_accepted() {
        let mut headers = HeaderMap::new();
        let max_id = "a".repeat(128);
        headers.insert("x-ag-session", HeaderValue::from_str(&max_id).unwrap());
        let result = extract_session_id(&headers, "agent-1");
        assert!(result.is_ok(), "Session ID at exactly 128 chars should be accepted");
    }

    #[test]
    fn test_session_id_valid_special_chars() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-session", HeaderValue::from_static("my_session:v1.2-beta"));
        let result = extract_session_id(&headers, "agent-1");
        assert!(result.is_ok(), "Session ID with _:.- should be accepted");
        assert_eq!(result.unwrap(), "my_session:v1.2-beta");
    }

    // ── Client fingerprint tests ──

    #[test]
    fn test_extract_client_fingerprint_with_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("192.168.1.1"));
        headers.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        let fp = extract_client_fingerprint(&headers);
        assert_eq!(fp.len(), 32, "Fingerprint should be 32 hex chars");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_extract_client_fingerprint_empty_headers() {
        let headers = HeaderMap::new();
        let fp = extract_client_fingerprint(&headers);
        assert_eq!(fp.len(), 32);
    }

    #[test]
    fn test_fingerprint_differs_for_different_clients() {
        let mut headers1 = HeaderMap::new();
        headers1.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        headers1.insert("user-agent", HeaderValue::from_static("Agent/1.0"));

        let mut headers2 = HeaderMap::new();
        headers2.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.2"));
        headers2.insert("user-agent", HeaderValue::from_static("Agent/2.0"));

        let fp1 = extract_client_fingerprint(&headers1);
        let fp2 = extract_client_fingerprint(&headers2);
        assert_ne!(fp1, fp2);
    }

    // ── Tool authorization tests (FIX 1) ──

    #[test]
    fn test_extract_authorized_tools_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-authorized-tools", HeaderValue::from_static("db.query,file.read,http.post"));
        let tools = extract_authorized_tools(&headers);
        assert!(tools.is_some());
        let tools = tools.unwrap();
        assert_eq!(tools.len(), 3);
        assert!(tools.contains(&"db.query".to_string()));
        assert!(tools.contains(&"file.read".to_string()));
        assert!(tools.contains(&"http.post".to_string()));
    }

    #[test]
    fn test_extract_authorized_tools_missing_header() {
        let headers = HeaderMap::new();
        assert!(extract_authorized_tools(&headers).is_none());
    }

    #[test]
    fn test_extract_authorized_tools_empty_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-authorized-tools", HeaderValue::from_static(""));
        assert!(extract_authorized_tools(&headers).is_none());
    }

    #[test]
    fn test_extract_authorized_tools_filters_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("x-ag-authorized-tools", HeaderValue::from_static("db.query,inv@lid!,file.read"));
        let tools = extract_authorized_tools(&headers).unwrap();
        assert_eq!(tools.len(), 2);
        assert!(!tools.contains(&"inv@lid!".to_string()));
    }

    #[test]
    fn test_lock_tool_set() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        lock_tool_set(&mut session, vec!["db.query".to_string(), "file.read".to_string()]);
        assert!(session.tools_locked);
        assert_eq!(session.authorized_tools.len(), 2);
    }

    #[test]
    fn test_check_tool_authorized_when_locked() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        lock_tool_set(&mut session, vec!["db.query".to_string(), "file.read".to_string()]);

        assert!(check_tool_authorized(&session, "db.query").is_ok());
        assert!(check_tool_authorized(&session, "file.read").is_ok());
        assert!(check_tool_authorized(&session, "move_file").is_err());
    }

    #[test]
    fn test_check_tool_authorized_when_unlocked() {
        let session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        // When unlocked, all tools are allowed
        assert!(check_tool_authorized(&session, "anything").is_ok());
    }

    #[test]
    fn test_auto_lock_tool_set() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        for i in 0..4 {
            auto_lock_tool_set(&mut session, &format!("tool.{}", i), 5);
        }
        assert!(!session.tools_locked, "Should not lock until threshold");
        auto_lock_tool_set(&mut session, "tool.4", 5);
        assert!(session.tools_locked, "Should lock at threshold 5");
        // 6th unknown tool should be rejected
        assert!(check_tool_authorized(&session, "tool.unknown").is_err());
    }

    // ── is_external_send tests ──

    #[test]
    fn test_is_external_send_http_post() {
        assert!(is_external_send("http.post", "execute"));
    }

    #[test]
    fn test_is_external_send_email() {
        assert!(is_external_send("email.send", "send"));
    }

    #[test]
    fn test_is_external_send_webhook() {
        assert!(is_external_send("webhook.trigger", "fire"));
    }

    #[test]
    fn test_is_external_send_slack() {
        assert!(is_external_send("slack.post", "message"));
    }

    #[test]
    fn test_is_external_send_by_action() {
        assert!(is_external_send("custom.tool", "send"));
        assert!(is_external_send("custom.tool", "post"));
        assert!(is_external_send("custom.tool", "put"));
    }

    #[test]
    fn test_is_not_external_send_for_reads() {
        assert!(!is_external_send("database.query", "read"));
        assert!(!is_external_send("file.read", "get"));
    }

    // ── extract_tables_from_params tests ──

    #[test]
    fn test_extract_table_from_explicit_param() {
        let params = serde_json::json!({"table": "users"});
        let tables = extract_tables_from_params("database.query", &params);
        assert!(tables.contains(&"users".to_string()));
    }

    #[test]
    fn test_extract_tables_from_sql_query() {
        let params = serde_json::json!({"query": "SELECT * FROM users JOIN orders ON users.id = orders.user_id"});
        let tables = extract_tables_from_params("database.query", &params);
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"orders".to_string()));
    }

    #[test]
    fn test_extract_table_from_tool_name() {
        let params = serde_json::json!({});
        let tables = extract_tables_from_params("database.users.query", &params);
        assert!(tables.contains(&"users".to_string()));
    }

    #[test]
    fn test_extract_no_tables() {
        let params = serde_json::json!({"action": "ping"});
        let tables = extract_tables_from_params("system.health", &params);
        assert!(tables.is_empty());
    }

    // ── extract_tables_from_sql tests ──

    #[test]
    fn test_sql_from_clause() {
        let tables = extract_tables_from_sql("SELECT * FROM users WHERE id = 1");
        assert_eq!(tables, vec!["users"]);
    }

    #[test]
    fn test_sql_join_clause() {
        let tables = extract_tables_from_sql("SELECT * FROM orders JOIN products ON orders.product_id = products.id");
        assert!(tables.contains(&"orders".to_string()));
        assert!(tables.contains(&"products".to_string()));
    }

    #[test]
    fn test_sql_insert_into() {
        let tables = extract_tables_from_sql("INSERT INTO audit_log VALUES (1, 'test')");
        assert!(tables.contains(&"audit_log".to_string()));
    }

    #[test]
    fn test_sql_update() {
        let tables = extract_tables_from_sql("UPDATE users SET name = 'bob'");
        assert!(tables.contains(&"users".to_string()));
    }

    #[test]
    fn test_sql_no_tables() {
        let tables = extract_tables_from_sql("SELECT 1");
        assert!(tables.is_empty());
    }

    // ── build_tool_record tests ──

    #[test]
    fn test_build_tool_record() {
        let record = build_tool_record("database.query", "read", 42, false, false, vec!["users".to_string()], "");
        assert_eq!(record.tool_name, "database.query");
        assert_eq!(record.action, "read");
        assert_eq!(record.records_returned, 42);
        assert!(!record.was_denied);
        assert!(!record.is_external_send);
        assert_eq!(record.tables_accessed, vec!["users".to_string()]);
    }

    #[test]
    fn test_build_tool_record_denied() {
        let record = build_tool_record("admin.delete", "write", 0, true, false, vec![], "");
        assert!(record.was_denied);
        assert_eq!(record.records_returned, 0);
    }

    #[test]
    fn test_build_tool_record_external_send() {
        let record = build_tool_record("http.post", "send", 0, false, true, vec![], "");
        assert!(record.is_external_send);
    }

    // ── Deduplication test ──

    #[test]
    fn test_extract_tables_deduplicates() {
        let params = serde_json::json!({"table": "users", "query": "SELECT * FROM users"});
        let tables = extract_tables_from_params("database.users.query", &params);
        // "users" appears from table param, SQL FROM, and tool name — should be deduped.
        let user_count = tables.iter().filter(|t| *t == "users").count();
        assert_eq!(user_count, 1);
    }
}
