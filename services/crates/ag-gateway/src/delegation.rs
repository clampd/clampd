//! Cross-service delegation correlation.
//!
//! When an SDK sends a proxy request with delegation context (headers or body
//! fields), this module extracts, merges, and validates the delegation chain
//! before passing it downstream to ag-intent and ag-policy via proto fields.
//!
//! Validation enforces:
//! - Maximum delegation depth of 5 to prevent unbounded chains.
//! - Cycle detection to prevent circular delegation loops.

use std::collections::HashSet;

use axum::http::HeaderMap;
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use tracing::{debug, warn};

/// Maximum number of agents in a delegation chain.
/// Configurable via CLAMPD_MAX_DELEGATION_DEPTH (default: 5).
static MAX_DELEGATION_DEPTH: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
    std::env::var("CLAMPD_MAX_DELEGATION_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
});

/// Errors that can occur during delegation chain validation.
#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("Delegation depth {depth} exceeds maximum {max}")]
    DepthExceeded { depth: usize, max: usize },
    #[error("Circular delegation: agent {agent} appears twice in chain {chain:?}")]
    CycleDetected { agent: String, chain: Vec<String> },
}

/// Delegation context extracted from headers and/or request body.
#[derive(Debug, Clone, Default)]
pub struct DelegationContext {
    /// Agent ID of the immediate caller that delegated this request.
    pub caller_agent_id: Option<String>,
    /// Ordered chain of agent IDs from root caller to current agent.
    pub chain: Vec<String>,
    /// Trace ID linking all requests in a single delegation tree.
    pub trace_id: Option<String>,
    /// Confidence level: "verified", "inferred", or "declared".
    pub confidence: String,
    /// Human-readable purpose for the delegation.
    pub purpose: Option<String>,
}

/// Delegation context parsed from HTTP headers only.
struct HeaderDelegation {
    trace_id: Option<String>,
    chain: Vec<String>,
    confidence: String,
    caller_agent_id: Option<String>,
}

/// Extract delegation context from HTTP headers.
///
/// Headers recognized:
/// - `X-Clampd-Delegation-Trace`: trace ID string
/// - `X-Clampd-Delegation-Chain`: comma-separated agent IDs
/// - `X-Clampd-Delegation-Confidence`: "verified" | "inferred" | "declared"
fn extract_from_headers(headers: &HeaderMap) -> Option<HeaderDelegation> {
    let trace_id = headers
        .get("x-clampd-delegation-trace")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let chain: Vec<String> = headers
        .get("x-clampd-delegation-chain")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let caller_agent_id = chain.last().cloned();

    let confidence = headers
        .get("x-clampd-delegation-confidence")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("declared")
        .to_string();

    // Only return Some if there is meaningful delegation data.
    if chain.is_empty() && trace_id.is_none() {
        return None;
    }

    Some(HeaderDelegation {
        trace_id,
        chain,
        confidence,
        caller_agent_id,
    })
}

/// Merge delegation context from request body fields and HTTP headers.
///
/// Body fields take priority over headers. If neither source provides
/// delegation data, returns `None`.
pub fn extract_delegation(
    headers: &HeaderMap,
    body_caller_agent_id: &Option<String>,
    body_delegation_chain: &Option<Vec<String>>,
    body_delegation_trace_id: &Option<String>,
    body_delegation_purpose: &Option<String>,
) -> Option<DelegationContext> {
    let header_ctx = extract_from_headers(headers);

    // Determine if we have any delegation data at all.
    let has_body = body_caller_agent_id.is_some()
        || body_delegation_chain.as_ref().is_some_and(|c| !c.is_empty())
        || body_delegation_trace_id.is_some();
    let has_header = header_ctx.is_some();

    if !has_body && !has_header {
        return None;
    }

    let header = header_ctx.unwrap_or(HeaderDelegation {
        trace_id: None,
        chain: Vec::new(),
        confidence: "declared".to_string(),
        caller_agent_id: None,
    });

    // Body takes priority over headers for each field.
    let chain = if body_delegation_chain
        .as_ref()
        .is_some_and(|c| !c.is_empty())
    {
        body_delegation_chain.clone().unwrap_or_default()
    } else {
        header.chain
    };

    let caller_agent_id = body_caller_agent_id
        .clone()
        .or(header.caller_agent_id)
        .or_else(|| chain.last().cloned());

    let trace_id = body_delegation_trace_id.clone().or(header.trace_id);

    // Confidence: body takes priority over headers.
    let confidence = if has_body {
        "verified".to_string()
    } else {
        header.confidence
    };

    Some(DelegationContext {
        caller_agent_id,
        chain,
        trace_id,
        confidence,
        purpose: body_delegation_purpose.clone(),
    })
}

/// Validate a delegation chain for depth and cycles.
///
/// Returns `Ok(())` if the chain is valid, or a `DelegationError` if
/// the chain exceeds the maximum depth or contains a cycle.
pub fn validate_chain(chain: &[String]) -> Result<(), DelegationError> {
    if chain.len() > *MAX_DELEGATION_DEPTH {
        return Err(DelegationError::DepthExceeded {
            depth: chain.len(),
            max: *MAX_DELEGATION_DEPTH,
        });
    }

    let mut seen = HashSet::new();
    for agent in chain {
        if !seen.insert(agent.as_str()) {
            return Err(DelegationError::CycleDetected {
                agent: agent.clone(),
                chain: chain.to_vec(),
            });
        }
    }

    Ok(())
}

// ── Enforcement mode ────────────────────────────────────

/// Check if enforcement mode is active (fail-open: if Redis unavailable, allow).
/// Key format: ag:delegation:enforcement:{org_id}
/// Written by ag-control's delegation Redis sync loop.
pub async fn is_enforcement_enabled(redis_pool: &Pool<RedisConnectionManager>, org_id: &str) -> bool {
    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Redis unavailable for enforcement check: {e} — defaulting to learning mode");
            return false;
        }
    };
    let key = format!("ag:delegation:enforcement:{org_id}");
    let result: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut *conn)
        .await
        .unwrap_or(None);
    matches!(result.as_deref(), Some("true") | Some("on") | Some("1"))
}

/// Check if a delegation relationship is approved in Redis.
/// Returns (approved, allowed_tools).
/// Key format: ag:delegation:approved:{parent_id}:{child_id}
/// Written by ag-control's delegation Redis sync loop.
pub async fn check_delegation_approved(
    redis_pool: &Pool<RedisConnectionManager>,
    parent_id: &str,
    child_id: &str,
) -> (bool, Vec<String>) {
    let key = format!("ag:delegation:approved:{parent_id}:{child_id}");
    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(_) => return (true, vec![]), // fail-open
    };
    let result: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut *conn)
        .await
        .unwrap_or(None);

    match result {
        Some(json_str) => {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                let status = val.get("status").and_then(|s| s.as_str()).unwrap_or("observed");
                if status == "blocked" {
                    return (false, vec![]);
                }
                let tools: Vec<String> = val
                    .get("allowed_tools")
                    .and_then(|t| t.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let approved = status == "approved" || status == "declared";
                (approved, tools)
            } else {
                (true, vec![]) // can't parse = permissive
            }
        }
        // No cached entry — in enforcement mode, unknown relationships are blocked
        None => (false, vec![]),
    }
}

/// Check if a specific tool is allowed for a delegation.
/// Empty allowed_tools list means all tools are allowed.
pub fn is_tool_allowed(allowed_tools: &[String], tool: &str) -> bool {
    if allowed_tools.is_empty() {
        return true;
    }
    allowed_tools
        .iter()
        .any(|t| t == tool || tool.starts_with(&format!("{t}.")))
}

/// Record an observed delegation in Redis (fire-and-forget, best-effort).
/// Key format: ag:delegation:observed:{org_id}:{parent_id}:{child_id}
/// This must match the SCAN pattern used by ag-control's delegation_sync.
pub async fn record_observed_delegation(
    redis_pool: &Pool<RedisConnectionManager>,
    org_id: &str,
    parent_id: &str,
    child_id: &str,
    confidence: &str,
    tool: &str,
    trace_id: &str,
) {
    let key = format!("ag:delegation:observed:{org_id}:{parent_id}:{child_id}");
    let mut value = serde_json::json!({
        "parent_agent_id": parent_id,
        "child_agent_id": child_id,
        "confidence": confidence,
        "last_tool": tool,
    });
    if !trace_id.is_empty() {
        value["trace_id"] = serde_json::Value::String(trace_id.to_string());
    }
    if let Ok(mut conn) = redis_pool.get().await {
        let _: Result<(), _> = redis::cmd("SET")
            .arg(&key)
            .arg(value.to_string())
            .arg("EX")
            .arg(86400u64) // 24h TTL
            .query_async(&mut *conn)
            .await;
        debug!(parent = parent_id, child = child_id, "Recorded observed delegation");
    }
}

/// Check org-level rate limit for delegated calls.
/// Only root requests (depth <= 1) are counted. Delegated hops are free.
/// Returns (current_count, limit_exceeded).
pub async fn check_delegation_rate_limit(
    redis_pool: &Pool<RedisConnectionManager>,
    org_id: &str,
    delegation_depth: usize,
    rate_limit: u32,
) -> (u64, bool) {
    let month_key = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Approximate month key: year*12 + month
        let days = now / 86400;
        let months = days / 30;
        format!("{months}")
    };
    let key = format!("ag:ratelimit:org:{org_id}:{month_key}");

    let mut conn = match redis_pool.get().await {
        Ok(c) => c,
        Err(_) => return (0, false), // fail-open
    };

    if delegation_depth <= 1 {
        let count: u64 = redis::cmd("INCR")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(0);
        if count == 1 {
            let _: Result<(), _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(2678400u64) // 31 days
                .query_async(&mut *conn)
                .await;
        }
        (count, rate_limit > 0 && count > rate_limit as u64)
    } else {
        let count: u64 = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(0);
        (count, false) // never block delegated hops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_chain_ok() {
        let chain = vec!["a".into(), "b".into(), "c".into()];
        assert!(validate_chain(&chain).is_ok());
    }

    #[test]
    fn test_validate_chain_empty() {
        assert!(validate_chain(&[]).is_ok());
    }

    #[test]
    fn test_validate_chain_depth_exceeded() {
        let chain: Vec<String> = (0..6).map(|i| format!("agent-{i}")).collect();
        let err = validate_chain(&chain).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_validate_chain_cycle_detected() {
        let chain = vec!["a".into(), "b".into(), "a".into()];
        let err = validate_chain(&chain).unwrap_err();
        assert!(err.to_string().contains("Circular delegation"));
    }

    #[test]
    fn test_extract_from_headers_none_when_empty() {
        let headers = HeaderMap::new();
        assert!(extract_from_headers(&headers).is_none());
    }

    #[test]
    fn test_extract_from_headers_chain_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-clampd-delegation-chain",
            "agent-1, agent-2".parse().unwrap(),
        );
        let ctx = extract_from_headers(&headers).unwrap();
        assert_eq!(ctx.chain, vec!["agent-1", "agent-2"]);
        assert_eq!(ctx.caller_agent_id, Some("agent-2".into()));
        assert_eq!(ctx.confidence, "declared");
    }

    #[test]
    fn test_extract_delegation_body_priority() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-clampd-delegation-chain",
            "header-agent".parse().unwrap(),
        );
        headers.insert(
            "x-clampd-delegation-confidence",
            "inferred".parse().unwrap(),
        );

        let body_chain = Some(vec!["body-agent-1".into(), "body-agent-2".into()]);
        let body_caller = Some("body-caller".into());
        let body_trace = Some("trace-123".into());
        let body_purpose = Some("data lookup".into());

        let ctx =
            extract_delegation(&headers, &body_caller, &body_chain, &body_trace, &body_purpose)
                .unwrap();

        assert_eq!(ctx.caller_agent_id, Some("body-caller".into()));
        assert_eq!(ctx.chain, vec!["body-agent-1", "body-agent-2"]);
        assert_eq!(ctx.trace_id, Some("trace-123".into()));
        assert_eq!(ctx.purpose, Some("data lookup".into()));
        // Body present → SDK-verified delegation
        assert_eq!(ctx.confidence, "verified");
    }

    #[test]
    fn test_extract_delegation_none_when_nothing() {
        let headers = HeaderMap::new();
        let ctx = extract_delegation(&headers, &None, &None, &None, &None);
        assert!(ctx.is_none());
    }

    #[test]
    fn test_is_tool_allowed_empty_means_all() {
        assert!(is_tool_allowed(&[], "anything"));
    }

    #[test]
    fn test_is_tool_allowed_exact_match() {
        let tools = vec!["db.query".into(), "file.read".into()];
        assert!(is_tool_allowed(&tools, "db.query"));
        assert!(is_tool_allowed(&tools, "file.read"));
        assert!(!is_tool_allowed(&tools, "shell.exec"));
    }

    #[test]
    fn test_is_tool_allowed_prefix_match() {
        let tools = vec!["db".into()];
        assert!(is_tool_allowed(&tools, "db.query"));
        assert!(is_tool_allowed(&tools, "db.write"));
        assert!(!is_tool_allowed(&tools, "file.read"));
    }
}
