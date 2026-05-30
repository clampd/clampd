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
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use dashmap::DashMap;
use tracing::{debug, warn};

/// L1 cache TTL for delegation approval and agent-existence Redis lookups.
///
/// Why 5 seconds: dashboard approval revocations propagate through ag-control's
/// Redis-sync loop in O(seconds) anyway, so a 5s L1 cache adds negligible
/// staleness. The win is cutting Redis round-trips on hot delegation paths
/// (the same parent→child pair calls hundreds of times/sec). At 50k QPS with
/// p99 Redis latency 1ms, this saves ~50 CPU-seconds/sec across the fleet.
///
/// Big-co reference: AWS IAM evaluates ~500M policies/sec by hitting an
/// in-process LRU first; SPIFFE Workload API uses a similar 5–30s TTL.
const L1_CACHE_TTL: Duration = Duration::from_secs(5);

/// In-process L1 cache for delegation approval and agent-existence lookups.
///
/// Held in `AppState` (alongside `baseline_cache::BaselineCache`) so the
/// caching layer's lifetime is tied to the gateway process, instrumentation
/// can read it, and tests can drop it between cases. Mirrors the
/// `BaselineCache` design — same Redis-pool dependency, same DashMap +
/// `Instant` deadline fields, same `pub fn new(redis)` constructor — so
/// future readers see one consistent gateway-side cache pattern instead
/// of two.
pub struct DelegationCache {
    redis: Pool<RedisConnectionManager>,
    /// (parent_id, child_id) → (approved, allowed_tools, deadline).
    approval: DashMap<(String, String), (bool, Vec<String>, Instant)>,
    /// agent_id → (exists, deadline).
    exists: DashMap<String, (bool, Instant)>,
}

impl DelegationCache {
    pub fn new(redis: Pool<RedisConnectionManager>) -> Self {
        Self {
            redis,
            approval: DashMap::new(),
            exists: DashMap::new(),
        }
    }
}

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
    #[error("Non-ASCII character in agent ID '{agent}' (codepoint U+{codepoint:04X}) — agent IDs must be UUIDs")]
    NonAsciiAgentId { agent: String, codepoint: u32 },
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
    /// A2: Signed delegation proof (JWT-SVID-style token chain). Set when
    /// the SDK supplied `X-Clampd-Delegation-Signature` AND the feature
    /// flag is on AND verification succeeded. When present, the gateway
    /// upgrades `confidence` to `"verified"` (real cryptographic meaning,
    /// not just SDK-asserted). None on the legacy path.
    pub signed_proof: Option<String>,
}

/// Delegation context parsed from HTTP headers only.
struct HeaderDelegation {
    trace_id: Option<String>,
    chain: Vec<String>,
    confidence: String,
    caller_agent_id: Option<String>,
    signed_proof: Option<String>,
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

    // A2: signed proof — JWT-shaped token chain (RFC 8693).
    let signed_proof = headers
        .get("x-clampd-delegation-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Only return Some if there is meaningful delegation data.
    if chain.is_empty() && trace_id.is_none() {
        return None;
    }

    Some(HeaderDelegation {
        trace_id,
        chain,
        confidence,
        caller_agent_id,
        signed_proof,
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
    body_signed_proof: &Option<String>,
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
        signed_proof: None,
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

    // Confidence: body fields are SDK-provided but not cryptographically signed.
    // "declared" (not "verified") because we cannot prove the body wasn't forged.
    // Only cryptographic proof (e.g., signed delegation token) should upgrade to "verified".
    let confidence = if has_body {
        "declared".to_string()
    } else {
        header.confidence
    };

    // Body takes priority over headers for the proof, matching the
    // body-first rule applied to other delegation fields.
    let signed_proof = body_signed_proof.clone().or(header.signed_proof);

    Some(DelegationContext {
        caller_agent_id,
        chain,
        trace_id,
        confidence,
        purpose: body_delegation_purpose.clone(),
        signed_proof,
    })
}

/// Canonicalize an agent ID for cycle detection.
///
/// Lowercases an already-validated ASCII agent ID. This is only safe to call
/// AFTER [`reject_non_ascii_agent_id`] has approved the input — otherwise
/// homograph attacks (Cyrillic 'а' vs Latin 'a') and zero-width-space
/// insertions can defeat cycle detection.
///
/// Production agent IDs are UUIDs (ag-gateway enforces `uuid::Uuid::parse_str`
/// on the caller), which are pure ASCII alphanumeric + hyphen.
fn canonicalize_agent_id(agent: &str) -> String {
    agent.to_ascii_lowercase()
}

/// Reject any agent ID that contains characters outside `[A-Za-z0-9-]`.
///
/// This is more aggressive than canonicalization: instead of silently
/// stripping homoglyphs / zero-width chars, we surface a typed error so
/// the request is rejected with a clear forensic trail. Big-co identity
/// systems (SPIFFE, Cognito, Auth0) all enforce strict charset on
/// identifier inputs for the same reason.
///
/// Returns the offending codepoint on failure for telemetry / debugging.
fn reject_non_ascii_agent_id(agent: &str) -> Result<(), DelegationError> {
    if agent.is_empty() {
        return Err(DelegationError::NonAsciiAgentId {
            agent: agent.to_string(),
            codepoint: 0,
        });
    }
    for c in agent.chars() {
        if !(c.is_ascii_alphanumeric() || c == '-') {
            return Err(DelegationError::NonAsciiAgentId {
                agent: agent.to_string(),
                codepoint: c as u32,
            });
        }
    }
    Ok(())
}

/// Validate a delegation chain for depth, cycles, and homograph attacks.
///
/// Returns `Ok(())` if the chain is valid, or a `DelegationError` if the
/// chain exceeds the maximum depth, contains a cycle (case-insensitive,
/// after charset validation), or contains an agent ID with non-ASCII
/// characters.
///
/// Order of checks (cheapest first, most-discriminating first):
///   1. Depth — O(1).
///   2. Charset — O(total chars). Catches homograph / zero-width attacks
///      before they could defeat cycle detection.
///   3. Cycle — O(n) with HashSet on lowercased ASCII.
pub fn validate_chain(chain: &[String]) -> Result<(), DelegationError> {
    if chain.len() > *MAX_DELEGATION_DEPTH {
        return Err(DelegationError::DepthExceeded {
            depth: chain.len(),
            max: *MAX_DELEGATION_DEPTH,
        });
    }

    let mut seen = HashSet::with_capacity(chain.len());
    for agent in chain {
        reject_non_ascii_agent_id(agent)?;
        let canon = canonicalize_agent_id(agent);
        if !seen.insert(canon) {
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
            warn!("Redis unavailable for enforcement check: {e} - defaulting to learning mode");
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
impl DelegationCache {
    /// Check if a delegation relationship is approved in Redis (L1-cached).
    /// Returns (approved, allowed_tools).
    /// Key format: `ag:delegation:approved:{parent_id}:{child_id}`
    /// Written by ag-control's delegation Redis sync loop.
    pub async fn check_delegation_approved(
        &self,
        parent_id: &str,
        child_id: &str,
    ) -> (bool, Vec<String>) {
        // L1 cache: skip Redis on hot duplicate calls.
        let cache_key = (parent_id.to_string(), child_id.to_string());
        if let Some(entry) = self.approval.get(&cache_key) {
            let (approved, ref tools, deadline) = *entry;
            if deadline > Instant::now() {
                return (approved, tools.clone());
            }
        }

        let key = format!("ag:delegation:approved:{parent_id}:{child_id}");
        let mut conn = match self.redis.get().await {
            Ok(c) => c,
            Err(_) => return (false, vec![]), // fail-closed: deny delegation if Redis unavailable
        };
        let result: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);

        let (approved, tools): (bool, Vec<String>) = match result {
            Some(json_str) => {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    let status = val.get("status").and_then(|s| s.as_str()).unwrap_or("observed");
                    if status == "blocked" {
                        (false, vec![])
                    } else {
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
                    }
                } else {
                    (true, vec![]) // can't parse = permissive
                }
            }
            // No cached entry - in enforcement mode, unknown relationships are blocked
            None => (false, vec![]),
        };
        // L1 write-through.
        self.approval.insert(cache_key, (approved, tools.clone(), Instant::now() + L1_CACHE_TTL));
        (approved, tools)
    }

    /// Verify that an agent exists by checking its credential cache in Redis (L1-cached).
    /// Returns false if the agent has no credential key (likely fabricated UUID).
    /// Uses `ag:agent:cred:{id}` which is populated by ag-control for all registered agents.
    ///
    /// Fail-CLOSED on every error (pool acquisition AND command execution).
    /// Callers depend on `false ⇒ probably forged` — a transient Redis blip
    /// must not silently re-enable spoofed agent IDs in delegation chains.
    /// The 5-second L1 TTL means legitimate agents resolve on the next call,
    /// so a brief Redis hiccup costs at most 5s of false rejection per
    /// (agent_id) — acceptable when the alternative is letting a fabricated
    /// UUID through during a Redis hiccup.
    pub async fn verify_agent_exists(&self, agent_id: &str) -> bool {
        if let Some(entry) = self.exists.get(agent_id) {
            let (exists, deadline) = *entry;
            if deadline > Instant::now() {
                return exists;
            }
        }
        let key = format!("ag:agent:cred:{}", agent_id);
        let mut conn = match self.redis.get().await {
            Ok(c) => c,
            Err(_) => return false, // fail-closed: pool unavailable
        };
        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(false); // fail-closed: command error
        self.exists.insert(agent_id.to_string(), (exists, Instant::now() + L1_CACHE_TTL));
        exists
    }
}

/// A2: Feature flag — when "on", the gateway expects an
/// `X-Clampd-Delegation-Signature` JWT for any non-root delegation hop and
/// rejects unsigned ones with `delegation_signature_required`. When "off"
/// (the default during the SDK migration window), unsigned delegations
/// are accepted as `confidence = "declared"` (current behavior).
///
/// Set `CLAMPD_DELEGATION_SIGNATURES=on` to enforce.
pub fn signatures_enforced() -> bool {
    std::env::var("CLAMPD_DELEGATION_SIGNATURES")
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "on" | "true" | "1" | "enforce"))
        .unwrap_or(false)
}

/// SHA-256 of the lower-cased chain joined by ','. Binds a delegation
/// proof to a specific chain so the same token can't be replayed under
/// a different ancestry. Mirrored bit-for-bit in the SDK
/// (`sdk/python/clampd/delegation.py::_chain_hash`); changes here MUST
/// be made there too or the gateway rejects every signed call.
pub fn chain_hash(chain: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let joined = chain
        .iter()
        .map(|s| s.to_lowercase())
        .collect::<Vec<_>>()
        .join(",");
    let mut h = Sha256::new();
    h.update(joined.as_bytes());
    format!("{:x}", h.finalize())
}

/// A2: Verify a signed delegation proof.
///
/// Trust model (HS256 with per-agent secret, matches the existing JWT
/// validation flow at `proxy.rs::validate_jwt_with_agent_credential`):
///
/// 1. Fetch the leaf (executor) agent's credential hash from
///    `ag:agent:cred:{agent_id}` in Redis. The SDK signed the proof
///    with this same hash, so a mismatch = rejection.
/// 2. Decode the JWT with HS256 against that secret.
/// 3. Assert `sub == expected_subject` (the leaf agent in the chain).
/// 4. Assert `chain_hash == sha256(expected_chain joined by ',')`.
///    This is what makes the proof non-replayable across chains: a
///    token minted for [orch, research, writer] won't validate for
///    [orch, research, attacker] even with a valid signature.
/// 5. Assert `exp` is in the future. The SDK mints with a 30s TTL,
///    so a captured proof is useless after at most 30s.
/// 6. Assert `aud == "ag-gateway"` and `iss == "clampd-sdk"`.
///
/// Returns `Ok(())` on valid + fresh; a typed `Err` string otherwise.
/// Fail-closed on Redis errors (no fallback to global secret) so a
/// transient Redis blip can't silently downgrade enforcement.
pub async fn verify_signed_delegation(
    proof: &str,
    expected_chain: &[String],
    expected_subject: &str,
    redis_pool: &Pool<RedisConnectionManager>,
) -> Result<(), String> {
    use base64::Engine as _;

    // Step 1: fetch the leaf agent's Ed25519 PUBLIC key. The proof MUST be
    // signed by the executor (the agent making the call) with its private key,
    // not by any ancestor — otherwise a compromised root could mint proofs for
    // any descendant. The gateway only ever holds the public key.
    let cred_key = format!("ag:agent:cred:{}", expected_subject);
    let mut conn = redis_pool
        .get()
        .await
        .map_err(|e| format!("redis_unavailable: {}", e))?;
    let pubkey_b64: Option<String> = redis::cmd("GET")
        .arg(&cred_key)
        .query_async(&mut *conn)
        .await
        .map_err(|e| format!("redis_error: {}", e))?;
    let pubkey_b64 = pubkey_b64.ok_or_else(|| {
        format!("agent_credential_missing: no ag:agent:cred:{}", expected_subject)
    })?;

    // Step 2: verify the EdDSA signature against the agent's public key.
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pubkey_b64.trim_end_matches('='))
        .map_err(|e| format!("invalid_agent_pubkey: {e}"))?;
    let key_arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "invalid_agent_pubkey: expected 32 bytes".to_string())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| format!("invalid_agent_pubkey: {e}"))?;

    let parts: Vec<&str> = proof.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("jwt_invalid: malformed".to_string());
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| format!("jwt_invalid: signature encoding {e}"))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("jwt_invalid: signature {e}"))?;
    {
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| "jwt_invalid: signature verification failed".to_string())?;
    }

    // Decode claims and enforce exp / aud / iss.
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("jwt_invalid: payload {e}"))?;
    let claims: DelegationProofClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("jwt_invalid: {e}"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if claims.exp != 0 && claims.exp < now - 5 {
        return Err("jwt_invalid: expired".to_string());
    }
    if claims.aud != "ag-gateway" {
        return Err("jwt_invalid: bad audience".to_string());
    }
    if claims.iss != "clampd-sdk" {
        return Err("jwt_invalid: bad issuer".to_string());
    }

    // Step 3: leaf must match.
    if claims.sub != expected_subject {
        return Err(format!(
            "subject_mismatch: proof sub='{}' but request leaf='{}'",
            claims.sub, expected_subject
        ));
    }

    // Step 4: chain binding — the same key signs many proofs, but each proof
    // carries the chain it was minted for.
    let expected_hash = chain_hash(expected_chain);
    if claims.chain_hash != expected_hash {
        return Err(format!(
            "chain_hash_mismatch: proof claims chain_hash for a different ancestry"
        ));
    }

    Ok(())
}

/// JWT claims for a signed delegation proof. The SDK mints a token with
/// these claims and signs it with the leaf agent's credential hash.
#[derive(Debug, serde::Deserialize)]
struct DelegationProofClaims {
    sub: String,
    #[allow(dead_code)] // validated by jsonwebtoken via Validation::set_audience
    aud: String,
    #[allow(dead_code)] // validated by jsonwebtoken via Validation::set_issuer
    iss: String,
    #[allow(dead_code)] // validated by jsonwebtoken via Validation::validate_exp (default)
    exp: i64,
    chain_hash: String,
}

// (Tool-caveat enforcement is performed by ag-policy via
// `delegation_workflow::check_tool_restriction`, the single source of truth
// for the (parent, child, tool) authorization decision. A duplicate
// `is_tool_allowed` previously lived here as a gateway-side helper but
// had no production callers after the gateway delegated this check to
// ag-policy, so it was deleted to prevent future drift between two
// implementations of the same logic.)

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
            extract_delegation(&headers, &body_caller, &body_chain, &body_trace, &body_purpose, &None)
                .unwrap();

        assert_eq!(ctx.caller_agent_id, Some("body-caller".into()));
        assert_eq!(ctx.chain, vec!["body-agent-1", "body-agent-2"]);
        assert_eq!(ctx.trace_id, Some("trace-123".into()));
        assert_eq!(ctx.purpose, Some("data lookup".into()));
        // Body present → declared (not verified - no crypto proof)
        assert_eq!(ctx.confidence, "declared");
    }

    #[test]
    fn test_extract_delegation_none_when_nothing() {
        let headers = HeaderMap::new();
        let ctx = extract_delegation(&headers, &None, &None, &None, &None, &None);
        assert!(ctx.is_none());
    }

    // (Tests for `is_tool_allowed` were removed alongside the function —
    // the canonical tool-caveat tests live in
    // ag-policy/src/delegation_workflow.rs.)

    // ══════════════════════════════════════════════════════════════════
    // ADVERSARIAL TESTS - Red team against delegation enforcement
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_cycle_detection_case_bypass() {
        // Same agent with different casing - should detect cycle
        let chain = vec!["Agent-A".to_string(), "agent-a".to_string()];
        let result = validate_chain(&chain);
        assert!(result.is_err(),
            "VULNERABILITY: Case variation bypasses cycle detection - 'Agent-A' and 'agent-a' are the same agent");
    }

    #[test]
    fn adversarial_cycle_detection_exact_duplicate() {
        let chain = vec!["agent-a".to_string(), "agent-b".to_string(), "agent-a".to_string()];
        let result = validate_chain(&chain);
        assert!(result.is_err(), "Exact duplicate should be detected as cycle");
    }

    #[test]
    fn adversarial_max_depth_boundary() {
        // Chain at exactly MAX_DELEGATION_DEPTH - should be allowed
        let chain: Vec<String> = (0..*MAX_DELEGATION_DEPTH).map(|i| format!("agent-{}", i)).collect();
        let result = validate_chain(&chain);
        assert!(result.is_ok(), "Chain at exactly max depth should be allowed");
    }

    #[test]
    fn adversarial_max_depth_exceeded() {
        let chain: Vec<String> = (0..=*MAX_DELEGATION_DEPTH).map(|i| format!("agent-{}", i)).collect();
        let result = validate_chain(&chain);
        assert!(result.is_err(), "Chain exceeding max depth should be rejected");
    }

    #[test]
    fn adversarial_empty_chain() {
        let result = validate_chain(&[]);
        assert!(result.is_ok(), "Empty chain should be valid");
    }

    #[test]
    fn adversarial_unicode_in_chain() {
        // Zero-width-space (U+200B): rejected as non-ASCII before cycle check.
        let chain = vec!["agent-\u{200B}a".to_string(), "agent-a".to_string()];
        let err = validate_chain(&chain).unwrap_err();
        assert!(matches!(err, DelegationError::NonAsciiAgentId { .. }),
            "Zero-width-space must produce typed NonAsciiAgentId error, got: {err:?}");
    }

    #[test]
    fn adversarial_bom_in_chain() {
        let chain = vec!["\u{FEFF}agent-a".to_string(), "agent-a".to_string()];
        let err = validate_chain(&chain).unwrap_err();
        assert!(matches!(err, DelegationError::NonAsciiAgentId { codepoint: 0xFEFF, .. }));
    }

    #[test]
    fn adversarial_rtl_override_in_chain() {
        let chain = vec!["agent\u{202E}-a".to_string(), "agent-a".to_string()];
        let err = validate_chain(&chain).unwrap_err();
        assert!(matches!(err, DelegationError::NonAsciiAgentId { codepoint: 0x202E, .. }));
    }

    #[test]
    fn adversarial_empty_entry() {
        let chain = vec!["".to_string()];
        let err = validate_chain(&chain).unwrap_err();
        assert!(matches!(err, DelegationError::NonAsciiAgentId { codepoint: 0, .. }));
    }

    #[test]
    fn adversarial_homograph_cyrillic() {
        // Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061) — a classic
        // homograph attack. SPIFFE / Auth0 / AWS IAM all reject these on identifier
        // input. Without this check, an attacker could register an agent named
        // "agent-а" (Cyrillic) that visually equals an existing "agent-a" (Latin),
        // defeating both cycle detection and registry lookups.
        let chain = vec!["agent-\u{0430}".to_string(), "agent-a".to_string()];
        let err = validate_chain(&chain).unwrap_err();
        assert!(matches!(err, DelegationError::NonAsciiAgentId { codepoint: 0x0430, .. }));
    }

    #[test]
    fn adversarial_emoji_in_chain() {
        let chain = vec!["agent-a-\u{1F4A9}".to_string()];
        assert!(matches!(validate_chain(&chain).unwrap_err(),
            DelegationError::NonAsciiAgentId { .. }));
    }

    #[test]
    fn adversarial_underscore_rejected() {
        // Strict charset: only [A-Za-z0-9-]. Underscore is rejected even though
        // it's ASCII — UUIDs don't contain underscores. Tighter charset =
        // smaller surface for parser-confusion attacks downstream.
        let chain = vec!["agent_a".to_string()];
        assert!(matches!(validate_chain(&chain).unwrap_err(),
            DelegationError::NonAsciiAgentId { codepoint: 0x5F, .. }));
    }

    // ── #11: Delegation confidence auto-upgrade ────────────────────

    #[test]
    fn adversarial_body_auto_escalates_to_verified() {
        // Any body field presence → confidence becomes "verified" without crypto proof
        let headers = hyper::header::HeaderMap::new();
        let ctx = extract_delegation(
            &headers,
            &Some("attacker-agent".to_string()), // body caller_agent_id
            &None,
            &None,
            &None,
            &None,
        );
        let ctx = ctx.expect("Should extract delegation from body");
        assert_eq!(ctx.confidence, "declared",
            "Body-provided delegation should be 'declared', not 'verified' - no crypto proof");
    }

    // ── #12: Signed delegation proof — parity + verify ────────────

    #[test]
    fn chain_hash_is_lowercased_comma_joined_sha256() {
        // SDK and gateway MUST agree on this hash byte-for-byte.
        // The literal below was verified against the Python SDK
        // (sdk/python/clampd/auth.py::_delegation_chain_hash) and the
        // TypeScript SDK (sdk/typescript/src/auth.ts::delegationChainHash)
        // by 3-way parity test. If this assertion ever changes, both
        // SDKs MUST be updated in the same commit or every signed call
        // will fail.
        let chain: Vec<String> = vec!["Alice".into(), "BOB".into(), "carol".into()];
        assert_eq!(
            chain_hash(&chain),
            "838b5dca3cc384bddd68b832fddd52e5243860b759bd8370dcc187061af26abb",
        );
    }

    #[test]
    fn signed_proof_minted_with_correct_key_passes_validation() {
        // We can't exercise the Redis lookup in a unit test, but we CAN
        // verify the JWT-decode path with the exact same Validation
        // settings the live function uses. This catches mismatches in
        // aud/iss/alg between SDK and gateway.
        use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

        #[derive(serde::Serialize, serde::Deserialize)]
        struct C {
            sub: String, aud: String, iss: String,
            iat: i64, exp: i64, chain_hash: String,
        }

        let chain = vec!["agent-a".to_string(), "agent-b".to_string()];
        let secret_hash = "deadbeef".repeat(8); // simulate sha256 hex of ags_ secret
        let now = chrono::Utc::now().timestamp();
        let claims = C {
            sub: "agent-b".into(),
            aud: "ag-gateway".into(),
            iss: "clampd-sdk".into(),
            iat: now, exp: now + 30,
            chain_hash: chain_hash(&chain),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret_hash.as_bytes()),
        )
        .unwrap();

        let mut v = Validation::new(Algorithm::HS256);
        v.set_audience(&["ag-gateway"]);
        v.set_issuer(&["clampd-sdk"]);
        let decoded: jsonwebtoken::TokenData<C> = decode(
            &token,
            &DecodingKey::from_secret(secret_hash.as_bytes()),
            &v,
        )
        .unwrap();
        assert_eq!(decoded.claims.sub, "agent-b");
        assert_eq!(decoded.claims.chain_hash, chain_hash(&chain));
    }

    #[test]
    fn signed_proof_with_wrong_chain_hash_fails() {
        // A proof minted for chain [A, B] must not validate for [A, X].
        // We verify by computing two distinct chain_hashes.
        let h1 = chain_hash(&vec!["a".into(), "b".into()]);
        let h2 = chain_hash(&vec!["a".into(), "x".into()]);
        assert_ne!(h1, h2, "chain_hash must be unique per ancestry");
    }

    #[test]
    fn adversarial_header_only_stays_declared() {
        // Header-only delegation should stay as "declared" confidence
        let mut headers = hyper::header::HeaderMap::new();
        headers.insert("x-clampd-delegation-caller", "header-agent".parse().unwrap());
        let ctx = extract_delegation(
            &headers,
            &None,
            &None,
            &None,
            &None,
            &None,
        );
        if let Some(ctx) = ctx {
            assert_ne!(ctx.confidence, "verified",
                "Header-only delegation should NOT be 'verified'");
        }
    }
}
