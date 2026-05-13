use ag_common::descriptor::{Classification, Descriptor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Incoming inspect request from SDK (POST /v1/inspect).
#[derive(Debug, Deserialize)]
pub struct InspectRequest {
    pub tool: String,
    pub response_data: serde_json::Value,
    #[serde(default)]
    pub request_id: Option<String>,
    /// Scope token from proxy() call - used to verify the response
    /// doesn't violate the granted scope (e.g., read-only scope but mutation evidence).
    #[serde(default)]
    pub scope_token: Option<String>,
}

/// Incoming proxy request from SDK.
#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    pub tool: String,
    pub params: serde_json::Value,
    pub target_url: String,
    #[serde(default)]
    pub prompt_context: Option<String>,
    /// Agent ID of the caller that delegated this request.
    #[serde(default)]
    pub caller_agent_id: Option<String>,
    /// Ordered chain of agent IDs from root caller to current agent.
    #[serde(default)]
    pub delegation_chain: Option<Vec<String>>,
    /// Trace ID linking all requests in a delegation tree.
    #[serde(default)]
    pub delegation_trace_id: Option<String>,
    /// Purpose description for why this delegation was made.
    #[serde(default)]
    pub delegation_purpose: Option<String>,
    /// HS256-signed delegation proof minted by the leaf SDK. Verified
    /// when CLAMPD_DELEGATION_SIGNATURES=on. Carries `sub` (leaf agent)
    /// + `chain_hash` (binds to a specific ancestry) so it can't be
    /// replayed under a different chain.
    #[serde(default)]
    pub signed_proof: Option<String>,
    /// SHA-256 hex hash of the tool descriptor (name + description + params schema).
    /// Sent by SDK for rug-pull detection. 64 hex chars when present.
    #[serde(default)]
    pub tool_descriptor_hash: Option<String>,
    /// Human-readable description of the tool (from SDK tool definition).
    #[serde(default)]
    pub tool_description: Option<String>,
    /// JSON schema of the tool's parameters (from SDK tool definition).
    #[serde(default)]
    pub tool_params_schema: Option<String>,
}

/// Structured error response for non-pipeline failures (auth, rate limit, etc.).
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Structured security error response with detailed detection metadata.
/// Used for schema injection, rug-pull detection, and constraint weakening alerts.
#[derive(Debug, Serialize)]
pub struct SecurityErrorResponse {
    pub error: String,
    pub error_code: String,
    pub rule_id: Option<String>,
    pub severity: String,          // "critical", "high", "medium"
    pub matched_pattern: Option<String>,
    pub action: String,            // "blocked", "flagged"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Security-specific error codes for the gateway.
/// These extend the existing error_code field in ErrorResponse.
pub struct SecurityErrorCodes;

impl SecurityErrorCodes {
    pub const SCHEMA_INJECTION: &'static str = "schema_injection";
    pub const SCHEMA_WEAKENING: &'static str = "schema_weakening";
    pub const TOOL_CONFUSION: &'static str = "tool_confusion";
    pub const DESCRIPTOR_MISMATCH: &'static str = "descriptor_mismatch";
    pub const SCHEMA_LOCKED: &'static str = "schema_locked";
}

/// Outgoing proxy response to SDK.
#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub request_id: String,
    pub allowed: bool,
    /// Intent action: "pass", "flag", or "block".
    pub action: String,
    pub risk_score: f64,
    pub scope_granted: Option<String>,
    pub tool_response: Option<serde_json::Value>,
    pub denial_reason: Option<String>,
    /// Human-readable explanation of the risk score (rule breakdown).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    /// Policy/intent rules that matched this request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<String>,
    pub latency_ms: u64,
    /// Per-stage latency breakdown in microseconds.
    /// Keys: auth, identify, normalize, session, classify, policy, risk, token, forward.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stage_latencies_us: Vec<(String, u64)>,
    pub degraded_stages: Vec<String>,
    pub session_flags: Vec<String>,
    /// Compact JWT containing scope grant, tool binding, and expiry.
    /// SDK passes this back with /v1/scan-output to prove the response came from
    /// a Clampd-approved tool call. Empty when denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_trace: Option<ag_common::DecisionTrace>,
}

/// Extract a ToolCall-like structure from the request body.
///
/// `descriptor` is the tool's typed descriptor (from `baseline_cache.resolve_typed_descriptor`),
/// passed through to `infer_action` so a classified operation overrides the
/// substring heuristic. Pass `None` when the descriptor is not available.
pub fn extract_tool_call(
    req: &ProxyRequest,
    descriptor: Option<&Descriptor>,
) -> (String, String, String, String, Option<String>) {
    let tool_name = req.tool.clone();

    let action = infer_action(&tool_name, &req.params, descriptor);

    let params_json = serde_json::to_string(&req.params).unwrap_or_default();
    let params_hash = sha256_hex(&params_json);

    let prompt_hash = req.prompt_context.as_ref().map(|p| sha256_hex(p));

    (tool_name, action, params_json, params_hash, prompt_hash)
}

/// Infer the action verb for a tool call. Resolution order:
///   1. SQL verb in `params.query` (SELECT/INSERT/UPDATE/DELETE/DROP) — preserves
///      the destructive-action signal used by recon-then-attack scoring.
///   2. The descriptor's classified `operation` — authoritative when the tool
///      has been classified by an admin / SDK author. This is what fixes
///      tool-name-blind cases like `send_reply` (which the substring heuristic
///      mis-labels as `"write"` instead of the descriptor's `"send"`).
///   3. Tool-name substring heuristic — last-resort fallback for unclassified
///      tools so existing default behavior is preserved.
fn infer_action(
    tool_name: &str,
    params: &serde_json::Value,
    descriptor: Option<&Descriptor>,
) -> String {
    // 1. SQL verb from params.query
    if let Some(query) = params.get("query").and_then(|v| v.as_str()) {
        let upper = query.trim().to_uppercase();
        if upper.starts_with("SELECT") {
            return "SELECT".to_string();
        } else if upper.starts_with("INSERT") {
            return "INSERT".to_string();
        } else if upper.starts_with("UPDATE") {
            return "UPDATE".to_string();
        } else if upper.starts_with("DELETE") {
            return "DELETE".to_string();
        } else if upper.starts_with("DROP") {
            return "DROP".to_string();
        }
    }

    // 2. Authoritative classification from the descriptor.
    if let Some(d) = descriptor {
        if let Classification::Classified { operation, .. } = &d.classification {
            return operation.clone();
        }
    }

    // 3. Tool-name substring fallback for unclassified tools.
    if tool_name.contains("query") || tool_name.contains("read") {
        "read".to_string()
    } else if tool_name.contains("write") || tool_name.contains("send") {
        "write".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Incoming scan-input request (POST /v1/scan-input).
#[derive(Debug, Deserialize)]
pub struct ScanInputRequest {
    pub text: String,
    #[serde(default)]
    pub message_count: Option<u32>,
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    /// Resolved scope for the input (e.g. "comms:email:send"). Optional.
    /// When set and the input is JSON tool-call params, ag-intent strips
    /// operational fields (to/cc/recipient/etc.) before content rules scan.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Incoming scan-output request (POST /v1/scan-output).
#[derive(Debug, Deserialize)]
pub struct ScanOutputRequest {
    pub text: String,
    #[serde(default)]
    pub request_id: Option<String>,
    /// Resolved scope of the source tool (e.g. "comms:email:send",
    /// "payment:transfer:execute"). Optional but recommended: enables
    /// operational-field stripping in ag-intent so legitimate
    /// `to`/`from`/`recipient` keys do not trigger PII rules.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Response for scan-input endpoint.
#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub allowed: bool,
    pub risk_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    pub matched_rules: Vec<String>,
    pub latency_ms: u64,
}

/// Response for scan-output endpoint.
#[derive(Debug, Serialize)]
pub struct ScanOutputResponse {
    pub allowed: bool,
    pub risk_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    pub matched_rules: Vec<String>,
    pub pii_found: Vec<PiiMatch>,
    pub secrets_found: Vec<SecretMatch>,
    pub latency_ms: u64,
}

/// A PII detection match with type and occurrence count.
#[derive(Debug, Serialize, Clone)]
pub struct PiiMatch {
    pub pii_type: String,
    pub count: usize,
}

/// A secrets detection match with type and occurrence count.
#[derive(Debug, Serialize, Clone)]
pub struct SecretMatch {
    pub secret_type: String,
    pub count: usize,
}

fn sha256_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── infer_action tests ──────────────────────────────────────────────────

    #[test]
    fn infer_action_select_query() {
        let params = serde_json::json!({"query": "SELECT * FROM users"});
        assert_eq!(infer_action("db.query", &params, None), "SELECT");
    }

    #[test]
    fn infer_action_insert_query() {
        let params = serde_json::json!({"query": "INSERT INTO users VALUES (1)"});
        assert_eq!(infer_action("db.query", &params, None), "INSERT");
    }

    #[test]
    fn infer_action_update_query() {
        let params = serde_json::json!({"query": "UPDATE users SET name='x'"});
        assert_eq!(infer_action("db.query", &params, None), "UPDATE");
    }

    #[test]
    fn infer_action_delete_query() {
        let params = serde_json::json!({"query": "DELETE FROM users"});
        assert_eq!(infer_action("db.query", &params, None), "DELETE");
    }

    #[test]
    fn infer_action_drop_query() {
        let params = serde_json::json!({"query": "DROP TABLE users"});
        assert_eq!(infer_action("db.query", &params, None), "DROP");
    }

    #[test]
    fn infer_action_case_insensitive_query() {
        let params = serde_json::json!({"query": "select * from users"});
        assert_eq!(infer_action("db.query", &params, None), "SELECT");
    }

    #[test]
    fn infer_action_from_tool_name_read() {
        let params = serde_json::json!({});
        assert_eq!(infer_action("file.read", &params, None), "read");
    }

    #[test]
    fn infer_action_from_tool_name_write() {
        let params = serde_json::json!({});
        assert_eq!(infer_action("email.send", &params, None), "write");
    }

    #[test]
    fn infer_action_from_tool_name_query() {
        let params = serde_json::json!({});
        assert_eq!(infer_action("db.query", &params, None), "read");
    }

    #[test]
    fn infer_action_unknown() {
        let params = serde_json::json!({});
        assert_eq!(infer_action("custom.tool", &params, None), "unknown");
    }

    // ── descriptor-path tests (T1) ──────────────────────────────────────────

    fn classified_descriptor(name: &str, cat: &str, sub: &str, op: &str) -> Descriptor {
        let mut d = Descriptor::new_unclassified("acme", name, 0);
        d.classify(cat, sub, op, "test", 0, ag_common::descriptor::ClassificationSource::Sdk);
        d
    }

    #[test]
    fn infer_action_descriptor_send_overrides_substring_write() {
        // The substring heuristic mis-labels `send_reply` as "write"
        // (because the name contains "send"). With a classified descriptor
        // declaring operation="send", we get the authoritative answer.
        let params = serde_json::json!({});
        let d = classified_descriptor("send_reply", "comms", "email", "send");
        assert_eq!(infer_action("send_reply", &params, Some(&d)), "send");
    }

    #[test]
    fn infer_action_descriptor_read_classified() {
        let params = serde_json::json!({});
        let d = classified_descriptor("fetch_data", "db", "query", "read");
        assert_eq!(infer_action("fetch_data", &params, Some(&d)), "read");
    }

    #[test]
    fn infer_action_sql_query_beats_descriptor() {
        // SQL verb wins over descriptor — preserves the destructive-action
        // signal (DELETE/DROP) used by the recon-then-attack risk multiplier.
        let params = serde_json::json!({"query": "DELETE FROM users"});
        let d = classified_descriptor("db.query", "db", "query", "read");
        assert_eq!(infer_action("db.query", &params, Some(&d)), "DELETE");
    }

    #[test]
    fn infer_action_unclassified_descriptor_falls_to_substring() {
        // An Unclassified descriptor must NOT short-circuit the heuristic —
        // we fall through to the existing substring fallback.
        let params = serde_json::json!({});
        let d = Descriptor::new_unclassified("acme", "custom.tool", 0);
        assert_eq!(infer_action("custom.tool", &params, Some(&d)), "unknown");
    }

    // ── sha256_hex tests ────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_deterministic() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_hex_length() {
        let hash = sha256_hex("test");
        assert_eq!(hash.len(), 64); // 32 bytes hex-encoded
    }

    #[test]
    fn sha256_hex_different_inputs() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("world");
        assert_ne!(h1, h2);
    }

    // ── extract_tool_call tests ─────────────────────────────────────────────

    #[test]
    fn extract_tool_call_basic() {
        let req = ProxyRequest {
            tool: "db.query".to_string(),
            params: serde_json::json!({"query": "SELECT 1"}),
            target_url: "http://localhost".to_string(),
            prompt_context: None,
            caller_agent_id: None,
            delegation_chain: None,
            delegation_trace_id: None,
            delegation_purpose: None,
            tool_descriptor_hash: None,
            tool_description: None,
            tool_params_schema: None,
            signed_proof: None,
        };
        let (tool, action, params_json, params_hash, prompt_hash) = extract_tool_call(&req, None);
        assert_eq!(tool, "db.query");
        assert_eq!(action, "SELECT");
        assert!(!params_json.is_empty());
        assert_eq!(params_hash.len(), 64);
        assert!(prompt_hash.is_none());
    }

    #[test]
    fn extract_tool_call_with_prompt() {
        let req = ProxyRequest {
            tool: "shell.exec".to_string(),
            params: serde_json::json!({"cmd": "ls"}),
            target_url: "http://localhost".to_string(),
            prompt_context: Some("list directory contents".to_string()),
            caller_agent_id: None,
            delegation_chain: None,
            delegation_trace_id: None,
            delegation_purpose: None,
            tool_descriptor_hash: None,
            tool_description: None,
            tool_params_schema: None,
            signed_proof: None,
        };
        let (_, _, _, _, prompt_hash) = extract_tool_call(&req, None);
        assert!(prompt_hash.is_some());
        assert_eq!(prompt_hash.unwrap().len(), 64);
    }

    // ── Deserialization tests ───────────────────────────────────────────────

    #[test]
    fn proxy_request_minimal_deserialization() {
        let json = r#"{"tool":"db.query","params":{},"target_url":"http://x"}"#;
        let req: ProxyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tool, "db.query");
        assert!(req.caller_agent_id.is_none());
        assert!(req.delegation_chain.is_none());
    }

    #[test]
    fn proxy_request_full_deserialization() {
        let json = r#"{
            "tool": "db.query",
            "params": {"query": "SELECT 1"},
            "target_url": "http://x",
            "caller_agent_id": "agent-a",
            "delegation_chain": ["root", "agent-a"],
            "delegation_trace_id": "trace-123",
            "tool_descriptor_hash": "abc123"
        }"#;
        let req: ProxyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.caller_agent_id.unwrap(), "agent-a");
        assert_eq!(req.delegation_chain.unwrap().len(), 2);
    }

    #[test]
    fn error_response_serialization() {
        let err = ErrorResponse {
            error: "unauthorized".to_string(),
            error_code: "AUTH_FAILED".to_string(),
            request_id: Some("req-1".to_string()),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"], "unauthorized");
        assert_eq!(json["error_code"], "AUTH_FAILED");
    }

    #[test]
    fn error_response_skips_none_request_id() {
        let err = ErrorResponse {
            error: "test".to_string(),
            error_code: "TEST".to_string(),
            request_id: None,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("request_id"));
    }

    #[test]
    fn security_error_codes_constants() {
        assert_eq!(SecurityErrorCodes::SCHEMA_INJECTION, "schema_injection");
        assert_eq!(SecurityErrorCodes::SCHEMA_WEAKENING, "schema_weakening");
        assert_eq!(SecurityErrorCodes::TOOL_CONFUSION, "tool_confusion");
        assert_eq!(SecurityErrorCodes::DESCRIPTOR_MISMATCH, "descriptor_mismatch");
        assert_eq!(SecurityErrorCodes::SCHEMA_LOCKED, "schema_locked");
    }

    #[test]
    fn scan_input_request_deserialization() {
        let json = r#"{"text":"hello world"}"#;
        let req: ScanInputRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.text, "hello world");
        assert!(req.message_count.is_none());
        assert!(req.roles.is_none());
    }

    #[test]
    fn scan_response_serialization() {
        let resp = ScanResponse {
            allowed: true,
            risk_score: 0.1,
            denial_reason: None,
            matched_rules: vec!["R001".to_string()],
            latency_ms: 5,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["allowed"], true);
        assert!(!json.to_string().contains("denial_reason")); // skipped when None
    }
}
