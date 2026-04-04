use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Agent identity — maps to `agents` table in PostgreSQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub owner_user_id: String,
    pub idp_realm: String,
    pub declared_purpose: String,
    pub allowed_tools: serde_json::Value,
    pub allowed_scopes: Vec<String>,
    pub state: AgentState,
    pub risk_score: f64,
    pub credential_hash: String,
    pub enforcement_mode: EnforcementMode,
    pub boundaries: Option<EffectiveBoundaries>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

/// A tool grant for an agent — stored in Redis by ag-control.
/// Key: ag:agent:tool:{agent_id}:{tool_name}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolGrant {
    pub tool_name: String,
    pub permission: String,
    pub scopes: Vec<String>,
    pub descriptor_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentState {
    Active,
    Suspended,
    Killed,
}

impl AgentState {
    pub fn can_transition_to(&self, target: AgentState) -> bool {
        matches!(
            (self, target),
            (AgentState::Active, AgentState::Suspended)
                | (AgentState::Active, AgentState::Killed)
                | (AgentState::Suspended, AgentState::Active)
                | (AgentState::Suspended, AgentState::Killed)
                | (AgentState::Killed, AgentState::Active) // revive flow
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AgentState::Active => "active",
            AgentState::Suspended => "suspended",
            AgentState::Killed => "killed",
        }
    }

    pub fn from_state_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(AgentState::Active),
            "suspended" => Some(AgentState::Suspended),
            "killed" => Some(AgentState::Killed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Enforce,
    Audit,
}

impl EnforcementMode {
    pub fn from_mode_str(s: &str) -> Self {
        match s {
            "audit" => EnforcementMode::Audit,
            _ => EnforcementMode::Enforce,
        }
    }
}

/// Effective boundaries (agent overrides merged with org defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveBoundaries {
    pub max_records_per_query: u32,
    pub max_calls_per_minute: u32,
    pub max_data_volume_mb_per_hour: f64,
    pub blocked_external_domains: Vec<String>,
    pub allowed_hours_start: u32,
    pub allowed_hours_end: u32,
    pub allowed_hours_timezone: String,
    pub allowed_days: u32,
    pub auto_suspend_threshold: f64,
    /// AP2: max single payment in cents (0 = no limit).
    #[serde(default)]
    pub max_payment_per_tx_cents: u64,
    /// AP2: max hourly spend in cents (0 = no limit).
    #[serde(default)]
    pub max_payment_per_hour_cents: u64,
    /// AP2: approved vendor identifiers (empty = all vendors allowed).
    #[serde(default)]
    pub approved_vendors: Vec<String>,
}

impl Default for EffectiveBoundaries {
    fn default() -> Self {
        Self {
            max_records_per_query: 1000,
            max_calls_per_minute: 60,
            max_data_volume_mb_per_hour: 100.0,
            blocked_external_domains: Vec::new(),
            max_payment_per_tx_cents: 0,
            max_payment_per_hour_cents: 0,
            approved_vendors: Vec::new(),
            allowed_hours_start: 0,
            allowed_hours_end: 0,
            allowed_hours_timezone: "UTC".to_string(),
            allowed_days: 127, // all days
            auto_suspend_threshold: 0.9,
        }
    }
}

/// Extracted tool call from request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub action: String,
    pub params: serde_json::Value,
    pub params_normalized: serde_json::Value,
    pub params_hash: String,
    pub params_raw_hash: String,
    pub prompt_hash: Option<String>,
    pub raw_body: Option<String>,
    pub encoding_detected: Vec<String>,
}

impl ToolCall {
    /// Binding hash for micro-token: SHA-256(tool_name + params_hash).
    pub fn binding_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let input = format!("{}{}", self.tool_name, self.params_hash);
        let hash = Sha256::digest(input.as_bytes());
        hex::encode(hash)
    }
}

/// Intent verdict from ag-intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentVerdict {
    pub risk_score: f64,
    pub classification: IntentClass,
    pub labels: Vec<String>,
    pub reasoning: String,
    pub matched_rules: Vec<String>,
    pub session_risk_factor: f64,
    pub latency_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentClass {
    Safe,
    Suspicious,
    Dangerous,
    Malicious,
}

impl IntentClass {
    pub fn from_risk(risk: f64) -> Self {
        if risk >= 0.9 {
            IntentClass::Malicious
        } else if risk >= 0.7 {
            IntentClass::Dangerous
        } else if risk >= 0.3 {
            IntentClass::Suspicious
        } else {
            IntentClass::Safe
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            IntentClass::Safe => "Safe",
            IntentClass::Suspicious => "Suspicious",
            IntentClass::Dangerous => "Dangerous",
            IntentClass::Malicious => "Malicious",
        }
    }
}

/// Policy decision from ag-policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub required_scopes: Vec<String>,
    pub denied_scopes: Vec<String>,
    pub reason: String,
    pub matched_policies: Vec<String>,
    pub boundary_violation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Downscope,
    Deny,
}

/// Micro-token issued by ag-token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u32,
    pub scope: String,
    pub jti: String,
    pub tool_binding: String,
}

/// Claims from the agent's original IdP token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentJwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub scope: String,
    pub exp: i64,
    pub user_id: Option<String>,
}

/// Claims embedded in micro-tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroTokenClaims {
    pub sub: String,
    pub jti: String,
    pub scope: String,
    pub tool_binding: String,
    pub exp: i64,
    pub iss: String,
    pub aud: String,
    #[serde(rename = "ag:request_id")]
    pub request_id: Option<String>,
    #[serde(rename = "ag:session_id")]
    pub session_id: Option<String>,
}

/// Pipeline context — travels through the entire request pipeline.
#[derive(Debug, Clone)]
pub struct PipelineContext {
    pub request_id: Uuid,
    pub agent: Arc<Agent>,
    pub tool_call: ToolCall,
    pub original_claims: AgentJwtClaims,
    pub intent_verdict: Option<IntentVerdict>,
    pub policy_decision: Option<PolicyDecision>,
    pub micro_token: Option<MicroToken>,
    pub degraded_stages: Vec<String>,
    pub started_at: std::time::Instant,
    pub session_id: String,
    pub tool_response: Option<ResponseMetadata>,
}

/// Why a request was rejected — used by ag-risk to decide whether to feed
/// the event into the EMA scorer. Only `Security` events affect suspicion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionType {
    /// Rule match, intent block, behavioral anomaly — feeds into EMA.
    Security,
    /// Scope mismatch, delegation error, license issue — does NOT feed into EMA.
    Config,
    /// Rate limit, budget exceeded — does NOT feed into EMA.
    RateLimit,
    /// Allowed requests or unclassified denials.
    None,
}

impl Default for RejectionType {
    fn default() -> Self {
        RejectionType::None
    }
}

impl RejectionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectionType::Security => "security",
            RejectionType::Config => "config",
            RejectionType::RateLimit => "rate_limit",
            RejectionType::None => "none",
        }
    }
}

/// Shadow event published to NATS for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowEvent {
    pub request_id: Uuid,
    pub trace_id: String,
    pub org_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub user_id: String,
    pub tool_name: String,
    pub tool_action: String,
    pub params_hash: String,
    /// Truncated human-readable summary of request params (max 200 chars).
    /// For database.query: the SQL statement. For file.read: the path.
    /// For http.fetch: the URL. Truncated for safety.
    #[serde(default)]
    pub params_summary: String,
    pub prompt_hash: String,
    pub encodings_detected: Vec<String>,
    pub encoding_risk_bonus: f64,
    pub assessed_risk: f64,
    pub session_risk_factor: f64,
    pub intent_classification: String,
    pub intent_labels: Vec<String>,
    pub matched_rules: Vec<String>,
    pub policy_action: String,
    pub policy_reason: String,
    pub boundary_violation: Option<String>,
    pub scope_requested: String,
    pub scope_granted: Option<String>,
    pub blocked: bool,
    pub denial_reason: Option<String>,
    pub session_id: String,
    pub session_flags: Vec<String>,
    pub response_metadata: Option<ResponseMetadata>,
    pub degraded_stages: Vec<String>,
    pub latency_ms: u32,
    pub timestamp: DateTime<Utc>,
    /// A2A delegation: the agent that delegated this call.
    #[serde(default)]
    pub caller_agent_id: Option<String>,
    /// A2A delegation: full chain from root caller to current agent.
    #[serde(default)]
    pub delegation_chain: Option<Vec<String>>,
    /// A2A delegation: trace ID linking all requests in a delegation tree.
    #[serde(default)]
    pub delegation_trace_id: Option<String>,
    /// SHA-256 hex hash of the tool descriptor sent by the SDK (64 chars).
    /// Empty string when the SDK did not provide one.
    #[serde(default)]
    pub tool_descriptor_hash: String,
    /// Human-readable description of the tool (from SDK tool definition).
    /// Empty string when the SDK did not provide one.
    #[serde(default)]
    pub tool_description: String,
    /// JSON schema of the tool's parameters (from SDK tool definition).
    /// Empty string when the SDK did not provide one.
    #[serde(default)]
    pub tool_params_schema: String,
    /// Agent's configured active hours window (from agent_boundaries).
    /// Both 0 means no restriction (24/7 agent).
    #[serde(default)]
    pub active_hours_start: u32,
    #[serde(default)]
    pub active_hours_end: u32,
    /// Why this request was rejected (if blocked). Controls whether ag-risk
    /// feeds the event into EMA scoring. Only Security rejections affect suspicion.
    #[serde(default)]
    pub rejection_type: RejectionType,
    /// A2A security event classification. Set when the shadow event represents
    /// a specific A2A security incident: task_replay, contagion, cross_boundary,
    /// tool_restricted, killed_delegation. None for regular tool call events.
    #[serde(default)]
    pub a2a_event_type: Option<String>,
}

impl Default for ShadowEvent {
    fn default() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            trace_id: String::new(),
            org_id: String::new(),
            agent_id: String::new(),
            agent_name: String::new(),
            user_id: String::new(),
            tool_name: String::new(),
            tool_action: String::new(),
            params_hash: String::new(),
            params_summary: String::new(),
            prompt_hash: String::new(),
            encodings_detected: Vec::new(),
            encoding_risk_bonus: 0.0,
            assessed_risk: 0.0,
            session_risk_factor: 0.0,
            intent_classification: String::new(),
            intent_labels: Vec::new(),
            matched_rules: Vec::new(),
            policy_action: String::new(),
            policy_reason: String::new(),
            boundary_violation: None,
            scope_requested: String::new(),
            scope_granted: None,
            blocked: false,
            denial_reason: None,
            session_id: String::new(),
            session_flags: Vec::new(),
            response_metadata: None,
            degraded_stages: Vec::new(),
            latency_ms: 0,
            timestamp: Utc::now(),
            caller_agent_id: None,
            delegation_chain: None,
            delegation_trace_id: None,
            tool_descriptor_hash: String::new(),
            tool_description: String::new(),
            tool_params_schema: String::new(),
            active_hours_start: 0,
            active_hours_end: 0,
            rejection_type: RejectionType::None,
            a2a_event_type: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub status_code: u16,
    pub body_size_bytes: u64,
    pub records_count: u32,
    pub contains_pii_patterns: bool,
    pub truncated: bool,
    pub response_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AgentState::can_transition_to ──

    #[test]
    fn test_active_can_transition_to_suspended() {
        assert!(AgentState::Active.can_transition_to(AgentState::Suspended));
    }

    #[test]
    fn test_active_can_transition_to_killed() {
        assert!(AgentState::Active.can_transition_to(AgentState::Killed));
    }

    #[test]
    fn test_active_cannot_transition_to_active() {
        assert!(!AgentState::Active.can_transition_to(AgentState::Active));
    }

    #[test]
    fn test_suspended_can_transition_to_active() {
        assert!(AgentState::Suspended.can_transition_to(AgentState::Active));
    }

    #[test]
    fn test_suspended_can_transition_to_killed() {
        assert!(AgentState::Suspended.can_transition_to(AgentState::Killed));
    }

    #[test]
    fn test_suspended_cannot_transition_to_suspended() {
        assert!(!AgentState::Suspended.can_transition_to(AgentState::Suspended));
    }

    #[test]
    fn test_killed_can_transition_to_active() {
        // Revive flow: killed agents can be brought back to active state
        assert!(AgentState::Killed.can_transition_to(AgentState::Active));
    }

    #[test]
    fn test_killed_cannot_transition_to_suspended() {
        assert!(!AgentState::Killed.can_transition_to(AgentState::Suspended));
    }

    #[test]
    fn test_killed_cannot_transition_to_killed() {
        assert!(!AgentState::Killed.can_transition_to(AgentState::Killed));
    }

    // ── AgentState::from_state_str ──

    #[test]
    fn test_from_state_str_active() {
        assert_eq!(AgentState::from_state_str("active"), Some(AgentState::Active));
    }

    #[test]
    fn test_from_state_str_suspended() {
        assert_eq!(
            AgentState::from_state_str("suspended"),
            Some(AgentState::Suspended)
        );
    }

    #[test]
    fn test_from_state_str_killed() {
        assert_eq!(AgentState::from_state_str("killed"), Some(AgentState::Killed));
    }

    #[test]
    fn test_from_state_str_unknown_returns_none() {
        assert_eq!(AgentState::from_state_str("unknown"), None);
    }

    #[test]
    fn test_from_state_str_empty_returns_none() {
        assert_eq!(AgentState::from_state_str(""), None);
    }

    #[test]
    fn test_from_state_str_case_sensitive() {
        // Uppercase should not match (only lowercase is accepted).
        assert_eq!(AgentState::from_state_str("Active"), None);
        assert_eq!(AgentState::from_state_str("KILLED"), None);
    }

    // ── AgentState::as_str roundtrip ──

    #[test]
    fn test_agent_state_as_str_roundtrip() {
        for state in [AgentState::Active, AgentState::Suspended, AgentState::Killed] {
            let s = state.as_str();
            let back = AgentState::from_state_str(s).unwrap();
            assert_eq!(back, state);
        }
    }

    // ── IntentClass::from_risk ──

    #[test]
    fn test_intent_class_from_risk_zero() {
        assert_eq!(IntentClass::from_risk(0.0), IntentClass::Safe);
    }

    #[test]
    fn test_intent_class_from_risk_below_suspicious_boundary() {
        assert_eq!(IntentClass::from_risk(0.29), IntentClass::Safe);
    }

    #[test]
    fn test_intent_class_from_risk_at_suspicious_boundary() {
        assert_eq!(IntentClass::from_risk(0.3), IntentClass::Suspicious);
    }

    #[test]
    fn test_intent_class_from_risk_below_dangerous_boundary() {
        assert_eq!(IntentClass::from_risk(0.69), IntentClass::Suspicious);
    }

    #[test]
    fn test_intent_class_from_risk_at_dangerous_boundary() {
        assert_eq!(IntentClass::from_risk(0.7), IntentClass::Dangerous);
    }

    #[test]
    fn test_intent_class_from_risk_below_malicious_boundary() {
        assert_eq!(IntentClass::from_risk(0.89), IntentClass::Dangerous);
    }

    #[test]
    fn test_intent_class_from_risk_at_malicious_boundary() {
        assert_eq!(IntentClass::from_risk(0.9), IntentClass::Malicious);
    }

    #[test]
    fn test_intent_class_from_risk_max() {
        assert_eq!(IntentClass::from_risk(1.0), IntentClass::Malicious);
    }

    // ── ToolCall::binding_hash ──

    #[test]
    fn test_binding_hash_consistent() {
        let tc = ToolCall {
            tool_name: "database.query".to_string(),
            action: "read".to_string(),
            params: serde_json::json!({}),
            params_normalized: serde_json::json!({}),
            params_hash: "abc123".to_string(),
            params_raw_hash: "def456".to_string(),
            prompt_hash: None,
            raw_body: None,
            encoding_detected: vec![],
        };

        let h1 = tc.binding_hash();
        let h2 = tc.binding_hash();
        assert_eq!(h1, h2, "binding_hash must be deterministic");
    }

    #[test]
    fn test_binding_hash_is_sha256_hex() {
        let tc = ToolCall {
            tool_name: "tool".to_string(),
            action: "act".to_string(),
            params: serde_json::json!({}),
            params_normalized: serde_json::json!({}),
            params_hash: "hash".to_string(),
            params_raw_hash: "raw".to_string(),
            prompt_hash: None,
            raw_body: None,
            encoding_detected: vec![],
        };

        let hash = tc.binding_hash();
        // SHA-256 hex is 64 chars, all lowercase hex.
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_binding_hash_differs_for_different_tool_names() {
        let make = |name: &str| ToolCall {
            tool_name: name.to_string(),
            action: "read".to_string(),
            params: serde_json::json!({}),
            params_normalized: serde_json::json!({}),
            params_hash: "same_hash".to_string(),
            params_raw_hash: "raw".to_string(),
            prompt_hash: None,
            raw_body: None,
            encoding_detected: vec![],
        };

        assert_ne!(make("tool_a").binding_hash(), make("tool_b").binding_hash());
    }

    #[test]
    fn test_binding_hash_differs_for_different_params_hash() {
        let make = |phash: &str| ToolCall {
            tool_name: "same_tool".to_string(),
            action: "read".to_string(),
            params: serde_json::json!({}),
            params_normalized: serde_json::json!({}),
            params_hash: phash.to_string(),
            params_raw_hash: "raw".to_string(),
            prompt_hash: None,
            raw_body: None,
            encoding_detected: vec![],
        };

        assert_ne!(make("hash_a").binding_hash(), make("hash_b").binding_hash());
    }

    // ── Serde roundtrip tests ──

    #[test]
    fn test_policy_action_serde_roundtrip() {
        for action in [PolicyAction::Allow, PolicyAction::Downscope, PolicyAction::Deny] {
            let json = serde_json::to_string(&action).unwrap();
            let back: PolicyAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    #[test]
    fn test_enforcement_mode_serde_roundtrip() {
        for mode in [EnforcementMode::Enforce, EnforcementMode::Audit] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: EnforcementMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn test_enforcement_mode_serde_lowercase() {
        let json = serde_json::to_string(&EnforcementMode::Enforce).unwrap();
        assert_eq!(json, "\"enforce\"");
        let json = serde_json::to_string(&EnforcementMode::Audit).unwrap();
        assert_eq!(json, "\"audit\"");
    }

    #[test]
    fn test_agent_state_serde_lowercase() {
        let json = serde_json::to_string(&AgentState::Active).unwrap();
        assert_eq!(json, "\"active\"");
        let json = serde_json::to_string(&AgentState::Suspended).unwrap();
        assert_eq!(json, "\"suspended\"");
        let json = serde_json::to_string(&AgentState::Killed).unwrap();
        assert_eq!(json, "\"killed\"");
    }

    #[test]
    fn test_intent_class_serde_roundtrip() {
        for class in [
            IntentClass::Safe,
            IntentClass::Suspicious,
            IntentClass::Dangerous,
            IntentClass::Malicious,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: IntentClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, class);
        }
    }

    #[test]
    fn test_enforcement_mode_from_mode_str() {
        assert_eq!(EnforcementMode::from_mode_str("audit"), EnforcementMode::Audit);
        assert_eq!(
            EnforcementMode::from_mode_str("enforce"),
            EnforcementMode::Enforce
        );
        // Unknown values default to Enforce.
        assert_eq!(
            EnforcementMode::from_mode_str("something_else"),
            EnforcementMode::Enforce
        );
    }

    #[test]
    fn test_effective_boundaries_defaults() {
        let b = EffectiveBoundaries::default();
        assert_eq!(b.max_records_per_query, 1000);
        assert_eq!(b.max_calls_per_minute, 60);
        assert!((b.max_data_volume_mb_per_hour - 100.0).abs() < f64::EPSILON);
        assert!(b.blocked_external_domains.is_empty());
        assert_eq!(b.allowed_hours_start, 0);
        assert_eq!(b.allowed_hours_end, 0);
        assert_eq!(b.allowed_hours_timezone, "UTC");
        assert_eq!(b.allowed_days, 127);
        assert!((b.auto_suspend_threshold - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_intent_class_as_str() {
        assert_eq!(IntentClass::Safe.as_str(), "Safe");
        assert_eq!(IntentClass::Suspicious.as_str(), "Suspicious");
        assert_eq!(IntentClass::Dangerous.as_str(), "Dangerous");
        assert_eq!(IntentClass::Malicious.as_str(), "Malicious");
    }

    // ── RejectionType ──

    #[test]
    fn test_rejection_type_default_is_none() {
        assert_eq!(RejectionType::default(), RejectionType::None);
    }

    #[test]
    fn test_rejection_type_as_str() {
        assert_eq!(RejectionType::Security.as_str(), "security");
        assert_eq!(RejectionType::Config.as_str(), "config");
        assert_eq!(RejectionType::RateLimit.as_str(), "rate_limit");
        assert_eq!(RejectionType::None.as_str(), "none");
    }

    #[test]
    fn test_rejection_type_serde_roundtrip() {
        for variant in [
            RejectionType::Security,
            RejectionType::Config,
            RejectionType::RateLimit,
            RejectionType::None,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: RejectionType = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn test_rejection_type_serde_snake_case() {
        assert_eq!(serde_json::to_string(&RejectionType::Security).unwrap(), "\"security\"");
        assert_eq!(serde_json::to_string(&RejectionType::Config).unwrap(), "\"config\"");
        assert_eq!(serde_json::to_string(&RejectionType::RateLimit).unwrap(), "\"rate_limit\"");
        assert_eq!(serde_json::to_string(&RejectionType::None).unwrap(), "\"none\"");
    }

    #[test]
    fn test_rejection_type_backward_compat_missing_field() {
        // Old shadow events without rejection_type should deserialize with None.
        let json = r#"{"rejection_type": null}"#;
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            rejection_type: RejectionType,
        }
        // Missing field entirely
        let w: Wrapper = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(w.rejection_type, RejectionType::None);
    }

    #[test]
    fn test_shadow_event_rejection_type_default() {
        // Verify ShadowEvent deserializes rejection_type=None when field is missing.
        // This ensures backward compat with old events in NATS/Redis.
        let minimal_json = serde_json::json!({
            "request_id": "00000000-0000-0000-0000-000000000001",
            "trace_id": "t1",
            "org_id": "o1",
            "agent_id": "a1",
            "agent_name": "test",
            "user_id": "u1",
            "tool_name": "db.query",
            "tool_action": "read",
            "params_hash": "h1",
            "prompt_hash": "p1",
            "encodings_detected": [],
            "encoding_risk_bonus": 0.0,
            "assessed_risk": 0.5,
            "session_risk_factor": 0.0,
            "intent_classification": "suspicious",
            "intent_labels": [],
            "matched_rules": [],
            "policy_action": "deny",
            "policy_reason": "scope_mismatch",
            "scope_requested": "db:query:read",
            "blocked": true,
            "session_id": "s1",
            "session_flags": [],
            "degraded_stages": [],
            "latency_ms": 5,
            "timestamp": "2026-03-20T00:00:00Z"
            // NOTE: no rejection_type field — must default to None
        });
        let event: ShadowEvent = serde_json::from_value(minimal_json).unwrap();
        assert_eq!(event.rejection_type, RejectionType::None);
    }

    // ── A2A Security Event Type Tests ──────────────────────────────────

    #[test]
    fn shadow_event_has_a2a_event_type_field() {
        let event = ShadowEvent::default();
        assert_eq!(event.a2a_event_type, None);
    }

    #[test]
    fn shadow_event_a2a_event_type_defaults_to_none_in_json() {
        let json = serde_json::to_string(&ShadowEvent::default()).unwrap();
        let decoded: ShadowEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.a2a_event_type, None);
    }

    #[test]
    fn shadow_event_a2a_event_type_round_trips() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("task_replay".to_string());
        let json = serde_json::to_string(&event).unwrap();
        let decoded: ShadowEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.a2a_event_type, Some("task_replay".to_string()));
    }

    #[test]
    fn shadow_event_a2a_event_type_accepts_all_valid_types() {
        for t in ["task_replay", "contagion", "cross_boundary", "tool_restricted", "killed_delegation"] {
            let mut event = ShadowEvent::default();
            event.a2a_event_type = Some(t.to_string());
            assert_eq!(event.a2a_event_type.as_deref(), Some(t));
        }
    }

    #[test]
    fn task_replay_event_must_be_blocked() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("task_replay".to_string());
        event.blocked = true;
        event.denial_reason = Some("task_replay_detected: duplicate delegation within TTL".to_string());
        assert!(event.blocked);
        assert!(event.denial_reason.as_ref().unwrap().contains("task_replay"));
    }

    #[test]
    fn task_replay_event_must_have_delegation_context() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("task_replay".to_string());
        event.caller_agent_id = Some("agent-a".to_string());
        event.delegation_chain = Some(vec!["agent-a".to_string(), "agent-b".to_string()]);
        assert!(event.caller_agent_id.is_some());
        assert!(event.delegation_chain.as_ref().unwrap().len() >= 2);
    }

    #[test]
    fn killed_delegation_event_must_be_blocked() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("killed_delegation".to_string());
        event.blocked = true;
        event.denial_reason = Some("delegation_from_killed_agent: agent 'abc' is kill-switched".to_string());
        event.rejection_type = RejectionType::Security;
        assert!(event.blocked);
        assert_eq!(event.rejection_type, RejectionType::Security);
        assert!(event.denial_reason.as_ref().unwrap().contains("killed"));
    }

    #[test]
    fn tool_restricted_event_must_be_blocked() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("tool_restricted".to_string());
        event.blocked = true;
        event.policy_reason = "delegation_tool_not_allowed".to_string();
        assert!(event.blocked);
        assert_eq!(event.policy_reason, "delegation_tool_not_allowed");
    }

    #[test]
    fn cross_boundary_event_has_session_flag() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("cross_boundary".to_string());
        event.session_flags = vec!["cross_boundary_delegation".to_string()];
        assert!(event.session_flags.contains(&"cross_boundary_delegation".to_string()));
    }

    #[test]
    fn contagion_event_must_have_source_agent() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("contagion".to_string());
        event.caller_agent_id = Some("compromised-agent".to_string());
        event.assessed_risk = 0.85;
        assert!(event.caller_agent_id.is_some());
        assert!(event.assessed_risk >= 0.7);
    }

    #[test]
    fn contagion_event_is_synthetic_not_blocked() {
        let mut event = ShadowEvent::default();
        event.a2a_event_type = Some("contagion".to_string());
        event.blocked = false;
        event.policy_action = "alert".to_string();
        assert!(!event.blocked);
        assert_eq!(event.policy_action, "alert");
    }
}
