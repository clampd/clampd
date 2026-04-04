//! Agent lifecycle state machine enforcement.
//!
//! This module provides local state machine validation for the ag-registry
//! service. It complements the `AgentState::can_transition_to` logic in
//! ag-common but adds registry-specific concerns like reason_code validation
//! and transition metadata.
//!
//! The canonical state machine is:
//!
//! ```text
//!   Active  -> Suspended  (manual_admin | risk_threshold | policy_violation)
//!   Active  -> Killed     (credential_compromised | manual_admin)
//!   Suspended -> Active   (manual_admin — reactivation)
//!   Suspended -> Killed   (credential_compromised | manual_admin)
//!   Killed  -> Active     (manual_admin — revive flow)
//! ```

/// Valid reason codes for state transitions.
///
/// These are persisted in the audit log and displayed in the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReasonCode {
    ManualAdmin,
    RiskThreshold,
    PolicyViolation,
    CredentialCompromised,
    Decommission,
    Unknown(String),
}

impl ReasonCode {
    /// Parse a reason code from a string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "manual_admin" => ReasonCode::ManualAdmin,
            "risk_threshold" => ReasonCode::RiskThreshold,
            "policy_violation" => ReasonCode::PolicyViolation,
            "credential_compromised" => ReasonCode::CredentialCompromised,
            "decommission" => ReasonCode::Decommission,
            other => ReasonCode::Unknown(other.to_string()),
        }
    }

    /// Convert the reason code back to its string representation.
    pub fn as_str(&self) -> &str {
        match self {
            ReasonCode::ManualAdmin => "manual_admin",
            ReasonCode::RiskThreshold => "risk_threshold",
            ReasonCode::PolicyViolation => "policy_violation",
            ReasonCode::CredentialCompromised => "credential_compromised",
            ReasonCode::Decommission => "decommission",
            ReasonCode::Unknown(s) => s.as_str(),
        }
    }
}

/// Describes a state transition with metadata for auditing.
#[derive(Debug, Clone)]
pub struct StateTransition {
    pub from_state: String,
    pub to_state: String,
    pub reason: String,
    pub reason_code: ReasonCode,
}

impl StateTransition {
    pub fn new(from: &str, to: &str, reason: &str, reason_code: &str) -> Self {
        Self {
            from_state: from.to_string(),
            to_state: to.to_string(),
            reason: reason.to_string(),
            reason_code: ReasonCode::from_str(reason_code),
        }
    }

    /// Format this transition as a human-readable audit detail string.
    pub fn audit_detail(&self) -> String {
        format!(
            "{} -> {} (reason_code: {}, reason: {})",
            self.from_state,
            self.to_state,
            self.reason_code.as_str(),
            self.reason
        )
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ReasonCode parsing ──

    #[test]
    fn test_reason_code_from_str_all_known() {
        assert_eq!(ReasonCode::from_str("manual_admin"), ReasonCode::ManualAdmin);
        assert_eq!(
            ReasonCode::from_str("risk_threshold"),
            ReasonCode::RiskThreshold
        );
        assert_eq!(
            ReasonCode::from_str("policy_violation"),
            ReasonCode::PolicyViolation
        );
        assert_eq!(
            ReasonCode::from_str("credential_compromised"),
            ReasonCode::CredentialCompromised
        );
        assert_eq!(
            ReasonCode::from_str("decommission"),
            ReasonCode::Decommission
        );
    }

    #[test]
    fn test_reason_code_from_str_unknown() {
        let rc = ReasonCode::from_str("something_else");
        assert_eq!(rc, ReasonCode::Unknown("something_else".to_string()));
    }

    #[test]
    fn test_reason_code_from_str_empty() {
        let rc = ReasonCode::from_str("");
        assert_eq!(rc, ReasonCode::Unknown("".to_string()));
    }

    // ── ReasonCode as_str roundtrip ──

    #[test]
    fn test_reason_code_as_str_roundtrip() {
        let codes = [
            "manual_admin",
            "risk_threshold",
            "policy_violation",
            "credential_compromised",
            "decommission",
        ];
        for code in codes {
            let rc = ReasonCode::from_str(code);
            assert_eq!(rc.as_str(), code);
        }
    }

    #[test]
    fn test_reason_code_unknown_as_str() {
        let rc = ReasonCode::Unknown("custom_reason".to_string());
        assert_eq!(rc.as_str(), "custom_reason");
    }

    // ── StateTransition ──

    #[test]
    fn test_state_transition_new() {
        let t = StateTransition::new("active", "suspended", "risk too high", "risk_threshold");
        assert_eq!(t.from_state, "active");
        assert_eq!(t.to_state, "suspended");
        assert_eq!(t.reason, "risk too high");
        assert_eq!(t.reason_code, ReasonCode::RiskThreshold);
    }

    #[test]
    fn test_state_transition_audit_detail() {
        let t = StateTransition::new("active", "suspended", "risk too high", "risk_threshold");
        let detail = t.audit_detail();
        assert!(detail.contains("active -> suspended"));
        assert!(detail.contains("risk_threshold"));
        assert!(detail.contains("risk too high"));
    }

    #[test]
    fn test_state_transition_audit_detail_unknown_reason() {
        let t = StateTransition::new("suspended", "active", "admin override", "custom_code");
        let detail = t.audit_detail();
        assert!(detail.contains("suspended -> active"));
        assert!(detail.contains("custom_code"));
        assert!(detail.contains("admin override"));
    }

    #[test]
    fn test_state_transition_killed_to_active() {
        let t = StateTransition::new("killed", "active", "revive agent", "manual_admin");
        assert_eq!(t.from_state, "killed");
        assert_eq!(t.to_state, "active");
        assert_eq!(t.reason_code, ReasonCode::ManualAdmin);
    }
}
