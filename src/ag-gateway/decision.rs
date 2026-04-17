//! Decision gate - the core ALLOW/DENY logic for every proxy request.
//!
//! Extracted from proxy.rs into a pure function for testability.
//! No I/O, no Redis, no gRPC - takes primitive inputs, returns a decision.
//!
//! Priority chain:
//!   (0) suspicion > 0.8 → auto-deny (behavioral anomaly override)
//!   (1) policy DENY → always deny
//!   (2) policy ALLOW with scope_exemption → always allow
//!   (3) intent FLAG → allow (warn only)
//!   (4) intent BLOCK OR risk >= threshold → deny
//!   (5) otherwise → allow

use ag_common::models::RejectionType;

/// Inputs to the decision gate - all the signals from upstream stages.
#[derive(Debug, Clone)]
pub struct DecisionInput {
    /// Suspicion score from ag-risk (Redis hot-path read). Range: 0.0-1.0.
    pub suspicion_score: f64,
    /// Assessed risk from ag-intent (rule engine + session + encoding). Range: 0.0-1.0.
    pub assessed_risk: f64,
    /// AP2 mandate risk modifier (+0.2 for human-not-present, 0.0 otherwise).
    pub ap2_risk_modifier: f64,
    /// Intent action: 0=PASS, 1=FLAG, 2=BLOCK.
    pub intent_action: i32,
    /// Policy action (ag_proto::agentguard::policy::PolicyAction as i32).
    /// 0=Allow, 1=Downscope, 2=Deny.
    pub policy_action: i32,
    /// Policy reason string (e.g., "scope_exemption:R001", "delegation_chain_invalid").
    pub policy_reason: String,
    /// Global risk threshold from gateway config (default 0.70).
    pub risk_threshold: f64,
    /// Matched rule IDs from ag-intent (for denial reason).
    pub matched_rules: Vec<String>,
    /// Active session flags (for denial reason).
    pub session_flags: Vec<String>,
    /// Intent reasoning string (optional).
    pub reasoning: Option<String>,
}

/// Output of the decision gate.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionOutput {
    /// Whether the request is blocked.
    pub blocked: bool,
    /// Final assessed risk after suspicion + AP2 adjustments.
    pub assessed_risk: f64,
    /// Human-readable denial reason (if blocked).
    pub denial_reason: Option<String>,
    /// Rejection type for ag-risk EMA classification.
    pub rejection_type: RejectionType,
}

/// Policy action constants (matching ag_proto::agentguard::policy::PolicyAction).
const POLICY_ALLOW: i32 = 0;
const POLICY_DENY: i32 = 2;

/// Evaluate the decision gate.
///
/// This is the ONLY place that decides ALLOW vs DENY for proxy requests.
/// Pure function - no I/O, fully deterministic, fully testable.
pub fn evaluate(input: &DecisionInput) -> DecisionOutput {
    // Assessed risk = intent classification risk + AP2 modifier only.
    // Suspicion is a separate signal used for the BLOCK decision but must NOT
    // inflate assessed_risk - otherwise it feeds back into the EMA via the
    // shadow event and creates a death spiral (one bad call → high suspicion →
    // assessed_risk inflated → EMA rises → suspicion stays high forever).
    let assessed_risk = (input.assessed_risk + input.ap2_risk_modifier).clamp(0.0, 1.0);

    let intent_says_block = input.intent_action == 2;
    let intent_says_flag = input.intent_action == 1;
    let policy_explicitly_allows = input.policy_action == POLICY_ALLOW
        && input.policy_reason.starts_with("scope_exemption:");
    let policy_denies = input.policy_action == POLICY_DENY;
    let suspicion_auto_deny = input.suspicion_score > 0.8;

    let blocked = if suspicion_auto_deny {
        true
    } else if policy_denies {
        true
    } else if policy_explicitly_allows || intent_says_flag {
        false
    } else {
        intent_says_block || assessed_risk >= input.risk_threshold
    };

    if !blocked {
        return DecisionOutput {
            blocked: false,
            assessed_risk,
            denial_reason: None,
            rejection_type: RejectionType::None,
        };
    }

    // Classify rejection type + build denial reason.
    let (denial_reason, rejection_type) = if suspicion_auto_deny {
        (
            format!(
                "Behavioral anomaly: suspicion score {:.2} exceeds auto-deny threshold 0.80 | risk {:.2}",
                input.suspicion_score, assessed_risk
            ),
            RejectionType::Security,
        )
    } else if policy_denies {
        let is_config_denial = input.policy_reason.starts_with("scope_")
            || input.policy_reason.starts_with("delegation_")
            || input.policy_reason.starts_with("license_")
            || input.policy_reason.starts_with("unapproved_tool")
            || input.policy_reason.starts_with("boundary_");
        let rtype = if is_config_denial {
            RejectionType::Config
        } else {
            RejectionType::Security
        };
        let reason = if input.policy_reason.is_empty() {
            "Policy denied this request".to_string()
        } else {
            format!("Policy denied: {}", input.policy_reason)
        };
        (reason, rtype)
    } else if intent_says_block || assessed_risk >= input.risk_threshold {
        let mut reason = format!(
            "Risk score {:.2} exceeds threshold {:.2}",
            assessed_risk, input.risk_threshold
        );
        if !input.matched_rules.is_empty() {
            reason.push_str(&format!(" | rules: {}", input.matched_rules.join(", ")));
        }
        if !input.session_flags.is_empty() {
            reason.push_str(&format!(" | session: {}", input.session_flags.join(", ")));
        }
        if let Some(ref r) = input.reasoning {
            reason.push_str(&format!(" | {}", r));
        }
        (reason, RejectionType::Security)
    } else {
        (input.policy_reason.clone(), RejectionType::Config)
    };

    DecisionOutput {
        blocked: true,
        assessed_risk,
        denial_reason: Some(denial_reason),
        rejection_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_input() -> DecisionInput {
        DecisionInput {
            suspicion_score: 0.0,
            assessed_risk: 0.0,
            ap2_risk_modifier: 0.0,
            intent_action: 0, // PASS
            policy_action: POLICY_ALLOW,
            policy_reason: String::new(),
            risk_threshold: 0.70,
            matched_rules: Vec::new(),
            session_flags: Vec::new(),
            reasoning: None,
        }
    }

    // ── Priority 0: Suspicion auto-deny ──

    #[test]
    fn suspicion_above_08_blocks_regardless() {
        let d = evaluate(&DecisionInput {
            suspicion_score: 0.85,
            policy_action: POLICY_ALLOW,
            policy_reason: "scope_exemption:R001".to_string(),
            ..default_input()
        });
        assert!(d.blocked, "Suspicion > 0.8 must block even with scope exemption");
        assert_eq!(d.rejection_type, RejectionType::Security);
    }

    #[test]
    fn suspicion_exactly_08_does_not_auto_deny_and_does_not_inflate_risk() {
        // Suspicion == 0.8 does NOT trigger auto-deny (requires > 0.8).
        // Suspicion also does NOT inflate assessed_risk (prevents death spiral).
        // So a safe call (0.30 risk) is allowed even with suspicion at 0.80.
        let d = evaluate(&DecisionInput {
            suspicion_score: 0.80,
            assessed_risk: 0.30,
            ..default_input()
        });
        assert!(!d.blocked, "Suspicion=0.80 should not block safe call (0.30 risk)");
        assert!((d.assessed_risk - 0.30).abs() < 0.01, "Risk should stay at 0.30");
    }

    #[test]
    fn suspicion_below_threshold_allows() {
        // If suspicion is 0.50 and assessed_risk is 0.30, max = 0.50 < 0.70 threshold → allow
        let d = evaluate(&DecisionInput {
            suspicion_score: 0.50,
            assessed_risk: 0.30,
            ..default_input()
        });
        assert!(!d.blocked, "Suspicion below threshold should allow");
    }

    // ── Priority 1: Policy DENY ──

    #[test]
    fn policy_deny_blocks() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "never_exemptable_rule".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Security);
    }

    #[test]
    fn policy_deny_scope_is_config_rejection() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "scope_mismatch".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Config,
            "scope_ prefix denial must be Config, not Security");
    }

    #[test]
    fn policy_deny_delegation_is_config_rejection() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "delegation_chain_invalid".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Config);
    }

    #[test]
    fn policy_deny_license_is_config_rejection() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "license_expired".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Config);
    }

    #[test]
    fn policy_deny_unapproved_tool_is_config_rejection() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "unapproved_tool".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Config);
    }

    #[test]
    fn policy_deny_boundary_is_config_rejection() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "boundary_volume_exceeded".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Config);
    }

    #[test]
    fn policy_deny_unknown_reason_is_security() {
        let d = evaluate(&DecisionInput {
            policy_action: POLICY_DENY,
            policy_reason: "something_else".to_string(),
            ..default_input()
        });
        assert!(d.blocked);
        assert_eq!(d.rejection_type, RejectionType::Security,
            "Unknown policy deny reason should be Security (fail-safe)");
    }

    // ── Priority 2: Scope exemption ALLOW ──

    #[test]
    fn scope_exemption_allows_even_when_intent_blocks() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.95,
            intent_action: 2, // BLOCK
            policy_action: POLICY_ALLOW,
            policy_reason: "scope_exemption:R001".to_string(),
            ..default_input()
        });
        assert!(!d.blocked, "Scope exemption must override intent BLOCK");
    }

    #[test]
    fn policy_allow_without_exemption_does_not_override() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.95,
            intent_action: 2, // BLOCK
            policy_action: POLICY_ALLOW,
            policy_reason: "some_other_reason".to_string(),
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(d.blocked, "Policy ALLOW without scope_exemption: prefix should NOT override intent BLOCK");
    }

    // ── Priority 3: Intent FLAG ──

    #[test]
    fn intent_flag_allows_below_threshold() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.60,
            intent_action: 1, // FLAG
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(!d.blocked, "Intent FLAG should allow (warn only)");
    }

    // ── Priority 4: Intent BLOCK / risk threshold ──

    #[test]
    fn intent_block_denies() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.50,
            intent_action: 2, // BLOCK
            ..default_input()
        });
        assert!(d.blocked, "Intent BLOCK must deny");
        assert_eq!(d.rejection_type, RejectionType::Security);
    }

    #[test]
    fn risk_above_threshold_denies() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.75,
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(d.blocked, "Risk above threshold must deny");
    }

    #[test]
    fn risk_below_threshold_allows() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.50,
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(!d.blocked, "Risk below threshold must allow");
    }

    #[test]
    fn risk_exactly_at_threshold_denies() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.70,
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(d.blocked, "Risk == threshold must deny (>= comparison)");
    }

    // ── AP2 modifier ──

    #[test]
    fn ap2_modifier_pushes_over_threshold() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.60,
            ap2_risk_modifier: 0.20, // human-not-present
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(d.blocked, "AP2 modifier should push 0.60 + 0.20 = 0.80 above threshold 0.70");
    }

    // ── Assessed risk adjustments ──

    #[test]
    fn suspicion_below_threshold_does_not_block_safe_call() {
        // Suspicion below 0.80 auto-deny threshold should NOT inflate
        // assessed_risk or block a safe call. This prevents the death
        // spiral where one bad call permanently locks out an agent.
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.30,
            suspicion_score: 0.75, // below 0.8 auto-deny
            risk_threshold: 0.70,
            ..default_input()
        });
        // assessed_risk stays at 0.30 (suspicion does NOT inflate it)
        assert!(!d.blocked, "Suspicion below auto-deny should not block");
        assert!((d.assessed_risk - 0.30).abs() < 0.01);
    }

    #[test]
    fn assessed_risk_clamped_to_1() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.90,
            ap2_risk_modifier: 0.20,
            ..default_input()
        });
        assert!((d.assessed_risk - 1.0).abs() < 0.001, "Risk should be clamped to 1.0");
    }

    // ── Safe call ──

    #[test]
    fn safe_call_produces_clean_output() {
        let d = evaluate(&default_input());
        assert!(!d.blocked);
        assert_eq!(d.rejection_type, RejectionType::None);
        assert!(d.denial_reason.is_none());
    }

    // ── Denial reason includes rules and session flags ──

    #[test]
    fn denial_reason_includes_matched_rules() {
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.90,
            risk_threshold: 0.70,
            matched_rules: vec!["R001".to_string(), "R005".to_string()],
            session_flags: vec!["ScopeProbing".to_string()],
            reasoning: Some("destructive SQL detected".to_string()),
            ..default_input()
        });
        let reason = d.denial_reason.unwrap();
        assert!(reason.contains("R001"), "Reason should include rule IDs: {}", reason);
        assert!(reason.contains("R005"), "Reason should include R005: {}", reason);
        assert!(reason.contains("ScopeProbing"), "Reason should include session flags: {}", reason);
        assert!(reason.contains("destructive SQL"), "Reason should include reasoning: {}", reason);
    }

    // ── Death spiral prevention ──

    #[test]
    fn one_bad_call_does_not_lock_out_agent() {
        // After one bad call, suspicion (EMA) would be ~0.30.
        // The next safe call should NOT be blocked.
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.0,       // safe call
            suspicion_score: 0.30,    // EMA after 1 bad call (alpha=0.3, risk=1.0)
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(!d.blocked, "Safe call should not be blocked by one prior bad call");
        assert!((d.assessed_risk - 0.0).abs() < 0.01, "Risk should reflect intent, not suspicion");
    }

    #[test]
    fn sustained_attacks_eventually_block() {
        // After 5+ consecutive attacks, EMA exceeds 0.80 → auto-deny.
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.0,       // even a safe call
            suspicion_score: 0.85,    // EMA after ~5 bad calls
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(d.blocked, "Agent with sustained high EMA should be auto-denied");
        assert!(d.denial_reason.as_ref().unwrap().contains("Behavioral anomaly"));
    }

    #[test]
    fn suspicion_does_not_inflate_assessed_risk_in_shadow_event() {
        // This is the key anti-feedback test. The assessed_risk in the output
        // feeds into the shadow event which feeds back to ag-risk EMA.
        // Suspicion must NOT contaminate it.
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.10,      // low intent risk
            suspicion_score: 0.90,    // high suspicion → auto-deny
            risk_threshold: 0.70,
            ..default_input()
        });
        assert!(d.blocked, "High suspicion should auto-deny");
        // But assessed_risk should stay at 0.10, not 0.90
        assert!((d.assessed_risk - 0.10).abs() < 0.01,
            "assessed_risk must not be inflated by suspicion (got {})", d.assessed_risk);
    }

    #[test]
    fn high_intent_risk_still_blocks_without_suspicion() {
        // Suspicion = 0 but intent says dangerous → still blocked by threshold
        let d = evaluate(&DecisionInput {
            assessed_risk: 0.95,
            suspicion_score: 0.0,
            risk_threshold: 0.70,
            matched_rules: vec!["R003".to_string()],
            reasoning: Some("broad read detected".to_string()),
            ..default_input()
        });
        assert!(d.blocked, "High intent risk should block regardless of suspicion");
        assert!((d.assessed_risk - 0.95).abs() < 0.01);
    }
}
