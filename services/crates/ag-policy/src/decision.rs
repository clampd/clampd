use ag_proto::agentguard::policy::PolicyAction;

/// Decision aggregation: scope_exemption > deny > downscope > default_allow.
///
/// When a scope exemption is granted, it overrides deny from the main OPA
/// evaluation - the whole point of scope exemptions is to authorize an agent
/// for actions that would otherwise be blocked by rules.
pub struct DecisionAggregator {
    deny_reasons: Vec<String>,
    denied_scopes: Vec<String>,
    matched_policies: Vec<String>,
    boundary_violation: Option<String>,
    /// Explicit allow reason from scope exemption (overrides deny + intent risk)
    explicit_allow_reason: Option<String>,
}

impl DecisionAggregator {
    pub fn new() -> Self {
        Self {
            deny_reasons: Vec::new(),
            denied_scopes: Vec::new(),
            matched_policies: Vec::new(),
            boundary_violation: None,
            explicit_allow_reason: None,
        }
    }

    pub fn add_deny(&mut self, reason: String, policy_id: String) {
        self.deny_reasons.push(reason);
        self.matched_policies.push(policy_id);
    }

    pub fn add_downscope(&mut self, denied: Vec<String>, policy_id: String) {
        self.denied_scopes.extend(denied);
        self.matched_policies.push(policy_id);
    }

    /// Add explicit allow from scope exemption (overrides deny + intent risk).
    /// Scope exemption takes highest priority in the decision aggregator.
    pub fn add_allow(&mut self, reason: String, policy_id: String) {
        self.explicit_allow_reason = Some(reason);
        self.matched_policies.push(policy_id);
    }

    /// Add an advisory flag (non-blocking, for monitoring/logging only).
    /// Advisories appear in matched_policies but do NOT trigger deny.
    pub fn add_advisory(&mut self, message: String) {
        self.matched_policies.push(format!("ADVISORY:{}", message));
    }

    pub fn set_boundary_violation(&mut self, violation: String) {
        self.boundary_violation = Some(violation);
    }

    pub fn resolve(
        self,
        requested_scopes: &[String],
        allowed_scopes: &[String],
    ) -> (
        PolicyAction,
        Vec<String>,
        Vec<String>,
        String,
        Option<String>,
        Vec<String>,
    ) {
        let matched = self.matched_policies;

        // Scope exemption overrides deny (agent is explicitly authorized)
        if self.explicit_allow_reason.is_some() {
            let reason = format!("scope_exemption: {}", self.explicit_allow_reason.as_deref().unwrap_or("granted"));
            let granted: Vec<String> = requested_scopes
                .iter()
                .filter(|req| {
                    allowed_scopes.iter().any(|allowed| {
                        ag_common::scopes::scope_matches(allowed, req)
                    })
                })
                .cloned()
                .collect();
            return (
                PolicyAction::Allow,
                granted,
                Vec::new(),
                reason,
                self.boundary_violation,
                matched,
            );
        }

        // Any deny wins (when no scope exemption)
        if !self.deny_reasons.is_empty() {
            return (
                PolicyAction::Deny,
                Vec::new(),
                Vec::new(),
                self.deny_reasons.join("; "),
                self.boundary_violation,
                matched,
            );
        }

        // Scope intersection with wildcard matching.
        // An allowed scope "db:query:*" grants "db:query:read".
        // Uses scope_matches() from ag-common for hierarchy support.
        let granted: Vec<String> = requested_scopes
            .iter()
            .filter(|req| {
                allowed_scopes.iter().any(|allowed| {
                    ag_common::scopes::scope_matches(allowed, req)
                })
            })
            .cloned()
            .collect();

        if granted.is_empty() && !requested_scopes.is_empty() {
            return (
                PolicyAction::Deny,
                Vec::new(),
                requested_scopes.to_vec(),
                "No requested scopes are in agent's allowed scopes".to_string(),
                self.boundary_violation,
                matched,
            );
        }

        // Apply downscoping: remove denied scopes from granted
        let final_scopes: Vec<String> = granted
            .into_iter()
            .filter(|s| !self.denied_scopes.contains(s))
            .collect();

        if final_scopes.is_empty() && !requested_scopes.is_empty() {
            return (
                PolicyAction::Deny,
                Vec::new(),
                self.denied_scopes,
                "All scopes denied by policy".to_string(),
                self.boundary_violation,
                matched,
            );
        }

        if !self.denied_scopes.is_empty() {
            return (
                PolicyAction::Downscope,
                final_scopes,
                self.denied_scopes,
                "Scopes downscoped by policy".to_string(),
                self.boundary_violation,
                matched,
            );
        }

        let reason = "Allowed".to_string();

        (
            PolicyAction::Allow,
            final_scopes,
            Vec::new(),
            reason,
            self.boundary_violation,
            matched,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_deny_wins() {
        let mut agg = DecisionAggregator::new();
        agg.add_deny("bad agent".to_string(), "P-DENY-001".to_string());
        let (action, granted, _, reason, _, matched) =
            agg.resolve(&["db:read".to_string()], &["db:read".to_string()]);
        assert_eq!(action, PolicyAction::Deny);
        assert!(granted.is_empty());
        assert!(reason.contains("bad agent"));
        assert!(matched.contains(&"P-DENY-001".to_string()));
    }

    #[test]
    fn test_multiple_downscopes_union() {
        let mut agg = DecisionAggregator::new();
        agg.add_downscope(vec!["db:write".to_string()], "P-SESSION-001".to_string());
        agg.add_downscope(vec!["db:admin".to_string()], "P-RISK-001".to_string());
        let requested = vec![
            "db:read".to_string(),
            "db:write".to_string(),
            "db:admin".to_string(),
        ];
        let allowed = requested.clone();
        let (action, granted, denied, _, _, matched) = agg.resolve(&requested, &allowed);
        assert_eq!(action, PolicyAction::Downscope);
        assert_eq!(granted, vec!["db:read".to_string()]);
        assert!(denied.contains(&"db:write".to_string()));
        assert!(denied.contains(&"db:admin".to_string()));
        assert!(matched.contains(&"P-SESSION-001".to_string()));
        assert!(matched.contains(&"P-RISK-001".to_string()));
    }

    #[test]
    fn test_deny_plus_downscope_deny_wins() {
        let mut agg = DecisionAggregator::new();
        agg.add_deny("malicious".to_string(), "P-DENY-002".to_string());
        agg.add_downscope(vec!["db:write".to_string()], "P-SESSION-001".to_string());
        let (action, _, _, reason, _, _) =
            agg.resolve(&["db:read".to_string()], &["db:read".to_string()]);
        assert_eq!(action, PolicyAction::Deny);
        assert!(reason.contains("malicious"));
    }

    #[test]
    fn test_all_scopes_denied_escalates() {
        let mut agg = DecisionAggregator::new();
        agg.add_downscope(
            vec!["db:read".to_string(), "db:write".to_string()],
            "P-RISK-002".to_string(),
        );
        let requested = vec!["db:read".to_string(), "db:write".to_string()];
        let allowed = requested.clone();
        let (action, _, _, reason, _, _) = agg.resolve(&requested, &allowed);
        assert_eq!(action, PolicyAction::Deny);
        assert!(reason.contains("All scopes denied"));
    }

    #[test]
    fn test_no_policies_allow() {
        let agg = DecisionAggregator::new();
        let requested = vec!["db:read".to_string()];
        let allowed = vec!["db:read".to_string()];
        let (action, granted, denied, reason, _, _) = agg.resolve(&requested, &allowed);
        assert_eq!(action, PolicyAction::Allow);
        assert_eq!(granted, vec!["db:read".to_string()]);
        assert!(denied.is_empty());
        assert_eq!(reason, "Allowed");
    }

    #[test]
    fn test_empty_requested_scopes() {
        let agg = DecisionAggregator::new();
        let (action, granted, _, reason, _, _) = agg.resolve(&[], &["db:read".to_string()]);
        assert_eq!(action, PolicyAction::Allow);
        assert!(granted.is_empty());
        assert_eq!(reason, "Allowed");
    }

    #[test]
    fn test_no_scopes_in_allowed() {
        let agg = DecisionAggregator::new();
        let requested = vec!["db:admin".to_string()];
        let allowed = vec!["db:read".to_string()];
        let (action, _, denied, reason, _, _) = agg.resolve(&requested, &allowed);
        assert_eq!(action, PolicyAction::Deny);
        assert!(denied.contains(&"db:admin".to_string()));
        assert!(reason.contains("No requested scopes"));
    }

    #[test]
    fn test_boundary_violation_propagation() {
        let mut agg = DecisionAggregator::new();
        agg.set_boundary_violation("volume_quota_exceeded".to_string());
        agg.add_deny("quota".to_string(), "B-001".to_string());
        let (action, _, _, _, violation, _) =
            agg.resolve(&["db:read".to_string()], &["db:read".to_string()]);
        assert_eq!(action, PolicyAction::Deny);
        assert_eq!(violation, Some("volume_quota_exceeded".to_string()));
    }

    #[test]
    fn test_scope_exemption_overrides_deny() {
        let mut agg = DecisionAggregator::new();
        agg.add_deny("destructive_sql".to_string(), "R001".to_string());
        agg.add_allow("Agent has db:write:destructive scope".to_string(), "SCOPE-EX".to_string());
        let requested = vec!["db:write:destructive".to_string()];
        let allowed = vec!["db:write:destructive".to_string()];
        let (action, granted, denied, reason, _, matched) = agg.resolve(&requested, &allowed);
        assert_eq!(action, PolicyAction::Allow);
        assert_eq!(granted, vec!["db:write:destructive".to_string()]);
        assert!(denied.is_empty());
        assert!(reason.contains("scope_exemption"));
        assert!(matched.contains(&"R001".to_string()));
        assert!(matched.contains(&"SCOPE-EX".to_string()));
    }

    #[test]
    fn test_scope_exemption_without_deny() {
        let mut agg = DecisionAggregator::new();
        agg.add_allow("Agent has scope".to_string(), "SCOPE-EX".to_string());
        let requested = vec!["db:read".to_string()];
        let allowed = vec!["db:read".to_string()];
        let (action, _, _, reason, _, _) = agg.resolve(&requested, &allowed);
        assert_eq!(action, PolicyAction::Allow);
        assert!(reason.contains("scope_exemption"));
    }

    #[test]
    fn test_scope_intersection() {
        let agg = DecisionAggregator::new();
        let requested = vec!["db:read".to_string(), "db:write".to_string(), "db:admin".to_string()];
        let allowed = vec!["db:read".to_string(), "db:write".to_string()];
        let (action, granted, _, _, _, _) = agg.resolve(&requested, &allowed);
        // db:admin not in allowed, but db:read and db:write are
        // Since some scopes are granted, it should be Allow (not Deny)
        assert_eq!(action, PolicyAction::Allow);
        assert_eq!(granted, vec!["db:read".to_string(), "db:write".to_string()]);
    }
}
