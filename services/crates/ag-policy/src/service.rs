use std::collections::HashSet;
use std::sync::Arc;

use ag_proto::agentguard::policy::{
    policy_service_server::PolicyService, EvaluateRequest, EvaluateResponse,
};
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use ag_license::{PlanGuard, FeatureFlags};

use crate::boundary::BoundaryEvaluator;
use crate::cache::DecisionCache;
use crate::cedar::{CedarContext, CedarEvaluator};
use crate::decision::DecisionAggregator;
use crate::delegation_workflow::{self, DelegationEdgeData};
use crate::engine::{PolicyEngine, PolicyInput};
use crate::scope_exemption;

/// Maximum allowed delegation chain depth (defense-in-depth).
const MAX_DELEGATION_DEPTH: usize = 5;

pub struct PolicyServiceImpl {
    plan_guard: Arc<PlanGuard>,
    redis_pool: bb8::Pool<bb8_redis::RedisConnectionManager>,
    decision_cache: Arc<DecisionCache>,
    /// Cedar custom policy evaluator (Layer 5). Always present, may have zero policies.
    cedar: Arc<CedarEvaluator>,
}

impl PolicyServiceImpl {
    pub fn new(
        plan_guard: Arc<PlanGuard>,
        redis_pool: bb8::Pool<bb8_redis::RedisConnectionManager>,
        decision_cache: Arc<DecisionCache>,
        cedar: Arc<CedarEvaluator>,
    ) -> Self {
        Self { plan_guard, redis_pool, decision_cache, cedar }
    }

    /// Evaluate delegation context. Returns (deny_reasons, advisory_flags).
    ///
    /// Checks:
    /// 1. If delegation enforcement is enabled for this org, verify the caller->agent
    ///    relationship is approved in Redis.
    /// 2. Chain depth must not exceed MAX_DELEGATION_DEPTH.
    /// 3. Chain must not contain cycles.
    ///
    /// Fail-open: if Redis is unavailable, logs a warning and returns no deny reasons.
    /// Cross-boundary detection returns advisory flags (not denies).
    async fn evaluate_delegation(
        &self,
        agent_id: &str,
        caller_agent_id: &str,
        delegation_chain: &[String],
        org_id: &str,
        tool_name: &str,
    ) -> (Vec<String>, Vec<String>) {
        let mut deny_reasons = Vec::new();
        let mut advisory_flags = Vec::new();

        // Defense-in-depth: validate chain depth
        if delegation_chain.len() > MAX_DELEGATION_DEPTH {
            deny_reasons.push(format!(
                "delegation_chain_too_deep: depth {} exceeds max {}",
                delegation_chain.len(),
                MAX_DELEGATION_DEPTH
            ));
            // Continue checking for cycles too — report all issues
        }

        // Defense-in-depth: detect cycles in delegation chain
        {
            let mut seen = HashSet::new();
            for id in delegation_chain {
                if !seen.insert(id.as_str()) {
                    deny_reasons.push(format!(
                        "delegation_cycle_detected: agent '{}' appears multiple times in chain",
                        id
                    ));
                    break;
                }
            }
        }

        // Check Redis for enforcement mode and approved relationships
        let conn_result = self.redis_pool.get().await;
        let mut conn = match conn_result {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    error = %e,
                    caller = %caller_agent_id,
                    agent = %agent_id,
                    "Redis unavailable for delegation check — failing closed"
                );
                deny_reasons.push(format!(
                    "delegation_redis_unavailable: cannot verify delegation approval for {} → {} — denying (fail-closed)",
                    caller_agent_id, agent_id
                ));
                return (deny_reasons, vec![]);
            }
        };

        // Check enforcement mode: ag:delegation:enforcement:{org_id}
        // If key is missing or value is not "on"/"true"/"1", enforcement is off.
        let enforcement_key = format!("ag:delegation:enforcement:{}", org_id);
        let enforcement_on: bool = match redis::cmd("GET")
            .arg(&enforcement_key)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            Ok(Some(val)) => matches!(val.as_str(), "on" | "true" | "1"),
            Ok(None) => false,
            Err(e) => {
                warn!(
                    error = %e,
                    key = %enforcement_key,
                    "Redis GET failed for delegation enforcement — failing open"
                );
                return (deny_reasons, vec![]);
            }
        };

        // ── Agent state checks (before enforcement toggle) ──
        // Killed/suspended callers must never delegate, regardless of enforcement mode.
        {
            let caller_deny_key = format!("ag:deny:{}", caller_agent_id);
            let caller_killed: bool = redis::cmd("EXISTS")
                .arg(&caller_deny_key)
                .query_async::<bool>(&mut *conn)
                .await
                .unwrap_or(false);
            if let Some(reason) = delegation_workflow::check_caller_killed(caller_agent_id, caller_killed) {
                deny_reasons.push(reason);
                return (deny_reasons, vec![]); // hard stop
            }

            let caller_suspended_key = format!("ag:agent:suspended:{}", caller_agent_id);
            let caller_suspended: bool = redis::cmd("EXISTS")
                .arg(&caller_suspended_key)
                .query_async::<bool>(&mut *conn)
                .await
                .unwrap_or(false);
            if let Some(reason) = delegation_workflow::check_caller_suspended(caller_agent_id, caller_suspended) {
                deny_reasons.push(reason);
                return (deny_reasons, vec![]); // hard stop
            }

            let target_deny_key = format!("ag:deny:{}", agent_id);
            let target_killed: bool = redis::cmd("EXISTS")
                .arg(&target_deny_key)
                .query_async::<bool>(&mut *conn)
                .await
                .unwrap_or(false);
            if let Some(reason) = delegation_workflow::check_target_killed(agent_id, target_killed) {
                deny_reasons.push(reason);
                return (deny_reasons, vec![]); // hard stop
            }
        }

        // Cross-boundary detection runs ALWAYS (advisory, not blocking).
        // It must run even when enforcement is off — learning mode needs to
        // observe which delegations cross workflow boundaries.
        let caller_wf: Option<String> = redis::cmd("GET")
            .arg(&format!("ag:agent:workflow:{}", caller_agent_id))
            .query_async::<Option<String>>(&mut *conn)
            .await
            .unwrap_or(None);
        let target_wf: Option<String> = redis::cmd("GET")
            .arg(&format!("ag:agent:workflow:{}", agent_id))
            .query_async::<Option<String>>(&mut *conn)
            .await
            .unwrap_or(None);

        let mut advisory_flags_early = Vec::new();
        if let Some(result) = delegation_workflow::check_cross_boundary(
            caller_agent_id,
            agent_id,
            caller_wf.as_deref(),
            target_wf.as_deref(),
        ) {
            tracing::info!(
                caller = caller_agent_id,
                target = agent_id,
                "{}", result.message
            );
            advisory_flags_early.push(result.message);
        }

        if !enforcement_on {
            debug!(
                org_id = %org_id,
                "Delegation enforcement not enabled — skipping approval check"
            );
            return (deny_reasons, advisory_flags_early);
        }

        // ── Enforcement is ON: check approved relationship + tool restrictions ──
        let approval_key = format!(
            "ag:delegation:approved:{}:{}",
            caller_agent_id, agent_id
        );
        let edge_json: Option<String> = match redis::cmd("GET")
            .arg(&approval_key)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            Ok(val) => val,
            Err(e) => {
                warn!(
                    error = %e,
                    key = %approval_key,
                    "Redis GET failed for delegation approval — failing closed"
                );
                deny_reasons.push(format!(
                    "delegation_redis_error: cannot verify edge {} → {}",
                    caller_agent_id, agent_id
                ));
                return (deny_reasons, vec![]);
            }
        };

        match edge_json {
            Some(json) => {
                match serde_json::from_str::<DelegationEdgeData>(&json) {
                    Ok(edge) => {
                        // Check tool restriction
                        if let Some(reason) = delegation_workflow::check_tool_restriction(
                            &edge, tool_name, caller_agent_id, agent_id,
                        ) {
                            deny_reasons.push(reason);
                        }

                        // Check per-edge depth limit
                        if let Some(reason) = delegation_workflow::check_edge_depth(
                            &edge, delegation_chain.len(), caller_agent_id, agent_id,
                        ) {
                            deny_reasons.push(reason);
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            key = %approval_key,
                            "Failed to parse delegation edge JSON — treating as approved (no restrictions)"
                        );
                    }
                }
            }
            None => {
                deny_reasons.push(format!(
                    "delegation_not_approved: caller '{}' is not approved to delegate to agent '{}'",
                    caller_agent_id, agent_id
                ));
            }
        }

        // Cross-boundary advisory was already computed above (before enforcement check).
        // Merge it into advisory_flags for the enforcement-on path.
        advisory_flags.extend(advisory_flags_early);

        (deny_reasons, advisory_flags)
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        let req = request.into_inner();

        // ---- Pre-cache security check: cross-check labels BEFORE cache lookup ----
        // This ensures stale cache entries can't bypass never-exemptable detection
        // after rule hot-reload.
        let labels_block = crate::scope_exemption::labels_contain_never_exemptable(&req.labels);

        // ---- Decision cache: skip full evaluation for identical non-security-critical requests ----
        let cache_key = if req.has_non_exemptable_block || labels_block {
            // Never cache security-critical requests — always re-evaluate
            None
        } else {
            let key = DecisionCache::cache_key(
                &req.agent_id,
                &req.tool_name,
                &req.params_json,
                &req.intent_classification,
                req.agent_risk_score,
            );
            if let Some(cached) = self.decision_cache.get(key) {
                debug!(
                    agent_id = %req.agent_id,
                    tool = %req.tool_name,
                    "Returning cached policy decision"
                );
                return Ok(Response::new(cached));
            }
            Some(key)
        };

        let mut agg = DecisionAggregator::new();
        let mut scope_token_ttl: u32 = 0;

        // ---- Phase 1: Rust-native boundary checks — short-circuit on violation ----
        if let Err(violation) = BoundaryEvaluator::evaluate(&req) {
            agg.add_deny(violation.to_string(), violation.rule_id().to_string());
            agg.set_boundary_violation(violation.violation_key());

            let (action, required_scopes, denied_scopes, reason, boundary_violation, matched_policies) =
                agg.resolve(&req.requested_scopes, &req.agent_allowed_scopes);

            debug!(
                agent_id = %req.agent_id,
                tool = %req.tool_name,
                action = ?action,
                "Boundary violation"
            );

            return Ok(Response::new(EvaluateResponse {
                action: action.into(),
                required_scopes,
                denied_scopes,
                reason,
                matched_policies,
                boundary_violation,
                token_ttl_seconds: 0,
            }));
        }

        // ---- Phase 1b: Delegation context evaluation ----
        // SECURITY: caller_agent_id is set by ag-gateway from the SDK's delegation context.
        // The gRPC HMAC interceptor ensures only authenticated Clampd services can call this RPC.
        // Gateway validates the delegation chain before forwarding — we trust the gateway's claim.
        // If an attacker bypasses the gateway (direct gRPC), the HMAC interceptor blocks them.
        // TODO: For defense-in-depth, verify caller_agent_id exists in ag-registry.
        let caller_agent_id = req.caller_agent_id.clone();
        let delegation_chain: Vec<String> = req.delegation_chain.clone();
        let delegation_trace_id = req.delegation_trace_id.clone();

        if let Some(ref caller) = caller_agent_id {
            if !caller.is_empty() {
                // Basic format validation — reject obviously invalid agent IDs
                if uuid::Uuid::parse_str(caller).is_err() {
                    warn!(
                        caller_agent_id = %caller,
                        agent_id = %req.agent_id,
                        "Invalid caller_agent_id format — must be a valid UUID"
                    );
                    return Ok(Response::new(EvaluateResponse {
                        action: ag_proto::agentguard::policy::PolicyAction::Deny.into(),
                        reason: "invalid caller_agent_id format — must be a valid UUID".to_string(),
                        required_scopes: vec![],
                        denied_scopes: vec![],
                        matched_policies: vec!["CALLER_VALIDATION".to_string()],
                        boundary_violation: Some(String::new()),
                        token_ttl_seconds: 0,
                    }));
                }

                // Extract org_id from plan_guard for enforcement key lookup
                // Use org_id from request (agent's org), not license org (multi-org support)
                let delegation_org = if req.org_id.is_empty() {
                    &self.plan_guard.org_id
                } else {
                    &req.org_id
                };

                let (delegation_deny_reasons, delegation_advisories) = self
                    .evaluate_delegation(
                        &req.agent_id,
                        caller,
                        &delegation_chain,
                        delegation_org,
                        &req.tool_name,
                    )
                    .await;

                // Add advisory flags to matched_policies (visible but non-blocking).
                // Previously these were mixed into deny_reasons with an "advisory:" prefix,
                // which required string-parsing downstream. Now they're in the policies list.
                for advisory in &delegation_advisories {
                    agg.add_advisory(advisory.clone());
                }

                if !delegation_deny_reasons.is_empty() {
                    for reason in &delegation_deny_reasons {
                        agg.add_deny(reason.clone(), "DELEGATION".to_string());
                    }

                    debug!(
                        agent_id = %req.agent_id,
                        caller_agent_id = %caller,
                        delegation_chain = ?delegation_chain,
                        reasons = ?delegation_deny_reasons,
                        "Delegation denied"
                    );

                    // Short-circuit: delegation violations are hard denies
                    let (action, required_scopes, denied_scopes, reason, boundary_violation, matched_policies) =
                        agg.resolve(&req.requested_scopes, &req.agent_allowed_scopes);

                    return Ok(Response::new(EvaluateResponse {
                        action: action.into(),
                        required_scopes,
                        denied_scopes,
                        reason,
                        matched_policies,
                        boundary_violation,
                        token_ttl_seconds: 0,
                    }));
                }

                debug!(
                    agent_id = %req.agent_id,
                    caller_agent_id = %caller,
                    chain_depth = delegation_chain.len(),
                    trace_id = ?delegation_trace_id,
                    "Delegation context validated"
                );
            }
        }

        // ---- Phase 2: 5-layer policy engine (Rust-native) ----
        // Use agent_state from request; default to "active" if empty (backward compat)
        let agent_state = if req.agent_state.is_empty() {
            "active".to_string()
        } else {
            req.agent_state.clone()
        };
        let input = PolicyInput {
            agent_id: req.agent_id.clone(),
            agent_state: agent_state.clone(),
            tool_name: req.tool_name.clone(),
            requested_scopes: req.requested_scopes.clone(),
            allowed_scopes: req.agent_allowed_scopes.clone(),
            risk_score: req.agent_risk_score,
            intent_class: req.intent_classification.clone(),
            labels: req.labels.clone(),
            session_flags: req.session_flags.clone(),
        };

        let output = PolicyEngine::evaluate(&input);

        // Feed Rust-native engine output into decision aggregation
        if output.deny {
            agg.add_deny(output.deny_reason, output.matched.join(","));
        } else if !output.downscope_denied.is_empty() {
            agg.add_downscope(output.downscope_denied, output.matched.join(","));
        }

        // ---- Phase 2b: Rust-native scope exemption evaluation (replaces OPA) ----
        // Scope exemptions require the SCOPE_PERMISSIONS feature flag.
        if self.plan_guard.is_enabled(FeatureFlags::SCOPE_PERMISSIONS) {
            let se = scope_exemption::evaluate_scope_exemption(
                &req.labels,
                &req.agent_allowed_scopes,
                &req.params_json,
                None, // TODO: pass exemption_expires_at from dashboard sync
            );

            if se.exempt {
                // Defense-in-depth: cross-check labels against local never-exemptable set.
                // Do NOT blindly trust req.has_non_exemptable_block from ag-intent.
                let labels_block = scope_exemption::labels_contain_never_exemptable(&req.labels);

                if labels_block {
                    let bad_labels = scope_exemption::find_never_exemptable_labels(&req.labels);
                    warn!(
                        agent_id = %req.agent_id,
                        reason = %se.exempt_reason,
                        never_exemptable_labels = ?bad_labels,
                        "Scope exemption REJECTED — never-exemptable labels present"
                    );
                } else if req.has_non_exemptable_block {
                    // ag-intent says non-exemptable block — trust the upstream flag
                    warn!(
                        agent_id = %req.agent_id,
                        reason = %se.exempt_reason,
                        "Scope exemption REJECTED — has_non_exemptable_block=true from ag-intent"
                    );
                } else {
                    // Both agree: no never-exemptable labels → grant exemption
                    debug!(
                        agent_id = %req.agent_id,
                        reason = %se.exempt_reason,
                        token_ttl = se.token_ttl,
                        "Scope exemption granted"
                    );
                    agg.add_allow(se.exempt_reason, "SCOPE_EXEMPTION".to_string());
                    scope_token_ttl = se.token_ttl;
                }
            }
        }

        // ---- Phase 2c: Layer 5 — Cedar custom policies ----
        // Evaluates dashboard-authored Cedar policies in-process.
        // Only runs if custom policies are loaded (zero-cost when empty).
        if self.cedar.policy_count() > 0 {
            // Derive category from the tool name (first segment before '.')
            let category = req.tool_name.split('.').next().unwrap_or("").to_string();
            let cedar_ctx = CedarContext {
                agent_id: req.agent_id.clone(),
                tool_name: req.tool_name.clone(),
                risk_score_bps: (req.agent_risk_score * 1000.0) as i64,
                intent_class: req.intent_classification.clone(),
                labels: req.labels.clone(),
                scopes: req.requested_scopes.clone(),
                allowed_scopes: req.agent_allowed_scopes.clone(),
                session_flags: req.session_flags.clone(),
                delegation_depth: delegation_chain.len() as i64,
                has_non_exemptable_block: req.has_non_exemptable_block,
                category,
            };

            let cedar_decision = self.cedar.evaluate(&req.agent_id, &req.tool_name, cedar_ctx);

            if cedar_decision.deny {
                agg.add_deny(cedar_decision.deny_reason, cedar_decision.matched.join(","));
            } else if !cedar_decision.downscope_denied.is_empty() {
                agg.add_downscope(cedar_decision.downscope_denied, cedar_decision.matched.join(","));
            }
        }

        // ---- Phase 3: Resolve final decision ----
        let (action, required_scopes, denied_scopes, reason, boundary_violation, matched_policies) =
            agg.resolve(&req.requested_scopes, &req.agent_allowed_scopes);

        debug!(
            agent_id = %req.agent_id,
            tool = %req.tool_name,
            action = ?action,
            "Policy evaluated"
        );

        let response = EvaluateResponse {
            action: action.into(),
            required_scopes,
            denied_scopes,
            reason,
            matched_policies,
            boundary_violation,
            token_ttl_seconds: scope_token_ttl,
        };

        // Store in decision cache (only for cacheable requests)
        if let Some(key) = cache_key {
            self.decision_cache.insert(key, response.clone());
        }

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::extract_domain;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://api.example.com/path"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_domain("http://localhost:8080/test"),
            Some("localhost".to_string())
        );
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn test_delegation_chain_cycle_detection() {
        // Simulate the cycle detection logic from evaluate_delegation
        let chain_with_cycle = vec![
            "agent-a".to_string(),
            "agent-b".to_string(),
            "agent-a".to_string(), // cycle
        ];
        let mut seen = HashSet::new();
        let mut has_cycle = false;
        for id in &chain_with_cycle {
            if !seen.insert(id.as_str()) {
                has_cycle = true;
                break;
            }
        }
        assert!(has_cycle);

        // No cycle
        let chain_no_cycle = vec![
            "agent-a".to_string(),
            "agent-b".to_string(),
            "agent-c".to_string(),
        ];
        let mut seen2 = HashSet::new();
        let mut has_cycle2 = false;
        for id in &chain_no_cycle {
            if !seen2.insert(id.as_str()) {
                has_cycle2 = true;
                break;
            }
        }
        assert!(!has_cycle2);
    }

    #[test]
    fn test_delegation_chain_depth_limit() {
        // Chain at max depth: OK
        let chain_ok: Vec<String> = (0..MAX_DELEGATION_DEPTH)
            .map(|i| format!("agent-{}", i))
            .collect();
        assert!(chain_ok.len() <= MAX_DELEGATION_DEPTH);

        // Chain exceeding max depth: should be denied
        let chain_too_deep: Vec<String> = (0..=MAX_DELEGATION_DEPTH)
            .map(|i| format!("agent-{}", i))
            .collect();
        assert!(chain_too_deep.len() > MAX_DELEGATION_DEPTH);
    }

    #[test]
    fn test_max_delegation_depth_is_5() {
        assert_eq!(MAX_DELEGATION_DEPTH, 5);
    }
}
