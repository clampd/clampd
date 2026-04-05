use std::sync::Arc;
use std::time::Instant;

use ag_common::categories::{classify_tool, DefenseTier};
use ag_common::models::IntentClass;
use ag_common::scopes;
use ag_engine::compile::CompiledRuleset;
use ag_engine::execute::ExecutionContext;
use ag_engine::scheme::{clampd_scheme, FieldId, FieldValue, Scheme};
use ag_policy::thresholds::{self, FinalAction, RiskThresholds, ThresholdOverride, ScopeExemption};
use ag_proto::agentguard::intent::{
    intent_service_server::IntentService, Action, ClassifyRequest, ClassifyResponse,
};
use arc_swap::ArcSwap;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use ag_license::{FeatureFlags, PlanGuard};

use crate::encoding;
use crate::rules::a2a::{self, DelegationRecord};
use crate::session;

pub struct IntentServiceImpl {
    engine: Arc<ArcSwap<CompiledRuleset>>,
    scheme: Scheme,
    plan_guard: Arc<PlanGuard>,
    redis_pool: Option<bb8::Pool<bb8_redis::RedisConnectionManager>>,
    /// Dashboard threshold overrides (hot-reloaded from Redis).
    threshold_overrides: Arc<ArcSwap<Vec<ThresholdOverride>>>,
    /// Scope-based exemptions (hot-reloaded from Redis).
    scope_exemptions: Arc<ArcSwap<Vec<ScopeExemption>>>,
}

impl IntentServiceImpl {
    pub fn new(
        engine: Arc<ArcSwap<CompiledRuleset>>,
        plan_guard: Arc<PlanGuard>,
        redis_pool: Option<bb8::Pool<bb8_redis::RedisConnectionManager>>,
    ) -> Self {
        Self {
            engine,
            scheme: clampd_scheme(),
            plan_guard,
            redis_pool,
            threshold_overrides: Arc::new(ArcSwap::from_pointee(Vec::new())),
            scope_exemptions: Arc::new(ArcSwap::from_pointee(Vec::new())),
        }
    }

    /// Get a handle to threshold overrides for hot-reload from outside.
    pub fn threshold_overrides(&self) -> Arc<ArcSwap<Vec<ThresholdOverride>>> {
        self.threshold_overrides.clone()
    }

    /// Get a handle to scope exemptions for hot-reload from outside.
    pub fn scope_exemptions(&self) -> Arc<ArcSwap<Vec<ScopeExemption>>> {
        self.scope_exemptions.clone()
    }

    /// Load threshold overrides from Redis.
    pub async fn load_thresholds_from_redis(&self) {
        let pool = match &self.redis_pool {
            Some(p) => p,
            None => return,
        };
        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(_) => return,
        };
        let json: String = match bb8_redis::redis::cmd("GET")
            .arg("ag:config:thresholds")
            .query_async(&mut *conn)
            .await
        {
            Ok(v) => v,
            Err(_) => return,
        };
        let overrides = thresholds::parse_threshold_overrides(&json);
        let count = overrides.len();
        self.threshold_overrides.store(Arc::new(overrides));
        if count > 0 {
            tracing::info!(count, "Loaded threshold overrides from Redis");
        }
    }

    /// Load scope exemptions from Redis.
    pub async fn load_exemptions_from_redis(&self) {
        let pool = match &self.redis_pool {
            Some(p) => p,
            None => return,
        };
        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(_) => return,
        };
        let json: String = match bb8_redis::redis::cmd("GET")
            .arg("ag:config:exemptions")
            .query_async(&mut *conn)
            .await
        {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Ok(exemptions) = serde_json::from_str::<Vec<ScopeExemption>>(&json) {
            let count = exemptions.len();
            self.scope_exemptions.store(Arc::new(exemptions));
            if count > 0 {
                tracing::info!(count, "Loaded scope exemptions from Redis");
            }
        }
    }

    /// Build an ExecutionContext from a ClassifyRequest.
    fn build_context(&self, req: &ClassifyRequest) -> ExecutionContext {
        let mut ctx = ExecutionContext::new(&self.scheme);

        // Canonicalize tool name: "db.query" → "database.query", "file.read" → "filesystem.read"
        // Belt-and-suspenders: gateway already canonicalizes for HTTP traffic,
        // but direct gRPC callers (redteam, A2A, internal) bypass the gateway.
        let tool_name = ag_common::tool_names::canonicalize(&req.tool_name);
        ctx.set(FieldId(0), FieldValue::String(Arc::from(tool_name.as_str())));
        ctx.set(FieldId(1), FieldValue::String(Arc::from(req.action.as_str())));
        ctx.set(FieldId(5), FieldValue::String(Arc::from(req.agent_id.as_str())));
        ctx.set(FieldId(6), FieldValue::Float(req.agent_risk_score));

        // Use normalized params if available, otherwise raw
        let params_text = if req.params_normalized_json.is_empty() {
            &req.params_json
        } else {
            &req.params_normalized_json
        };

        // Set raw params as tool.args_text (FieldId 4) — rules match against this
        ctx.set(FieldId(4), FieldValue::String(Arc::from(params_text.as_str())));

        // Set JSON args for field-specific matching
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(params_text) {
            ctx.set(FieldId(2), FieldValue::Json(Arc::new(json_val)));
        }

        // all_text = raw params_json (NOT extracted values).
        // evaluate_full() handles JSON extraction internally via L1b field-joining.
        // This matches the old engine's behavior where evaluate_full() received
        // the raw params_json and did its own collect_strings + normalization.
        ctx.set_all_text(Arc::from(params_text.as_str()));

        // Unified scope: tool_name → scope (e.g., "database.query" → "db:query:read")
        // This is the single key used for rule matching, routing, and permissions.
        let scope = scopes::tool_to_scope(&tool_name);
        ctx.set(FieldId(22), FieldValue::String(Arc::from(scope.as_str())));

        ctx
    }

    /// Check if a tool descriptor hash is approved in Redis.
    async fn check_descriptor_approved(&self, tool_name: &str, hash: &str) -> Option<bool> {
        let pool = self.redis_pool.as_ref()?;
        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Redis pool error for descriptor lookup — fail-open");
                return None;
            }
        };

        let exact_key = format!("ag:tool:approved:{}:{}", tool_name, hash);
        let exists: bool = redis::cmd("EXISTS")
            .arg(&exact_key)
            .query_async(&mut *conn)
            .await
            .unwrap_or(false);

        if exists {
            return Some(true);
        }

        let scan_pattern = format!("ag:tool:approved:{}:*", tool_name);
        let (_, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(0u64)
            .arg("MATCH")
            .arg(&scan_pattern)
            .arg("COUNT")
            .arg(10u64)
            .query_async(&mut *conn)
            .await
            .unwrap_or((0, vec![]));

        if keys.is_empty() {
            None
        } else {
            Some(false)
        }
    }
}

#[tonic::async_trait]
impl IntentService for IntentServiceImpl {
    async fn classify_intent(
        &self,
        request: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();

        // ── Classify tool into category and defense tier ─────────────────
        let tool_cat = classify_tool(&req.tool_name);
        let tier = tool_cat.category.defense_tier();
        let category_name = tool_cat.category.name().to_string();
        let defense_tier_label = match tier {
            DefenseTier::Rules => "rules",
            DefenseTier::Policy => "policy",
            DefenseTier::Hybrid => "hybrid",
        };

        // ── Policy-only tier: skip engine, let ag-policy decide ──────────
        if tier == DefenseTier::Policy {
            let latency_us = start.elapsed().as_micros() as u64;

            debug!(
                tool = %req.tool_name,
                category = %category_name,
                defense_tier = defense_tier_label,
                latency_us,
                "Policy-only tool — skipping engine evaluation"
            );

            return Ok(Response::new(ClassifyResponse {
                intent_risk: 0.0,
                encoding_bonus: 0.0,
                session_factor: 0.0,
                assessed_risk: 0.0,
                classification: "safe".to_string(),
                labels: vec![],
                reasoning: format!(
                    "Tool category '{}' is policy-enforced only — engine evaluation skipped",
                    category_name
                ),
                matched_rules: vec![],
                session_flags: req.session_flags.clone(),
                action: Action::Pass.into(),
                latency_us,
                has_non_exemptable_block: false,
                schema_injection_detected: false,
                schema_injection_type: String::new(),
                category: category_name,
                defense_tier: defense_tier_label.to_string(),
            }));
        }

        // ── Rules / Hybrid tier: run the full engine pipeline ────────────

        // Build ExecutionContext from request
        let ctx = self.build_context(&req);

        // Load compiled ruleset via ArcSwap (~10ns, lock-free)
        let ruleset = self.engine.load();

        // Full 5-layer evaluation: L0 funnel → L4 normalize → L1 regex → L2 dictionary → L3 signals
        let eval = ruleset.evaluate_full(&ctx);

        let intent_risk = eval.assessed_risk;
        let rule_action = eval.action;

        // 6-tier encoding detection
        let content_changed = !req.params_normalized_json.is_empty()
            && req.params_json != req.params_normalized_json;
        let (encoding_bonus, _encoding_detail) = encoding::detector::score_encoding(
            &req.encodings_detected,
            content_changed,
            !eval.rule_matches.is_empty() && content_changed,
        );

        // Session correlation analysis
        let session_analysis = session::analyzer::analyze_session(
            &req.session_flags,
            req.session_risk_factor,
            &req.tool_name,
            &req.action,
            &req.session_context_json,
        );

        // ── A2A delegation chain validation ──────────────────────────────
        let mut delegation_risk: f64 = 0.0;
        let mut delegation_flags: Vec<String> = Vec::new();

        if !req.delegation_chain.is_empty() {
            let chain: Vec<DelegationRecord> = req
                .delegation_chain
                .iter()
                .filter_map(|entry| {
                    let parts: Vec<&str> = entry.splitn(5, '|').collect();
                    if parts.len() >= 5 {
                        Some(DelegationRecord {
                            source_agent: parts[0].to_string(),
                            target_agent: parts[1].to_string(),
                            tool_name: parts[2].to_string(),
                            timestamp: parts[3].parse().unwrap_or(0),
                            depth: parts[4].parse().unwrap_or(0),
                        })
                    } else {
                        Some(DelegationRecord {
                            source_agent: entry.clone(),
                            target_agent: String::new(),
                            tool_name: req.tool_name.clone(),
                            timestamp: 0,
                            depth: 0,
                        })
                    }
                })
                .collect();

            if let Err(e) = a2a::validate_delegation(&chain) {
                if e.contains("cycle") {
                    delegation_risk += 0.98;
                    delegation_flags.push("delegation_cycle".to_string());
                } else if e.contains("exceeds maximum") {
                    delegation_risk += 0.90;
                    delegation_flags.push("delegation_depth_exceeded".to_string());
                } else {
                    delegation_risk += 0.85;
                    delegation_flags.push("delegation_chain_invalid".to_string());
                }
            }

            let depth = req.delegation_chain.len();
            if depth > 3 && !delegation_flags.contains(&"delegation_depth_exceeded".to_string()) {
                let depth_score = 0.15 * (depth as f64 - 3.0).min(3.0);
                delegation_risk += depth_score;
                delegation_flags.push("deep_delegation_chain".to_string());
            }

            if let Some(ref caller) = req.caller_agent_id {
                if !caller.is_empty() {
                    delegation_flags.push(format!("delegated_from:{}", caller));
                }
            }

            delegation_risk = delegation_risk.min(0.98);
        }

        // ── Tool descriptor hash check (rug-pull detection) ─────────────
        let mut descriptor_risk: f64 = 0.0;
        let mut descriptor_flags: Vec<String> = Vec::new();

        if !req.tool_descriptor_hash.is_empty() && req.tool_descriptor_hash.len() == 64 {
            match self
                .check_descriptor_approved(&req.tool_name, &req.tool_descriptor_hash)
                .await
            {
                Some(true) => {
                    debug!(tool = %req.tool_name, "Tool descriptor hash verified");
                }
                Some(false) => {
                    descriptor_risk = 0.98;
                    descriptor_flags.push("rug_pull_detected".to_string());
                }
                None => {
                    descriptor_flags.push("unknown_descriptor".to_string());
                }
            }
        }

        // Merge session flags
        let mut all_session_flags = req.session_flags.clone();
        all_session_flags.extend(session_analysis.additional_flags.clone());
        all_session_flags.extend(delegation_flags.clone());
        all_session_flags.extend(descriptor_flags.clone());

        let session_factor = req.session_risk_factor + session_analysis.additional_risk;
        let truncation_penalty =
            if req.session_context_window > 0 && req.session_context_window < req.session_total_calls
            {
                0.05
            } else {
                0.0
            };

        let assessed_risk = (intent_risk
            + encoding_bonus
            + session_factor
            + truncation_penalty
            + delegation_risk
            + descriptor_risk)
            .min(1.0);

        let classification = IntentClass::from_risk(assessed_risk);

        // Resolve final action via the policy threshold layer.
        // Dashboard overrides are checked first, then per-tool-category defaults.
        let risk_thresholds = RiskThresholds::default();
        let overrides = self.threshold_overrides.load();
        let final_action = thresholds::resolve_action_with_overrides(
            &overrides,
            &risk_thresholds,
            &req.tool_name,
            assessed_risk,
            rule_action.severity(),
        );
        let action = match final_action {
            FinalAction::Block => Action::Block,
            FinalAction::Flag => Action::Flag,
            FinalAction::Pass => Action::Pass,
        };

        // Apply scope-based exemptions: filter out exempted rules.
        // A rule is exempted when is_rule_exempted(rule_id, scope, agent_id) returns true
        // AND the rule is marked exemptable. Non-exemptable rules are NEVER filtered.
        let scope_str = scopes::tool_to_scope(&req.tool_name).as_str();
        let exemptions = self.scope_exemptions.load();
        let effective_matches: Vec<_> = eval.rule_matches.iter().filter(|m| {
            if m.exemptable && thresholds::is_rule_exempted(&m.rule_id, &scope_str, &req.agent_id, &exemptions) {
                debug!(rule_id = %m.rule_id, scope = %scope_str, agent = %req.agent_id, "Rule exempted by scope");
                false // filtered out
            } else {
                true // kept
            }
        }).collect();

        let labels: Vec<String> = effective_matches
            .iter()
            .flat_map(|m| m.labels.clone())
            .collect();
        let matched_rules: Vec<String> = effective_matches.iter().map(|m| m.rule_id.clone()).collect();

        let has_non_exemptable_block =
            if self.plan_guard.is_enabled(FeatureFlags::SCOPE_PERMISSIONS) {
                effective_matches.iter().any(|m| m.action == ag_engine::compile::RuleAction::Block && !m.exemptable)
            } else {
                false
            };

        let mut reasoning = if eval.rule_matches.is_empty() {
            "No rules matched".to_string()
        } else {
            eval.rule_matches
                .iter()
                .map(|m| m.reasoning.clone())
                .collect::<Vec<_>>()
                .join("; ")
        };

        if delegation_risk > 0.0 {
            reasoning.push_str(&format!(
                "; A2A delegation risk={:.3}: {}",
                delegation_risk,
                delegation_flags.join(", ")
            ));
        }
        if descriptor_risk > 0.0 {
            reasoning.push_str(&format!(
                "; A2A descriptor risk={:.3}: {}",
                descriptor_risk,
                descriptor_flags.join(", ")
            ));
        }

        if eval.rule_matches.is_empty() {
            reasoning.push_str(" — classified as safe");
        }

        // For Hybrid tier, annotate that policy should also check scope
        if tier == DefenseTier::Hybrid {
            reasoning.push_str("; [hybrid] policy scope check also required");
        }

        let latency_us = start.elapsed().as_micros() as u64;

        debug!(
            tool = %req.tool_name,
            category = %category_name,
            defense_tier = defense_tier_label,
            assessed_risk,
            classification = classification.as_str(),
            rules_matched = matched_rules.len(),
            latency_us,
            "Intent classified"
        );

        // Detect schema injection from rule labels (not hardcoded IDs)
        let schema_injection_detected = labels
            .iter()
            .any(|l| l == "schema_injection" || l == "tool_confusion" || l == "schema_weakening" || l == "tool_surface_expansion");
        let schema_injection_type = if labels.iter().any(|l| l == "schema_injection" || l == "tool_surface_expansion") {
            "xml_injection".to_string()
        } else if labels.iter().any(|l| l == "tool_confusion") {
            "tool_steering".to_string()
        } else if labels.iter().any(|l| l == "schema_weakening") {
            "constraint_weakening".to_string()
        } else {
            String::new()
        };

        Ok(Response::new(ClassifyResponse {
            intent_risk,
            encoding_bonus,
            session_factor,
            assessed_risk,
            classification: classification.as_str().to_string(),
            labels,
            reasoning,
            matched_rules,
            session_flags: all_session_flags,
            action: action.into(),
            latency_us,
            has_non_exemptable_block,
            schema_injection_detected,
            schema_injection_type,
            category: category_name,
            defense_tier: defense_tier_label.to_string(),
        }))
    }
}

/// Recursively collect all string values from a JSON value.
fn collect_json_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for v in arr { collect_json_strings(v, out); }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() { collect_json_strings(v, out); }
        }
        _ => {}
    }
}
