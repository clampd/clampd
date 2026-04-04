use std::sync::Arc;

use ag_common::models::AgentState;
use ag_proto::agentguard::{
    common::{AgentProfile, BoundaryConfig},
    registry::{
        registry_service_server::RegistryService, AgentRelationship, GetAgentRequest,
        GetAgentResponse, GetAgentRelationshipsRequest, GetAgentRelationshipsResponse,
        GetChildAgentsRequest, GetChildAgentsResponse,
        GetRelationshipGraphRequest, GetRelationshipGraphResponse, RecordDelegationRequest,
        RecordDelegationResponse, RegisterAgentRequest, RegisterAgentResponse,
        TouchAgentRequest, TouchAgentResponse, UpdateAgentStateRequest,
        UpdateAgentStateResponse, UpdateRiskScoreRequest, UpdateRiskScoreResponse,
    },
};
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use ag_license::PlanGuard;

use crate::audit::{self, AuditLogger, AuditEvent};
use crate::cache;
use crate::lifecycle::StateTransition;
use crate::repository::{AgentRepository, AgentRow};
use crate::risk;

pub struct RegistryServiceImpl {
    repo: Arc<AgentRepository>,
    redis: Pool<RedisConnectionManager>,
    audit: AuditLogger,
    plan_guard: Arc<PlanGuard>,
}

impl RegistryServiceImpl {
    pub fn new(
        repo: Arc<AgentRepository>,
        redis: Pool<RedisConnectionManager>,
        audit: AuditLogger,
        plan_guard: Arc<PlanGuard>,
    ) -> Self {
        Self { repo, redis, audit, plan_guard }
    }

    fn relationship_to_proto(row: &crate::relationships::RelationshipRow) -> AgentRelationship {
        AgentRelationship {
            id: row.id.to_string(),
            parent_agent_id: row.parent_agent_id.to_string(),
            child_agent_id: row.child_agent_id.to_string(),
            relationship_type: row.relationship_type.clone(),
            confidence: row.confidence.clone(),
            allowed_tools: row.allowed_tools.clone(),
            max_delegation_depth: row.max_delegation_depth,
            first_observed_at: row.first_observed_at.to_rfc3339(),
            last_observed_at: row.last_observed_at.to_rfc3339(),
            observation_count: row.observation_count,
            status: row.status.clone(),
            tool_descriptor_hash: row.tool_descriptor_hash.clone().unwrap_or_default(),
        }
    }

    fn row_to_profile(row: &AgentRow, boundaries: Option<BoundaryConfig>) -> AgentProfile {
        AgentProfile {
            id: row.id.to_string(),
            org_id: row.org_id.to_string(),
            name: row.name.clone(),
            owner_user_id: String::new(),
            idp_realm: row.idp_subject.clone().unwrap_or_default(),
            declared_purpose: row.declared_purpose.clone().unwrap_or_default(),
            allowed_tools: Vec::new(),
            allowed_scopes: row.allowed_scopes.clone().unwrap_or_default(),
            state: row.state.clone(),
            risk_score: 0.0,
            // SECURITY: Never expose credential hashes in RPC responses.
            // The hash is only needed for ag-gateway's auth validation, which
            // reads directly from Redis (synced by ag-control), not via this RPC.
            credential_hash: String::new(),
            enforcement_mode: "enforce".to_string(),
            created_at: row.created_at.to_rfc3339(),
            last_active_at: row.updated_at.to_rfc3339(),
            boundaries,
        }
    }
}

#[tonic::async_trait]
impl RegistryService for RegistryServiceImpl {
    async fn get_agent(
        &self,
        request: Request<GetAgentRequest>,
    ) -> Result<Response<GetAgentResponse>, Status> {
        // TRUST BOUNDARY: ag-registry trusts that ag-gateway has verified org
        // ownership before calling this RPC. The gateway validates the caller's
        // API key → org_id mapping and only forwards requests for agents belonging
        // to that org. The proto GetAgentRequest does not carry org_id; org
        // isolation is enforced at the gateway level.
        let req = request.into_inner();
        let agent_id = req
            .agent_id
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid agent_id UUID"))?;

        // 1. Check Redis cache first
        if let Some(cached_profile) = cache::get_agent_cached(&self.redis, &req.agent_id).await {
            return Ok(Response::new(GetAgentResponse {
                agent: Some(cached_profile),
            }));
        }

        // 2. Cache miss — query DB
        let row = self
            .repo
            .get_agent(agent_id)
            .await
            .map_err(|e| e.to_tonic_status())?;

        let boundary_row = self.repo.get_boundaries(agent_id).await.ok().flatten();
        let boundaries = boundary_row.map(|b| BoundaryConfig {
            max_records_per_query: b.max_records_per_query.unwrap_or(1000) as u32,
            max_calls_per_minute: b.max_calls_per_min.unwrap_or(60) as u32,
            max_calls_per_session: b.max_calls_per_session.unwrap_or(0) as u32,
            max_data_volume_mb_per_hour: b.max_data_mb_per_hour.unwrap_or(100.0),
            blocked_external_domains: b.blocked_domains.unwrap_or_default(),
            allowed_hours_start: 0,
            allowed_hours_end: 0,
            allowed_hours_timezone: "UTC".to_string(),
            allowed_days: 127,
            auto_suspend_threshold: 0.9,
            allowed_external_domains: b.allowed_domains.unwrap_or_default(),
            max_payment_per_tx_cents: b.max_payment_per_tx_cents.unwrap_or(0) as u64,
            max_payment_per_hour_cents: b.max_payment_per_hour_cents.unwrap_or(0) as u64,
            approved_vendors: b.approved_vendors.unwrap_or_default(),
        });

        let profile = Self::row_to_profile(&row, boundaries);

        // 3. Populate cache on miss
        cache::set_agent_cached(
            &self.redis,
            &req.agent_id,
            &profile,
            cache::AGENT_CACHE_TTL_SECS,
        )
        .await;

        Ok(Response::new(GetAgentResponse {
            agent: Some(profile),
        }))
    }

    async fn register_agent(
        &self,
        request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        let req = request.into_inner();

        // Validate required fields
        if req.org_id.is_empty() {
            return Err(Status::invalid_argument("org_id is required"));
        }
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        // ---- AGENT CARD SHADOWING DETECTION ----
        // Prevent duplicate agent names within the same org.
        // An attacker could register a clone with the same name to cause lookup ambiguity.
        match self.repo.agent_name_exists(&req.org_id, &req.name).await {
            Ok(true) => {
                return Err(Status::already_exists(format!(
                    "Agent '{}' already exists in this organization. Use a unique name or update the existing agent.",
                    req.name
                )));
            }
            Ok(false) => {} // Name is available
            Err(e) => {
                warn!(error = %e, "Failed to check agent name uniqueness — proceeding (fail-open)");
            }
        }

        // Check agent limit before creating
        let current_count = self.repo.count_agents(&req.org_id).await.unwrap_or(0) as u32;
        if let Err(e) = self.plan_guard.check_agent_limit(current_count) {
            return Err(Status::permission_denied(format!(
                "Feature requires Enterprise plan: {}",
                e
            )));
        }

        let row = self
            .repo
            .create_agent(
                &req.org_id,
                &req.name,
                &req.declared_purpose,
                &req.credential_hash,
                &req.framework,
                &req.auth_mode,
            )
            .await
            .map_err(|e| e.to_tonic_status())?;

        let profile = Self::row_to_profile(&row, None);

        // Publish audit event
        let register_details = format!("Agent '{}' registered in org {}", req.name, req.org_id);
        self.audit
            .log_event(&profile.id, "registered", &register_details, "system")
            .await;
        // Persist audit to DB
        let register_event = AuditEvent::new(&profile.id, "registered", &register_details, "system");
        if let Err(e) = audit::persist_audit_to_db(self.repo.pool(), &register_event).await {
            tracing::warn!(error = %e, "Failed to persist register audit event to DB");
        }

        info!(agent_id = %profile.id, name = %req.name, org_id = %req.org_id, "Agent registered");

        Ok(Response::new(RegisterAgentResponse {
            agent: Some(profile),
        }))
    }

    async fn update_agent_state(
        &self,
        request: Request<UpdateAgentStateRequest>,
    ) -> Result<Response<UpdateAgentStateResponse>, Status> {
        // TRUST BOUNDARY: ag-registry trusts that ag-gateway (or ag-kill/ag-control)
        // has verified org ownership before calling this RPC. State transitions are
        // only triggered by internal services that have already validated the caller's
        // authority over this agent_id.
        let req = request.into_inner();
        let agent_id = req
            .agent_id
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid agent_id UUID"))?;

        // Validate state transition
        let current = self
            .repo
            .get_agent(agent_id)
            .await
            .map_err(|e| e.to_tonic_status())?;
        let current_state = AgentState::from_state_str(&current.state)
            .ok_or_else(|| Status::internal("Unknown current state"))?;
        let new_state = AgentState::from_state_str(&req.new_state)
            .ok_or_else(|| Status::invalid_argument("Invalid target state"))?;

        if !current_state.can_transition_to(new_state) {
            return Err(Status::failed_precondition(format!(
                "Cannot transition from {} to {}",
                current.state, req.new_state
            )));
        }

        let kill_reason = if new_state == AgentState::Killed {
            Some(req.reason.as_str())
        } else {
            None
        };

        let row = self
            .repo
            .update_state(agent_id, &req.new_state, kill_reason)
            .await
            .map_err(|e| e.to_tonic_status())?;

        // Invalidate cache
        cache::invalidate_agent_cache(&self.redis, &req.agent_id).await;

        // Set deny entry for suspended/killed agents (immediate gateway effect)
        if let Ok(mut conn) = self.redis.get().await {
            if matches!(new_state, AgentState::Suspended | AgentState::Killed) {
                let deny_key = format!("ag:deny:{}", agent_id);
                if let Err(e) = redis::cmd("SET")
                    .arg(&deny_key)
                    .arg("1")
                    .arg("EX")
                    .arg(600)
                    .query_async::<()>(&mut *conn)
                    .await
                {
                    error!(error = %e, agent_id = %agent_id, "Failed to SET deny key in Redis");
                }
            }

            // If revived (back to active), clear the deny entry so gateway allows requests
            if matches!(new_state, AgentState::Active) {
                let deny_key = format!("ag:deny:{}", agent_id);
                if let Err(e) = redis::cmd("DEL")
                    .arg(&deny_key)
                    .query_async::<()>(&mut *conn)
                    .await
                {
                    error!(error = %e, agent_id = %agent_id, "Failed to DEL deny key from Redis");
                }
            }
        }

        // Publish audit event
        let transition = StateTransition::new(
            &current.state,
            &req.new_state,
            &req.reason,
            &req.reason_code,
        );
        let state_detail = transition.audit_detail();
        self.audit
            .log_event(&req.agent_id, "state_changed", &state_detail, "system")
            .await;
        // Persist audit to DB
        let state_event = AuditEvent::new(&req.agent_id, "state_changed", &state_detail, "system");
        if let Err(e) = audit::persist_audit_to_db(self.repo.pool(), &state_event).await {
            tracing::warn!(error = %e, "Failed to persist state_changed audit event to DB");
        }

        info!(agent_id = %agent_id, from = %current.state, to = %req.new_state, "Agent state updated");

        let profile = Self::row_to_profile(&row, None);
        Ok(Response::new(UpdateAgentStateResponse {
            agent: Some(profile),
        }))
    }

    async fn update_risk_score(
        &self,
        request: Request<UpdateRiskScoreRequest>,
    ) -> Result<Response<UpdateRiskScoreResponse>, Status> {
        // TRUST BOUNDARY: ag-registry trusts that ag-risk has verified the agent
        // belongs to a valid org before calling this RPC. Risk score updates are
        // only triggered by ag-risk via internal gRPC, never by external callers.
        let req = request.into_inner();
        let agent_id = req
            .agent_id
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid agent_id UUID"))?;

        // Validate risk score range [0.0, 1.0]
        risk::validate_risk_score(req.risk_score)
            .map_err(|msg| Status::invalid_argument(msg))?;

        let row = self
            .repo
            .update_risk_score(agent_id, req.risk_score)
            .await
            .map_err(|e| e.to_tonic_status())?;

        // Invalidate cache
        cache::invalidate_agent_cache(&self.redis, &req.agent_id).await;

        // Check auto-suspend threshold: if risk exceeds threshold, auto-suspend
        if risk::exceeds_threshold(req.risk_score, risk::DEFAULT_AUTO_SUSPEND_THRESHOLD) {
            // Check if the agent is currently active before attempting auto-suspend
            if row.state == ag_common::models::AgentState::Active.as_str() {
                info!(
                    agent_id = %agent_id,
                    risk_score = req.risk_score,
                    threshold = risk::DEFAULT_AUTO_SUSPEND_THRESHOLD,
                    "Risk score exceeded threshold — auto-suspending agent"
                );

                // Auto-suspend the agent
                let _suspend_result = self
                    .repo
                    .update_state(agent_id, "suspended", None)
                    .await;

                // Invalidate cache again after state change
                cache::invalidate_agent_cache(&self.redis, &req.agent_id).await;

                // Set deny entry for immediate gateway effect
                if let Ok(mut conn) = self.redis.get().await {
                    let deny_key = format!("ag:deny:{}", agent_id);
                    if let Err(e) = redis::cmd("SET")
                        .arg(&deny_key)
                        .arg("1")
                        .arg("EX")
                        .arg(600)
                        .query_async::<()>(&mut *conn)
                        .await
                    {
                        error!(error = %e, agent_id = %agent_id, "Failed to SET deny key for auto-suspend in Redis");
                    }
                }

                // Audit the auto-suspension
                let suspend_detail = format!(
                    "active -> suspended (auto-suspend: risk score {} exceeded threshold {})",
                    req.risk_score, risk::DEFAULT_AUTO_SUSPEND_THRESHOLD
                );
                self.audit
                    .log_event(&req.agent_id, "state_changed", &suspend_detail, "system")
                    .await;
                // Persist audit to DB
                let suspend_event = AuditEvent::new(&req.agent_id, "state_changed", &suspend_detail, "system");
                if let Err(e) = audit::persist_audit_to_db(self.repo.pool(), &suspend_event).await {
                    tracing::warn!(error = %e, "Failed to persist auto-suspend audit event to DB");
                }
            }
        }

        // Audit the risk score update
        let risk_detail = format!("risk_score updated to {}", req.risk_score);
        self.audit
            .log_event(&req.agent_id, "risk_updated", &risk_detail, "system")
            .await;
        // Persist audit to DB
        let risk_event = AuditEvent::new(&req.agent_id, "risk_updated", &risk_detail, "system");
        if let Err(e) = audit::persist_audit_to_db(self.repo.pool(), &risk_event).await {
            tracing::warn!(error = %e, "Failed to persist risk_updated audit event to DB");
        }

        let profile = Self::row_to_profile(&row, None);
        Ok(Response::new(UpdateRiskScoreResponse {
            agent: Some(profile),
        }))
    }

    async fn touch_agent(
        &self,
        request: Request<TouchAgentRequest>,
    ) -> Result<Response<TouchAgentResponse>, Status> {
        let req = request.into_inner();

        // Write to Redis (debounced — background flusher updates DB every 60s)
        let touch_key = format!("ag:touch:{}", req.agent_id);
        let now = chrono::Utc::now().timestamp().to_string();
        if let Ok(mut conn) = self.redis.get().await {
            if let Err(e) = redis::cmd("SET")
                .arg(&touch_key)
                .arg(&now)
                .arg("EX")
                .arg(120)
                .query_async::<()>(&mut *conn)
                .await
            {
                warn!(error = %e, agent_id = %req.agent_id, "Failed to SET touch key in Redis");
            }
        }

        Ok(Response::new(TouchAgentResponse {}))
    }

    // ── A2A Delegation Relationship RPCs ─────────────────────────────

    async fn record_delegation(
        &self,
        request: Request<RecordDelegationRequest>,
    ) -> Result<Response<RecordDelegationResponse>, Status> {
        let req = request.into_inner();

        if req.parent_agent_id.is_empty() || req.child_agent_id.is_empty() {
            return Err(Status::invalid_argument(
                "parent_agent_id and child_agent_id are required",
            ));
        }

        // Validate UUIDs
        req.parent_agent_id
            .parse::<uuid::Uuid>()
            .map_err(|_| Status::invalid_argument("Invalid parent_agent_id UUID"))?;
        req.child_agent_id
            .parse::<uuid::Uuid>()
            .map_err(|_| Status::invalid_argument("Invalid child_agent_id UUID"))?;

        let confidence = if req.confidence.is_empty() {
            "inferred"
        } else {
            &req.confidence
        };

        let row = crate::relationships::record_delegation(
            self.repo.pool(),
            &req.parent_agent_id,
            &req.child_agent_id,
            confidence,
            &req.tools_observed,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to record delegation");
            Status::internal(format!("Failed to record delegation: {}", e))
        })?;

        // Audit the delegation observation
        let detail = format!(
            "Delegation observed: {} -> {} (confidence: {}, tools: [{}])",
            req.parent_agent_id,
            req.child_agent_id,
            confidence,
            req.tools_observed.join(", ")
        );
        self.audit
            .log_event(&req.parent_agent_id, "delegation_observed", &detail, "gateway")
            .await;

        info!(
            parent = %req.parent_agent_id,
            child = %req.child_agent_id,
            confidence = %confidence,
            observation_count = row.observation_count,
            "Delegation recorded"
        );

        Ok(Response::new(RecordDelegationResponse {
            relationship: Some(Self::relationship_to_proto(&row)),
        }))
    }

    async fn get_agent_relationships(
        &self,
        request: Request<GetAgentRelationshipsRequest>,
    ) -> Result<Response<GetAgentRelationshipsResponse>, Status> {
        let req = request.into_inner();

        if req.agent_id.is_empty() {
            return Err(Status::invalid_argument("agent_id is required"));
        }

        req.agent_id
            .parse::<uuid::Uuid>()
            .map_err(|_| Status::invalid_argument("Invalid agent_id UUID"))?;

        let rows = crate::relationships::get_agent_relationships(
            self.repo.pool(),
            &req.agent_id,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get agent relationships");
            Status::internal(format!("Failed to get relationships: {}", e))
        })?;

        let relationships: Vec<AgentRelationship> = rows
            .iter()
            .map(Self::relationship_to_proto)
            .collect();

        Ok(Response::new(GetAgentRelationshipsResponse {
            relationships,
        }))
    }

    async fn get_relationship_graph(
        &self,
        request: Request<GetRelationshipGraphRequest>,
    ) -> Result<Response<GetRelationshipGraphResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit > 0 { req.limit as i64 } else { 100 };

        // SECURITY: Filter by org_id to enforce tenant isolation on the
        // delegation graph. The org_id field was added to the proto to
        // prevent cross-tenant data leakage.
        if req.org_id.is_empty() {
            warn!("GetRelationshipGraph called without org_id — returning empty graph for safety");
            return Ok(Response::new(GetRelationshipGraphResponse {
                relationships: Vec::new(),
            }));
        }

        let rows = crate::relationships::get_relationship_graph(
            self.repo.pool(),
            &req.org_id,
            limit,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get relationship graph");
            Status::internal(format!("Failed to get relationship graph: {}", e))
        })?;

        let relationships: Vec<AgentRelationship> = rows
            .iter()
            .map(Self::relationship_to_proto)
            .collect();

        Ok(Response::new(GetRelationshipGraphResponse {
            relationships,
        }))
    }

    async fn get_child_agents(
        &self,
        request: Request<GetChildAgentsRequest>,
    ) -> Result<Response<GetChildAgentsResponse>, Status> {
        let req = request.into_inner();

        if req.parent_agent_id.is_empty() {
            return Err(Status::invalid_argument("parent_agent_id is required"));
        }

        req.parent_agent_id
            .parse::<uuid::Uuid>()
            .map_err(|_| Status::invalid_argument("Invalid parent_agent_id UUID"))?;

        let child_ids = crate::relationships::get_child_ids(
            self.repo.pool(),
            &req.parent_agent_id,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get child agents");
            Status::internal(format!("Failed to get child agents: {}", e))
        })?;

        Ok(Response::new(GetChildAgentsResponse {
            child_agent_ids: child_ids,
        }))
    }
}
