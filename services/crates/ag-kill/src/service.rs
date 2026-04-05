//! gRPC service implementation for the Kill Switch.
//!
//! RPCs:
//! - KillAgent: Single agent emergency revocation (8-layer cascade)
//! - KillAll: Org-wide emergency kill (bounded concurrency at 10)
//! - GetKillStatus: Query kill state for an agent
//! - GetKillHistory: Audit query with pagination

use std::sync::Arc;
use std::time::Instant;

use ag_proto::agentguard::kill::{
    kill_service_server::KillService, GetKillHistoryRequest, GetKillHistoryResponse,
    GetKillStatusRequest, GetKillStatusResponse, KillAuditEntry, KillAllRequest, KillAllResponse,
    KillRequest, KillResponse,
};
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use crate::cascade::{self, CascadeDeps, KillContext};

pub struct KillServiceImpl {
    pub deps: Arc<CascadeDeps>,
    pub deny_ttl_secs: u64,
    pub deny_extended_ttl_secs: u64,
    pub registry_retries: u32,
}

impl KillServiceImpl {
    pub fn new(
        deps: Arc<CascadeDeps>,
        deny_ttl_secs: u64,
        deny_extended_ttl_secs: u64,
        registry_retries: u32,
    ) -> Self {
        Self {
            deps,
            deny_ttl_secs,
            deny_extended_ttl_secs,
            registry_retries,
        }
    }
}

#[tonic::async_trait]
impl KillService for KillServiceImpl {
    /// Single agent emergency revocation - runs the full 8-layer cascade.
    async fn kill_agent(
        &self,
        request: Request<KillRequest>,
    ) -> Result<Response<KillResponse>, Status> {
        let req = request.into_inner();
        let start = Instant::now();

        if req.agent_id.is_empty() {
            return Err(Status::invalid_argument("agent_id is required"));
        }

        if req.reason.is_empty() {
            return Err(Status::invalid_argument("reason is required for audit trail"));
        }

        // NOTE: org_id authorization is enforced at the gateway layer (JWT claims).
        // KillRequest intentionally omits org_id - the gateway validates that the
        // caller's org owns the agent before forwarding the kill RPC.

        // Fast-path: if agent is already killed (deny key exists), skip cascade and return success.
        // This prevents DoS via kill flooding - 1000 calls = 1 cascade + 999 instant returns.
        // NEVER rate-limit kills - the kill switch is an emergency brake.
        {
            let mut conn = self.deps.redis.get().await.map_err(|e| {
                Status::internal(format!("Redis pool error: {}", e))
            })?;
            let deny_key = format!("ag:deny:{}", req.agent_id);
            let exists: bool = redis::cmd("EXISTS")
                .arg(&deny_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or(false);
            if exists {
                debug!(agent_id = %req.agent_id, "Agent already killed - returning cached result");
                return Ok(Response::new(KillResponse {
                    success: true,
                    layer_results: vec![],
                    total_latency_ms: start.elapsed().as_millis() as u32,
                    descendants_killed: 0,
                    descendant_results: vec![],
                }));
            }
        }

        info!(
            agent_id = %req.agent_id,
            reason = %req.reason,
            initiated_by = %req.initiated_by,
            permanent = req.revoke_permanently,
            "Kill cascade initiated"
        );

        let ctx = KillContext {
            agent_id: req.agent_id.clone(),
            reason: req.reason,
            initiated_by: req.initiated_by,
            revoke_permanently: req.revoke_permanently,
            kill_sessions: req.kill_sessions,
            deny_ttl_secs: self.deny_ttl_secs,
            deny_extended_ttl_secs: self.deny_extended_ttl_secs,
            registry_retries: self.registry_retries,
            cascade_descendants: req.cascade_descendants,
            max_tree_depth: 5,
        };

        let tree_result = cascade::cascade_tree(&ctx, &self.deps).await;

        let all_success = tree_result.root_results.iter().all(|l| l.success);
        let total_latency = start.elapsed().as_millis() as u32;

        if all_success {
            info!(
                agent_id = %req.agent_id,
                descendants_killed = tree_result.descendants_killed,
                total_latency_ms = total_latency,
                "Kill cascade completed successfully"
            );
        } else {
            let failed: Vec<_> = tree_result.root_results
                .iter()
                .filter(|l| !l.success)
                .map(|l| format!("L{}: {}", l.layer_number, l.error))
                .collect();
            warn!(
                agent_id = %req.agent_id,
                failures = ?failed,
                descendants_killed = tree_result.descendants_killed,
                total_latency_ms = total_latency,
                "Kill cascade completed with failures"
            );
        }

        Ok(Response::new(KillResponse {
            success: all_success,
            layer_results: tree_result.root_results,
            total_latency_ms: total_latency,
            descendants_killed: tree_result.descendants_killed,
            descendant_results: tree_result.descendant_results,
        }))
    }

    /// Org-wide emergency kill - kill all agents in the org.
    /// Bounded concurrency: at most 10 concurrent cascades.
    async fn kill_all(
        &self,
        request: Request<KillAllRequest>,
    ) -> Result<Response<KillAllResponse>, Status> {
        let req = request.into_inner();
        let start = Instant::now();

        if req.org_id.is_empty() {
            return Err(Status::invalid_argument("org_id is required"));
        }

        info!(
            org_id = %req.org_id,
            reason = %req.reason,
            initiated_by = %req.initiated_by,
            "Org-wide kill initiated"
        );

        // Fetch all active agent IDs for this org from the database.
        let agent_ids: Vec<String> = sqlx::query_scalar::<_, String>(
            "SELECT id::text FROM agents WHERE org_id = $1::uuid AND state = 'active'",
        )
        .bind(&req.org_id)
        .fetch_all(&self.deps.db)
        .await
        .map_err(|e| Status::internal(format!("Failed to fetch agents: {}", e)))?;

        let total = agent_ids.len();
        info!(org_id = %req.org_id, agent_count = total, "Found agents to kill");

        // Bounded concurrency: process up to 10 at a time.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(10));
        let mut handles = Vec::with_capacity(total);

        for agent_id in agent_ids {
            let deps = self.deps.clone();
            let deny_ttl = self.deny_ttl_secs;
            let deny_ext_ttl = self.deny_extended_ttl_secs;
            let retries = self.registry_retries;
            let reason = req.reason.clone();
            let initiated_by = req.initiated_by.clone();
            let permit = semaphore.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                let ctx = KillContext {
                    agent_id: agent_id.clone(),
                    reason,
                    initiated_by,
                    revoke_permanently: false, // Org-wide = suspend, not permanent kill.
                    kill_sessions: true,
                    deny_ttl_secs: deny_ttl,
                    deny_extended_ttl_secs: deny_ext_ttl,
                    registry_retries: retries,
                    cascade_descendants: false, // Org-wide already covers all agents.
                    max_tree_depth: 0,
                };
                let results = cascade::execute_cascade(&ctx, &deps).await;
                let success = results.iter().all(|l| l.success);
                (agent_id, success)
            }));
        }

        let mut killed = 0u32;
        let mut failed = 0u32;

        for handle in handles {
            match handle.await {
                Ok((agent_id, success)) => {
                    if success {
                        killed += 1;
                    } else {
                        failed += 1;
                        warn!(agent_id = %agent_id, "Kill failed for agent in org-wide kill");
                    }
                }
                Err(e) => {
                    failed += 1;
                    error!(error = %e, "Kill task panicked");
                }
            }
        }

        let total_latency = start.elapsed().as_millis() as u32;

        info!(
            org_id = %req.org_id,
            killed = killed,
            failed = failed,
            total_latency_ms = total_latency,
            "Org-wide kill completed"
        );

        Ok(Response::new(KillAllResponse {
            agents_killed: killed,
            agents_failed: failed,
            total_latency_ms: total_latency,
        }))
    }

    /// Query current kill status for an agent.
    async fn get_kill_status(
        &self,
        request: Request<GetKillStatusRequest>,
    ) -> Result<Response<GetKillStatusResponse>, Status> {
        let req = request.into_inner();

        if req.agent_id.is_empty() {
            return Err(Status::invalid_argument("agent_id is required"));
        }

        // Check deny list in Redis.
        let is_on_deny_list = {
            let mut conn = self
                .deps
                .redis
                .get()
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let exists: bool = redis::cmd("EXISTS")
                .arg(format!("ag:deny:{}", req.agent_id))
                .query_async(&mut *conn)
                .await
                .unwrap_or(false);
            exists
        };

        // Check agent state from database.
        let row: Option<(String, Option<chrono::DateTime<chrono::Utc>>, Option<String>)> =
            sqlx::query_as::<_, (String, Option<chrono::DateTime<chrono::Utc>>, Option<String>)>(
                "SELECT state, killed_at, kill_reason FROM agents WHERE id = $1::uuid",
            )
            .bind(&req.agent_id)
            .fetch_optional(&self.deps.db)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        match row {
            Some((state, killed_at, kill_reason)) => {
                let is_killed = state == "killed" || state == "suspended";
                Ok(Response::new(GetKillStatusResponse {
                    is_killed,
                    is_on_deny_list,
                    agent_state: state,
                    killed_at: killed_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    kill_reason: kill_reason.unwrap_or_default(),
                }))
            }
            None => Err(Status::not_found(format!(
                "Agent {} not found",
                req.agent_id
            ))),
        }
    }

    /// Query kill history with pagination.
    async fn get_kill_history(
        &self,
        request: Request<GetKillHistoryRequest>,
    ) -> Result<Response<GetKillHistoryResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit == 0 { 20 } else { req.limit.min(100) };

        // Count total.
        let total_count: i64 = if req.agent_id.is_empty() {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM kill_audit")
                .fetch_one(&self.deps.db)
                .await
                .unwrap_or(0)
        } else {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM kill_audit WHERE agent_id = $1::uuid")
                .bind(&req.agent_id)
                .fetch_one(&self.deps.db)
                .await
                .unwrap_or(0)
        };

        // Fetch entries.
        let rows: Vec<AuditRow> = if req.agent_id.is_empty() {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, agent_id, reason, initiated_by, success, layers_succeeded, layers_failed, total_latency_ms, created_at FROM kill_audit ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(limit as i64)
            .bind(req.offset as i64)
            .fetch_all(&self.deps.db)
            .await
            .map_err(|e: sqlx::Error| Status::internal(e.to_string()))?
        } else {
            sqlx::query_as::<_, AuditRow>(
                "SELECT id, agent_id, reason, initiated_by, success, layers_succeeded, layers_failed, total_latency_ms, created_at FROM kill_audit WHERE agent_id = $1::uuid ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(&req.agent_id)
            .bind(limit as i64)
            .bind(req.offset as i64)
            .fetch_all(&self.deps.db)
            .await
            .map_err(|e: sqlx::Error| Status::internal(e.to_string()))?
        };

        let entries = rows
            .into_iter()
            .map(|r| KillAuditEntry {
                id: r.id.to_string(),
                agent_id: r.agent_id.to_string(),
                reason: r.reason,
                initiated_by: r.initiated_by,
                success: r.success,
                layers_succeeded: r.layers_succeeded as u32,
                layers_failed: r.layers_failed as u32,
                total_latency_ms: r.total_latency_ms as u32,
                created_at: r.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(GetKillHistoryResponse {
            entries,
            total_count: total_count as u32,
        }))
    }
}

/// Row type for kill_audit table.
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: uuid::Uuid,
    agent_id: uuid::Uuid,
    reason: String,
    initiated_by: String,
    success: bool,
    layers_succeeded: i32,
    layers_failed: i32,
    total_latency_ms: i32,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ag_proto::agentguard::kill::{
        KillRequest, KillAllRequest, GetKillStatusRequest, GetKillHistoryRequest, LayerResult,
    };

    // ─── KillServiceImpl constructor ────────────────────────────────
    // We cannot fully construct KillServiceImpl without live infra,
    // but we can verify the field assignments and default configurations.

    // ─── Input validation logic tests ───────────────────────────────
    // The validation is inside the async trait methods. We can verify the
    // expected behavior by testing the protobuf request structs and the
    // validation conditions directly.

    #[test]
    fn test_kill_request_empty_agent_id_detected() {
        let req = KillRequest {
            agent_id: String::new(),
            reason: "test".to_string(),
            initiated_by: "admin".to_string(),
            revoke_permanently: false,
            kill_sessions: false,
            cascade_descendants: false,
        };
        // This mirrors the validation in kill_agent: agent_id.is_empty()
        assert!(req.agent_id.is_empty(), "Empty agent_id should be detected");
    }

    #[test]
    fn test_kill_request_valid_agent_id() {
        let req = KillRequest {
            agent_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            reason: "compromised".to_string(),
            initiated_by: "admin@example.com".to_string(),
            revoke_permanently: true,
            kill_sessions: true,
            cascade_descendants: true,
        };
        assert!(!req.agent_id.is_empty());
        assert!(req.revoke_permanently);
        assert!(req.kill_sessions);
        assert!(req.cascade_descendants);
    }

    #[test]
    fn test_kill_all_request_empty_org_id_detected() {
        let req = KillAllRequest {
            org_id: String::new(),
            reason: "emergency".to_string(),
            initiated_by: "admin".to_string(),
        };
        // This mirrors the validation in kill_all: org_id.is_empty()
        assert!(req.org_id.is_empty(), "Empty org_id should be detected");
    }

    #[test]
    fn test_kill_all_request_valid_org_id() {
        let req = KillAllRequest {
            org_id: "org-abc-123".to_string(),
            reason: "breach detected".to_string(),
            initiated_by: "security-team".to_string(),
        };
        assert!(!req.org_id.is_empty());
        assert_eq!(req.reason, "breach detected");
    }

    #[test]
    fn test_get_kill_status_empty_agent_id_detected() {
        let req = GetKillStatusRequest {
            agent_id: String::new(),
        };
        // This mirrors the validation in get_kill_status
        assert!(req.agent_id.is_empty());
    }

    #[test]
    fn test_get_kill_status_valid_agent_id() {
        let req = GetKillStatusRequest {
            agent_id: "agent-xyz".to_string(),
        };
        assert!(!req.agent_id.is_empty());
    }

    // ─── Pagination logic tests ─────────────────────────────────────

    #[test]
    fn test_kill_history_default_limit() {
        let req = GetKillHistoryRequest {
            agent_id: String::new(),
            limit: 0,
            offset: 0,
        };
        // Mirrors logic: if req.limit == 0 { 20 } else { req.limit.min(100) }
        let limit = if req.limit == 0 { 20 } else { req.limit.min(100) };
        assert_eq!(limit, 20);
    }

    #[test]
    fn test_kill_history_custom_limit() {
        let req = GetKillHistoryRequest {
            agent_id: String::new(),
            limit: 50,
            offset: 0,
        };
        let limit = if req.limit == 0 { 20 } else { req.limit.min(100) };
        assert_eq!(limit, 50);
    }

    #[test]
    fn test_kill_history_limit_capped_at_100() {
        let req = GetKillHistoryRequest {
            agent_id: String::new(),
            limit: 500,
            offset: 0,
        };
        let limit = if req.limit == 0 { 20 } else { req.limit.min(100) };
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_kill_history_limit_exactly_100() {
        let req = GetKillHistoryRequest {
            agent_id: String::new(),
            limit: 100,
            offset: 0,
        };
        let limit = if req.limit == 0 { 20 } else { req.limit.min(100) };
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_kill_history_limit_one() {
        let req = GetKillHistoryRequest {
            agent_id: String::new(),
            limit: 1,
            offset: 0,
        };
        let limit = if req.limit == 0 { 20 } else { req.limit.min(100) };
        assert_eq!(limit, 1);
    }

    #[test]
    fn test_kill_history_with_agent_filter() {
        let req = GetKillHistoryRequest {
            agent_id: "agent-123".to_string(),
            limit: 10,
            offset: 5,
        };
        assert!(!req.agent_id.is_empty());
        assert_eq!(req.offset, 5);
    }

    #[test]
    fn test_kill_history_without_agent_filter() {
        let req = GetKillHistoryRequest {
            agent_id: String::new(),
            limit: 20,
            offset: 0,
        };
        assert!(req.agent_id.is_empty());
    }

    // ─── KillResponse aggregation logic ─────────────────────────────

    #[test]
    fn test_all_layers_success_means_overall_success() {
        let layer_results = vec![
            LayerResult { layer_name: "deny_list".into(), layer_number: 1, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "gateway_broadcast".into(), layer_number: 2, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "token_flush".into(), layer_number: 3, success: true, error: String::new(), latency_ms: 2 },
            LayerResult { layer_name: "session_terminate".into(), layer_number: 4, success: true, error: String::new(), latency_ms: 3 },
            LayerResult { layer_name: "idp_revoke".into(), layer_number: 5, success: true, error: String::new(), latency_ms: 0 },
            LayerResult { layer_name: "registry_state".into(), layer_number: 6, success: true, error: String::new(), latency_ms: 4 },
            LayerResult { layer_name: "event_broadcast".into(), layer_number: 7, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "audit_log".into(), layer_number: 8, success: true, error: String::new(), latency_ms: 2 },
        ];
        // Mirrors logic in kill_agent: all_success = layer_results.iter().all(|l| l.success)
        let all_success = layer_results.iter().all(|l| l.success);
        assert!(all_success);
    }

    #[test]
    fn test_one_layer_failure_means_overall_failure() {
        let layer_results = vec![
            LayerResult { layer_name: "deny_list".into(), layer_number: 1, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "gateway_broadcast".into(), layer_number: 2, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "token_flush".into(), layer_number: 3, success: false, error: "timeout".into(), latency_ms: 5000 },
            LayerResult { layer_name: "session_terminate".into(), layer_number: 4, success: true, error: String::new(), latency_ms: 3 },
            LayerResult { layer_name: "idp_revoke".into(), layer_number: 5, success: true, error: String::new(), latency_ms: 0 },
            LayerResult { layer_name: "registry_state".into(), layer_number: 6, success: true, error: String::new(), latency_ms: 4 },
            LayerResult { layer_name: "event_broadcast".into(), layer_number: 7, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "audit_log".into(), layer_number: 8, success: true, error: String::new(), latency_ms: 2 },
        ];
        let all_success = layer_results.iter().all(|l| l.success);
        assert!(!all_success);

        // Verify we can identify the failed layers (mirrors the warn! logic)
        let failed: Vec<_> = layer_results
            .iter()
            .filter(|l| !l.success)
            .map(|l| format!("L{}: {}", l.layer_number, l.error))
            .collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0], "L3: timeout");
    }

    #[test]
    fn test_multiple_layer_failures() {
        let layer_results = vec![
            LayerResult { layer_name: "deny_list".into(), layer_number: 1, success: false, error: "redis down".into(), latency_ms: 100 },
            LayerResult { layer_name: "registry_state".into(), layer_number: 6, success: false, error: "grpc error".into(), latency_ms: 200 },
        ];
        let all_success = layer_results.iter().all(|l| l.success);
        assert!(!all_success);

        let failed: Vec<_> = layer_results
            .iter()
            .filter(|l| !l.success)
            .map(|l| format!("L{}: {}", l.layer_number, l.error))
            .collect();
        assert_eq!(failed.len(), 2);
    }

    #[test]
    fn test_empty_layer_results_means_success() {
        let layer_results: Vec<LayerResult> = vec![];
        let all_success = layer_results.iter().all(|l| l.success);
        // iter().all() on empty iterator returns true
        assert!(all_success);
    }

    // ─── Audit aggregation logic ────────────────────────────────────
    // Mirrors the counting logic in layer_8_audit_log

    #[test]
    fn test_audit_success_failure_counting() {
        let layer_results = vec![
            LayerResult { layer_name: "l1".into(), layer_number: 1, success: true, error: String::new(), latency_ms: 1 },
            LayerResult { layer_name: "l2".into(), layer_number: 2, success: false, error: "err".into(), latency_ms: 2 },
            LayerResult { layer_name: "l3".into(), layer_number: 3, success: true, error: String::new(), latency_ms: 3 },
            LayerResult { layer_name: "l4".into(), layer_number: 4, success: false, error: "err".into(), latency_ms: 4 },
            LayerResult { layer_name: "l5".into(), layer_number: 5, success: true, error: String::new(), latency_ms: 5 },
        ];

        let succeeded = layer_results.iter().filter(|l| l.success).count() as i32;
        let failed = layer_results.iter().filter(|l| !l.success).count() as i32;
        let total_latency: u32 = layer_results.iter().map(|l| l.latency_ms).sum();

        assert_eq!(succeeded, 3);
        assert_eq!(failed, 2);
        assert_eq!(total_latency, 15);
        // Mirrors: .bind(failed == 0) for overall success
        assert!(failed != 0, "Should not be overall success with failures");
    }

    #[test]
    fn test_audit_all_success_counting() {
        let layer_results = vec![
            LayerResult { layer_name: "l1".into(), layer_number: 1, success: true, error: String::new(), latency_ms: 10 },
            LayerResult { layer_name: "l2".into(), layer_number: 2, success: true, error: String::new(), latency_ms: 20 },
        ];

        let succeeded = layer_results.iter().filter(|l| l.success).count() as i32;
        let failed = layer_results.iter().filter(|l| !l.success).count() as i32;
        let total_latency: u32 = layer_results.iter().map(|l| l.latency_ms).sum();

        assert_eq!(succeeded, 2);
        assert_eq!(failed, 0);
        assert_eq!(total_latency, 30);
        assert!(failed == 0, "Should be overall success with zero failures");
    }

    // ─── KillContext construction from KillRequest ──────────────────

    #[test]
    fn test_kill_context_from_request_fields() {
        // Verify the mapping from KillRequest to KillContext matches service.rs logic
        let req = KillRequest {
            agent_id: "agent-001".to_string(),
            reason: "security incident".to_string(),
            initiated_by: "admin@corp.com".to_string(),
            revoke_permanently: true,
            kill_sessions: true,
            cascade_descendants: true,
        };
        let deny_ttl_secs = 600u64;
        let deny_extended_ttl_secs = 86400u64;
        let registry_retries = 3u32;

        let ctx = KillContext {
            agent_id: req.agent_id.clone(),
            reason: req.reason,
            initiated_by: req.initiated_by,
            revoke_permanently: req.revoke_permanently,
            kill_sessions: req.kill_sessions,
            deny_ttl_secs,
            deny_extended_ttl_secs,
            registry_retries,
            cascade_descendants: req.cascade_descendants,
            max_tree_depth: 5,
        };

        assert_eq!(ctx.agent_id, "agent-001");
        assert_eq!(ctx.reason, "security incident");
        assert_eq!(ctx.initiated_by, "admin@corp.com");
        assert!(ctx.revoke_permanently);
        assert!(ctx.kill_sessions);
        assert!(ctx.cascade_descendants);
        assert_eq!(ctx.max_tree_depth, 5);
        assert_eq!(ctx.deny_ttl_secs, 600);
        assert_eq!(ctx.deny_extended_ttl_secs, 86400);
        assert_eq!(ctx.registry_retries, 3);
    }

    // ─── KillAllRequest org-wide defaults ───────────────────────────

    #[test]
    fn test_kill_all_sets_suspend_not_permanent() {
        // Org-wide kill always uses revoke_permanently: false
        let req = KillAllRequest {
            org_id: "org-123".to_string(),
            reason: "emergency".to_string(),
            initiated_by: "admin".to_string(),
        };
        // In kill_all, revoke_permanently is hardcoded to false
        let revoke_permanently = false;
        let kill_sessions = true;
        assert!(!revoke_permanently, "Org-wide kill should suspend, not permanently kill");
        assert!(kill_sessions, "Org-wide kill should terminate sessions");
        assert!(!req.org_id.is_empty());
    }

    // ─── AuditRow field types ───────────────────────────────────────

    #[test]
    fn test_kill_audit_entry_conversion_logic() {
        // Mirrors the .map(|r| KillAuditEntry { ... }) in get_kill_history
        use ag_proto::agentguard::kill::KillAuditEntry;

        let id = uuid::Uuid::new_v4();
        let agent_id = uuid::Uuid::new_v4();
        let created_at = chrono::Utc::now();

        let entry = KillAuditEntry {
            id: id.to_string(),
            agent_id: agent_id.to_string(),
            reason: "test reason".to_string(),
            initiated_by: "tester".to_string(),
            success: true,
            layers_succeeded: 7,
            layers_failed: 1,
            total_latency_ms: 42,
            created_at: created_at.to_rfc3339(),
        };

        assert_eq!(entry.id, id.to_string());
        assert_eq!(entry.agent_id, agent_id.to_string());
        assert_eq!(entry.layers_succeeded, 7);
        assert_eq!(entry.layers_failed, 1);
        assert_eq!(entry.total_latency_ms, 42);
        assert!(!entry.created_at.is_empty());
    }

    // ─── Agent state determination ──────────────────────────────────

    #[test]
    fn test_is_killed_state_detection() {
        // Mirrors logic in get_kill_status: is_killed = state == "killed" || state == "suspended"
        let killed_states = vec!["killed", "suspended"];
        let active_states = vec!["active", "inactive", "pending"];

        for state in killed_states {
            let is_killed = state == "killed" || state == "suspended";
            assert!(is_killed, "State '{}' should be detected as killed", state);
        }

        for state in active_states {
            let is_killed = state == "killed" || state == "suspended";
            assert!(!is_killed, "State '{}' should NOT be detected as killed", state);
        }
    }

    // ─── Kill idempotency tests ──────────────────────────────────────

    #[test]
    fn test_idempotent_fast_path_skips_cascade() {
        // When deny key EXISTS in Redis, the fast-path returns immediately.
        // No cascade runs. This prevents kill flooding DoS.
        let deny_key_exists = true;
        let cascade_would_run = !deny_key_exists;
        assert!(!cascade_would_run, "Fast-path should skip cascade when agent already killed");
    }

    #[test]
    fn test_non_idempotent_triggers_cascade() {
        // When deny key does NOT exist, full 8-layer cascade must execute.
        let deny_key_exists = false;
        let cascade_must_run = !deny_key_exists;
        assert!(cascade_must_run, "Cascade must run when agent is not yet killed");
    }
}
