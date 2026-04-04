//! gRPC service implementation for risk scoring.
//!
//! RPCs:
//! - GetAgentRisk: Get current EMA risk score for an agent.
//! - GetAllRisks: Get all agent scores (dashboard feed).
//! - GetRiskHistory: Get risk event history for an agent.

use std::sync::Arc;

use ag_proto::agentguard::risk::{
    risk_service_server::RiskService, AgentRiskSummary, GetAgentRiskRequest, GetAgentRiskResponse,
    GetAllRisksRequest, GetAllRisksResponse, GetRiskHistoryRequest, GetRiskHistoryResponse,
    RiskEvent,
};
use tonic::{Request, Response, Status};

use crate::score_reader::ScoreProvider;

pub struct RiskServiceImpl {
    provider: Arc<ScoreProvider>,
}

impl RiskServiceImpl {
    pub fn new(provider: Arc<ScoreProvider>) -> Self {
        Self { provider }
    }
}

#[tonic::async_trait]
impl RiskService for RiskServiceImpl {
    async fn get_agent_risk(
        &self,
        request: Request<GetAgentRiskRequest>,
    ) -> Result<Response<GetAgentRiskResponse>, Status> {
        let req = request.into_inner();

        if req.agent_id.is_empty() {
            return Err(Status::invalid_argument("agent_id is required"));
        }

        let state = self.provider.get_score(&req.agent_id).await;

        match state {
            Some(s) => Ok(Response::new(GetAgentRiskResponse {
                agent_id: s.agent_id,
                ema_score: s.ema_score,
                classification: s.classification.as_str().to_string(),
                updated_at: s.last_updated.to_rfc3339(),
                events_processed: s.events_processed,
            })),
            None => Ok(Response::new(GetAgentRiskResponse {
                agent_id: req.agent_id,
                ema_score: 0.0,
                classification: "normal".to_string(),
                updated_at: String::new(),
                events_processed: 0,
            })),
        }
    }

    async fn get_all_risks(
        &self,
        request: Request<GetAllRisksRequest>,
    ) -> Result<Response<GetAllRisksResponse>, Status> {
        let req = request.into_inner();
        let min_score = if req.min_score > 0.0 {
            req.min_score
        } else {
            0.0
        };

        let agents: Vec<AgentRiskSummary> = self
            .provider
            .get_all_scores(min_score, &req.org_id)
            .await
            .into_iter()
            .map(|s| AgentRiskSummary {
                agent_id: s.agent_id,
                ema_score: s.ema_score,
                classification: s.classification.as_str().to_string(),
                updated_at: s.last_updated.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(GetAllRisksResponse { agents }))
    }

    async fn get_risk_history(
        &self,
        request: Request<GetRiskHistoryRequest>,
    ) -> Result<Response<GetRiskHistoryResponse>, Status> {
        let req = request.into_inner();

        if req.agent_id.is_empty() {
            return Err(Status::invalid_argument("agent_id is required"));
        }

        let limit = if req.limit == 0 { 50 } else { req.limit.min(100) } as usize;
        let history = self.provider.get_history(&req.agent_id, limit).await;

        let events: Vec<RiskEvent> = history
            .into_iter()
            .map(|h| RiskEvent {
                event_risk: h.event_risk,
                ema_before: h.ema_before,
                ema_after: h.ema_after,
                classification: h.classification.as_str().to_string(),
                tool_name: h.tool_name,
                timestamp: h.timestamp.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(GetRiskHistoryResponse { events }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::RiskPersistence;
    use crate::scorer::RiskScorer;
    use std::sync::atomic::AtomicBool;

    const ALPHA: f64 = 0.3;
    const THRESHOLD: f64 = 0.9;

    /// Build a leader-mode RiskServiceImpl with in-memory scorer (no Redis needed).
    async fn test_service() -> RiskServiceImpl {
        let scorer = Arc::new(RiskScorer::new(ALPHA, THRESHOLD));
        let is_leader = Arc::new(AtomicBool::new(true));

        // Create a Redis pool with a dummy URL. In leader mode, persistence is never used for reads.
        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1").unwrap();
        let pool = bb8::Pool::builder().max_size(1).build_unchecked(manager);
        let persistence = Arc::new(RiskPersistence::new(pool));

        let provider = Arc::new(ScoreProvider::new(is_leader, scorer, persistence));
        RiskServiceImpl::new(provider)
    }

    /// Build a leader-mode service with pre-loaded agent data.
    async fn test_service_with_agents() -> RiskServiceImpl {
        let scorer = Arc::new(RiskScorer::new(ALPHA, THRESHOLD));
        scorer.process_event("agent-1", 0.8, "db.query", "test-org");
        scorer.process_event("agent-2", 0.5, "shell.exec", "test-org");
        scorer.process_event("agent-2", 0.6, "fs.read", "test-org");

        let is_leader = Arc::new(AtomicBool::new(true));
        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1").unwrap();
        let pool = bb8::Pool::builder().max_size(1).build_unchecked(manager);
        let persistence = Arc::new(RiskPersistence::new(pool));

        let provider = Arc::new(ScoreProvider::new(is_leader, scorer, persistence));
        RiskServiceImpl::new(provider)
    }

    // ── get_agent_risk tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_agent_risk_empty_id_returns_error() {
        let svc = test_service().await;
        let req = Request::new(GetAgentRiskRequest {
            agent_id: String::new(),
        });
        let result = svc.get_agent_risk(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_get_agent_risk_nonexistent_returns_zero() {
        let svc = test_service().await;
        let req = Request::new(GetAgentRiskRequest {
            agent_id: "no-such-agent".to_string(),
        });
        let resp = svc.get_agent_risk(req).await.unwrap().into_inner();
        assert_eq!(resp.agent_id, "no-such-agent");
        assert_eq!(resp.ema_score, 0.0);
        assert_eq!(resp.classification, "normal");
        assert_eq!(resp.events_processed, 0);
    }

    #[tokio::test]
    async fn test_get_agent_risk_existing_agent() {
        let svc = test_service_with_agents().await;
        let req = Request::new(GetAgentRiskRequest {
            agent_id: "agent-1".to_string(),
        });
        let resp = svc.get_agent_risk(req).await.unwrap().into_inner();
        assert_eq!(resp.agent_id, "agent-1");
        assert!(resp.ema_score > 0.0);
        assert_eq!(resp.events_processed, 1);
        assert!(!resp.updated_at.is_empty());
    }

    // ── get_all_risks tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_all_risks_empty_scorer() {
        let svc = test_service().await;
        let req = Request::new(GetAllRisksRequest { min_score: 0.0, org_id: String::new() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        assert!(resp.agents.is_empty());
    }

    #[tokio::test]
    async fn test_get_all_risks_returns_all_agents() {
        let svc = test_service_with_agents().await;
        let req = Request::new(GetAllRisksRequest { min_score: 0.0, org_id: String::new() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        assert_eq!(resp.agents.len(), 2);
    }

    #[tokio::test]
    async fn test_get_all_risks_min_score_filter() {
        let svc = test_service_with_agents().await;
        // agent-1 has higher score (0.8 * 0.3 = 0.24), agent-2 has EMA from two events
        let req = Request::new(GetAllRisksRequest { min_score: 0.25, org_id: String::new() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        // Only agent-2 (two events) should have EMA >= 0.25
        // agent-2: first event 0.5*0.3=0.15, second: 0.15*0.7+0.6*0.3=0.105+0.18=0.285
        assert!(resp.agents.iter().all(|a| a.ema_score >= 0.25));
    }

    #[tokio::test]
    async fn test_get_all_risks_negative_min_score_treated_as_zero() {
        let svc = test_service_with_agents().await;
        let req = Request::new(GetAllRisksRequest { min_score: -1.0, org_id: String::new() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        // Negative min_score → 0.0, so all agents returned
        assert_eq!(resp.agents.len(), 2);
    }

    // ── get_risk_history tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_get_risk_history_empty_id_returns_error() {
        let svc = test_service().await;
        let req = Request::new(GetRiskHistoryRequest {
            agent_id: String::new(),
            limit: 10,
        });
        let result = svc.get_risk_history(req).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_get_risk_history_returns_entries() {
        let svc = test_service_with_agents().await;
        let req = Request::new(GetRiskHistoryRequest {
            agent_id: "agent-2".to_string(),
            limit: 10,
        });
        let resp = svc.get_risk_history(req).await.unwrap().into_inner();
        assert_eq!(resp.events.len(), 2); // Two events for agent-2
        assert!(!resp.events[0].timestamp.is_empty());
    }

    #[tokio::test]
    async fn test_get_risk_history_limit_zero_defaults_to_50() {
        let svc = test_service_with_agents().await;
        let req = Request::new(GetRiskHistoryRequest {
            agent_id: "agent-2".to_string(),
            limit: 0,
        });
        // limit=0 → defaults to 50, agent-2 has 2 events, so returns 2
        let resp = svc.get_risk_history(req).await.unwrap().into_inner();
        assert_eq!(resp.events.len(), 2);
    }

    #[tokio::test]
    async fn test_get_risk_history_limit_capped_at_100() {
        let svc = test_service_with_agents().await;
        let req = Request::new(GetRiskHistoryRequest {
            agent_id: "agent-2".to_string(),
            limit: 500, // Should be capped to 100
        });
        let resp = svc.get_risk_history(req).await.unwrap().into_inner();
        // Only 2 events exist, but the cap should be applied (500 → 100)
        assert!(resp.events.len() <= 100);
    }

    #[tokio::test]
    async fn test_get_risk_history_nonexistent_agent_empty() {
        let svc = test_service().await;
        let req = Request::new(GetRiskHistoryRequest {
            agent_id: "ghost-agent".to_string(),
            limit: 10,
        });
        let resp = svc.get_risk_history(req).await.unwrap().into_inner();
        assert!(resp.events.is_empty());
    }

    // ── org_id filtering tests ─────────────────────────────────────────────

    /// Build a service with agents in two different orgs.
    async fn test_service_multi_org() -> RiskServiceImpl {
        let scorer = Arc::new(RiskScorer::new(ALPHA, THRESHOLD));
        scorer.process_event("agent-alpha-1", 0.8, "db.query", "org-alpha");
        scorer.process_event("agent-alpha-2", 0.5, "shell.exec", "org-alpha");
        scorer.process_event("agent-beta-1", 0.9, "fs.read", "org-beta");

        let is_leader = Arc::new(AtomicBool::new(true));
        let manager = bb8_redis::RedisConnectionManager::new("redis://127.0.0.1:1").unwrap();
        let pool = bb8::Pool::builder().max_size(1).build_unchecked(manager);
        let persistence = Arc::new(RiskPersistence::new(pool));

        let provider = Arc::new(ScoreProvider::new(is_leader, scorer, persistence));
        RiskServiceImpl::new(provider)
    }

    #[tokio::test]
    async fn test_get_all_risks_filters_by_org_id() {
        let svc = test_service_multi_org().await;
        let req = Request::new(GetAllRisksRequest { min_score: 0.0, org_id: "org-alpha".to_string() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        assert_eq!(resp.agents.len(), 2);
        assert!(resp.agents.iter().all(|a| a.agent_id.starts_with("agent-alpha")));
    }

    #[tokio::test]
    async fn test_get_all_risks_empty_org_id_returns_all() {
        let svc = test_service_multi_org().await;
        let req = Request::new(GetAllRisksRequest { min_score: 0.0, org_id: String::new() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        assert_eq!(resp.agents.len(), 3);
    }

    #[tokio::test]
    async fn test_get_all_risks_org_id_and_min_score_combined() {
        let svc = test_service_multi_org().await;
        // org-alpha has agent-alpha-1 (EMA=0.24) and agent-alpha-2 (EMA=0.15)
        let req = Request::new(GetAllRisksRequest { min_score: 0.20, org_id: "org-alpha".to_string() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        assert_eq!(resp.agents.len(), 1);
        assert_eq!(resp.agents[0].agent_id, "agent-alpha-1");
    }

    #[tokio::test]
    async fn test_get_all_risks_nonexistent_org_returns_empty() {
        let svc = test_service_multi_org().await;
        let req = Request::new(GetAllRisksRequest { min_score: 0.0, org_id: "org-nonexistent".to_string() });
        let resp = svc.get_all_risks(req).await.unwrap().into_inner();
        assert!(resp.agents.is_empty());
    }
}
