//! gRPC service implementation for the control plane.
//!
//! RPCs:
//! - GetStatus: Get control plane status (leader, license, versions).
//! - GetClusterHealth: Get cluster-wide health report.
//! - GetLicenseStatus: Get current license info.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ag_common::license::{LicenseStatus, LicenseValidator};
use ag_license::PlanGuard;
use ag_proto::agentguard::control::{
    control_service_server::ControlService, GetClusterHealthRequest, GetClusterHealthResponse,
    GetLicenseStatusRequest, GetLicenseStatusResponse, GetStatusRequest, GetStatusResponse,
    ServiceHealth,
};
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use chrono::Utc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

use crate::health;
use crate::leader::LeaderElection;

pub struct ControlServiceImpl {
    pub leader: Arc<LeaderElection>,
    pub is_leader: Arc<AtomicBool>,
    pub license_validator: Arc<RwLock<LicenseValidator>>,
    pub redis: Pool<RedisConnectionManager>,
    pub nats: async_nats::Client,
    pub rules_version: Arc<std::sync::atomic::AtomicU32>,
    pub policy_version: Arc<std::sync::atomic::AtomicU32>,
    pub started_at: std::time::Instant,
    /// License plan guard for feature gating (RBAC, WEBHOOKS, COMPLIANCE_EXPORT).
    pub plan_guard: Arc<PlanGuard>,
}

#[tonic::async_trait]
impl ControlService for ControlServiceImpl {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let is_leader = self.is_leader.load(Ordering::Relaxed);
        let leader_id = self
            .leader
            .current_leader()
            .await
            .unwrap_or_else(|| "unknown".to_string());

        let license = self.license_validator.read().await;
        let license_status = match license.status() {
            LicenseStatus::Valid(_) => "valid",
            LicenseStatus::Expired => "expired",
            LicenseStatus::GracePeriod { .. } => "grace_period",
            LicenseStatus::Revoked => "revoked",
            LicenseStatus::NoLicense => "community",
            LicenseStatus::InvalidSignature => "invalid",
            LicenseStatus::FeatureDisabled(_) => "feature_disabled",
        };
        let license_tier = license.tier().as_str().to_string();

        let uptime = self.started_at.elapsed();
        let uptime_str = format!("{}h{}m", uptime.as_secs() / 3600, (uptime.as_secs() % 3600) / 60);

        Ok(Response::new(GetStatusResponse {
            leader_id,
            is_leader,
            license_status: license_status.to_string(),
            license_tier,
            rules_version: self.rules_version.load(Ordering::Relaxed),
            policy_version: self.policy_version.load(Ordering::Relaxed),
            last_heartbeat: {
                let mut conn = match self.redis.get().await {
                    Ok(c) => Some(c),
                    Err(_) => None,
                };
                if let Some(ref mut c) = conn {
                    redis::cmd("GET")
                        .arg("ag:license:last_heartbeat")
                        .query_async::<String>(&mut **c)
                        .await
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            },
            uptime: uptime_str,
        }))
    }

    async fn get_cluster_health(
        &self,
        _request: Request<GetClusterHealthRequest>,
    ) -> Result<Response<GetClusterHealthResponse>, Status> {
        let license = self.license_validator.read().await;
        let license_status = match license.status() {
            LicenseStatus::Valid(_) => "valid",
            LicenseStatus::NoLicense => "community",
            other => "degraded",
        };

        let cluster = health::run_health_check(
            &self.redis,
            &self.nats,
            license_status,
            self.rules_version.load(Ordering::Relaxed),
        )
        .await;

        let services = cluster
            .services
            .into_iter()
            .map(|s| ServiceHealth {
                name: s.name,
                healthy: s.healthy,
                status: s.status,
                latency_ms: s.latency_ms,
            })
            .collect();

        Ok(Response::new(GetClusterHealthResponse {
            overall_status: cluster.overall_status,
            services,
            license_status: cluster.license_status,
            rules_version: cluster.rules_version,
            nats_status: cluster.nats_status,
            redis_status: cluster.redis_status,
            postgres_status: cluster.postgres_status,
            checked_at: cluster.checked_at,
        }))
    }

    async fn get_license_status(
        &self,
        _request: Request<GetLicenseStatusRequest>,
    ) -> Result<Response<GetLicenseStatusResponse>, Status> {
        let license = self.license_validator.read().await;

        let (status, tier, max_agents, max_rps, features, expires_at, grace_hours) =
            match license.status() {
                LicenseStatus::Valid(claims) => (
                    "valid".to_string(),
                    claims.tier_enum().as_str().to_string(),
                    claims.max_agents,
                    claims.max_rps,
                    claims.features.clone(),
                    chrono::DateTime::from_timestamp(claims.exp, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default(),
                    0u32,
                ),
                LicenseStatus::GracePeriod {
                    claims,
                    hours_remaining,
                } => (
                    "grace_period".to_string(),
                    claims.tier_enum().as_str().to_string(),
                    claims.max_agents,
                    claims.max_rps,
                    claims.features.clone(),
                    chrono::DateTime::from_timestamp(claims.exp, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default(),
                    *hours_remaining,
                ),
                LicenseStatus::NoLicense => (
                    "community".to_string(),
                    "community".to_string(),
                    5,
                    100,
                    vec![],
                    String::new(),
                    0,
                ),
                LicenseStatus::Expired => (
                    "expired".to_string(),
                    "community".to_string(),
                    0,
                    0,
                    vec![],
                    String::new(),
                    0,
                ),
                LicenseStatus::Revoked => (
                    "revoked".to_string(),
                    "community".to_string(),
                    0,
                    0,
                    vec![],
                    String::new(),
                    0,
                ),
                _ => (
                    "unknown".to_string(),
                    "community".to_string(),
                    0,
                    0,
                    vec![],
                    String::new(),
                    0,
                ),
            };

        Ok(Response::new(GetLicenseStatusResponse {
            status,
            tier,
            max_agents,
            max_rps,
            features,
            expires_at,
            grace_hours_remaining: grace_hours,
            last_heartbeat: String::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    /// Replicates the uptime formatting logic from `get_status`:
    ///   `format!("{}h{}m", secs / 3600, (secs % 3600) / 60)`
    fn format_uptime(secs: u64) -> String {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }

    // ── Uptime formatting ────────────────────────────────────────────

    #[test]
    fn uptime_zero_seconds() {
        assert_eq!(format_uptime(0), "0h0m");
    }

    #[test]
    fn uptime_less_than_one_minute() {
        // 30 seconds: 0 hours, 0 minutes (seconds are truncated)
        assert_eq!(format_uptime(30), "0h0m");
    }

    #[test]
    fn uptime_exactly_one_minute() {
        assert_eq!(format_uptime(60), "0h1m");
    }

    #[test]
    fn uptime_several_minutes() {
        // 5 minutes 30 seconds = 330 seconds
        assert_eq!(format_uptime(330), "0h5m");
    }

    #[test]
    fn uptime_exactly_one_hour() {
        assert_eq!(format_uptime(3600), "1h0m");
    }

    #[test]
    fn uptime_one_hour_thirty_minutes() {
        assert_eq!(format_uptime(5400), "1h30m");
    }

    #[test]
    fn uptime_multiple_hours_and_minutes() {
        // 2 hours 15 minutes = 8100 seconds
        assert_eq!(format_uptime(8100), "2h15m");
    }

    #[test]
    fn uptime_24_hours() {
        assert_eq!(format_uptime(86400), "24h0m");
    }

    #[test]
    fn uptime_more_than_24_hours() {
        // 25 hours 59 minutes = 93540 seconds
        assert_eq!(format_uptime(93540), "25h59m");
    }

    #[test]
    fn uptime_large_value() {
        // 1000 hours = 3600000 seconds
        assert_eq!(format_uptime(3_600_000), "1000h0m");
    }

    #[test]
    fn uptime_59_minutes_59_seconds() {
        // 3599 seconds = 0h59m (59 seconds are truncated)
        assert_eq!(format_uptime(3599), "0h59m");
    }

    #[test]
    fn uptime_one_second_before_one_hour() {
        assert_eq!(format_uptime(3599), "0h59m");
    }

    #[test]
    fn uptime_one_second_after_one_hour() {
        assert_eq!(format_uptime(3601), "1h0m");
    }

    #[test]
    fn uptime_exact_boundary_two_hours() {
        assert_eq!(format_uptime(7200), "2h0m");
    }

    #[test]
    fn uptime_format_does_not_pad_with_zeros() {
        // Verify that single-digit values are NOT zero-padded (e.g., "1h5m" not "01h05m")
        let result = format_uptime(3900); // 1h5m
        assert_eq!(result, "1h5m");
        assert!(!result.starts_with('0'));
    }

    #[test]
    fn uptime_format_contains_h_and_m_markers() {
        let result = format_uptime(7260); // 2h1m
        assert!(result.contains('h'));
        assert!(result.ends_with('m'));
    }
}
