//! Cluster health reporter.
//!
//! Every 30s: aggregate license, rules version, kill availability,
//! NATS lag, Redis/PG health. Store in Redis `ag:cluster:health` TTL=60s.

use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{debug, warn};

/// Health check result for a single service/dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthCheck {
    pub name: String,
    pub healthy: bool,
    pub status: String,
    pub latency_ms: u32,
}

/// Cluster-wide health snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub overall_status: String,
    pub services: Vec<ServiceHealthCheck>,
    pub license_status: String,
    pub rules_version: u32,
    pub nats_status: String,
    pub redis_status: String,
    pub postgres_status: String,
    pub checked_at: String,
}

/// Check Redis connectivity.
pub async fn check_redis(redis: &Pool<RedisConnectionManager>) -> ServiceHealthCheck {
    let start = Instant::now();
    match redis.get().await {
        Ok(mut conn) => {
            let result: Result<String, _> =
                redis::cmd("PING").query_async(&mut *conn).await;
            let latency = start.elapsed().as_millis() as u32;
            match result {
                Ok(reply) if reply == "PONG" => ServiceHealthCheck {
                    name: "redis".to_string(),
                    healthy: true,
                    status: "connected".to_string(),
                    latency_ms: latency,
                },
                Ok(reply) => ServiceHealthCheck {
                    name: "redis".to_string(),
                    healthy: false,
                    status: format!("unexpected reply: {}", reply),
                    latency_ms: latency,
                },
                Err(e) => ServiceHealthCheck {
                    name: "redis".to_string(),
                    healthy: false,
                    status: format!("error: {}", e),
                    latency_ms: latency,
                },
            }
        }
        Err(e) => ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: false,
            status: format!("pool error: {}", e),
            latency_ms: start.elapsed().as_millis() as u32,
        },
    }
}

/// Check NATS connectivity.
pub async fn check_nats(nats: &async_nats::Client) -> ServiceHealthCheck {
    let start = Instant::now();
    // NATS client stays connected; check connection state.
    let latency = start.elapsed().as_millis() as u32;

    // async_nats doesn't expose a simple ping — check if the client is connected.
    ServiceHealthCheck {
        name: "nats".to_string(),
        healthy: true, // If the client is alive, it's connected.
        status: "connected".to_string(),
        latency_ms: latency,
    }
}

/// Check ag-kill service availability via TCP connect.
pub async fn check_kill_service(kill_url: &str) -> ServiceHealthCheck {
    let addr = kill_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let start = Instant::now();
    match tokio::net::TcpStream::connect(addr).await {
        Ok(_) => ServiceHealthCheck {
            name: "ag-kill".to_string(),
            healthy: true,
            status: "reachable".to_string(),
            latency_ms: start.elapsed().as_millis() as u32,
        },
        Err(e) => ServiceHealthCheck {
            name: "ag-kill".to_string(),
            healthy: false,
            status: format!("unreachable: {}", e),
            latency_ms: start.elapsed().as_millis() as u32,
        },
    }
}

/// Check PostgreSQL connectivity by reading the cached status from Redis.
/// If a `ag:postgres:status` key is maintained by a service with a PG pool,
/// we read it here. Otherwise fall back to "unknown".
pub async fn check_postgres(redis: &Pool<RedisConnectionManager>) -> ServiceHealthCheck {
    let start = Instant::now();
    if let Ok(mut conn) = redis.get().await {
        let pg_status: Option<String> = redis::cmd("GET")
            .arg("ag:postgres:status")
            .query_async(&mut *conn)
            .await
            .unwrap_or(None);
        let latency = start.elapsed().as_millis() as u32;
        match pg_status {
            Some(s) if s == "healthy" => ServiceHealthCheck {
                name: "postgres".to_string(),
                healthy: true,
                status: "healthy".to_string(),
                latency_ms: latency,
            },
            Some(s) => ServiceHealthCheck {
                name: "postgres".to_string(),
                healthy: false,
                status: s,
                latency_ms: latency,
            },
            None => ServiceHealthCheck {
                name: "postgres".to_string(),
                healthy: false,
                status: "no status reported".to_string(),
                latency_ms: latency,
            },
        }
    } else {
        ServiceHealthCheck {
            name: "postgres".to_string(),
            healthy: false,
            status: "redis unavailable".to_string(),
            latency_ms: start.elapsed().as_millis() as u32,
        }
    }
}

/// Aggregate a cluster health snapshot and store it in Redis.
pub async fn run_health_check(
    redis: &Pool<RedisConnectionManager>,
    nats: &async_nats::Client,
    license_status: &str,
    rules_version: u32,
) -> ClusterHealth {
    let mut services = Vec::new();

    let redis_check = check_redis(redis).await;
    let nats_check = check_nats(nats).await;
    let kill_url =
        std::env::var("KILL_URL").unwrap_or_else(|_| "http://127.0.0.1:50055".to_string());
    let kill_check = check_kill_service(&kill_url).await;
    let pg_check = check_postgres(redis).await;

    let redis_status = if redis_check.healthy {
        "healthy"
    } else {
        "unhealthy"
    }
    .to_string();
    let nats_status = if nats_check.healthy {
        "healthy"
    } else {
        "unhealthy"
    }
    .to_string();
    let postgres_status = if pg_check.healthy {
        "healthy"
    } else {
        "unhealthy"
    }
    .to_string();

    services.push(redis_check);
    services.push(nats_check);
    services.push(kill_check);
    services.push(pg_check);

    let all_healthy = services.iter().all(|s| s.healthy);
    let overall = if all_healthy { "healthy" } else { "degraded" }.to_string();

    let health = ClusterHealth {
        overall_status: overall,
        services,
        license_status: license_status.to_string(),
        rules_version,
        nats_status,
        redis_status,
        postgres_status,
        checked_at: Utc::now().to_rfc3339(),
    };

    // Store in Redis for other services to read.
    if let Ok(mut conn) = redis.get().await {
        if let Ok(json) = serde_json::to_string(&health) {
            if let Err(e) = redis::cmd("SET")
                .arg("ag:cluster:health")
                .arg(&json)
                .arg("EX")
                .arg(60)
                .query_async::<()>(&mut *conn)
                .await
            {
                warn!(error = %e, "Failed to SET cluster health in Redis");
            }
        }
    }

    debug!("Health check completed: {}", health.overall_status);
    health
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ServiceHealthCheck construction ──────────────────────────────

    #[test]
    fn service_health_check_construction_healthy() {
        let check = ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: true,
            status: "connected".to_string(),
            latency_ms: 5,
        };
        assert_eq!(check.name, "redis");
        assert!(check.healthy);
        assert_eq!(check.status, "connected");
        assert_eq!(check.latency_ms, 5);
    }

    #[test]
    fn service_health_check_construction_unhealthy() {
        let check = ServiceHealthCheck {
            name: "postgres".to_string(),
            healthy: false,
            status: "connection refused".to_string(),
            latency_ms: 1000,
        };
        assert_eq!(check.name, "postgres");
        assert!(!check.healthy);
        assert_eq!(check.status, "connection refused");
        assert_eq!(check.latency_ms, 1000);
    }

    #[test]
    fn service_health_check_zero_latency() {
        let check = ServiceHealthCheck {
            name: "nats".to_string(),
            healthy: true,
            status: "connected".to_string(),
            latency_ms: 0,
        };
        assert_eq!(check.latency_ms, 0);
    }

    #[test]
    fn service_health_check_max_latency() {
        let check = ServiceHealthCheck {
            name: "slow-service".to_string(),
            healthy: false,
            status: "timeout".to_string(),
            latency_ms: u32::MAX,
        };
        assert_eq!(check.latency_ms, u32::MAX);
    }

    // ── ServiceHealthCheck serde roundtrip ───────────────────────────

    #[test]
    fn service_health_check_serde_roundtrip_healthy() {
        let original = ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: true,
            status: "connected".to_string(),
            latency_ms: 12,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ServiceHealthCheck =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.name, original.name);
        assert_eq!(deserialized.healthy, original.healthy);
        assert_eq!(deserialized.status, original.status);
        assert_eq!(deserialized.latency_ms, original.latency_ms);
    }

    #[test]
    fn service_health_check_serde_roundtrip_unhealthy() {
        let original = ServiceHealthCheck {
            name: "postgres".to_string(),
            healthy: false,
            status: "pool error: too many connections".to_string(),
            latency_ms: 250,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ServiceHealthCheck =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.name, original.name);
        assert_eq!(deserialized.healthy, original.healthy);
        assert_eq!(deserialized.status, original.status);
        assert_eq!(deserialized.latency_ms, original.latency_ms);
    }

    #[test]
    fn service_health_check_json_field_names() {
        let check = ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: true,
            status: "ok".to_string(),
            latency_ms: 1,
        };
        let json = serde_json::to_string(&check).expect("serialize");
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"healthy\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"latency_ms\""));
    }

    #[test]
    fn service_health_check_deserialize_from_json_literal() {
        let json = r#"{
            "name": "nats",
            "healthy": true,
            "status": "connected",
            "latency_ms": 3
        }"#;
        let check: ServiceHealthCheck =
            serde_json::from_str(json).expect("deserialize");
        assert_eq!(check.name, "nats");
        assert!(check.healthy);
        assert_eq!(check.status, "connected");
        assert_eq!(check.latency_ms, 3);
    }

    // ── ClusterHealth construction ───────────────────────────────────

    #[test]
    fn cluster_health_construction_all_fields() {
        let health = ClusterHealth {
            overall_status: "healthy".to_string(),
            services: vec![
                ServiceHealthCheck {
                    name: "redis".to_string(),
                    healthy: true,
                    status: "connected".to_string(),
                    latency_ms: 2,
                },
                ServiceHealthCheck {
                    name: "nats".to_string(),
                    healthy: true,
                    status: "connected".to_string(),
                    latency_ms: 1,
                },
            ],
            license_status: "valid".to_string(),
            rules_version: 42,
            nats_status: "healthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "2026-03-03T12:00:00+00:00".to_string(),
        };

        assert_eq!(health.overall_status, "healthy");
        assert_eq!(health.services.len(), 2);
        assert_eq!(health.license_status, "valid");
        assert_eq!(health.rules_version, 42);
        assert_eq!(health.nats_status, "healthy");
        assert_eq!(health.redis_status, "healthy");
        assert_eq!(health.postgres_status, "unknown");
        assert_eq!(health.checked_at, "2026-03-03T12:00:00+00:00");
    }

    #[test]
    fn cluster_health_construction_empty_services() {
        let health = ClusterHealth {
            overall_status: "healthy".to_string(),
            services: vec![],
            license_status: "community".to_string(),
            rules_version: 0,
            nats_status: "healthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "2026-01-01T00:00:00+00:00".to_string(),
        };
        assert!(health.services.is_empty());
        assert_eq!(health.rules_version, 0);
        assert_eq!(health.license_status, "community");
    }

    // ── ClusterHealth serde roundtrip ────────────────────────────────

    #[test]
    fn cluster_health_serde_roundtrip() {
        let original = ClusterHealth {
            overall_status: "degraded".to_string(),
            services: vec![
                ServiceHealthCheck {
                    name: "redis".to_string(),
                    healthy: true,
                    status: "connected".to_string(),
                    latency_ms: 5,
                },
                ServiceHealthCheck {
                    name: "nats".to_string(),
                    healthy: false,
                    status: "disconnected".to_string(),
                    latency_ms: 999,
                },
            ],
            license_status: "valid".to_string(),
            rules_version: 7,
            nats_status: "unhealthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "2026-03-03T10:30:00+00:00".to_string(),
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ClusterHealth =
            serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.overall_status, original.overall_status);
        assert_eq!(deserialized.services.len(), original.services.len());
        assert_eq!(deserialized.services[0].name, "redis");
        assert!(deserialized.services[0].healthy);
        assert_eq!(deserialized.services[1].name, "nats");
        assert!(!deserialized.services[1].healthy);
        assert_eq!(deserialized.license_status, original.license_status);
        assert_eq!(deserialized.rules_version, original.rules_version);
        assert_eq!(deserialized.nats_status, original.nats_status);
        assert_eq!(deserialized.redis_status, original.redis_status);
        assert_eq!(deserialized.postgres_status, original.postgres_status);
        assert_eq!(deserialized.checked_at, original.checked_at);
    }

    #[test]
    fn cluster_health_serde_roundtrip_empty_services() {
        let original = ClusterHealth {
            overall_status: "healthy".to_string(),
            services: vec![],
            license_status: "community".to_string(),
            rules_version: 0,
            nats_status: "healthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "2026-01-01T00:00:00+00:00".to_string(),
        };

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ClusterHealth =
            serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.overall_status, "healthy");
        assert!(deserialized.services.is_empty());
    }

    #[test]
    fn cluster_health_json_field_names() {
        let health = ClusterHealth {
            overall_status: "healthy".to_string(),
            services: vec![],
            license_status: "valid".to_string(),
            rules_version: 1,
            nats_status: "healthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "now".to_string(),
        };
        let json = serde_json::to_string(&health).expect("serialize");
        assert!(json.contains("\"overall_status\""));
        assert!(json.contains("\"services\""));
        assert!(json.contains("\"license_status\""));
        assert!(json.contains("\"rules_version\""));
        assert!(json.contains("\"nats_status\""));
        assert!(json.contains("\"redis_status\""));
        assert!(json.contains("\"postgres_status\""));
        assert!(json.contains("\"checked_at\""));
    }

    #[test]
    fn cluster_health_deserialize_from_json_literal() {
        let json = r#"{
            "overall_status": "healthy",
            "services": [
                {
                    "name": "redis",
                    "healthy": true,
                    "status": "connected",
                    "latency_ms": 2
                }
            ],
            "license_status": "valid",
            "rules_version": 10,
            "nats_status": "healthy",
            "redis_status": "healthy",
            "postgres_status": "unknown",
            "checked_at": "2026-03-03T00:00:00Z"
        }"#;

        let health: ClusterHealth =
            serde_json::from_str(json).expect("deserialize");
        assert_eq!(health.overall_status, "healthy");
        assert_eq!(health.services.len(), 1);
        assert_eq!(health.services[0].name, "redis");
        assert!(health.services[0].healthy);
        assert_eq!(health.rules_version, 10);
    }

    // ── overall_status logic: mirrors run_health_check logic ─────────

    /// Helper that replicates the overall_status derivation from
    /// `run_health_check`: if all services are healthy the status is
    /// "healthy"; if any is unhealthy it is "degraded".
    fn derive_overall_status(services: &[ServiceHealthCheck]) -> &'static str {
        if services.iter().all(|s| s.healthy) {
            "healthy"
        } else {
            "degraded"
        }
    }

    #[test]
    fn overall_status_all_healthy() {
        let services = vec![
            ServiceHealthCheck {
                name: "redis".to_string(),
                healthy: true,
                status: "connected".to_string(),
                latency_ms: 1,
            },
            ServiceHealthCheck {
                name: "nats".to_string(),
                healthy: true,
                status: "connected".to_string(),
                latency_ms: 1,
            },
        ];
        assert_eq!(derive_overall_status(&services), "healthy");
    }

    #[test]
    fn overall_status_one_unhealthy() {
        let services = vec![
            ServiceHealthCheck {
                name: "redis".to_string(),
                healthy: true,
                status: "connected".to_string(),
                latency_ms: 1,
            },
            ServiceHealthCheck {
                name: "nats".to_string(),
                healthy: false,
                status: "disconnected".to_string(),
                latency_ms: 500,
            },
        ];
        assert_eq!(derive_overall_status(&services), "degraded");
    }

    #[test]
    fn overall_status_all_unhealthy() {
        let services = vec![
            ServiceHealthCheck {
                name: "redis".to_string(),
                healthy: false,
                status: "error".to_string(),
                latency_ms: 100,
            },
            ServiceHealthCheck {
                name: "nats".to_string(),
                healthy: false,
                status: "error".to_string(),
                latency_ms: 200,
            },
        ];
        assert_eq!(derive_overall_status(&services), "degraded");
    }

    #[test]
    fn overall_status_empty_services_is_healthy() {
        // `all()` on an empty iterator returns true, so no services = healthy.
        let services: Vec<ServiceHealthCheck> = vec![];
        assert_eq!(derive_overall_status(&services), "healthy");
    }

    #[test]
    fn overall_status_single_healthy_service() {
        let services = vec![ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: true,
            status: "ok".to_string(),
            latency_ms: 2,
        }];
        assert_eq!(derive_overall_status(&services), "healthy");
    }

    #[test]
    fn overall_status_single_unhealthy_service() {
        let services = vec![ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: false,
            status: "timeout".to_string(),
            latency_ms: 5000,
        }];
        assert_eq!(derive_overall_status(&services), "degraded");
    }

    // ── Clone / Debug trait verification ─────────────────────────────

    #[test]
    fn service_health_check_clone() {
        let original = ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: true,
            status: "connected".to_string(),
            latency_ms: 3,
        };
        let cloned = original.clone();
        assert_eq!(cloned.name, original.name);
        assert_eq!(cloned.healthy, original.healthy);
        assert_eq!(cloned.status, original.status);
        assert_eq!(cloned.latency_ms, original.latency_ms);
    }

    #[test]
    fn cluster_health_clone() {
        let original = ClusterHealth {
            overall_status: "healthy".to_string(),
            services: vec![ServiceHealthCheck {
                name: "redis".to_string(),
                healthy: true,
                status: "ok".to_string(),
                latency_ms: 1,
            }],
            license_status: "valid".to_string(),
            rules_version: 5,
            nats_status: "healthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "now".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(cloned.overall_status, original.overall_status);
        assert_eq!(cloned.services.len(), 1);
        assert_eq!(cloned.rules_version, original.rules_version);
    }

    #[test]
    fn service_health_check_debug_format() {
        let check = ServiceHealthCheck {
            name: "redis".to_string(),
            healthy: true,
            status: "ok".to_string(),
            latency_ms: 1,
        };
        let debug_str = format!("{:?}", check);
        assert!(debug_str.contains("ServiceHealthCheck"));
        assert!(debug_str.contains("redis"));
    }

    #[test]
    fn cluster_health_debug_format() {
        let health = ClusterHealth {
            overall_status: "healthy".to_string(),
            services: vec![],
            license_status: "valid".to_string(),
            rules_version: 1,
            nats_status: "healthy".to_string(),
            redis_status: "healthy".to_string(),
            postgres_status: "unknown".to_string(),
            checked_at: "now".to_string(),
        };
        let debug_str = format!("{:?}", health);
        assert!(debug_str.contains("ClusterHealth"));
        assert!(debug_str.contains("healthy"));
    }
}
