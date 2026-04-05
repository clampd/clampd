//! Redis-based leader election for ag-control.
//!
//! Uses `SET ag:control:leader {pod_id} NX EX 30` pattern.
//! - Renewal every 10s.
//! - Failover <30s (TTL expiry).
//! - Leader runs all background jobs. Standby only serves gRPC health/status.

use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

const LEADER_KEY: &str = "ag:control:leader";

/// Leader election manager.
pub struct LeaderElection {
    redis: Pool<RedisConnectionManager>,
    pod_id: String,
    ttl_secs: u64,
    renew_secs: u64,
    is_leader: Arc<AtomicBool>,
}

impl LeaderElection {
    pub fn new(
        redis: Pool<RedisConnectionManager>,
        pod_id: String,
        ttl_secs: u64,
        renew_secs: u64,
    ) -> Self {
        Self {
            redis,
            pod_id,
            ttl_secs,
            renew_secs,
            is_leader: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get a handle to check leader status (cheap, lock-free).
    pub fn is_leader_handle(&self) -> Arc<AtomicBool> {
        self.is_leader.clone()
    }

    /// Get the pod ID.
    pub fn pod_id(&self) -> &str {
        &self.pod_id
    }

    /// Try to acquire or renew leadership. Call this periodically.
    pub async fn try_acquire(&self) -> bool {
        let result = async {
            let mut conn = self.redis.get().await.map_err(|e| e.to_string())?;

            if self.is_leader.load(Ordering::Relaxed) {
                // Already leader — try to renew.
                let current: Option<String> = redis::cmd("GET")
                    .arg(LEADER_KEY)
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| e.to_string())?;

                if current.as_deref() == Some(&self.pod_id) {
                    // We are still the leader — extend TTL.
                    redis::cmd("EXPIRE")
                        .arg(LEADER_KEY)
                        .arg(self.ttl_secs)
                        .query_async::<bool>(&mut *conn)
                        .await
                        .map_err(|e| e.to_string())?;
                    return Ok(true);
                } else {
                    // Someone else took over.
                    warn!(
                        expected_pod_id = %self.pod_id,
                        current_pod_id = %current.as_deref().unwrap_or("<none>"),
                        "Leadership lost: Redis leader key held by a different pod"
                    );
                    return Ok(false);
                }
            }

            // Not currently leader — try to acquire.
            let acquired: bool = redis::cmd("SET")
                .arg(LEADER_KEY)
                .arg(&self.pod_id)
                .arg("NX")
                .arg("EX")
                .arg(self.ttl_secs)
                .query_async(&mut *conn)
                .await
                .unwrap_or(false);

            Ok::<bool, String>(acquired)
        }
        .await;

        match result {
            Ok(is_leader) => {
                let was_leader = self.is_leader.swap(is_leader, Ordering::Relaxed);
                if is_leader && !was_leader {
                    info!(pod_id = %self.pod_id, "Acquired leadership");
                } else if !is_leader && was_leader {
                    warn!(pod_id = %self.pod_id, "Lost leadership");
                }
                is_leader
            }
            Err(e) => {
                warn!(error = %e, "Leader election failed — assuming not leader");
                self.is_leader.store(false, Ordering::Relaxed);
                false
            }
        }
    }

    /// Run the leader election loop. Blocks forever.
    pub async fn run_loop(&self) {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(self.renew_secs));

        loop {
            interval.tick().await;
            self.try_acquire().await;
            debug!(
                is_leader = self.is_leader.load(Ordering::Relaxed),
                "Leader election tick"
            );
        }
    }

    /// Get the current leader ID from Redis.
    pub async fn current_leader(&self) -> Option<String> {
        let mut conn = self.redis.get().await.ok()?;
        redis::cmd("GET")
            .arg(LEADER_KEY)
            .query_async(&mut *conn)
            .await
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn leader_key_constant_value() {
        assert_eq!(LEADER_KEY, "ag:control:leader");
    }

    #[test]
    fn leader_key_starts_with_ag_prefix() {
        assert!(
            LEADER_KEY.starts_with("ag:"),
            "Leader key should be namespaced under the ag: prefix"
        );
    }

    #[test]
    fn leader_key_contains_control_namespace() {
        assert!(
            LEADER_KEY.contains("control"),
            "Leader key should reference the control service"
        );
    }

    #[test]
    fn leader_key_is_static_str() {
        // Ensures the constant is a &'static str (compile-time check, but
        // explicitly asserting it is non-empty at runtime).
        let key: &'static str = LEADER_KEY;
        assert!(!key.is_empty());
    }

    #[test]
    fn leader_key_no_whitespace() {
        assert!(
            !LEADER_KEY.contains(' '),
            "Redis keys should not contain whitespace"
        );
    }

    #[test]
    fn leader_key_colon_separated_segments() {
        let segments: Vec<&str> = LEADER_KEY.split(':').collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0], "ag");
        assert_eq!(segments[1], "control");
        assert_eq!(segments[2], "leader");
    }
}
