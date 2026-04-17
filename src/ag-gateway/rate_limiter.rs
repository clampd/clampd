//! Dual-tier rate limiter for ag-gateway.
//!
//! Tier 1: Global Redis sliding window - accurate, shared across pods.
//! Key pattern: `ag:ratelimit:{key}:{epoch_window}`
//! Uses Redis INCR + EXPIRE pattern for O(1) per-request cost.
//!
//! Two levels:
//! - Per-agent: `ag:ratelimit:agent:{agent_id}:{window}`
//! - Global (per API key): `ag:ratelimit:apikey:{key_prefix}:{window}`
//!
//! Returns remaining requests and retry-after header value.

use tracing::warn;

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window.
    pub remaining: u32,
    /// Seconds until the current window resets (for Retry-After header).
    pub retry_after: Option<u32>,
}

/// Redis-backed rate limiter using sliding window counters.
pub struct RateLimiter;

impl RateLimiter {
    /// Check and increment the rate limit for a given key.
    ///
    /// Uses a sliding window counter with two adjacent buckets:
    ///   - Current bucket: `ag:ratelimit:{key}:{current_epoch / window_secs}`
    ///   - Previous bucket: same key with `current_epoch / window_secs - 1`
    ///
    /// The effective count is: current_count + prev_count * overlap_factor.
    /// For simplicity (matching the existing `increment_and_get_calls` pattern),
    /// we use a simple sum of current + previous bucket.
    ///
    /// # Arguments
    /// * `pool` - Redis connection pool
    /// * `key` - Rate limit key (e.g., `agent:{agent_id}` or `apikey:{prefix}`)
    /// * `max_requests` - Maximum requests allowed per window
    /// * `window_secs` - Window duration in seconds
    pub async fn check_rate_limit(
        pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
        key: &str,
        max_requests: u32,
        window_secs: u32,
    ) -> RateLimitResult {
        let now_secs = current_epoch_secs();
        let window = window_secs as u64;
        let current_bucket = now_secs / window;
        let prev_bucket = current_bucket.saturating_sub(1);

        let current_key = format!("ag:ratelimit:{}:{}", key, current_bucket);
        let prev_key = format!("ag:ratelimit:{}:{}", key, prev_bucket);

        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(e) => {
                warn!(key = %key, "Rate limit fail-open - Redis unavailable: {}", e);
                crate::metrics::increment_rate_limit_fail_open();
                return RateLimitResult {
                    allowed: true,
                    remaining: max_requests,
                    retry_after: None,
                };
            }
        };

        // INCR current bucket + set TTL.
        let current_count: u32 = match redis::cmd("INCR")
            .arg(&current_key)
            .query_async::<i64>(&mut *conn)
            .await
        {
            Ok(val) => {
                if val == 1 {
                    // First request in this window - set expiry to 2x window_secs
                    // to ensure the key survives into the next window for overlap.
                    if let Err(e) = redis::cmd("EXPIRE")
                        .arg(&current_key)
                        .arg(window_secs * 2)
                        .query_async::<()>(&mut *conn)
                        .await
                    {
                        warn!(error = %e, key = %current_key, "Failed to EXPIRE rate limit key in Redis");
                    }
                }
                val.max(0) as u32
            }
            Err(e) => {
                warn!(key = %key, "Rate limit fail-open - Redis INCR failed: {}", e);
                crate::metrics::increment_rate_limit_fail_open();
                return RateLimitResult {
                    allowed: true,
                    remaining: max_requests,
                    retry_after: None,
                };
            }
        };

        // GET previous bucket count.
        let prev_count: u32 = match redis::cmd("GET")
            .arg(&prev_key)
            .query_async::<Option<i64>>(&mut *conn)
            .await
        {
            Ok(Some(val)) => val.max(0) as u32,
            Ok(None) => 0,
            Err(_) => 0, // fail-open on previous bucket read error
        };

        let total = current_count + prev_count;

        if total > max_requests {
            let seconds_into_window = (now_secs % window) as u32;
            let retry_after = window_secs.saturating_sub(seconds_into_window);
            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after: Some(retry_after),
            }
        } else {
            RateLimitResult {
                allowed: true,
                remaining: max_requests.saturating_sub(total),
                retry_after: None,
            }
        }
    }

    /// Check per-agent rate limit.
    pub async fn check_agent_rate_limit(
        pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
        agent_id: &str,
        max_requests: u32,
        window_secs: u32,
    ) -> RateLimitResult {
        let key = format!("agent:{}", agent_id);
        Self::check_rate_limit(pool, &key, max_requests, window_secs).await
    }

    /// Check global (per API key prefix) rate limit.
    pub async fn check_global_rate_limit(
        pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
        api_key_prefix: &str,
        max_requests: u32,
        window_secs: u32,
    ) -> RateLimitResult {
        let key = format!("apikey:{}", api_key_prefix);
        Self::check_rate_limit(pool, &key, max_requests, window_secs).await
    }

    /// Check cumulative byte rate limit per agent (FIX 5: write bomb mitigation).
    ///
    /// Tracks total bytes processed per agent using INCRBY in a sliding window.
    /// Key pattern: `ag:ratelimit:bytes:{agent_id}:{bucket}`
    pub async fn check_byte_rate_limit(
        pool: &bb8::Pool<bb8_redis::RedisConnectionManager>,
        agent_id: &str,
        bytes: u64,
        max_bytes: u64,
        window_secs: u32,
    ) -> RateLimitResult {
        let now_secs = current_epoch_secs();
        let window = window_secs as u64;
        let current_bucket = now_secs / window;

        let key = format!("ag:ratelimit:bytes:{}:{}", agent_id, current_bucket);

        let mut conn = match pool.get().await {
            Ok(c) => c,
            Err(e) => {
                warn!(agent_id = %agent_id, "Byte rate limit fail-open - Redis unavailable: {}", e);
                return RateLimitResult {
                    allowed: true,
                    remaining: 0,
                    retry_after: None,
                };
            }
        };

        // INCRBY current bucket with the request size
        let current_total: u64 = match redis::cmd("INCRBY")
            .arg(&key)
            .arg(bytes)
            .query_async::<i64>(&mut *conn)
            .await
        {
            Ok(val) => {
                if val == bytes as i64 {
                    // First request in this window - set expiry
                    if let Err(e) = redis::cmd("EXPIRE")
                        .arg(&key)
                        .arg(window_secs * 2)
                        .query_async::<()>(&mut *conn)
                        .await
                    {
                        warn!(error = %e, key = %key, "Failed to EXPIRE byte rate limit key");
                    }
                }
                val.max(0) as u64
            }
            Err(e) => {
                warn!(agent_id = %agent_id, "Byte rate limit fail-open - Redis INCRBY failed: {}", e);
                return RateLimitResult {
                    allowed: true,
                    remaining: 0,
                    retry_after: None,
                };
            }
        };

        if current_total > max_bytes {
            let seconds_into_window = (now_secs % window) as u32;
            let retry_after = window_secs.saturating_sub(seconds_into_window);
            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after: Some(retry_after),
            }
        } else {
            RateLimitResult {
                allowed: true,
                remaining: 0, // not meaningful for byte limits
                retry_after: None,
            }
        }
    }
}

/// Get current epoch time in seconds.
fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build rate limit response headers.
pub fn rate_limit_headers(result: &RateLimitResult, max_requests: u32) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "X-RateLimit-Limit".to_string(),
            max_requests.to_string(),
        ),
        (
            "X-RateLimit-Remaining".to_string(),
            result.remaining.to_string(),
        ),
    ];
    if let Some(retry_after) = result.retry_after {
        headers.push(("Retry-After".to_string(), retry_after.to_string()));
        headers.push((
            "X-RateLimit-Reset".to_string(),
            (current_epoch_secs() + retry_after as u64).to_string(),
        ));
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RateLimitResult tests ──

    #[test]
    fn test_rate_limit_result_allowed() {
        let result = RateLimitResult {
            allowed: true,
            remaining: 95,
            retry_after: None,
        };
        assert!(result.allowed);
        assert_eq!(result.remaining, 95);
        assert!(result.retry_after.is_none());
    }

    #[test]
    fn test_rate_limit_result_denied() {
        let result = RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after: Some(30),
        };
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
        assert_eq!(result.retry_after, Some(30));
    }

    // ── rate_limit_headers tests ──

    #[test]
    fn test_headers_when_allowed() {
        let result = RateLimitResult {
            allowed: true,
            remaining: 50,
            retry_after: None,
        };
        let headers = rate_limit_headers(&result, 100);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("X-RateLimit-Limit".to_string(), "100".to_string()));
        assert_eq!(
            headers[1],
            ("X-RateLimit-Remaining".to_string(), "50".to_string())
        );
    }

    #[test]
    fn test_headers_when_limited() {
        let result = RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after: Some(15),
        };
        let headers = rate_limit_headers(&result, 100);
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].0, "X-RateLimit-Limit");
        assert_eq!(headers[1].0, "X-RateLimit-Remaining");
        assert_eq!(headers[2], ("Retry-After".to_string(), "15".to_string()));
        assert_eq!(headers[3].0, "X-RateLimit-Reset");
    }

    // ── Key format tests ──

    #[test]
    fn test_agent_key_format() {
        // Validate the key format used by check_agent_rate_limit.
        let agent_id = "agent-abc-123";
        let key = format!("agent:{}", agent_id);
        let full_key = format!("ag:ratelimit:{}:{}", key, 12345);
        assert_eq!(full_key, "ag:ratelimit:agent:agent-abc-123:12345");
    }

    #[test]
    fn test_global_key_format() {
        let prefix = "ag_live_abc";
        let key = format!("apikey:{}", prefix);
        let full_key = format!("ag:ratelimit:{}:{}", key, 67890);
        assert_eq!(full_key, "ag:ratelimit:apikey:ag_live_abc:67890");
    }

    // ── Epoch time test ──

    #[test]
    fn test_current_epoch_secs_is_reasonable() {
        let secs = current_epoch_secs();
        // Should be after 2024-01-01 (1704067200) and before 2030-01-01 (1893456000).
        assert!(secs > 1704067200);
        assert!(secs < 1893456000);
    }

    // ── RateLimitResult clone/debug ──

    #[test]
    fn test_rate_limit_result_clone() {
        let original = RateLimitResult {
            allowed: true,
            remaining: 42,
            retry_after: Some(10),
        };
        let cloned = original.clone();
        assert_eq!(cloned.allowed, original.allowed);
        assert_eq!(cloned.remaining, original.remaining);
        assert_eq!(cloned.retry_after, original.retry_after);
    }

    #[test]
    fn test_rate_limit_result_debug() {
        let result = RateLimitResult {
            allowed: true,
            remaining: 5,
            retry_after: None,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("allowed: true"));
        assert!(debug_str.contains("remaining: 5"));
    }

    // ── Headers edge cases ──

    #[test]
    fn test_headers_with_zero_remaining() {
        let result = RateLimitResult {
            allowed: true,
            remaining: 0,
            retry_after: None,
        };
        let headers = rate_limit_headers(&result, 100);
        assert_eq!(headers[1].1, "0");
    }

    #[test]
    fn test_headers_with_zero_max() {
        let result = RateLimitResult {
            allowed: false,
            remaining: 0,
            retry_after: Some(60),
        };
        let headers = rate_limit_headers(&result, 0);
        assert_eq!(headers[0].1, "0");
    }
}
