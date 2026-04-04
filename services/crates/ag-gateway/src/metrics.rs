//! Lightweight Prometheus-compatible metrics using atomics.
//!
//! No external crate needed — renders text exposition format directly.
//! All counters use `AtomicU64` with `Relaxed` ordering (monotonic counters
//! don't need stronger guarantees).

use std::sync::atomic::{AtomicU64, Ordering};

/// Global metrics singleton. All fields are monotonic counters.
pub static METRICS: Metrics = Metrics::new();

pub struct Metrics {
    requests_total: AtomicU64,
    requests_denied: AtomicU64,
    requests_allowed: AtomicU64,
    requests_flagged: AtomicU64,
    circuit_breaker_open: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    latency_sum_us: AtomicU64,
    latency_count: AtomicU64,
    rate_limit_fail_open: AtomicU64,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_denied: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_flagged: AtomicU64::new(0),
            circuit_breaker_open: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            rate_limit_fail_open: AtomicU64::new(0),
        }
    }
}

// ── Increment helpers ──

pub fn increment_requests() {
    METRICS.requests_total.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_denied() {
    METRICS.requests_denied.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_allowed() {
    METRICS.requests_allowed.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_flagged() {
    METRICS.requests_flagged.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_circuit_breaker_open() {
    METRICS.circuit_breaker_open.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_cache_hits() {
    METRICS.cache_hits.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_cache_misses() {
    METRICS.cache_misses.fetch_add(1, Ordering::Relaxed);
}

pub fn record_latency(microseconds: u64) {
    METRICS.latency_sum_us.fetch_add(microseconds, Ordering::Relaxed);
    METRICS.latency_count.fetch_add(1, Ordering::Relaxed);
}

pub fn increment_rate_limit_fail_open() {
    METRICS.rate_limit_fail_open.fetch_add(1, Ordering::Relaxed);
}

// ── Prometheus exposition format renderer ──

pub fn render_prometheus() -> String {
    let requests_total = METRICS.requests_total.load(Ordering::Relaxed);
    let denied = METRICS.requests_denied.load(Ordering::Relaxed);
    let allowed = METRICS.requests_allowed.load(Ordering::Relaxed);
    let flagged = METRICS.requests_flagged.load(Ordering::Relaxed);
    let cb_open = METRICS.circuit_breaker_open.load(Ordering::Relaxed);
    let cache_hits = METRICS.cache_hits.load(Ordering::Relaxed);
    let cache_misses = METRICS.cache_misses.load(Ordering::Relaxed);
    let latency_sum = METRICS.latency_sum_us.load(Ordering::Relaxed);
    let latency_count = METRICS.latency_count.load(Ordering::Relaxed);
    let rl_fail_open = METRICS.rate_limit_fail_open.load(Ordering::Relaxed);

    format!(
        "\
# HELP agentguard_requests_total Total proxy requests processed.
# TYPE agentguard_requests_total counter
agentguard_requests_total {requests_total}
# HELP agentguard_requests_denied_total Total proxy requests denied.
# TYPE agentguard_requests_denied_total counter
agentguard_requests_denied_total {denied}
# HELP agentguard_requests_allowed_total Total proxy requests allowed.
# TYPE agentguard_requests_allowed_total counter
agentguard_requests_allowed_total {allowed}
# HELP agentguard_requests_flagged_total Total proxy requests flagged (warned but allowed).
# TYPE agentguard_requests_flagged_total counter
agentguard_requests_flagged_total {flagged}
# HELP agentguard_circuit_breaker_open_total Circuit breaker open events.
# TYPE agentguard_circuit_breaker_open_total counter
agentguard_circuit_breaker_open_total {cb_open}
# HELP agentguard_cache_hits_total Baseline cache hits.
# TYPE agentguard_cache_hits_total counter
agentguard_cache_hits_total {cache_hits}
# HELP agentguard_cache_misses_total Baseline cache misses (Redis fetch or no baseline).
# TYPE agentguard_cache_misses_total counter
agentguard_cache_misses_total {cache_misses}
# HELP agentguard_latency_sum_us Sum of request latency in microseconds.
# TYPE agentguard_latency_sum_us counter
agentguard_latency_sum_us {latency_sum}
# HELP agentguard_latency_count Number of requests with recorded latency.
# TYPE agentguard_latency_count counter
agentguard_latency_count {latency_count}
# HELP agentguard_rate_limit_fail_open_total Rate limit checks that fell back to fail-open due to Redis unavailability.
# TYPE agentguard_rate_limit_fail_open_total counter
agentguard_rate_limit_fail_open_total {rl_fail_open}
# HELP agentguard_up Whether the gateway is running.
# TYPE agentguard_up gauge
agentguard_up 1
"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_contains_all_metrics() {
        let output = render_prometheus();
        assert!(output.contains("agentguard_requests_total"));
        assert!(output.contains("agentguard_requests_denied_total"));
        assert!(output.contains("agentguard_requests_allowed_total"));
        assert!(output.contains("agentguard_requests_flagged_total"));
        assert!(output.contains("agentguard_circuit_breaker_open_total"));
        assert!(output.contains("agentguard_cache_hits_total"));
        assert!(output.contains("agentguard_cache_misses_total"));
        assert!(output.contains("agentguard_latency_sum_us"));
        assert!(output.contains("agentguard_latency_count"));
        assert!(output.contains("agentguard_rate_limit_fail_open_total"));
        assert!(output.contains("agentguard_up 1"));
    }

    #[test]
    fn test_increment_and_record() {
        // These are global, so values may be non-zero from other tests.
        // Just verify the functions don't panic and counters increase.
        let before = METRICS.requests_total.load(Ordering::Relaxed);
        increment_requests();
        let after = METRICS.requests_total.load(Ordering::Relaxed);
        assert!(after > before);

        let before_lat = METRICS.latency_count.load(Ordering::Relaxed);
        record_latency(500);
        let after_lat = METRICS.latency_count.load(Ordering::Relaxed);
        assert!(after_lat > before_lat);
    }
}
