//! Lightweight Prometheus-compatible metrics using atomics.
//!
//! No external crate needed - renders text exposition format directly.
//! Counters use `AtomicU64` with `Relaxed` ordering (monotonic counters
//! don't need stronger guarantees). Histograms use a small fixed bucket
//! array of `AtomicU64`s, also relaxed-ordered - bucket counts are
//! cumulative over time; no individual observation needs to be visible
//! in a specific cross-thread order.

use std::sync::atomic::{AtomicU64, Ordering};

use ag_common::metrics::{render_histogram, Histogram};

/// Global metrics singleton. All counter fields are monotonic.
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

// ── Histogram singletons ────────────────────────────────────────────────────
// Implementation moved to `ag_common::metrics` in #31 P1. The types,
// bucket consts, and render fn are now shared across ag-gateway, ag-policy,
// and ag-risk — produces byte-identical Prometheus output.

//
// Proposed SLO (from the issue):
//   - `agentguard_policy_eval_seconds` p99 ≤ 5 ms
//   - `agentguard_gateway_total_seconds` p99 ≤ 15 ms (excl. upstream network)

/// Total in-proc gateway time per proxied request (does NOT include the
/// upstream tool call once the gateway forwards the request).
pub static HIST_GATEWAY_TOTAL: Histogram = Histogram::new();

/// Wall-clock time spent in the gRPC call to `ag-policy`, including
/// Cedar + boundary + engine + scope-exemption evaluation. This is the
/// client-side measurement; `ag-policy` should expose its own
/// `cedar_eval_seconds` via a future commit.
pub static HIST_POLICY_EVAL: Histogram = Histogram::new();

// Per-prefix Redis GET histograms. The `key_prefix` label values are a
// small fixed vocabulary - keeping them hardcoded avoids an alloc on the
// hot path and bounds cardinality.
pub static HIST_REDIS_GET_BASELINE: Histogram = Histogram::new();
pub static HIST_REDIS_GET_SESSION: Histogram = Histogram::new();
pub static HIST_REDIS_GET_RISK: Histogram = Histogram::new();
pub static HIST_REDIS_GET_DENY: Histogram = Histogram::new();
pub static HIST_REDIS_GET_OTHER: Histogram = Histogram::new();

/// Observe end-to-end gateway latency for one request, in microseconds.
pub fn observe_gateway_total_us(value_us: u64) {
    HIST_GATEWAY_TOTAL.observe_us(value_us);
}

/// Observe time spent in the policy-evaluation gRPC call, in microseconds.
pub fn observe_policy_eval_us(value_us: u64) {
    HIST_POLICY_EVAL.observe_us(value_us);
}

/// Observe a Redis GET, routed to the histogram matching `key_prefix`.
/// Unknown prefixes fall through to `HIST_REDIS_GET_OTHER` to bound
/// cardinality - labels come from a fixed vocabulary, not user input.
pub fn observe_redis_get_us(key_prefix: &str, value_us: u64) {
    match key_prefix {
        "baseline" => HIST_REDIS_GET_BASELINE.observe_us(value_us),
        "session" => HIST_REDIS_GET_SESSION.observe_us(value_us),
        "risk" => HIST_REDIS_GET_RISK.observe_us(value_us),
        "deny" => HIST_REDIS_GET_DENY.observe_us(value_us),
        _ => HIST_REDIS_GET_OTHER.observe_us(value_us),
    }
}

// ── Counter helpers ─────────────────────────────────────────────────────────

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
    // Kept for backwards compatibility with existing counter-style
    // scrapers; operators should migrate to `agentguard_gateway_total_seconds`.
    METRICS.latency_sum_us.fetch_add(microseconds, Ordering::Relaxed);
    METRICS.latency_count.fetch_add(1, Ordering::Relaxed);
    observe_gateway_total_us(microseconds);
}

pub fn increment_rate_limit_fail_open() {
    METRICS.rate_limit_fail_open.fetch_add(1, Ordering::Relaxed);
}

// ── Prometheus exposition format renderer ───────────────────────────────────

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

    let mut out = format!(
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
    );

    // Histograms (#31). Bucket boundaries in seconds are emitted as `le`
    // labels; Grafana / Prometheus queries compute p50/p95/p99 via
    // `histogram_quantile()` over `_bucket` values.
    render_histogram(&HIST_GATEWAY_TOTAL, 
        "agentguard_gateway_total_seconds",
        "Total in-proc gateway time per proxied request (excludes upstream tool call).",
        "",
        &mut out,
    );
    render_histogram(&HIST_POLICY_EVAL, 
        "agentguard_policy_eval_seconds",
        "Wall-clock time spent in the gRPC call to ag-policy (full 5-layer evaluation).",
        "",
        &mut out,
    );

    let redis_help =
        "Wall-clock time spent in a Redis GET, labeled by key prefix.";
    render_histogram(&HIST_REDIS_GET_BASELINE, 
        "agentguard_redis_get_seconds",
        redis_help,
        "key_prefix=\"baseline\"",
        &mut out,
    );
    render_histogram(&HIST_REDIS_GET_SESSION, 
        "agentguard_redis_get_seconds",
        redis_help,
        "key_prefix=\"session\"",
        &mut out,
    );
    render_histogram(&HIST_REDIS_GET_RISK, 
        "agentguard_redis_get_seconds",
        redis_help,
        "key_prefix=\"risk\"",
        &mut out,
    );
    render_histogram(&HIST_REDIS_GET_DENY, 
        "agentguard_redis_get_seconds",
        redis_help,
        "key_prefix=\"deny\"",
        &mut out,
    );
    render_histogram(&HIST_REDIS_GET_OTHER, 
        "agentguard_redis_get_seconds",
        redis_help,
        "key_prefix=\"other\"",
        &mut out,
    );

    out
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
    fn test_render_contains_histograms() {
        let output = render_prometheus();
        assert!(output.contains("agentguard_gateway_total_seconds_bucket"));
        assert!(output.contains("agentguard_gateway_total_seconds_sum"));
        assert!(output.contains("agentguard_gateway_total_seconds_count"));
        assert!(output.contains("agentguard_policy_eval_seconds_bucket"));
        assert!(output.contains("agentguard_redis_get_seconds_bucket"));
        // Must emit the labeled variants
        assert!(output.contains("key_prefix=\"baseline\""));
        assert!(output.contains("key_prefix=\"session\""));
        // All eight bucket boundaries + +Inf
        for le in &["0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "+Inf"] {
            assert!(
                output.contains(&format!("le=\"{}\"", le)),
                "missing bucket label le=\"{}\"", le
            );
        }
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

    #[test]
    fn test_histogram_bucketing() {
        let h = Histogram::new();
        // One observation below the smallest bucket upper bound.
        h.observe_us(50);
        // One observation spanning several bucket ranges (only increments
        // its own range - the render step makes it cumulative).
        h.observe_us(7_500);
        // One observation in the +Inf bucket.
        h.observe_us(1_000_000);

        assert_eq!(h.count(), 3);

        let mut out = String::new();
        render_histogram(&h, "test_metric_seconds", "test", "", &mut out);

        // The 50 µs observation must land in le="0.0001".
        assert!(out.contains("test_metric_seconds_bucket{le=\"0.0001\"} 1"));
        // 7 500 µs belongs to le="0.01" (> 5 ms, ≤ 10 ms).
        // Cumulative: the 50 µs and 7 500 µs observations are both ≤ 10 ms.
        assert!(out.contains("test_metric_seconds_bucket{le=\"0.01\"} 2"));
        // All three observations are ≤ +Inf.
        assert!(out.contains("test_metric_seconds_bucket{le=\"+Inf\"} 3"));
        assert!(out.contains("test_metric_seconds_count 3"));
    }

    #[test]
    fn test_histogram_observe_us_hot_path_cost() {
        // Sanity guard: observing into a histogram must not panic or
        // allocate on the hot path. This test just hammers the function
        // many times to catch accidental Mutex/alloc introductions.
        let h = Histogram::new();
        for i in 0..10_000u64 {
            h.observe_us(i);
        }
        assert_eq!(h.count(), 10_000);
    }

    #[test]
    fn test_redis_get_prefix_routing() {
        let start_baseline = HIST_REDIS_GET_BASELINE.count();
        let start_other = HIST_REDIS_GET_OTHER.count();

        observe_redis_get_us("baseline", 42);
        observe_redis_get_us("bogus-unknown-prefix", 42);

        assert_eq!(HIST_REDIS_GET_BASELINE.count(), start_baseline + 1);
        assert_eq!(HIST_REDIS_GET_OTHER.count(), start_other + 1);
    }
}
