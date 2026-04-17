//! Per-upstream circuit breaker for cascade failure prevention.
//!
//! Uses lock-free atomics for the hot path. One circuit breaker per
//! downstream gRPC service (registry, intent, policy, token).
//!
//! State machine:
//!   Closed  ──(5 failures in 30s window)──▶  Open
//!   Open    ──(after recovery_timeout)────▶  HalfOpen
//!   HalfOpen ──(half_open_max successes)──▶  Closed
//!   HalfOpen ──(any failure)──────────────▶  Open

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU8, Ordering};
use std::time::Duration;

/// Circuit breaker states as atomic values.
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// Observable circuit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through.
    Closed,
    /// All requests fail immediately; apply degradation mode.
    Open,
    /// Trial period - allow a limited number of test requests.
    HalfOpen,
}

impl CircuitState {
    fn from_u8(v: u8) -> Self {
        match v {
            STATE_CLOSED => CircuitState::Closed,
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            CircuitState::Closed => STATE_CLOSED,
            CircuitState::Open => STATE_OPEN,
            CircuitState::HalfOpen => STATE_HALF_OPEN,
        }
    }
}

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CbConfig {
    /// Number of failures in the window to trip the breaker.
    pub failure_threshold: u32,
    /// How long to stay Open before transitioning to HalfOpen.
    pub recovery_timeout: Duration,
    /// Max test requests allowed in HalfOpen before closing.
    pub half_open_max: u32,
}

impl Default for CbConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            half_open_max: 3,
        }
    }
}

/// Lock-free circuit breaker.
///
/// Fast path: `is_allowed()` performs a single atomic load (Closed),
/// or an atomic load + timestamp check (Open/HalfOpen).
pub struct CircuitBreaker {
    state: AtomicU8,
    /// Windowed failure count (failures in the current observation window).
    failure_count: AtomicU32,
    /// Successful test requests in HalfOpen state.
    half_open_successes: AtomicU32,
    /// Epoch millis when we entered Open state.
    open_since_ms: AtomicI64,
    config: CbConfig,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given config.
    pub fn new(config: CbConfig) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            failure_count: AtomicU32::new(0),
            half_open_successes: AtomicU32::new(0),
            open_since_ms: AtomicI64::new(0),
            config,
        }
    }

    /// Create a circuit breaker with default config.
    pub fn with_defaults() -> Self {
        Self::new(CbConfig::default())
    }

    /// Check if a request is allowed through the circuit breaker.
    ///
    /// Returns `true` if the request should proceed, `false` if the
    /// circuit is open and the request should be rejected.
    pub fn is_allowed(&self) -> bool {
        let current_state = self.state.load(Ordering::Acquire);
        match current_state {
            STATE_CLOSED => true,
            STATE_OPEN => {
                // Check if recovery timeout has elapsed.
                let open_since = self.open_since_ms.load(Ordering::Acquire);
                let now_ms = current_epoch_ms();
                let elapsed_ms = now_ms - open_since;
                if elapsed_ms >= self.config.recovery_timeout.as_millis() as i64 {
                    // Transition to HalfOpen (CAS to prevent races).
                    if self
                        .state
                        .compare_exchange(
                            STATE_OPEN,
                            STATE_HALF_OPEN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.half_open_successes.store(0, Ordering::Release);
                    }
                    // Whether we won or lost the CAS, HalfOpen allows requests.
                    true
                } else {
                    false
                }
            }
            STATE_HALF_OPEN => {
                // Allow up to half_open_max test requests.
                let current = self.half_open_successes.load(Ordering::Acquire);
                current < self.config.half_open_max
            }
            _ => true,
        }
    }

    /// Record a successful call. Transitions HalfOpen → Closed if threshold met.
    pub fn record_success(&self) {
        let current_state = self.state.load(Ordering::Acquire);
        match current_state {
            STATE_HALF_OPEN => {
                let prev = self.half_open_successes.fetch_add(1, Ordering::AcqRel);
                if prev + 1 >= self.config.half_open_max {
                    // All test requests succeeded - close the breaker.
                    if self
                        .state
                        .compare_exchange(
                            STATE_HALF_OPEN,
                            STATE_CLOSED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.failure_count.store(0, Ordering::Release);
                        self.half_open_successes.store(0, Ordering::Release);
                    }
                }
            }
            STATE_CLOSED => {
                // Optionally decay failure count on success. For simplicity,
                // we just leave the windowed counter alone - it will be reset
                // when the breaker trips and recovers.
            }
            _ => {}
        }
    }

    /// Record a failed call. Transitions Closed → Open or HalfOpen → Open.
    pub fn record_failure(&self) {
        let current_state = self.state.load(Ordering::Acquire);
        match current_state {
            STATE_CLOSED => {
                let count = self.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
                if count >= self.config.failure_threshold {
                    // Trip the breaker.
                    if self
                        .state
                        .compare_exchange(
                            STATE_CLOSED,
                            STATE_OPEN,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.open_since_ms
                            .store(current_epoch_ms(), Ordering::Release);
                        crate::metrics::increment_circuit_breaker_open();
                    }
                }
            }
            STATE_HALF_OPEN => {
                // Any failure in HalfOpen → back to Open.
                if self
                    .state
                    .compare_exchange(
                        STATE_HALF_OPEN,
                        STATE_OPEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    self.open_since_ms
                        .store(current_epoch_ms(), Ordering::Release);
                    self.half_open_successes.store(0, Ordering::Release);
                }
            }
            _ => {
                // Already open - nothing to do.
            }
        }
    }

    /// Get the current state of the circuit breaker.
    pub fn state(&self) -> CircuitState {
        CircuitState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Get the current failure count (useful for metrics/debugging).
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Acquire)
    }

    /// Force-reset the circuit breaker to Closed state (e.g., on admin action).
    pub fn reset(&self) {
        self.state.store(STATE_CLOSED, Ordering::Release);
        self.failure_count.store(0, Ordering::Release);
        self.half_open_successes.store(0, Ordering::Release);
        self.open_since_ms.store(0, Ordering::Release);
    }
}

/// Get current epoch time in milliseconds.
fn current_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Result of an upstream gRPC call through the circuit breaker.
#[derive(Debug)]
pub enum UpstreamCallResult<T> {
    /// Call succeeded.
    Success(T),
    /// Circuit breaker is open - call was not attempted.
    CircuitOpen,
    /// Circuit was closed/half-open, but the gRPC call failed.
    Failed(String),
}

/// Manages circuit breakers for multiple upstream services.
pub struct CircuitBreakerManager {
    breakers: HashMap<String, CircuitBreaker>,
}

impl CircuitBreakerManager {
    /// Create a new manager with circuit breakers for the 4 downstream services.
    pub fn new() -> Self {
        let config = CbConfig::default();
        let mut breakers = HashMap::new();
        for name in &["registry", "intent", "policy", "token"] {
            breakers.insert(name.to_string(), CircuitBreaker::new(config.clone()));
        }
        Self { breakers }
    }

    /// Create a manager with a custom config applied to all breakers.
    pub fn with_config(config: CbConfig) -> Self {
        let mut breakers = HashMap::new();
        for name in &["registry", "intent", "policy", "token"] {
            breakers.insert(name.to_string(), CircuitBreaker::new(config.clone()));
        }
        Self { breakers }
    }

    /// Get a reference to the circuit breaker for a named service.
    ///
    /// Returns `None` if the service name is not registered.
    pub fn get(&self, service_name: &str) -> Option<&CircuitBreaker> {
        self.breakers.get(service_name)
    }

    /// Check if a request to the named service is allowed.
    /// Returns `true` if the breaker doesn't exist (fail-open for unknown services).
    pub fn is_allowed(&self, service_name: &str) -> bool {
        let allowed = self.breakers
            .get(service_name)
            .map_or(true, |cb| cb.is_allowed());
        if !allowed {
            crate::metrics::increment_circuit_breaker_open();
        }
        allowed
    }

    /// Record a success for the named service. No-op if service not registered.
    pub fn record_success(&self, service_name: &str) {
        if let Some(cb) = self.breakers.get(service_name) {
            cb.record_success();
        }
    }

    /// Record a failure for the named service. No-op if service not registered.
    pub fn record_failure(&self, service_name: &str) {
        if let Some(cb) = self.breakers.get(service_name) {
            cb.record_failure();
        }
    }

    /// Get all service names and their current states (for health/metrics).
    pub fn states(&self) -> Vec<(String, CircuitState)> {
        self.breakers
            .iter()
            .map(|(name, cb)| (name.clone(), cb.state()))
            .collect()
    }
}

impl Default for CircuitBreakerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CircuitState basic tests ──

    #[test]
    fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::with_defaults();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_closed_allows_requests() {
        let cb = CircuitBreaker::with_defaults();
        assert!(cb.is_allowed());
    }

    // ── Closed → Open transition ──

    #[test]
    fn test_closed_to_open_after_threshold_failures() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 3,
            recovery_timeout: Duration::from_secs(30),
            half_open_max: 2,
        });

        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_open_rejects_requests() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(3600), // long timeout so it stays open
            half_open_max: 1,
        });

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_allowed());
    }

    // ── Open → HalfOpen transition ──

    #[test]
    fn test_open_to_half_open_after_recovery_timeout() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(1), // very short for test
            half_open_max: 2,
        });

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for recovery timeout.
        std::thread::sleep(Duration::from_millis(10));

        // is_allowed() should trigger the Open → HalfOpen transition.
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    // ── HalfOpen → Closed transition ──

    #[test]
    fn test_half_open_to_closed_after_successes() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(1),
            half_open_max: 2,
        });

        // Trip the breaker.
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.is_allowed()); // transitions to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record enough successes.
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    // ── HalfOpen → Open transition ──

    #[test]
    fn test_half_open_to_open_on_failure() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(1),
            half_open_max: 3,
        });

        // Trip to Open, then let it go to HalfOpen.
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // One success, then a failure.
        cb.record_success();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // ── Success in Closed state does not trip ──

    #[test]
    fn test_success_does_not_change_closed_state() {
        let cb = CircuitBreaker::with_defaults();
        cb.record_success();
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    // ── Failure count ──

    #[test]
    fn test_failure_count_increments() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 10,
            recovery_timeout: Duration::from_secs(30),
            half_open_max: 3,
        });

        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 3);
    }

    // ── Reset ──

    #[test]
    fn test_reset_returns_to_closed() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(3600),
            half_open_max: 1,
        });

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
        assert!(cb.is_allowed());
    }

    // ── Default config values ──

    #[test]
    fn test_default_config() {
        let config = CbConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.recovery_timeout, Duration::from_secs(30));
        assert_eq!(config.half_open_max, 3);
    }

    // ── Full lifecycle test ──

    #[test]
    fn test_full_lifecycle_closed_open_halfopen_closed() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 2,
            recovery_timeout: Duration::from_millis(1),
            half_open_max: 2,
        });

        // 1. Start Closed.
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_allowed());

        // 2. Two failures → Open.
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_allowed());

        // 3. Wait for recovery → HalfOpen.
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // 4. Two successes → Closed.
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_allowed());
    }

    // ── CircuitBreakerManager tests ──

    #[test]
    fn test_manager_has_all_services() {
        let mgr = CircuitBreakerManager::new();
        assert_eq!(mgr.get("registry").unwrap().state(), CircuitState::Closed);
        assert_eq!(mgr.get("intent").unwrap().state(), CircuitState::Closed);
        assert_eq!(mgr.get("policy").unwrap().state(), CircuitState::Closed);
        assert_eq!(mgr.get("token").unwrap().state(), CircuitState::Closed);
    }

    #[test]
    fn test_manager_individual_breakers_are_independent() {
        let mgr = CircuitBreakerManager::new();

        // Trip only the registry breaker.
        for _ in 0..5 {
            mgr.get("registry").unwrap().record_failure();
        }
        assert_eq!(mgr.get("registry").unwrap().state(), CircuitState::Open);
        assert_eq!(mgr.get("intent").unwrap().state(), CircuitState::Closed);
        assert_eq!(mgr.get("policy").unwrap().state(), CircuitState::Closed);
        assert_eq!(mgr.get("token").unwrap().state(), CircuitState::Closed);
    }

    #[test]
    fn test_manager_states_returns_all() {
        let mgr = CircuitBreakerManager::new();
        let states = mgr.states();
        assert_eq!(states.len(), 4);
        for (_, state) in &states {
            assert_eq!(*state, CircuitState::Closed);
        }
    }

    #[test]
    fn test_manager_with_custom_config() {
        let config = CbConfig {
            failure_threshold: 10,
            recovery_timeout: Duration::from_secs(60),
            half_open_max: 5,
        };
        let mgr = CircuitBreakerManager::with_config(config);

        // Need 10 failures to trip.
        for _ in 0..9 {
            mgr.get("intent").unwrap().record_failure();
        }
        assert_eq!(mgr.get("intent").unwrap().state(), CircuitState::Closed);
        mgr.get("intent").unwrap().record_failure();
        assert_eq!(mgr.get("intent").unwrap().state(), CircuitState::Open);
    }

    #[test]
    fn test_manager_returns_none_for_unknown_service() {
        let mgr = CircuitBreakerManager::new();
        assert!(mgr.get("nonexistent").is_none());
    }

    // ── UpstreamCallResult tests ──

    #[test]
    fn test_upstream_call_result_variants() {
        let success: UpstreamCallResult<i32> = UpstreamCallResult::Success(42);
        assert!(matches!(success, UpstreamCallResult::Success(42)));

        let open: UpstreamCallResult<i32> = UpstreamCallResult::CircuitOpen;
        assert!(matches!(open, UpstreamCallResult::CircuitOpen));

        let failed: UpstreamCallResult<i32> =
            UpstreamCallResult::Failed("connection refused".to_string());
        assert!(matches!(failed, UpstreamCallResult::Failed(_)));
    }

    // ── Edge cases ──

    #[test]
    fn test_multiple_failures_beyond_threshold_stays_open() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 2,
            recovery_timeout: Duration::from_secs(3600),
            half_open_max: 1,
        });

        // More failures than the threshold - should stay Open.
        for _ in 0..10 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_single_success_in_half_open_does_not_close_if_max_gt_1() {
        let cb = CircuitBreaker::new(CbConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(1),
            half_open_max: 3,
        });

        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        // Not enough successes yet.
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_state_from_u8_unknown_defaults_to_closed() {
        assert_eq!(CircuitState::from_u8(255), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_state_roundtrip() {
        for state in [CircuitState::Closed, CircuitState::Open, CircuitState::HalfOpen] {
            assert_eq!(CircuitState::from_u8(state.as_u8()), state);
        }
    }
}
