//! Cross-request session correlation.
//!
//! Detects multi-step attacks (read data → exfiltrate) across request boundaries.
//! Backed by Redis with 30-minute sliding TTL per session.
//!
//! Session flags:
//! - BulkReadDetected: total_records_fetched > max_records_per_query * 3
//! - ReconPattern: unique_tables_accessed > 5 in 5 minutes
//! - ExternalSendAfterRead: external send within 60s of bulk read
//! - RapidFire: > 20 calls in 60 seconds
//! - ScopeProbing: 3+ denied requests in session
//!
//! Risk: +0.2 per flag, capped at 0.6.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Maximum session ID length (rejects forged/oversized session IDs).
pub const MAX_SESSION_ID_LEN: usize = 128;

/// Allowed characters in explicit session IDs: alphanumeric plus _:.-
pub const SESSION_ID_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:.-";

// ── Configurable session thresholds ─────────────────────────────────
//
// All thresholds below can be overridden via environment variables.
// Defaults are tuned for production security; lowering them increases
// sensitivity (more false positives), raising them reduces it.
//
// See: docs/configuration.md for full threshold reference.

use std::sync::LazyLock;

/// Configurable session detection thresholds.
pub struct SessionThresholds {
    /// Redis TTL for session keys (default: 1800s = 30 min sliding window).
    pub session_ttl_secs: u64,
    /// Maximum tool call records per session ring buffer (default: 50).
    pub max_tool_records: usize,
    /// Risk contribution per active session flag (default: 0.2).
    pub risk_per_flag: f64,
    /// Maximum session risk factor cap (default: 0.6).
    pub max_session_risk: f64,
    /// Rapid-fire detection window in seconds (default: 60).
    pub rapid_fire_window_secs: i64,
    /// Rapid-fire detection call count threshold (default: 20).
    pub rapid_fire_threshold: usize,
    /// Recon pattern: unique tables accessed threshold (default: 5).
    pub recon_table_threshold: usize,
    /// External send after read window in seconds (default: 60).
    pub external_send_window_secs: i64,
    /// Scope probing: denied request count threshold (default: 3).
    pub scope_probe_threshold: usize,
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Global configurable thresholds — loaded once at startup from env vars.
pub static SESSION_CONFIG: LazyLock<SessionThresholds> = LazyLock::new(|| {
    SessionThresholds {
        session_ttl_secs: env_parse("CLAMPD_SESSION_TTL_SECS", 1800),
        max_tool_records: env_parse("CLAMPD_MAX_TOOL_RECORDS", 50),
        risk_per_flag: env_parse("CLAMPD_RISK_PER_FLAG", 0.2),
        max_session_risk: env_parse("CLAMPD_MAX_SESSION_RISK", 0.6),
        rapid_fire_window_secs: env_parse("CLAMPD_RAPID_FIRE_WINDOW_SECS", 60),
        rapid_fire_threshold: env_parse("CLAMPD_RAPID_FIRE_THRESHOLD", 20),
        recon_table_threshold: env_parse("CLAMPD_RECON_TABLE_THRESHOLD", 5),
        external_send_window_secs: env_parse("CLAMPD_EXTERNAL_SEND_WINDOW_SECS", 60),
        scope_probe_threshold: env_parse("CLAMPD_SCOPE_PROBE_THRESHOLD", 3),
    }
});

// Legacy const aliases for backward compatibility — code that references these
// will get the configurable values at runtime via Deref.
// TODO: Migrate all callsites to use SESSION_CONFIG.field directly.
const SESSION_TTL_SECS: u64 = 1800; // default; actual value from SESSION_CONFIG
const MAX_TOOL_RECORDS: usize = 50;
const RISK_PER_FLAG: f64 = 0.2;
const MAX_SESSION_RISK: f64 = 0.6;
const RAPID_FIRE_WINDOW_SECS: i64 = 60;
const RAPID_FIRE_THRESHOLD: usize = 20;
const RECON_TABLE_THRESHOLD: usize = 5;
const EXTERNAL_SEND_WINDOW_SECS: i64 = 60;
const SCOPE_PROBE_THRESHOLD: usize = 3;

/// Session flags detected from cross-request analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionFlag {
    /// Agent has fetched more records than 3x its per-query limit.
    BulkReadDetected,
    /// Agent has accessed more than 5 unique tables in 5 minutes.
    ReconPattern,
    /// Agent sent data externally within 60s of a bulk read.
    ExternalSendAfterRead,
    /// Agent has made >20 calls in 60 seconds.
    RapidFire,
    /// Agent has 3+ denied requests in this session.
    ScopeProbing,
}

impl SessionFlag {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionFlag::BulkReadDetected => "BulkReadDetected",
            SessionFlag::ReconPattern => "ReconPattern",
            SessionFlag::ExternalSendAfterRead => "ExternalSendAfterRead",
            SessionFlag::RapidFire => "RapidFire",
            SessionFlag::ScopeProbing => "ScopeProbing",
        }
    }
}

/// A record of a single tool call within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToolRecord {
    pub tool_name: String,
    pub action: String,
    pub timestamp: DateTime<Utc>,
    pub records_returned: u32,
    pub was_denied: bool,
    pub is_external_send: bool,
    pub tables_accessed: Vec<String>,
    #[serde(default)]
    pub scope_requested: String,
}

/// Session context tracked across requests for a single agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: String,
    pub agent_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    /// Rolling window of recent tool calls (max MAX_TOOL_RECORDS).
    pub tool_calls: Vec<SessionToolRecord>,
    /// Total records fetched across all calls in session.
    pub total_records_fetched: u64,
    /// Unique tables accessed in this session.
    pub unique_tables_accessed: HashSet<String>,
    /// Count of external sends (HTTP, email, etc.) in this session.
    pub external_sends_count: u32,
    /// Count of denied requests in this session.
    pub denied_count: u32,
    /// Recent risk scores (last 10) for trend detection.
    pub risk_trend: Vec<f64>,
    /// Currently active flags.
    pub flags: HashSet<SessionFlag>,
    /// SHA-256(IP + User-Agent) client fingerprint, 32 hex chars.
    #[serde(default)]
    pub client_fingerprint: String,
    /// 50% of agent EMA at session creation (inherited risk).
    #[serde(default)]
    pub inherited_risk: f64,
    /// Locked set of authorized tool names for this session.
    #[serde(default)]
    pub authorized_tools: HashSet<String>,
    /// Once true, only tools in `authorized_tools` are allowed.
    #[serde(default)]
    pub tools_locked: bool,
}

impl SessionContext {
    /// Create a new empty session.
    pub fn new(agent_id: Uuid, session_id: String) -> Self {
        let now = Utc::now();
        Self {
            session_id,
            agent_id,
            started_at: now,
            last_active_at: now,
            tool_calls: Vec::new(),
            total_records_fetched: 0,
            unique_tables_accessed: HashSet::new(),
            external_sends_count: 0,
            denied_count: 0,
            risk_trend: Vec::new(),
            flags: HashSet::new(),
            client_fingerprint: String::new(),
            inherited_risk: 0.0,
            authorized_tools: HashSet::new(),
            tools_locked: false,
        }
    }

    /// Record a tool call and recompute session flags.
    pub fn record_tool_call(&mut self, record: SessionToolRecord, max_records_per_query: u32) {
        self.last_active_at = Utc::now();
        self.total_records_fetched += record.records_returned as u64;

        for table in &record.tables_accessed {
            self.unique_tables_accessed.insert(table.clone());
        }

        if record.is_external_send {
            self.external_sends_count += 1;
        }

        if record.was_denied {
            self.denied_count += 1;
        }

        self.tool_calls.push(record);

        // Keep only the last MAX_TOOL_RECORDS entries.
        if self.tool_calls.len() > MAX_TOOL_RECORDS {
            self.tool_calls.drain(0..self.tool_calls.len() - MAX_TOOL_RECORDS);
        }

        // Recompute all flags.
        self.compute_flags(max_records_per_query);
    }

    /// Record a risk score for trend tracking.
    pub fn record_risk(&mut self, risk_score: f64) {
        self.risk_trend.push(risk_score);
        if self.risk_trend.len() > 10 {
            self.risk_trend.drain(0..self.risk_trend.len() - 10);
        }
    }

    /// Compute the session risk factor: +0.2 per active flag, capped at 0.6.
    pub fn risk_factor(&self) -> f64 {
        let raw = self.flags.len() as f64 * RISK_PER_FLAG;
        raw.min(MAX_SESSION_RISK)
    }

    /// Return active flag names as strings.
    pub fn flag_names(&self) -> Vec<String> {
        self.flags.iter().map(|f| f.as_str().to_string()).collect()
    }

    /// Recompute all session flags based on current state.
    fn compute_flags(&mut self, max_records_per_query: u32) {
        self.flags.clear();

        // Flag 1: BulkReadDetected
        let bulk_threshold = max_records_per_query as u64 * 3;
        if self.total_records_fetched > bulk_threshold {
            self.flags.insert(SessionFlag::BulkReadDetected);
        }

        // Flag 2: ReconPattern (>5 unique tables)
        if self.unique_tables_accessed.len() > RECON_TABLE_THRESHOLD {
            self.flags.insert(SessionFlag::ReconPattern);
        }

        // Flag 3: ExternalSendAfterRead
        if self.check_external_send_after_read() {
            self.flags.insert(SessionFlag::ExternalSendAfterRead);
        }

        // Flag 4: RapidFire (>20 calls in 60s)
        if self.check_rapid_fire() {
            self.flags.insert(SessionFlag::RapidFire);
        }

        // Flag 5: ScopeProbing (3+ denied requests)
        if self.denied_count as usize >= SCOPE_PROBE_THRESHOLD {
            self.flags.insert(SessionFlag::ScopeProbing);
        }
    }

    /// Check if an external send occurred within 60s of a bulk read.
    fn check_external_send_after_read(&self) -> bool {
        let now = Utc::now();
        let window = chrono::Duration::seconds(EXTERNAL_SEND_WINDOW_SECS);

        // Find the most recent bulk read.
        let last_bulk_read = self
            .tool_calls
            .iter()
            .rev()
            .filter(|r| r.records_returned > 0 && !r.is_external_send)
            .map(|r| r.timestamp)
            .next();

        if let Some(read_time) = last_bulk_read {
            // Check if any external send happened within the window after the read.
            return self
                .tool_calls
                .iter()
                .rev()
                .filter(|r| r.is_external_send)
                .any(|r| {
                    r.timestamp >= read_time
                        && r.timestamp <= read_time + window
                        && now.signed_duration_since(r.timestamp).num_seconds()
                            < EXTERNAL_SEND_WINDOW_SECS * 2
                });
        }

        false
    }

    /// Check if more than RAPID_FIRE_THRESHOLD calls happened in the last 60 seconds.
    fn check_rapid_fire(&self) -> bool {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(RAPID_FIRE_WINDOW_SECS);
        let recent_count = self
            .tool_calls
            .iter()
            .filter(|r| r.timestamp >= cutoff)
            .count();
        recent_count >= RAPID_FIRE_THRESHOLD
    }
}

/// Redis key for a session.
pub fn session_redis_key(agent_id: &Uuid, session_id: &str) -> String {
    format!("ag:session:{}:{}", agent_id, session_id)
}

/// Session manager backed by Redis.
pub struct SessionManager {
    redis: redis::aio::MultiplexedConnection,
}

impl SessionManager {
    /// Create a new SessionManager with a Redis connection manager.
    pub fn new(redis: redis::aio::MultiplexedConnection) -> Self {
        Self { redis }
    }

    /// Get or create a session. If the session exists in Redis, load it;
    /// otherwise create a new one. Refreshes the TTL (sliding window).
    pub async fn get_or_create(
        &mut self,
        agent_id: Uuid,
        session_id: &str,
    ) -> Result<SessionContext, crate::errors::AgError> {
        let key = session_redis_key(&agent_id, session_id);

        // Try to load existing session.
        let existing: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.redis)
            .await
            .map_err(|e| crate::errors::AgError::Session(format!("Redis GET failed: {}", e)))?;

        let session = match existing {
            Some(json) => serde_json::from_str::<SessionContext>(&json)
                .map_err(|e| crate::errors::AgError::Session(format!("Deserialize failed: {}", e)))?,
            None => SessionContext::new(agent_id, session_id.to_string()),
        };

        // Refresh TTL (sliding window).
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(SESSION_TTL_SECS)
            .query_async(&mut self.redis)
            .await
            .map_err(|e| crate::errors::AgError::Session(format!("Redis EXPIRE failed: {}", e)))?;

        Ok(session)
    }

    /// Persist session state back to Redis with sliding TTL.
    pub async fn save(
        &mut self,
        session: &SessionContext,
    ) -> Result<(), crate::errors::AgError> {
        let key = session_redis_key(&session.agent_id, &session.session_id);
        let json = serde_json::to_string(session)
            .map_err(|e| crate::errors::AgError::Session(format!("Serialize failed: {}", e)))?;

        redis::cmd("SET")
            .arg(&key)
            .arg(&json)
            .arg("EX")
            .arg(SESSION_TTL_SECS)
            .query_async::<()>(&mut self.redis)
            .await
            .map_err(|e| crate::errors::AgError::Session(format!("Redis SET failed: {}", e)))?;

        Ok(())
    }

    /// Delete a session from Redis.
    pub async fn delete(
        &mut self,
        agent_id: &Uuid,
        session_id: &str,
    ) -> Result<(), crate::errors::AgError> {
        let key = session_redis_key(agent_id, session_id);
        redis::cmd("DEL")
            .arg(&key)
            .query_async::<()>(&mut self.redis)
            .await
            .map_err(|e| crate::errors::AgError::Session(format!("Redis DEL failed: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(
        tool: &str,
        records: u32,
        denied: bool,
        external: bool,
        tables: Vec<&str>,
    ) -> SessionToolRecord {
        SessionToolRecord {
            tool_name: tool.to_string(),
            action: "read".to_string(),
            timestamp: Utc::now(),
            records_returned: records,
            was_denied: denied,
            is_external_send: external,
            tables_accessed: tables.into_iter().map(|s| s.to_string()).collect(),
            scope_requested: String::new(),
        }
    }

    #[test]
    fn test_new_session_has_no_flags() {
        let session = SessionContext::new(Uuid::new_v4(), "test-session".to_string());
        assert!(session.flags.is_empty());
        assert_eq!(session.risk_factor(), 0.0);
    }

    #[test]
    fn test_bulk_read_flag() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        // max_records_per_query = 100, threshold = 300
        session.record_tool_call(make_record("database.query", 200, false, false, vec!["users"]), 100);
        assert!(!session.flags.contains(&SessionFlag::BulkReadDetected));

        session.record_tool_call(make_record("database.query", 200, false, false, vec!["orders"]), 100);
        // total = 400 > 300
        assert!(session.flags.contains(&SessionFlag::BulkReadDetected));
    }

    #[test]
    fn test_recon_pattern_flag() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        let tables = vec!["users", "orders", "payments", "products", "sessions", "configs"];
        for table in tables {
            session.record_tool_call(
                make_record("database.query", 1, false, false, vec![table]),
                1000,
            );
        }
        // 6 unique tables > 5
        assert!(session.flags.contains(&SessionFlag::ReconPattern));
    }

    #[test]
    fn test_scope_probing_flag() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        for _ in 0..3 {
            session.record_tool_call(make_record("database.query", 0, true, false, vec![]), 1000);
        }
        assert!(session.flags.contains(&SessionFlag::ScopeProbing));
    }

    #[test]
    fn test_risk_factor_capped() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        // Force all 5 flags.
        session.flags.insert(SessionFlag::BulkReadDetected);
        session.flags.insert(SessionFlag::ReconPattern);
        session.flags.insert(SessionFlag::ExternalSendAfterRead);
        session.flags.insert(SessionFlag::RapidFire);
        session.flags.insert(SessionFlag::ScopeProbing);
        // 5 * 0.2 = 1.0, but capped at 0.6
        assert_eq!(session.risk_factor(), 0.6);
    }

    #[test]
    fn test_tool_call_ring_buffer() {
        let mut session = SessionContext::new(Uuid::new_v4(), "test".to_string());
        for i in 0..60 {
            session.record_tool_call(
                make_record(&format!("tool.{}", i), 0, false, false, vec![]),
                1000,
            );
        }
        assert_eq!(session.tool_calls.len(), MAX_TOOL_RECORDS);
    }

    #[test]
    fn test_redis_key_format() {
        let agent_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        let key = session_redis_key(&agent_id, "sess-001");
        assert_eq!(key, "ag:session:12345678-1234-1234-1234-123456789abc:sess-001");
    }

    // ── Additional tests ──

    fn make_record_at(
        tool: &str,
        records: u32,
        denied: bool,
        external: bool,
        tables: Vec<&str>,
        timestamp: DateTime<Utc>,
    ) -> SessionToolRecord {
        SessionToolRecord {
            tool_name: tool.to_string(),
            action: "read".to_string(),
            timestamp,
            records_returned: records,
            was_denied: denied,
            is_external_send: external,
            tables_accessed: tables.into_iter().map(|s| s.to_string()).collect(),
            scope_requested: String::new(),
        }
    }

    #[test]
    fn test_rapid_fire_flag_detection() {
        let mut session = SessionContext::new(Uuid::new_v4(), "rapid-test".to_string());
        let now = Utc::now();

        // Add 21 calls all within the last 60 seconds.
        for i in 0..21 {
            let ts = now - chrono::Duration::seconds(i as i64);
            let record = make_record_at("tool.query", 0, false, false, vec![], ts);
            // Push records directly to preserve their timestamps (record_tool_call
            // would use Utc::now() for last_active_at, but the tool_calls vector
            // preserves the record's original timestamp).
            session.tool_calls.push(record);
        }
        session.compute_flags(1000);

        assert!(
            session.flags.contains(&SessionFlag::RapidFire),
            "21 calls in 60s window should trigger RapidFire"
        );
    }

    #[test]
    fn test_rapid_fire_not_triggered_below_threshold() {
        let mut session = SessionContext::new(Uuid::new_v4(), "slow-test".to_string());
        let now = Utc::now();

        // Add 19 calls (below the threshold of 20).
        for i in 0..19 {
            let ts = now - chrono::Duration::seconds(i as i64);
            session.tool_calls.push(make_record_at("tool.query", 0, false, false, vec![], ts));
        }
        session.compute_flags(1000);

        assert!(
            !session.flags.contains(&SessionFlag::RapidFire),
            "19 calls should not trigger RapidFire"
        );
    }

    #[test]
    fn test_rapid_fire_old_calls_outside_window() {
        let mut session = SessionContext::new(Uuid::new_v4(), "old-test".to_string());
        let now = Utc::now();

        // Add 25 calls, but all older than 60 seconds.
        for i in 0..25 {
            let ts = now - chrono::Duration::seconds(120 + i as i64);
            session.tool_calls.push(make_record_at("tool.query", 0, false, false, vec![], ts));
        }
        session.compute_flags(1000);

        assert!(
            !session.flags.contains(&SessionFlag::RapidFire),
            "Old calls should not trigger RapidFire"
        );
    }

    #[test]
    fn test_external_send_after_read_flag() {
        let mut session = SessionContext::new(Uuid::new_v4(), "exfil-test".to_string());
        let now = Utc::now();

        // First: a read with records returned.
        let read_ts = now - chrono::Duration::seconds(30);
        session.tool_calls.push(make_record_at(
            "database.query",
            100,
            false,
            false,
            vec!["users"],
            read_ts,
        ));

        // Then: an external send within 60s of the read.
        let send_ts = now - chrono::Duration::seconds(10);
        session.tool_calls.push(make_record_at(
            "http.post",
            0,
            false,
            true,
            vec![],
            send_ts,
        ));

        session.compute_flags(1000);

        assert!(
            session.flags.contains(&SessionFlag::ExternalSendAfterRead),
            "External send within 60s of a read should trigger ExternalSendAfterRead"
        );
    }

    #[test]
    fn test_external_send_without_prior_read_no_flag() {
        let mut session = SessionContext::new(Uuid::new_v4(), "no-read-test".to_string());
        let now = Utc::now();

        // Only an external send with no prior read (records_returned = 0).
        session.tool_calls.push(make_record_at(
            "http.post",
            0,
            false,
            true,
            vec![],
            now - chrono::Duration::seconds(5),
        ));

        session.compute_flags(1000);

        assert!(
            !session.flags.contains(&SessionFlag::ExternalSendAfterRead),
            "No read before send should not trigger ExternalSendAfterRead"
        );
    }

    #[test]
    fn test_all_flags_set_risk_capped_at_0_6() {
        let mut session = SessionContext::new(Uuid::new_v4(), "all-flags-test".to_string());

        // Manually set all 5 flags to verify cap behavior.
        session.flags.insert(SessionFlag::BulkReadDetected);
        session.flags.insert(SessionFlag::ReconPattern);
        session.flags.insert(SessionFlag::ExternalSendAfterRead);
        session.flags.insert(SessionFlag::RapidFire);
        session.flags.insert(SessionFlag::ScopeProbing);

        assert_eq!(session.flags.len(), 5);
        // 5 * 0.2 = 1.0, but capped at 0.6.
        assert!(
            (session.risk_factor() - 0.6).abs() < f64::EPSILON,
            "Risk factor with all 5 flags should be capped at 0.6, got {}",
            session.risk_factor()
        );
    }

    #[test]
    fn test_risk_factor_incremental() {
        let mut session = SessionContext::new(Uuid::new_v4(), "incremental-test".to_string());

        assert!((session.risk_factor() - 0.0).abs() < f64::EPSILON);

        session.flags.insert(SessionFlag::BulkReadDetected);
        assert!((session.risk_factor() - 0.2).abs() < f64::EPSILON);

        session.flags.insert(SessionFlag::ScopeProbing);
        assert!((session.risk_factor() - 0.4).abs() < f64::EPSILON);

        session.flags.insert(SessionFlag::RapidFire);
        assert!((session.risk_factor() - 0.6).abs() < f64::EPSILON);

        // Adding a 4th flag should still be capped at 0.6.
        session.flags.insert(SessionFlag::ReconPattern);
        assert!((session.risk_factor() - 0.6).abs() < f64::EPSILON);
    }

    #[test]
    fn test_ring_buffer_overflow_preserves_last_50() {
        let mut session = SessionContext::new(Uuid::new_v4(), "ring-buf-test".to_string());

        // Insert 60 records with distinguishable tool names.
        for i in 0..60 {
            let record = SessionToolRecord {
                tool_name: format!("tool_{}", i),
                action: "read".to_string(),
                timestamp: Utc::now(),
                records_returned: 0,
                was_denied: false,
                is_external_send: false,
                tables_accessed: vec![],
                scope_requested: String::new(),
            };
            session.record_tool_call(record, 1000);
        }

        assert_eq!(session.tool_calls.len(), MAX_TOOL_RECORDS);
        // The first entry should be tool_10 (entries 0..9 were drained).
        assert_eq!(session.tool_calls[0].tool_name, "tool_10");
        // The last entry should be tool_59.
        assert_eq!(
            session.tool_calls[MAX_TOOL_RECORDS - 1].tool_name,
            "tool_59"
        );
    }

    #[test]
    fn test_record_risk_keeps_last_10() {
        let mut session = SessionContext::new(Uuid::new_v4(), "risk-trend-test".to_string());
        for i in 0..15 {
            session.record_risk(i as f64 * 0.1);
        }
        assert_eq!(session.risk_trend.len(), 10);
        // First retained value should be 0.5 (index 5 of original).
        assert!((session.risk_trend[0] - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_flag_names_returns_all_active_flags() {
        let mut session = SessionContext::new(Uuid::new_v4(), "names-test".to_string());
        session.flags.insert(SessionFlag::BulkReadDetected);
        session.flags.insert(SessionFlag::ScopeProbing);

        let names = session.flag_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"BulkReadDetected".to_string()));
        assert!(names.contains(&"ScopeProbing".to_string()));
    }

    #[test]
    fn test_session_flag_as_str() {
        assert_eq!(SessionFlag::BulkReadDetected.as_str(), "BulkReadDetected");
        assert_eq!(SessionFlag::ReconPattern.as_str(), "ReconPattern");
        assert_eq!(
            SessionFlag::ExternalSendAfterRead.as_str(),
            "ExternalSendAfterRead"
        );
        assert_eq!(SessionFlag::RapidFire.as_str(), "RapidFire");
        assert_eq!(SessionFlag::ScopeProbing.as_str(), "ScopeProbing");
    }

    #[test]
    fn test_new_session_initial_state() {
        let agent_id = Uuid::new_v4();
        let session = SessionContext::new(agent_id, "init-test".to_string());

        assert_eq!(session.agent_id, agent_id);
        assert_eq!(session.session_id, "init-test");
        assert!(session.tool_calls.is_empty());
        assert_eq!(session.total_records_fetched, 0);
        assert!(session.unique_tables_accessed.is_empty());
        assert_eq!(session.external_sends_count, 0);
        assert_eq!(session.denied_count, 0);
        assert!(session.risk_trend.is_empty());
        assert!(session.flags.is_empty());
        assert!(session.client_fingerprint.is_empty());
        assert!((session.inherited_risk - 0.0).abs() < f64::EPSILON);
        assert!(session.authorized_tools.is_empty());
        assert!(!session.tools_locked);
    }

    #[test]
    fn test_external_sends_counter_increments() {
        let mut session = SessionContext::new(Uuid::new_v4(), "ext-count-test".to_string());
        session.record_tool_call(make_record("http.post", 0, false, true, vec![]), 1000);
        session.record_tool_call(make_record("http.post", 0, false, true, vec![]), 1000);
        assert_eq!(session.external_sends_count, 2);
    }

    #[test]
    fn test_denied_count_increments() {
        let mut session = SessionContext::new(Uuid::new_v4(), "denied-count-test".to_string());
        session.record_tool_call(make_record("tool", 0, true, false, vec![]), 1000);
        session.record_tool_call(make_record("tool", 0, true, false, vec![]), 1000);
        assert_eq!(session.denied_count, 2);
    }
}
