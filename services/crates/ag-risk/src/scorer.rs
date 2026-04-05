//! EMA-based cumulative risk scoring.
//!
//! Formula: new_ema = alpha × event_risk + (1 - alpha) × previous_ema
//! Default alpha = 0.3 (recent events weighted 30%, history weighted 70%).
//!
//! Classification thresholds:
//! | Score     | Classification | Action                              |
//! |-----------|---------------|--------------------------------------|
//! | 0.0–0.3   | Normal        | None                                |
//! | 0.3–0.5   | Elevated      | Dashboard indicator                 |
//! | 0.5–0.7   | Warning       | Dashboard + WebSocket push          |
//! | 0.7–0.9   | High          | + Slack/PagerDuty alert             |
//! | 0.9–1.0   | Critical      | Auto-suspend via ag-kill + all alerts|

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Decay factor applied when an agent has been idle for more than 1 hour.
const DECAY_FACTOR_1H: f64 = 0.95;
/// Decay factor applied when an agent has been idle for more than 24 hours.
const DECAY_FACTOR_24H: f64 = 0.85;
/// Idle threshold in seconds before the 1-hour decay factor applies.
const IDLE_THRESHOLD_1H_SECS: i64 = 3600;
/// Idle threshold in seconds before the 24-hour decay factor applies.
const IDLE_THRESHOLD_24H_SECS: i64 = 86400;
/// Maximum number of history entries kept per agent (ring buffer size).
const MAX_HISTORY_ENTRIES: usize = 100;

/// Risk classification based on score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskClassification {
    Normal,
    Elevated,
    Warning,
    High,
    Critical,
}

impl RiskClassification {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.9 {
            RiskClassification::Critical
        } else if score >= 0.7 {
            RiskClassification::High
        } else if score >= 0.5 {
            RiskClassification::Warning
        } else if score >= 0.3 {
            RiskClassification::Elevated
        } else {
            RiskClassification::Normal
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskClassification::Normal => "normal",
            RiskClassification::Elevated => "elevated",
            RiskClassification::Warning => "warning",
            RiskClassification::High => "high",
            RiskClassification::Critical => "critical",
        }
    }
}

/// Per-agent risk state tracked in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRiskState {
    pub agent_id: String,
    pub org_id: String,
    pub ema_score: f64,
    pub classification: RiskClassification,
    pub last_event_risk: f64,
    pub events_processed: u32,
    pub last_updated: DateTime<Utc>,
    pub last_decay: DateTime<Utc>,
}

/// A risk event recorded for history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskHistoryEntry {
    pub event_risk: f64,
    pub ema_before: f64,
    pub ema_after: f64,
    pub classification: RiskClassification,
    pub tool_name: String,
    pub timestamp: DateTime<Utc>,
}

/// In-memory risk scorer. Thread-safe via DashMap.
/// Grace period after revive: events during this window start from EMA=0
/// instead of accumulating on stale scores. Prevents the race where
/// ag-risk re-writes a high suspicion score before the revive propagates.
const REVIVE_GRACE_PERIOD_SECS: u64 = 30;

pub struct RiskScorer {
    /// Current EMA scores per agent.
    scores: DashMap<String, AgentRiskState>,
    /// Recent history per agent (ring buffer, last 100 entries).
    history: DashMap<String, Vec<RiskHistoryEntry>>,
    /// EMA smoothing factor.
    alpha: f64,
    /// Auto-suspend threshold.
    auto_suspend_threshold: f64,
    /// Agents that were recently revived (grace period - don't re-block immediately).
    revived_at: DashMap<String, Instant>,
}

impl RiskScorer {
    pub fn new(alpha: f64, auto_suspend_threshold: f64) -> Self {
        Self {
            scores: DashMap::new(),
            history: DashMap::new(),
            alpha,
            auto_suspend_threshold,
            revived_at: DashMap::new(),
        }
    }

    /// Check if an agent is in the post-revive grace period.
    pub fn is_in_grace_period(&self, agent_id: &str) -> bool {
        if let Some(entry) = self.revived_at.get(agent_id) {
            if entry.elapsed().as_secs() < REVIVE_GRACE_PERIOD_SECS {
                return true;
            }
            // Grace period expired - remove entry
            drop(entry);
            self.revived_at.remove(agent_id);
        }
        false
    }

    /// Process a new risk event for an agent.
    /// Returns the new EMA score and whether auto-suspend should trigger.
    pub fn process_event(
        &self,
        agent_id: &str,
        event_risk: f64,
        tool_name: &str,
        org_id: &str,
    ) -> (f64, RiskClassification, bool) {
        let now = Utc::now();

        let mut state = self
            .scores
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentRiskState {
                agent_id: agent_id.to_string(),
                org_id: org_id.to_string(),
                ema_score: 0.0,
                classification: RiskClassification::Normal,
                last_event_risk: 0.0,
                events_processed: 0,
                last_updated: now,
                last_decay: now,
            });

        // Update org_id if it was previously empty (graceful migration for pre-existing entries).
        if state.org_id.is_empty() && !org_id.is_empty() {
            state.org_id = org_id.to_string();
        }

        let ema_before = state.ema_score;

        // P1-6: Minimum event floor - prevent score dilution via benign floods.
        // Events with 0.0 risk still contribute to event count and history,
        // but don't actively pull the EMA toward 0. Only events with actual risk
        // (from intent classification) should influence the EMA.
        if event_risk < 0.01 {
            // Record in history for audit, but don't update EMA
            let entry = RiskHistoryEntry {
                event_risk,
                ema_before,
                ema_after: ema_before,
                classification: state.classification,
                tool_name: tool_name.to_string(),
                timestamp: now,
            };
            self.history
                .entry(agent_id.to_string())
                .or_insert_with(Vec::new)
                .push(entry);
            if let Some(mut hist) = self.history.get_mut(agent_id) {
                let len = hist.len();
                if len > MAX_HISTORY_ENTRIES {
                    hist.drain(0..len - MAX_HISTORY_ENTRIES);
                }
            }
            state.events_processed += 1;
            state.last_event_risk = event_risk;
            state.last_updated = now;
            return (ema_before, state.classification, false);
        }

        // EMA formula: new = alpha * event + (1 - alpha) * previous
        let new_ema = (self.alpha * event_risk + (1.0 - self.alpha) * state.ema_score)
            .min(1.0)
            .max(0.0);

        let classification = RiskClassification::from_score(new_ema);
        // Don't auto-suspend during grace period (agent was just revived)
        let should_auto_suspend = new_ema >= self.auto_suspend_threshold
            && !self.is_in_grace_period(agent_id);

        state.ema_score = new_ema;
        state.classification = classification;
        state.last_event_risk = event_risk;
        state.events_processed += 1;
        state.last_updated = now;

        // Record in history.
        let entry = RiskHistoryEntry {
            event_risk,
            ema_before,
            ema_after: new_ema,
            classification,
            tool_name: tool_name.to_string(),
            timestamp: now,
        };
        self.history
            .entry(agent_id.to_string())
            .or_insert_with(Vec::new)
            .push(entry);

        // Keep history bounded (last MAX_HISTORY_ENTRIES entries).
        if let Some(mut hist) = self.history.get_mut(agent_id) {
            let len = hist.len();
            if len > MAX_HISTORY_ENTRIES {
                hist.drain(0..len - MAX_HISTORY_ENTRIES);
            }
        }

        (new_ema, classification, should_auto_suspend)
    }

    /// Apply risk decay to all agents.
    /// Idle >1hr: multiply by DECAY_FACTOR_1H (0.95)
    /// Idle >24hr: multiply by DECAY_FACTOR_24H (0.85)
    /// Floor: 0.0
    pub fn apply_decay(&self) {
        let now = Utc::now();

        for mut entry in self.scores.iter_mut() {
            let idle_secs = now
                .signed_duration_since(entry.last_updated)
                .num_seconds();

            let factor = if idle_secs > IDLE_THRESHOLD_24H_SECS {
                DECAY_FACTOR_24H
            } else if idle_secs > IDLE_THRESHOLD_1H_SECS {
                DECAY_FACTOR_1H
            } else {
                continue; // No decay needed.
            };

            entry.ema_score = (entry.ema_score * factor).max(0.0);
            entry.classification = RiskClassification::from_score(entry.ema_score);
            entry.last_decay = now;
        }
    }

    /// Reset an agent's risk score (e.g. on revive/activate).
    /// Clears EMA, history, and event count.
    /// Starts a grace period to prevent immediate re-suspension.
    pub fn reset_score(&self, agent_id: &str) {
        self.scores.remove(agent_id);
        self.history.remove(agent_id);
        self.revived_at.insert(agent_id.to_string(), Instant::now());
    }

    /// Get current risk state for an agent.
    pub fn get_score(&self, agent_id: &str) -> Option<AgentRiskState> {
        self.scores.get(agent_id).map(|r| r.clone())
    }

    /// Get all agent scores (optionally filtered by minimum score and org_id).
    /// If org_id is empty, returns all agents (backward compatible).
    pub fn get_all_scores(&self, min_score: f64, org_id: &str) -> Vec<AgentRiskState> {
        self.scores
            .iter()
            .filter(|r| r.ema_score >= min_score)
            .filter(|r| org_id.is_empty() || r.org_id == org_id)
            .map(|r| r.clone())
            .collect()
    }

    /// Get risk history for an agent.
    pub fn get_history(&self, agent_id: &str, limit: usize) -> Vec<RiskHistoryEntry> {
        self.history
            .get(agent_id)
            .map(|h| {
                let hist = h.value();
                let start = if hist.len() > limit {
                    hist.len() - limit
                } else {
                    0
                };
                hist[start..].to_vec()
            })
            .unwrap_or_default()
    }

    /// Serialize all scores for Redis persistence.
    /// Returns (agent_id, org_id, ema, event_count, last_update_epoch).
    pub fn snapshot(&self) -> Vec<(String, String, f64, u64, i64)> {
        self.scores
            .iter()
            .map(|r| {
                (
                    r.agent_id.clone(),
                    r.org_id.clone(),
                    r.ema_score,
                    r.events_processed as u64,
                    r.last_updated.timestamp(),
                )
            })
            .collect()
    }

    /// Restore a single agent's score (e.g. from Redis on startup).
    pub fn restore_score(&self, agent_id: &str, org_id: &str, ema: f64, event_count: u64, last_update: i64) {
        let ts = DateTime::from_timestamp(last_update, 0).unwrap_or_else(Utc::now);
        self.scores.insert(
            agent_id.to_string(),
            AgentRiskState {
                agent_id: agent_id.to_string(),
                org_id: org_id.to_string(),
                ema_score: ema,
                classification: RiskClassification::from_score(ema),
                last_event_risk: ema, // best approximation
                events_processed: event_count as u32,
                last_updated: ts,
                last_decay: ts,
            },
        );
    }

    /// Batch restore scores from persistence.
    pub fn restore_scores(&self, entries: Vec<(String, String, f64, u64, i64)>) {
        for (agent_id, org_id, ema, event_count, last_update) in entries {
            self.restore_score(&agent_id, &org_id, ema, event_count, last_update);
        }
    }

    /// Directly set the last_updated timestamp for an agent (test helper).
    #[cfg(test)]
    pub fn set_last_updated(&self, agent_id: &str, ts: DateTime<Utc>) {
        if let Some(mut entry) = self.scores.get_mut(agent_id) {
            entry.last_updated = ts;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const ALPHA: f64 = 0.3;
    const THRESHOLD: f64 = 0.9;

    fn scorer() -> RiskScorer {
        RiskScorer::new(ALPHA, THRESHOLD)
    }

    // ---------------------------------------------------------------
    // Classification boundary tests
    // ---------------------------------------------------------------

    #[test]
    fn classification_score_0_0_is_normal() {
        assert_eq!(RiskClassification::from_score(0.0), RiskClassification::Normal);
    }

    #[test]
    fn classification_score_0_29_is_normal() {
        assert_eq!(RiskClassification::from_score(0.29), RiskClassification::Normal);
    }

    #[test]
    fn classification_score_0_3_is_elevated() {
        assert_eq!(RiskClassification::from_score(0.3), RiskClassification::Elevated);
    }

    #[test]
    fn classification_score_0_49_is_elevated() {
        assert_eq!(RiskClassification::from_score(0.49), RiskClassification::Elevated);
    }

    #[test]
    fn classification_score_0_5_is_warning() {
        assert_eq!(RiskClassification::from_score(0.5), RiskClassification::Warning);
    }

    #[test]
    fn classification_score_0_69_is_warning() {
        assert_eq!(RiskClassification::from_score(0.69), RiskClassification::Warning);
    }

    #[test]
    fn classification_score_0_7_is_high() {
        assert_eq!(RiskClassification::from_score(0.7), RiskClassification::High);
    }

    #[test]
    fn classification_score_0_89_is_high() {
        assert_eq!(RiskClassification::from_score(0.89), RiskClassification::High);
    }

    #[test]
    fn classification_score_0_9_is_critical() {
        assert_eq!(RiskClassification::from_score(0.9), RiskClassification::Critical);
    }

    #[test]
    fn classification_score_1_0_is_critical() {
        assert_eq!(RiskClassification::from_score(1.0), RiskClassification::Critical);
    }

    // ---------------------------------------------------------------
    // Classification as_str tests
    // ---------------------------------------------------------------

    #[test]
    fn classification_as_str_values() {
        assert_eq!(RiskClassification::Normal.as_str(), "normal");
        assert_eq!(RiskClassification::Elevated.as_str(), "elevated");
        assert_eq!(RiskClassification::Warning.as_str(), "warning");
        assert_eq!(RiskClassification::High.as_str(), "high");
        assert_eq!(RiskClassification::Critical.as_str(), "critical");
    }

    // ---------------------------------------------------------------
    // EMA formula correctness
    // ---------------------------------------------------------------

    #[test]
    fn ema_single_event_on_fresh_agent() {
        let s = scorer();
        let (ema, classification, _suspend) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
        // new_ema = 0.3 * 1.0 + 0.7 * 0.0 = 0.3
        assert!(
            (ema - 0.3).abs() < 1e-10,
            "Expected EMA 0.3, got {}",
            ema
        );
        assert_eq!(classification, RiskClassification::Elevated);
    }

    #[test]
    fn ema_accumulation_two_events() {
        let s = scorer();
        // Event 1: new_ema = 0.3 * 1.0 + 0.7 * 0.0 = 0.3
        s.process_event("agent-1", 1.0, "tool-a", "test-org");
        // Event 2: new_ema = 0.3 * 1.0 + 0.7 * 0.3 = 0.3 + 0.21 = 0.51
        let (ema, classification, _) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
        assert!(
            (ema - 0.51).abs() < 1e-10,
            "Expected EMA 0.51, got {}",
            ema
        );
        assert_eq!(classification, RiskClassification::Warning);
    }

    #[test]
    fn ema_accumulation_three_events() {
        let s = scorer();
        // Event 1: 0.3 * 1.0 + 0.7 * 0.0 = 0.3
        s.process_event("agent-1", 1.0, "tool-a", "test-org");
        // Event 2: 0.3 * 1.0 + 0.7 * 0.3 = 0.51
        s.process_event("agent-1", 1.0, "tool-a", "test-org");
        // Event 3: 0.3 * 1.0 + 0.7 * 0.51 = 0.657
        let (ema, classification, _) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
        assert!(
            (ema - 0.657).abs() < 1e-10,
            "Expected EMA 0.657, got {}",
            ema
        );
        assert_eq!(classification, RiskClassification::Warning);
    }

    #[test]
    fn ema_converges_toward_constant_input() {
        let s = scorer();
        // Feeding constant risk=1.0 many times should converge EMA toward 1.0.
        let mut last_ema = 0.0;
        for _ in 0..50 {
            let (ema, _, _) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
            assert!(ema >= last_ema, "EMA should monotonically increase with constant high input");
            last_ema = ema;
        }
        assert!(
            (last_ema - 1.0).abs() < 0.01,
            "After 50 events with risk=1.0, EMA should be near 1.0, got {}",
            last_ema
        );
    }

    #[test]
    fn ema_with_zero_risk_stays_zero() {
        let s = scorer();
        // P1-6: Zero-risk events no longer update EMA (score dilution floor).
        // EMA should remain at initial 0.0, event still counted.
        let (ema, classification, suspend) = s.process_event("agent-1", 0.0, "tool-a", "test-org");
        assert!((ema - 0.0).abs() < 1e-10);
        assert_eq!(classification, RiskClassification::Normal);
        assert!(!suspend);
        let state = s.get_score("agent-1").unwrap();
        assert_eq!(state.events_processed, 1); // Event still counted
    }

    #[test]
    fn zero_risk_events_do_not_dilute_ema() {
        // P1-6: Verify that 0.0-risk events cannot wash down a high EMA.
        let s = scorer();
        // Push EMA up with high risk events.
        for _ in 0..10 {
            s.process_event("agent-1", 1.0, "tool-a", "test-org");
        }
        let state = s.get_score("agent-1").unwrap();
        let high_ema = state.ema_score;

        // Send zero-risk events - EMA should NOT decrease (P1-6 floor).
        for _ in 0..10 {
            s.process_event("agent-1", 0.0, "tool-a", "test-org");
        }
        let state = s.get_score("agent-1").unwrap();
        assert!(
            (state.ema_score - high_ema).abs() < 1e-10,
            "EMA should not decrease after zero-risk events (P1-6 dilution floor); expected {}, got {}",
            high_ema,
            state.ema_score
        );
        // But events should still be counted
        assert_eq!(state.events_processed, 20);
    }

    #[test]
    fn ema_decreases_with_low_but_nonzero_risk() {
        let s = scorer();
        // Push EMA up with high risk events.
        for _ in 0..10 {
            s.process_event("agent-1", 1.0, "tool-a", "test-org");
        }
        let state = s.get_score("agent-1").unwrap();
        let high_ema = state.ema_score;

        // Send low-but-above-floor risk events to bring it down.
        for _ in 0..10 {
            s.process_event("agent-1", 0.05, "tool-a", "test-org");
        }
        let state = s.get_score("agent-1").unwrap();
        assert!(
            state.ema_score < high_ema,
            "EMA should decrease after low (but non-zero) risk events"
        );
    }

    // ---------------------------------------------------------------
    // Clamping tests: EMA stays in [0.0, 1.0]
    // ---------------------------------------------------------------

    #[test]
    fn ema_clamped_with_extreme_positive_input() {
        let s = scorer();
        // Even with event_risk > 1.0, EMA should be clamped at 1.0.
        let (ema, _, _) = s.process_event("agent-1", 100.0, "tool-a", "test-org");
        assert!(ema <= 1.0, "EMA must not exceed 1.0, got {}", ema);
    }

    #[test]
    fn ema_clamped_with_extreme_negative_input() {
        let s = scorer();
        // Even with event_risk < 0.0, EMA should be clamped at 0.0.
        let (ema, _, _) = s.process_event("agent-1", -100.0, "tool-a", "test-org");
        assert!(ema >= 0.0, "EMA must not go below 0.0, got {}", ema);
    }

    #[test]
    fn ema_stays_clamped_after_many_extreme_inputs() {
        let s = scorer();
        for _ in 0..20 {
            let (ema, _, _) = s.process_event("agent-1", 999.0, "tool-a", "test-org");
            assert!(ema >= 0.0 && ema <= 1.0, "EMA out of [0,1]: {}", ema);
        }
        for _ in 0..20 {
            let (ema, _, _) = s.process_event("agent-1", -999.0, "tool-a", "test-org");
            assert!(ema >= 0.0 && ema <= 1.0, "EMA out of [0,1]: {}", ema);
        }
    }

    // ---------------------------------------------------------------
    // Auto-suspend threshold
    // ---------------------------------------------------------------

    #[test]
    fn auto_suspend_triggers_at_threshold() {
        let s = scorer();
        // Feed enough high-risk events to cross 0.9.
        let mut triggered = false;
        for _ in 0..50 {
            let (_, _, suspend) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
            if suspend {
                triggered = true;
                break;
            }
        }
        assert!(triggered, "Auto-suspend should trigger when EMA crosses 0.9");
    }

    #[test]
    fn auto_suspend_does_not_trigger_below_threshold() {
        let s = scorer();
        // A single event with risk=1.0 produces EMA=0.3, well below 0.9.
        let (_, _, suspend) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
        assert!(!suspend, "Auto-suspend should not trigger at EMA=0.3");
    }

    #[test]
    fn auto_suspend_triggers_exactly_at_0_9() {
        // Use a custom scorer where alpha=1.0 so new_ema = event_risk exactly.
        let s = RiskScorer::new(1.0, 0.9);
        let (ema, _, suspend) = s.process_event("agent-1", 0.9, "tool-a", "test-org");
        assert!((ema - 0.9).abs() < 1e-10);
        assert!(suspend, "Auto-suspend should trigger at exactly 0.9");
    }

    // ---------------------------------------------------------------
    // Decay tests
    // ---------------------------------------------------------------

    #[test]
    fn decay_idle_over_one_hour_applies_0_95_factor() {
        let s = scorer();
        // Set up an agent with known EMA.
        s.process_event("agent-1", 1.0, "tool-a", "test-org"); // EMA=0.3
        // Manually push last_updated back by >1 hour.
        let past = Utc::now() - Duration::hours(2);
        s.set_last_updated("agent-1", past);

        s.apply_decay();

        let state = s.get_score("agent-1").unwrap();
        let expected = 0.3 * 0.95;
        assert!(
            (state.ema_score - expected).abs() < 1e-10,
            "Expected EMA {}, got {}",
            expected,
            state.ema_score
        );
    }

    #[test]
    fn decay_idle_over_24_hours_applies_0_85_factor() {
        let s = scorer();
        s.process_event("agent-1", 1.0, "tool-a", "test-org"); // EMA=0.3
        let past = Utc::now() - Duration::hours(25);
        s.set_last_updated("agent-1", past);

        s.apply_decay();

        let state = s.get_score("agent-1").unwrap();
        let expected = 0.3 * 0.85;
        assert!(
            (state.ema_score - expected).abs() < 1e-10,
            "Expected EMA {}, got {}",
            expected,
            state.ema_score
        );
    }

    #[test]
    fn decay_no_change_for_recently_active_agent() {
        let s = scorer();
        s.process_event("agent-1", 1.0, "tool-a", "test-org"); // EMA=0.3
        // Agent is fresh (just processed), so no decay should apply.
        let before = s.get_score("agent-1").unwrap().ema_score;
        s.apply_decay();
        let after = s.get_score("agent-1").unwrap().ema_score;
        assert!(
            (before - after).abs() < 1e-10,
            "Recently active agent should not decay; before={}, after={}",
            before,
            after
        );
    }

    #[test]
    fn decay_updates_classification() {
        let s = scorer();
        // Build up to high score.
        for _ in 0..20 {
            s.process_event("agent-1", 1.0, "tool-a", "test-org");
        }
        let state = s.get_score("agent-1").unwrap();
        let _original_class = state.classification;
        let original_ema = state.ema_score;

        // Move agent to 25 hours idle.
        let past = Utc::now() - Duration::hours(25);
        s.set_last_updated("agent-1", past);
        s.apply_decay();

        let state = s.get_score("agent-1").unwrap();
        let decayed_ema = original_ema * 0.85;
        assert!(
            (state.ema_score - decayed_ema).abs() < 1e-10,
            "Expected decayed EMA {}, got {}",
            decayed_ema,
            state.ema_score
        );
        // Classification should be recalculated.
        assert_eq!(
            state.classification,
            RiskClassification::from_score(decayed_ema)
        );
    }

    #[test]
    fn decay_floor_at_zero() {
        let s = scorer();
        s.process_event("agent-1", 0.0, "tool-a", "test-org"); // EMA=0.0
        let past = Utc::now() - Duration::hours(25);
        s.set_last_updated("agent-1", past);
        s.apply_decay();
        let state = s.get_score("agent-1").unwrap();
        assert!(
            state.ema_score >= 0.0,
            "EMA after decay must not go below 0.0"
        );
    }

    // ---------------------------------------------------------------
    // History ring buffer
    // ---------------------------------------------------------------

    #[test]
    fn history_records_events() {
        let s = scorer();
        s.process_event("agent-1", 0.5, "tool-a", "test-org");
        s.process_event("agent-1", 0.7, "tool-b", "test-org");

        let history = s.get_history("agent-1", 100);
        assert_eq!(history.len(), 2);
        assert!((history[0].event_risk - 0.5).abs() < 1e-10);
        assert_eq!(history[0].tool_name, "tool-a");
        assert!((history[1].event_risk - 0.7).abs() < 1e-10);
        assert_eq!(history[1].tool_name, "tool-b");
    }

    #[test]
    fn history_ring_buffer_caps_at_100_entries() {
        let s = scorer();
        for i in 0..150 {
            s.process_event("agent-1", (i as f64) / 150.0, "tool-a", "test-org");
        }
        let history = s.get_history("agent-1", 200);
        assert_eq!(
            history.len(),
            100,
            "History should be capped at 100 entries, got {}",
            history.len()
        );
    }

    #[test]
    fn history_ring_buffer_keeps_most_recent() {
        let s = scorer();
        for i in 0..150 {
            s.process_event("agent-1", (i as f64) / 1000.0, &format!("tool-{}", i), "test-org");
        }
        let history = s.get_history("agent-1", 100);
        // The earliest entry should be from event 50 (0-indexed), i.e., tool-50.
        assert_eq!(history[0].tool_name, "tool-50");
        assert_eq!(history[99].tool_name, "tool-149");
    }

    #[test]
    fn history_ema_before_and_after_are_consistent() {
        let s = scorer();
        s.process_event("agent-1", 1.0, "tool-a", "test-org");
        let history = s.get_history("agent-1", 10);
        assert_eq!(history.len(), 1);
        assert!((history[0].ema_before - 0.0).abs() < 1e-10);
        assert!((history[0].ema_after - 0.3).abs() < 1e-10);
    }

    #[test]
    fn history_limit_parameter_works() {
        let s = scorer();
        for _ in 0..10 {
            s.process_event("agent-1", 0.5, "tool-a", "test-org");
        }
        let history = s.get_history("agent-1", 3);
        assert_eq!(history.len(), 3, "Limit=3 should return 3 entries");
    }

    // ---------------------------------------------------------------
    // Snapshot
    // ---------------------------------------------------------------

    #[test]
    fn snapshot_returns_all_agents() {
        let s = scorer();
        s.process_event("agent-1", 0.5, "tool-a", "test-org");
        s.process_event("agent-2", 0.8, "tool-b", "test-org");
        s.process_event("agent-3", 0.1, "tool-c", "test-org");

        let snap = s.snapshot();
        assert_eq!(snap.len(), 3);

        // Collect into a map for order-independent checks.
        let map: std::collections::HashMap<String, (f64, u64, i64)> =
            snap.into_iter().map(|(id, _org_id, ema, cnt, ts)| (id, (ema, cnt, ts))).collect();
        // agent-1: 0.3 * 0.5 + 0.7 * 0.0 = 0.15
        assert!((map["agent-1"].0 - 0.15).abs() < 1e-10);
        assert_eq!(map["agent-1"].1, 1); // 1 event
        // agent-2: 0.3 * 0.8 + 0.7 * 0.0 = 0.24
        assert!((map["agent-2"].0 - 0.24).abs() < 1e-10);
        // agent-3: 0.3 * 0.1 + 0.7 * 0.0 = 0.03
        assert!((map["agent-3"].0 - 0.03).abs() < 1e-10);
    }

    #[test]
    fn snapshot_empty_when_no_agents() {
        let s = scorer();
        let snap = s.snapshot();
        assert!(snap.is_empty());
    }

    // ---------------------------------------------------------------
    // Restore
    // ---------------------------------------------------------------

    #[test]
    fn restore_score_creates_agent_state() {
        let s = scorer();
        let now = Utc::now().timestamp();
        s.restore_score("agent-restored", "test-org", 0.65, 42, now);

        let state = s.get_score("agent-restored").unwrap();
        assert!((state.ema_score - 0.65).abs() < 1e-10);
        assert_eq!(state.events_processed, 42);
        assert_eq!(state.classification, RiskClassification::Warning);
    }

    #[test]
    fn restore_scores_batch() {
        let s = scorer();
        let now = Utc::now().timestamp();
        s.restore_scores(vec![
            ("a1".to_string(), "test-org".to_string(), 0.1, 5, now),
            ("a2".to_string(), "test-org".to_string(), 0.8, 100, now),
        ]);

        assert!((s.get_score("a1").unwrap().ema_score - 0.1).abs() < 1e-10);
        assert!((s.get_score("a2").unwrap().ema_score - 0.8).abs() < 1e-10);
    }

    #[test]
    fn restore_then_process_continues_ema() {
        let s = scorer();
        let now = Utc::now().timestamp();
        s.restore_score("agent-1", "test-org", 0.5, 10, now);
        // Process a new event: new_ema = 0.3 * 1.0 + 0.7 * 0.5 = 0.65
        let (ema, _, _) = s.process_event("agent-1", 1.0, "tool-a", "test-org");
        assert!((ema - 0.65).abs() < 1e-10);
        let state = s.get_score("agent-1").unwrap();
        assert_eq!(state.events_processed, 11);
    }

    // ---------------------------------------------------------------
    // get_score / get_all_scores
    // ---------------------------------------------------------------

    #[test]
    fn get_score_returns_none_for_nonexistent_agent() {
        let s = scorer();
        assert!(s.get_score("no-such-agent").is_none());
    }

    #[test]
    fn get_score_returns_correct_state() {
        let s = scorer();
        s.process_event("agent-1", 0.6, "tool-x", "test-org");
        let state = s.get_score("agent-1").unwrap();
        assert_eq!(state.agent_id, "agent-1");
        // EMA = 0.3 * 0.6 = 0.18
        assert!((state.ema_score - 0.18).abs() < 1e-10);
        assert_eq!(state.events_processed, 1);
        assert!((state.last_event_risk - 0.6).abs() < 1e-10);
    }

    #[test]
    fn get_all_scores_filters_by_min_score() {
        let s = scorer();
        s.process_event("agent-low", 0.1, "tool-a", "test-org"); // EMA=0.03
        s.process_event("agent-high", 1.0, "tool-b", "test-org"); // EMA=0.3

        let all = s.get_all_scores(0.0, "");
        assert_eq!(all.len(), 2);

        let filtered = s.get_all_scores(0.1, "");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].agent_id, "agent-high");
    }

    // ---------------------------------------------------------------
    // get_history for non-existent agent
    // ---------------------------------------------------------------

    #[test]
    fn get_history_returns_empty_for_nonexistent_agent() {
        let s = scorer();
        let history = s.get_history("no-such-agent", 50);
        assert!(history.is_empty());
    }

    // ---------------------------------------------------------------
    // Multiple agents are independent
    // ---------------------------------------------------------------

    #[test]
    fn multiple_agents_scores_are_independent() {
        let s = scorer();
        s.process_event("agent-1", 1.0, "tool-a", "test-org");
        s.process_event("agent-2", 0.0, "tool-b", "test-org");

        let state1 = s.get_score("agent-1").unwrap();
        let state2 = s.get_score("agent-2").unwrap();

        assert!((state1.ema_score - 0.3).abs() < 1e-10);
        assert!((state2.ema_score - 0.0).abs() < 1e-10);
    }

    // ---------------------------------------------------------------
    // Events processed counter
    // ---------------------------------------------------------------

    #[test]
    fn events_processed_counter_increments() {
        let s = scorer();
        s.process_event("agent-1", 0.5, "tool-a", "test-org");
        s.process_event("agent-1", 0.5, "tool-a", "test-org");
        s.process_event("agent-1", 0.5, "tool-a", "test-org");
        let state = s.get_score("agent-1").unwrap();
        assert_eq!(state.events_processed, 3);
    }

    // ---------------------------------------------------------------
    // Custom alpha values
    // ---------------------------------------------------------------

    #[test]
    fn custom_alpha_1_0_replaces_entirely() {
        let s = RiskScorer::new(1.0, 0.9);
        s.process_event("agent-1", 0.5, "tool-a", "test-org"); // EMA = 1.0 * 0.5 + 0.0 * 0.0 = 0.5
        let state = s.get_score("agent-1").unwrap();
        assert!((state.ema_score - 0.5).abs() < 1e-10);
        s.process_event("agent-1", 0.8, "tool-a", "test-org"); // EMA = 1.0 * 0.8 + 0.0 * 0.5 = 0.8
        let state = s.get_score("agent-1").unwrap();
        assert!((state.ema_score - 0.8).abs() < 1e-10);
    }

    #[test]
    fn custom_alpha_0_0_ignores_new_events() {
        let s = RiskScorer::new(0.0, 0.9);
        s.process_event("agent-1", 1.0, "tool-a", "test-org"); // EMA = 0.0 * 1.0 + 1.0 * 0.0 = 0.0
        let state = s.get_score("agent-1").unwrap();
        assert!((state.ema_score - 0.0).abs() < 1e-10);
    }

    // ---------------------------------------------------------------
    // Revive grace period tests
    // ---------------------------------------------------------------

    #[test]
    fn reset_score_starts_grace_period() {
        let s = scorer();
        // Build up high risk
        for _ in 0..10 {
            s.process_event("agent-g", 0.95, "tool", "test-org");
        }
        let state = s.get_score("agent-g").unwrap();
        assert!(state.ema_score > 0.8, "Score should be high before reset");

        // Reset (revive)
        s.reset_score("agent-g");

        // Score should be gone
        assert!(s.get_score("agent-g").is_none(), "Score should be cleared");
        // Grace period should be active
        assert!(s.is_in_grace_period("agent-g"), "Grace period should be active");
    }

    #[test]
    fn grace_period_prevents_auto_suspend() {
        let s = scorer();

        // Reset first to start grace period
        s.reset_score("agent-gp");

        // Process a high-risk event during grace period
        let (ema, _, should_suspend) = s.process_event("agent-gp", 0.99, "tool", "test-org");

        // EMA should be computed normally
        assert!(ema > 0.0, "EMA should be computed");
        // But auto-suspend should NOT trigger during grace period
        assert!(!should_suspend, "Should NOT auto-suspend during grace period");
    }

    #[test]
    fn no_grace_period_for_fresh_agent() {
        let s = scorer();
        assert!(!s.is_in_grace_period("new-agent"), "Fresh agent should not be in grace period");
    }

    #[test]
    fn grace_period_clears_history() {
        let s = scorer();

        // Add some history
        s.process_event("agent-h", 0.5, "tool-a", "test-org");
        s.process_event("agent-h", 0.7, "tool-b", "test-org");
        assert!(!s.get_history("agent-h", 10).is_empty());

        // Reset clears history
        s.reset_score("agent-h");
        assert!(s.get_history("agent-h", 10).is_empty(), "History should be cleared on reset");
    }

    // ── Fix #1: Config events must NOT inflate EMA ──
    // consumer.rs passes risk=0.0 for non-security events. The P1-6 floor
    // in process_event treats events < 0.01 as no-ops. Verify this.

    #[test]
    fn config_rejection_does_not_inflate_ema() {
        let s = scorer();
        // Simulate: config rejection → consumer passes 0.0
        let (ema, _, _) = s.process_event("agent-config", 0.0, "db.query", "test-org");
        assert_eq!(ema, 0.0, "Config rejection (risk=0.0) must not raise EMA");

        // Multiple config rejections should still leave EMA at 0
        for _ in 0..10 {
            let (ema, _, _) = s.process_event("agent-config", 0.0, "db.query", "test-org");
            assert_eq!(ema, 0.0, "Repeated config rejections must not raise EMA");
        }
    }

    #[test]
    fn security_rejection_inflates_ema_then_config_does_not() {
        let s = scorer();
        // One real security event
        let (ema1, _, _) = s.process_event("agent-mixed", 0.8, "shell.exec", "test-org");
        assert!(ema1 > 0.0);

        // Config rejection (0.0) does NOT pull EMA down (P1-6 floor)
        let (ema2, _, _) = s.process_event("agent-mixed", 0.0, "db.query", "test-org");
        assert_eq!(ema2, ema1, "Config rejection must not change EMA");
    }

    #[test]
    fn ema_death_spiral_prevented_for_new_agent() {
        let s = scorer();
        // Simulate: new agent with 5 config rejections (scope mismatch).
        // consumer.rs converts these to risk=0.0 before calling process_event.
        for i in 0..5 {
            let (ema, classification, should_suspend) =
                s.process_event("new-agent", 0.0, &format!("tool-{}", i), "test-org");
            assert_eq!(ema, 0.0, "EMA must stay at 0 after config rejection #{}", i);
            assert_eq!(classification, RiskClassification::Normal);
            assert!(!should_suspend, "Must not auto-suspend on config rejections");
        }

        // First real call should work fine (low risk)
        let (ema, classification, should_suspend) =
            s.process_event("new-agent", 0.1, "db.query", "test-org");
        assert!(ema < 0.1, "EMA should be modest after one low-risk event");
        assert_eq!(classification, RiskClassification::Normal);
        assert!(!should_suspend);
    }

    // ---------------------------------------------------------------
    // org_id filtering tests
    // ---------------------------------------------------------------

    #[test]
    fn get_all_scores_filters_by_org_id() {
        let s = scorer();
        s.process_event("agent-a", 0.5, "tool-a", "org-alpha");
        s.process_event("agent-b", 0.6, "tool-b", "org-alpha");
        s.process_event("agent-c", 0.7, "tool-c", "org-beta");

        let alpha_agents = s.get_all_scores(0.0, "org-alpha");
        assert_eq!(alpha_agents.len(), 2);
        assert!(alpha_agents.iter().all(|a| a.org_id == "org-alpha"));

        let beta_agents = s.get_all_scores(0.0, "org-beta");
        assert_eq!(beta_agents.len(), 1);
        assert_eq!(beta_agents[0].agent_id, "agent-c");
    }

    #[test]
    fn get_all_scores_empty_org_id_returns_all() {
        let s = scorer();
        s.process_event("agent-a", 0.5, "tool-a", "org-alpha");
        s.process_event("agent-b", 0.6, "tool-b", "org-beta");

        let all = s.get_all_scores(0.0, "");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn get_all_scores_org_id_and_min_score_combined() {
        let s = scorer();
        s.process_event("agent-low", 0.1, "tool-a", "org-alpha");  // EMA=0.03
        s.process_event("agent-high", 1.0, "tool-b", "org-alpha"); // EMA=0.30
        s.process_event("agent-other", 1.0, "tool-c", "org-beta"); // EMA=0.30

        // Both filters apply: org-alpha AND min_score 0.1
        let result = s.get_all_scores(0.1, "org-alpha");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].agent_id, "agent-high");
    }

    #[test]
    fn get_all_scores_nonexistent_org_returns_empty() {
        let s = scorer();
        s.process_event("agent-a", 0.5, "tool-a", "org-alpha");

        let result = s.get_all_scores(0.0, "org-nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn process_event_stores_org_id() {
        let s = scorer();
        s.process_event("agent-a", 0.5, "tool-a", "org-alpha");
        let state = s.get_score("agent-a").unwrap();
        assert_eq!(state.org_id, "org-alpha");
    }

    #[test]
    fn process_event_backfills_empty_org_id() {
        let s = scorer();
        // First event with empty org_id
        s.process_event("agent-a", 0.5, "tool-a", "");
        assert_eq!(s.get_score("agent-a").unwrap().org_id, "");

        // Second event with real org_id backfills
        s.process_event("agent-a", 0.3, "tool-b", "org-alpha");
        assert_eq!(s.get_score("agent-a").unwrap().org_id, "org-alpha");
    }

    #[test]
    fn snapshot_includes_org_id() {
        let s = scorer();
        s.process_event("agent-a", 0.5, "tool-a", "org-alpha");
        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "agent-a");
        assert_eq!(snap[0].1, "org-alpha");
    }

    #[test]
    fn restore_score_preserves_org_id() {
        let s = scorer();
        let now = Utc::now().timestamp();
        s.restore_score("agent-a", "org-alpha", 0.5, 10, now);
        let state = s.get_score("agent-a").unwrap();
        assert_eq!(state.org_id, "org-alpha");
    }
}
