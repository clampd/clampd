//! Behavioral baseline accumulator — tracks agent behavior for anomaly detection.
//!
//! Accumulates scope usage, active hours, per-tool record counts, and tool pairs
//! from shadow events. Produces enriched `Baselines` that feed into anomaly detection.

use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use tracing::warn;

/// Per-agent accumulated behavioral data for baseline derivation.
#[derive(Debug, Default)]
struct AgentBaselineData {
    /// All scopes the agent has ever requested.
    known_scopes: HashSet<String>,
    /// Event count per hour (0..23) for active hours computation.
    hourly_counts: [u64; 24],
    /// Total events tracked.
    total_events: u64,
    /// Per-tool cumulative records fetched.
    tool_records: HashMap<String, u64>,
    /// Per-tool event count.
    tool_event_counts: HashMap<String, u64>,
    /// Observed read->write tool pair combinations.
    tool_pairs: HashSet<(String, String)>,
    /// Last tool that fetched records (for pair detection).
    last_read_tool: Option<String>,
}

/// Accumulates behavioral data across shadow events for baseline computation.
pub struct BaselineAccumulator {
    data: DashMap<String, AgentBaselineData>,
}

impl BaselineAccumulator {
    pub fn new() -> Self {
        Self {
            data: DashMap::new(),
        }
    }

    /// Record a shadow event for baseline accumulation.
    pub fn record_event(
        &self,
        agent_id: &str,
        tool_name: &str,
        scope_requested: &str,
        hour: u8,
        records_fetched: u32,
        is_external_send: bool,
    ) {
        let mut entry = self.data.entry(agent_id.to_string()).or_default();
        let data = entry.value_mut();

        // Track scope
        if !scope_requested.is_empty() {
            data.known_scopes.insert(scope_requested.to_string());
        }

        // Track active hours
        if (hour as usize) < 24 {
            data.hourly_counts[hour as usize] += 1;
        }
        data.total_events += 1;

        // Track per-tool records
        *data.tool_records.entry(tool_name.to_string()).or_insert(0) += records_fetched as u64;
        *data.tool_event_counts.entry(tool_name.to_string()).or_insert(0) += 1;

        // Track tool pairs: if this is an external send and there was a prior read
        if is_external_send {
            if let Some(ref read_tool) = data.last_read_tool {
                data.tool_pairs.insert((read_tool.clone(), tool_name.to_string()));
            }
        }

        // Update last read tool (any tool that fetched records)
        if records_fetched > 0 && !is_external_send {
            data.last_read_tool = Some(tool_name.to_string());
        }
    }

    /// Compute enriched baselines for an agent.
    /// `calls_per_hour` and `age_days` come from the existing scorer data.
    pub fn compute_baselines(
        &self,
        agent_id: &str,
        calls_per_hour: f64,
        age_days: u32,
    ) -> crate::anomaly::Baselines {
        let data = self.data.get(agent_id);

        match data {
            None => crate::anomaly::Baselines {
                calls_per_hour,
                unique_tools_per_session: 3.0,
                avg_records_per_hour: calls_per_hour * 10.0,
                known_scopes: HashSet::new(),
                active_hours: (0..24).map(|h| (h, 1.0 / 24.0)).collect(),
                baseline_age_days: age_days,
                tool_avg_records: HashMap::new(),
                known_tool_pairs: Vec::new(),
            },
            Some(entry) => {
                let d = entry.value();

                // Compute active hours as fractions
                let active_hours: HashMap<u8, f64> = if d.total_events > 0 {
                    (0u8..24).map(|h| {
                        (h, d.hourly_counts[h as usize] as f64 / d.total_events as f64)
                    }).collect()
                } else {
                    (0..24).map(|h| (h, 1.0 / 24.0)).collect()
                };

                // Compute per-tool average records
                let tool_avg_records: HashMap<String, f64> = d.tool_event_counts.iter()
                    .map(|(tool, &count)| {
                        let total_records = d.tool_records.get(tool).copied().unwrap_or(0);
                        let avg = if count > 0 { total_records as f64 / count as f64 } else { 0.0 };
                        (tool.clone(), avg)
                    })
                    .collect();

                // Compute unique tools per session (approximate: total unique tools / age in sessions)
                let unique_tools = d.tool_event_counts.len() as f64;
                let age_sessions = (age_days as f64 * 24.0 * 4.0).max(1.0); // ~4 sessions/hour
                let unique_tools_per_session = (unique_tools / age_sessions).max(1.0).min(unique_tools);

                // Average records per hour
                let total_records: u64 = d.tool_records.values().sum();
                let age_hours = (age_days as f64 * 24.0).max(1.0);
                let avg_records_per_hour = total_records as f64 / age_hours;

                let mut baselines = crate::anomaly::Baselines {
                    calls_per_hour,
                    unique_tools_per_session,
                    avg_records_per_hour,
                    known_scopes: d.known_scopes.clone(),
                    active_hours,
                    baseline_age_days: age_days,
                    tool_avg_records,
                    known_tool_pairs: d.tool_pairs.iter().cloned().collect(),
                };

                // P1-7: Baseline reasonableness caps — prevent poisoned baselines.
                // An attacker who controls an agent for 7+ days could normalize
                // malicious behavior. Cap baseline values to reasonable maximums.
                const MAX_KNOWN_SCOPES: usize = 20;
                const MAX_UNIQUE_TOOLS: usize = 30;
                const MAX_CALLS_PER_HOUR: f64 = 500.0;

                if baselines.known_scopes.len() > MAX_KNOWN_SCOPES {
                    warn!(
                        agent_id = %agent_id,
                        scopes = baselines.known_scopes.len(),
                        "Baseline scope count exceeds cap — possible baseline poisoning"
                    );
                    // Retain only the first MAX_KNOWN_SCOPES scopes (deterministic truncation)
                    let kept: HashSet<String> = baselines.known_scopes.iter()
                        .take(MAX_KNOWN_SCOPES)
                        .cloned()
                        .collect();
                    baselines.known_scopes = kept;
                }
                if baselines.calls_per_hour > MAX_CALLS_PER_HOUR {
                    warn!(
                        agent_id = %agent_id,
                        cph = baselines.calls_per_hour,
                        "Baseline calls/hour exceeds cap"
                    );
                    baselines.calls_per_hour = MAX_CALLS_PER_HOUR;
                }
                if baselines.unique_tools_per_session > MAX_UNIQUE_TOOLS as f64 {
                    warn!(
                        agent_id = %agent_id,
                        tools = baselines.unique_tools_per_session,
                        "Baseline unique tools exceeds cap"
                    );
                    baselines.unique_tools_per_session = MAX_UNIQUE_TOOLS as f64;
                }

                baselines
            }
        }
    }

    /// Number of agents being tracked.
    pub fn agent_count(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_accumulator_empty() {
        let acc = BaselineAccumulator::new();
        assert_eq!(acc.agent_count(), 0);
    }

    #[test]
    fn test_record_event_tracks_scope() {
        let acc = BaselineAccumulator::new();
        acc.record_event("agent-1", "database.query", "data:pii:query", 14, 10, false);
        let baselines = acc.compute_baselines("agent-1", 5.0, 10);
        assert!(baselines.known_scopes.contains("data:pii:query"));
    }

    #[test]
    fn test_record_event_tracks_active_hours() {
        let acc = BaselineAccumulator::new();
        for _ in 0..8 {
            acc.record_event("agent-1", "db.query", "", 14, 0, false);
        }
        for _ in 0..2 {
            acc.record_event("agent-1", "db.query", "", 3, 0, false);
        }
        let baselines = acc.compute_baselines("agent-1", 1.0, 10);
        // Hour 14 should have 80% of activity
        assert!((baselines.active_hours[&14] - 0.8).abs() < 0.01);
        assert!((baselines.active_hours[&3] - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_per_tool_avg_records() {
        let acc = BaselineAccumulator::new();
        acc.record_event("agent-1", "database.query", "", 10, 100, false);
        acc.record_event("agent-1", "database.query", "", 10, 200, false);
        acc.record_event("agent-1", "file_read", "", 10, 1, false);
        let baselines = acc.compute_baselines("agent-1", 3.0, 10);
        assert!((baselines.tool_avg_records["database.query"] - 150.0).abs() < 0.01);
        assert!((baselines.tool_avg_records["file_read"] - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_tool_pair_tracking() {
        let acc = BaselineAccumulator::new();
        // Read data, then send externally
        acc.record_event("agent-1", "database.query", "", 10, 50, false);
        acc.record_event("agent-1", "http.post", "", 10, 0, true);
        let baselines = acc.compute_baselines("agent-1", 2.0, 10);
        assert!(baselines.known_tool_pairs.contains(&("database.query".to_string(), "http.post".to_string())));
    }

    #[test]
    fn test_no_pair_without_prior_read() {
        let acc = BaselineAccumulator::new();
        acc.record_event("agent-1", "http.post", "", 10, 0, true);
        let baselines = acc.compute_baselines("agent-1", 1.0, 10);
        assert!(baselines.known_tool_pairs.is_empty());
    }

    #[test]
    fn test_unknown_agent_returns_defaults() {
        let acc = BaselineAccumulator::new();
        let baselines = acc.compute_baselines("unknown", 5.0, 10);
        assert!(baselines.known_scopes.is_empty());
        assert!(baselines.tool_avg_records.is_empty());
        assert!(baselines.known_tool_pairs.is_empty());
        assert_eq!(baselines.baseline_age_days, 10);
    }

    #[test]
    fn test_empty_scope_not_tracked() {
        let acc = BaselineAccumulator::new();
        acc.record_event("agent-1", "db.query", "", 10, 0, false);
        let baselines = acc.compute_baselines("agent-1", 1.0, 7);
        assert!(baselines.known_scopes.is_empty());
    }

    #[test]
    fn test_multiple_agents_independent() {
        let acc = BaselineAccumulator::new();
        acc.record_event("agent-1", "db.query", "scope-a", 10, 0, false);
        acc.record_event("agent-2", "file_read", "scope-b", 14, 0, false);
        assert_eq!(acc.agent_count(), 2);
        let b1 = acc.compute_baselines("agent-1", 1.0, 7);
        let b2 = acc.compute_baselines("agent-2", 1.0, 7);
        assert!(b1.known_scopes.contains("scope-a"));
        assert!(!b1.known_scopes.contains("scope-b"));
        assert!(b2.known_scopes.contains("scope-b"));
    }
}
