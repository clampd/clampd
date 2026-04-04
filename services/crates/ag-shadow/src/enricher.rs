use ag_common::models::ShadowEvent;
use chrono::Timelike;

/// Derive flags from a shadow event for enrichment.
/// Returns a Vec of string flags that describe detected patterns.
pub fn enrich(event: &ShadowEvent) -> Vec<String> {
    let mut flags = Vec::new();

    // 1. Bulk response detection
    if let Some(ref meta) = event.response_metadata {
        if meta.records_count > 1000 {
            flags.push("bulk_response".to_string());
        }
    }

    // 2. Off-hours activity — uses agent's configured active hours window.
    //    Both equal (including 0,0) means no restriction (24/7 agent).
    let start = event.active_hours_start;
    let end = event.active_hours_end;
    if start != end {
        let hour = event.timestamp.hour();
        let in_range = if start < end {
            // Normal range: e.g. 9-17
            hour >= start && hour < end
        } else {
            // Midnight-crossing range: e.g. 22-6
            hour >= start || hour < end
        };
        if !in_range {
            flags.push("off_hours".to_string());
        }
    }

    // 3. Data flow detection (read tool followed by send/external tool)
    if (event.tool_name.contains("database") || event.tool_name.contains("file.read"))
        && event
            .session_flags
            .iter()
            .any(|f| f == "external_send_after_read")
    {
        flags.push("data_flow_detected".to_string());
    }

    // 4. Encoding anomaly (any encodings detected in params)
    if !event.encodings_detected.is_empty() {
        flags.push(format!(
            "encoding_layers:{}",
            event.encodings_detected.len()
        ));
    }

    // 5. High risk with write scope
    if event.assessed_risk >= 0.7 && event.scope_requested.contains("write") {
        flags.push("high_risk_write".to_string());
    }

    // 6. PII in response
    if let Some(ref meta) = event.response_metadata {
        if meta.contains_pii_patterns {
            flags.push("pii_in_response".to_string());
        }
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_event() -> ShadowEvent {
        ShadowEvent {
            request_id: Uuid::new_v4(),
            trace_id: "trace-1".to_string(),
            org_id: "org-1".to_string(),
            agent_id: "agent-1".to_string(),
            agent_name: "test-agent".to_string(),
            user_id: "user-1".to_string(),
            tool_name: "database.query".to_string(),
            tool_action: "read".to_string(),
            params_hash: "hash".to_string(),
            params_summary: "SELECT *".to_string(),
            prompt_hash: "phash".to_string(),
            encodings_detected: vec![],
            encoding_risk_bonus: 0.0,
            assessed_risk: 0.1,
            session_risk_factor: 0.0,
            intent_classification: "Safe".to_string(),
            intent_labels: vec![],
            matched_rules: vec![],
            policy_action: "Allow".to_string(),
            policy_reason: String::new(),
            boundary_violation: None,
            scope_requested: "database:read".to_string(),
            scope_granted: Some("database:read".to_string()),
            blocked: false,
            denial_reason: None,
            session_id: "sess-1".to_string(),
            session_flags: vec![],
            response_metadata: None,
            degraded_stages: vec![],
            latency_ms: 10,
            timestamp: Utc::now(),
            caller_agent_id: None,
            delegation_chain: None,
            delegation_trace_id: None,
            tool_descriptor_hash: String::new(),
            tool_description: String::new(),
            tool_params_schema: String::new(),
            active_hours_start: 0,
            active_hours_end: 0,
            rejection_type: ag_common::models::RejectionType::None,
        }
    }

    #[test]
    fn test_bulk_response_flag() {
        let mut event = make_event();
        event.response_metadata = Some(ag_common::models::ResponseMetadata {
            status_code: 200,
            body_size_bytes: 50000,
            records_count: 5000,
            contains_pii_patterns: false,
            truncated: false,
            response_hash: String::new(),
        });
        let flags = enrich(&event);
        assert!(flags.contains(&"bulk_response".to_string()));
    }

    #[test]
    fn test_encoding_flag() {
        let mut event = make_event();
        event.encodings_detected = vec!["base64".to_string(), "url_encoding".to_string()];
        let flags = enrich(&event);
        assert!(flags.contains(&"encoding_layers:2".to_string()));
    }

    #[test]
    fn test_high_risk_write_flag() {
        let mut event = make_event();
        event.assessed_risk = 0.8;
        event.scope_requested = "database:write".to_string();
        let flags = enrich(&event);
        assert!(flags.contains(&"high_risk_write".to_string()));
    }

    #[test]
    fn test_no_off_hours_for_24_7_agent() {
        let mut event = make_event();
        // active_hours_start=0, active_hours_end=0 → 24/7, no off_hours flag ever
        event.timestamp = chrono::NaiveDate::from_ymd_opt(2026, 3, 6)
            .unwrap()
            .and_hms_opt(3, 0, 0) // 3 AM
            .unwrap()
            .and_utc();
        let flags = enrich(&event);
        assert!(!flags.contains(&"off_hours".to_string()));
    }

    #[test]
    fn test_off_hours_with_configured_window() {
        let mut event = make_event();
        event.active_hours_start = 9;
        event.active_hours_end = 17;
        // 3 AM is outside 9-17
        event.timestamp = chrono::NaiveDate::from_ymd_opt(2026, 3, 6)
            .unwrap()
            .and_hms_opt(3, 0, 0)
            .unwrap()
            .and_utc();
        let flags = enrich(&event);
        assert!(flags.contains(&"off_hours".to_string()));
    }

    #[test]
    fn test_no_off_hours_within_configured_window() {
        let mut event = make_event();
        event.active_hours_start = 9;
        event.active_hours_end = 17;
        // 12 PM is within 9-17
        event.timestamp = chrono::NaiveDate::from_ymd_opt(2026, 3, 6)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();
        let flags = enrich(&event);
        assert!(!flags.contains(&"off_hours".to_string()));
    }

    #[test]
    fn test_off_hours_midnight_crossing() {
        let mut event = make_event();
        event.active_hours_start = 22;
        event.active_hours_end = 6;
        // 10 AM is outside 22-6
        event.timestamp = chrono::NaiveDate::from_ymd_opt(2026, 3, 6)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .and_utc();
        let flags = enrich(&event);
        assert!(flags.contains(&"off_hours".to_string()));

        // 23:00 is within 22-6
        event.timestamp = chrono::NaiveDate::from_ymd_opt(2026, 3, 6)
            .unwrap()
            .and_hms_opt(23, 0, 0)
            .unwrap()
            .and_utc();
        let flags = enrich(&event);
        assert!(!flags.contains(&"off_hours".to_string()));
    }

    #[test]
    fn test_pii_in_response_flag() {
        let mut event = make_event();
        event.response_metadata = Some(ag_common::models::ResponseMetadata {
            status_code: 200,
            body_size_bytes: 100,
            records_count: 1,
            contains_pii_patterns: true,
            truncated: false,
            response_hash: String::new(),
        });
        let flags = enrich(&event);
        assert!(flags.contains(&"pii_in_response".to_string()));
    }

    #[test]
    fn test_data_flow_detected_flag() {
        let mut event = make_event();
        event.tool_name = "database.query".to_string();
        event.session_flags = vec!["external_send_after_read".to_string()];
        let flags = enrich(&event);
        assert!(flags.contains(&"data_flow_detected".to_string()));
    }

    #[test]
    fn test_no_data_flow_without_session_flag() {
        let mut event = make_event();
        event.tool_name = "database.query".to_string();
        event.session_flags = vec![];
        let flags = enrich(&event);
        assert!(!flags.contains(&"data_flow_detected".to_string()));
    }

    #[test]
    fn test_no_flags_for_clean_event() {
        let event = make_event();
        let flags = enrich(&event);
        assert!(flags.is_empty(), "Clean event should produce no flags");
    }

    #[test]
    fn test_multiple_flags_simultaneously() {
        let mut event = make_event();
        event.assessed_risk = 0.9;
        event.scope_requested = "database:write".to_string();
        event.encodings_detected = vec!["base64".to_string()];
        event.response_metadata = Some(ag_common::models::ResponseMetadata {
            status_code: 200,
            body_size_bytes: 500000,
            records_count: 2000,
            contains_pii_patterns: true,
            truncated: false,
            response_hash: String::new(),
        });
        let flags = enrich(&event);
        assert!(flags.contains(&"high_risk_write".to_string()));
        assert!(flags.contains(&"encoding_layers:1".to_string()));
        assert!(flags.contains(&"bulk_response".to_string()));
        assert!(flags.contains(&"pii_in_response".to_string()));
    }

    #[test]
    fn test_bulk_threshold_boundary() {
        let mut event = make_event();
        // Exactly 1000 records should NOT trigger (needs > 1000)
        event.response_metadata = Some(ag_common::models::ResponseMetadata {
            status_code: 200,
            body_size_bytes: 10000,
            records_count: 1000,
            contains_pii_patterns: false,
            truncated: false,
            response_hash: String::new(),
        });
        let flags = enrich(&event);
        assert!(!flags.contains(&"bulk_response".to_string()));
    }

    #[test]
    fn test_high_risk_write_threshold() {
        let mut event = make_event();
        // 0.69 risk + write scope should NOT trigger (needs >= 0.7)
        event.assessed_risk = 0.69;
        event.scope_requested = "database:write".to_string();
        let flags = enrich(&event);
        assert!(!flags.contains(&"high_risk_write".to_string()));
    }
}
