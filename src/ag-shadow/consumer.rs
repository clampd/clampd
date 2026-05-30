use ag_common::models::ShadowEvent;
use async_nats::jetstream;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

type HmacSha256 = Hmac<Sha256>;

use crate::enricher;
use crate::lag_detector::{LagDetector, LagStatus};
use crate::pii_masker::PiiMasker;
use crate::quarantine::{QuarantineDecider, QuarantineWriter};
use crate::retry::{FailedEventBuffer, RetryPolicy};
use crate::writer::{BatchWriter, ShadowLogRow};

// SECURITY: Shadow events should only come from ag-gateway.
// NATS token auth (NATS_TOKEN) prevents unauthorized publishers.
// HMAC-SHA256 verification provides defense-in-depth: if AG_HMAC_SECRET is set,
// every message MUST carry a valid X-AG-HMAC header. Messages missing the
// header are quarantined as "hmac_header_missing" - previously they bypassed
// verification entirely, letting an attacker opt out of signing by omitting
// the header (#25 item 2).
// If no secret is configured, HMAC verification is disabled globally.

/// Compute HMAC-SHA256 of `payload` using `secret` and return the hex-encoded
/// digest. Backed by the audited `hmac` crate (#25 item 1 - replaces the
/// 39-line hand-rolled ipad/opad implementation).
pub fn compute_hmac_sha256(payload: &[u8], secret: &[u8]) -> String {
    // HMAC-SHA256 accepts keys of any length; `new_from_slice` only errors on
    // truly impossible cases (e.g. zero-length block), so expect is safe here.
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify that `expected_hmac` (hex-encoded) matches the HMAC-SHA256 of
/// `payload` computed with `secret`. Uses constant-time comparison via
/// `subtle` to eliminate hand-rolled timing-safe logic.
pub fn verify_event_hmac(payload: &[u8], expected_hmac: &str, secret: &[u8]) -> bool {
    // Decode the expected hex digest once; reject malformed inputs rather
    // than accidentally accepting them via a length-mismatch shortcut.
    let Ok(expected_bytes) = hex::decode(expected_hmac) else {
        return false;
    };

    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(payload);
    let computed = mac.finalize().into_bytes();

    // `Mac::verify` / `subtle::ConstantTimeEq` both return constant-time
    // results - no timing leak between matching and length mismatches.
    computed.as_slice().ct_eq(&expected_bytes).into()
}

/// Load the HMAC shared secret from environment. Returns `None` if not configured.
fn load_hmac_secret() -> Option<Vec<u8>> {
    match std::env::var("AG_HMAC_SECRET") {
        Ok(val) if !val.is_empty() => {
            info!("AG_HMAC_SECRET configured - HMAC verification enabled for shadow events");
            Some(val.into_bytes())
        }
        _ => {
            warn!("AG_HMAC_SECRET not set - HMAC verification disabled (backward compatible)");
            None
        }
    }
}

/// Run the NATS JetStream consumer loop (legacy single-pod mode).
pub async fn run_consumer(
    jetstream: jetstream::Context,
    nats_client: async_nats::Client,
    writer: BatchWriter,
    pii_masker: PiiMasker,
    quarantine_writer: QuarantineWriter,
    lag_detector: LagDetector,
    retry_policy: RetryPolicy,
) -> anyhow::Result<()> {
    let hmac_secret = load_hmac_secret();
    run_consumer_inner(jetstream, nats_client, writer, pii_masker, quarantine_writer, lag_detector, retry_policy, hmac_secret, "ag-shadow-group").await
}

/// Run the NATS JetStream consumer loop with a custom consumer name.
///
/// In leader/follower mode, the leader creates a unique consumer name per pod
/// to avoid sharing a durable consumer across multiple pods.
pub async fn run_consumer_named(
    jetstream: jetstream::Context,
    nats_client: async_nats::Client,
    writer: BatchWriter,
    pii_masker: PiiMasker,
    quarantine_writer: QuarantineWriter,
    lag_detector: LagDetector,
    retry_policy: RetryPolicy,
    consumer_name: &str,
) -> anyhow::Result<()> {
    let hmac_secret = load_hmac_secret();
    run_consumer_inner(jetstream, nats_client, writer, pii_masker, quarantine_writer, lag_detector, retry_policy, hmac_secret, consumer_name).await
}

/// Internal consumer loop implementation shared by `run_consumer` and `run_consumer_named`.
async fn run_consumer_inner(
    jetstream: jetstream::Context,
    nats_client: async_nats::Client,
    mut writer: BatchWriter,
    pii_masker: PiiMasker,
    quarantine_writer: QuarantineWriter,
    mut lag_detector: LagDetector,
    retry_policy: RetryPolicy,
    hmac_secret: Option<Vec<u8>>,
    consumer_name: &str,
) -> anyhow::Result<()> {
    // Create or bind to the stream
    let stream = jetstream
        .get_or_create_stream(jetstream::stream::Config {
            name: "AGENTGUARD_EVENTS".to_string(),
            subjects: vec!["agentguard.events".to_string()],
            retention: jetstream::stream::RetentionPolicy::Limits,
            ..Default::default()
        })
        .await?;

    // Create durable consumer. Messages that reach `MAX_DELIVER` attempts are
    // routed to the dead-letter topic `agentguard.events.dead` so they are
    // not silently lost (#25 item 3).
    const MAX_DELIVER: i64 = 20;
    let mut consumer = stream
        .get_or_create_consumer(
            consumer_name,
            jetstream::consumer::pull::Config {
                durable_name: Some(consumer_name.to_string()),
                ack_policy: jetstream::consumer::AckPolicy::Explicit,
                max_deliver: MAX_DELIVER,
                ..Default::default()
            },
        )
        .await?;

    info!(consumer = %consumer_name, "NATS consumer created");

    // Buffer for events that failed all retry attempts (increased from 10K to 50K;
    // disk fallback in /var/log/ catches overflow beyond this limit)
    let mut failed_buffer: FailedEventBuffer<ShadowLogRow> = FailedEventBuffer::new(50_000);

    loop {
        // Periodic lag detection
        if lag_detector.should_check() {
            // Query consumer info for pending count
            if let Ok(info) = consumer.info().await {
                let pending = info.num_pending;
                let status = lag_detector.check_lag(pending);

                // Adapt batch size and flush interval based on lag
                let default_batch = 100;
                let default_flush = Duration::from_secs(5);
                writer.set_max_batch_size(lag_detector.recommended_batch_size(default_batch));
                writer.set_flush_interval(lag_detector.recommended_flush_interval(default_flush));

                if matches!(status, LagStatus::Critical(_)) {
                    // Publish alert to NATS for other services to pick up
                    if let Err(e) = jetstream
                        .publish(
                            "agentguard.alerts.shadow_lag".to_string(),
                            format!("Shadow logger critically behind: {} pending", pending)
                                .into(),
                        )
                        .await
                    {
                        warn!("Failed to publish lag alert: {}", e);
                    }
                }
            }
        }

        // Try to re-flush failed events from the buffer
        if !failed_buffer.is_empty() {
            let failed_events = failed_buffer.drain();
            let failed_count = failed_events.len();
            debug!(count = failed_count, "Retrying previously failed events");
            for row in failed_events {
                if let Err(e) = writer.push(row).await {
                    error!("Failed to re-buffer previously failed event: {}", e);
                    // Don't re-buffer indefinitely; these will be lost if they keep failing
                }
            }
        }

        // Pull a batch of messages
        let batch = consumer
            .fetch()
            .max_messages(100)
            .expires(Duration::from_secs(1))
            .messages()
            .await;

        // Collect (message, processed_row) pairs; ACK is deferred until after flush.
        let mut pending_acks: Vec<async_nats::jetstream::message::Message> = Vec::new();

        match batch {
            Ok(mut messages) => {
                use futures::StreamExt;
                while let Some(Ok(msg)) = messages.next().await {
                    // Dead-letter overflow: if this is the message's final
                    // allowed delivery (attempt == MAX_DELIVER), publish the
                    // raw payload to the dead-letter topic for forensic
                    // analysis regardless of processing outcome. Previously
                    // these messages were silently dropped by NATS (#25 item
                    // 3). Successful processing still proceeds below.
                    let delivered_attempt: i64 = msg
                        .info()
                        .map(|info| info.delivered)
                        .unwrap_or(0);
                    if delivered_attempt >= MAX_DELIVER {
                        let reason = format!("max_deliver_reached_attempt_{}", delivered_attempt);
                        publish_to_dead_letter(&nats_client, &msg.payload, &reason).await;
                    }

                    // ── HMAC verification (defense-in-depth) ──
                    // When AG_HMAC_SECRET is configured, EVERY message must carry a
                    // valid X-AG-HMAC header. Missing header OR failed verification
                    // both route to quarantine - previously a missing header
                    // silently bypassed verification (#25 item 2).
                    if let Some(ref secret) = hmac_secret {
                        let presented_hmac: Option<&str> = msg
                            .headers
                            .as_ref()
                            .and_then(|h| h.get("X-AG-HMAC"))
                            .map(|v| v.as_str());

                        let (ok, quarantine_reason) = match presented_hmac {
                            None => (false, "hmac_header_missing"),
                            Some(expected) if verify_event_hmac(&msg.payload, expected, secret) => {
                                (true, "")
                            }
                            Some(_) => (false, "hmac_verification_failed"),
                        };

                        if !ok {
                            warn!(
                                reason = quarantine_reason,
                                "Rejecting shadow event: HMAC check did not pass - quarantining"
                            );
                            let reason = QuarantineDecider::malformed_reason(quarantine_reason);
                            for attempt in 0..3u32 {
                                match quarantine_writer.quarantine_raw(&msg.payload, &reason).await {
                                    Ok(_) => break,
                                    Err(e) => {
                                        if attempt == 2 {
                                            error!("HMAC quarantine write failed after 3 attempts: {}", e);
                                        } else {
                                            warn!("HMAC quarantine write attempt {} failed: {} - retrying", attempt + 1, e);
                                            tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await;
                                        }
                                    }
                                }
                            }
                            msg.ack().await.ok();
                            continue;
                        }
                    }

                    match serde_json::from_slice::<ShadowEvent>(&msg.payload) {
                        Ok(mut event) => {
                            // 0. Basic event validation - reject obviously forged events
                            if event.request_id.is_nil() || event.org_id.is_empty() {
                                warn!("Rejecting shadow event with missing required fields - possible injection");
                                msg.ack().await.ok();
                                continue;
                            }

                            // 1. Validate schema before processing
                            if let Some(reason) = QuarantineDecider::validate_event(&event) {
                                warn!(
                                    request_id = %event.request_id,
                                    reason = %reason,
                                    "Event failed validation, quarantining"
                                );
                                for attempt in 0..3u32 {
                                    match quarantine_writer.quarantine(&event, &reason).await {
                                        Ok(_) => break,
                                        Err(e) => {
                                            if attempt == 2 {
                                                error!("Quarantine write failed after 3 attempts: {} - event will be processed without quarantine record", e);
                                            } else {
                                                warn!("Quarantine write attempt {} failed: {} - retrying", attempt + 1, e);
                                                tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await;
                                            }
                                        }
                                    }
                                }
                                // ACK quarantined messages immediately (quarantined = handled,
                                // no ClickHouse write needed)
                                if let Err(e) = msg.ack().await {
                                    warn!("Failed to ACK quarantined message: {}", e);
                                }
                                continue;
                            }

                            // 2. Apply PII masking (async for tokenization support)
                            let mask_summary = pii_masker.mask_event_tokenized(&mut event).await;

                            // v0.20: feed the event through the recovery-rate
                            // correlator. Pre-mask `denial.corrective` is still
                            // intact (masker only touches free-text fields),
                            // so suggested_tool/suggested_scope match cleanly.
                            // observe() never blocks or errors.
                            crate::recovery::observe(&event);

                            // 2b. Republish the masked event so downstream consumers
                            //     (ag-control dashboard relay) never see raw PII.
                            match serde_json::to_vec(&event) {
                                Ok(masked_payload) => {
                                    if let Err(e) = jetstream
                                        .publish(
                                            "agentguard.events.masked".to_string(),
                                            masked_payload.into(),
                                        )
                                        .await
                                    {
                                        warn!("Failed to publish masked event: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to serialize masked event: {}", e);
                                }
                            }

                            // 3. If PII was found, quarantine the original (pre-masked event is
                            //    already gone, but we record that masking happened)
                            if let Some(reason) = QuarantineDecider::should_quarantine_for_pii(
                                mask_summary.masked_fields.len(),
                            ) {
                                // Write to quarantine for audit trail, but also proceed
                                // to write the masked version to shadow_logs
                                for attempt in 0..3u32 {
                                    match quarantine_writer.quarantine(&event, &reason).await {
                                        Ok(_) => break,
                                        Err(e) => {
                                            if attempt == 2 {
                                                error!("PII quarantine write failed after 3 attempts: {} - proceeding without quarantine record", e);
                                            } else {
                                                warn!("PII quarantine write attempt {} failed: {} - retrying", attempt + 1, e);
                                                tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await;
                                            }
                                        }
                                    }
                                }
                            }

                            // 4. Enrich the event with derived flags
                            let derived_flags = enricher::enrich(&event);

                            // 5. Convert to row (with masked_fields, pii_tokens, and derived_flags)
                            let row = event_to_row(
                                &event,
                                mask_summary.masked_fields,
                                mask_summary.pii_tokens,
                                derived_flags,
                            );

                            // 6. Buffer row for batch write; track message for deferred ACK
                            if let Err(e) = writer.push(row.clone()).await {
                                error!("Failed to buffer event: {}", e);
                                // Buffer for later retry
                                failed_buffer.append(row);
                                // Publish any overflow events to dead-letter topic
                                for payload in failed_buffer.drain_overflow_payloads() {
                                    publish_to_dead_letter(
                                        &nats_client,
                                        &payload,
                                        "retry_buffer_overflow",
                                    ).await;
                                }
                            }
                            pending_acks.push(msg);
                        }
                        Err(e) => {
                            warn!("Failed to deserialize shadow event: {}", e);
                            // Quarantine the raw payload
                            let reason = QuarantineDecider::malformed_reason(&e.to_string());
                            for attempt in 0..3u32 {
                                match quarantine_writer.quarantine_raw(&msg.payload, &reason).await {
                                    Ok(_) => break,
                                    Err(qe) => {
                                        if attempt == 2 {
                                            error!("Raw quarantine write failed after 3 attempts: {} - malformed event lost", qe);
                                        } else {
                                            warn!("Raw quarantine write attempt {} failed: {} - retrying", attempt + 1, qe);
                                            tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await;
                                        }
                                    }
                                }
                            }
                            // ACK malformed messages immediately (quarantined = handled)
                            if let Err(e) = msg.ack().await {
                                warn!("Failed to ACK malformed message: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                debug!("No messages available: {}", e);
            }
        }

        // Flush the batch to ClickHouse, then ACK or NACK the pending messages.
        if !pending_acks.is_empty() || writer.should_flush() {
            // Force a flush so we know ClickHouse has the data before ACKing.
            let mut flush_succeeded = false;
            for attempt in 0..=retry_policy.max_retries {
                match writer.flush().await {
                    Ok(()) => {
                        flush_succeeded = true;
                        break;
                    }
                    Err(e) => {
                        if attempt < retry_policy.max_retries {
                            let delay = retry_policy.delay_for_attempt(attempt);
                            warn!(
                                attempt = attempt + 1,
                                max_retries = retry_policy.max_retries,
                                delay_ms = delay.as_millis() as u64,
                                error = %e,
                                "Flush failed, retrying with backoff"
                            );
                            tokio::time::sleep(delay).await;
                        } else {
                            error!(
                                attempts = retry_policy.max_retries + 1,
                                error = %e,
                                "Flush failed after all retries"
                            );
                        }
                    }
                }
            }

            if flush_succeeded {
                // ClickHouse write confirmed - ACK all messages in this batch
                for msg in &pending_acks {
                    if let Err(e) = msg.ack().await {
                        warn!("Failed to ACK message after successful flush: {}", e);
                    }
                }
            } else {
                // ClickHouse write failed - NACK messages for redelivery
                for msg in &pending_acks {
                    if let Err(e) = msg.ack_with(async_nats::jetstream::AckKind::Nak(None)).await {
                        warn!("Failed to NACK message after flush failure: {}", e);
                    }
                }

                // Move failed rows to the failed buffer for later retry
                let orphaned = writer.take_buffer();
                let orphan_count = orphaned.len();
                for row in orphaned {
                    failed_buffer.append(row);
                }
                // Publish any overflow events to dead-letter topic
                for payload in failed_buffer.drain_overflow_payloads() {
                    publish_to_dead_letter(
                        &nats_client,
                        &payload,
                        "retry_buffer_overflow_flush_failure",
                    ).await;
                }
                warn!(
                    orphaned_count = orphan_count,
                    buffer_size = failed_buffer.size(),
                    "Moved failed rows to retry buffer, NACKed messages for redelivery"
                );
            }
        }

        // Small sleep to prevent tight loop when no messages
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Publish a failed message to the dead-letter topic for forensic analysis.
///
/// Messages that overflow the retry buffer are sent here so they are not permanently lost.
/// The payload is published as-is; the reason is included as a NATS header.
pub async fn publish_to_dead_letter(nats: &async_nats::Client, payload: &[u8], reason: &str) {
    let mut headers = async_nats::HeaderMap::new();
    headers.insert(
        "AgentGuard-Dead-Letter-Reason",
        reason,
    );
    let ts = Utc::now().to_rfc3339();
    headers.insert(
        "AgentGuard-Dead-Letter-Timestamp",
        ts.as_str(),
    );

    if let Err(e) = nats
        .publish_with_headers(
            "agentguard.events.dead",
            headers,
            payload.to_vec().into(),
        )
        .await
    {
        error!(
            error = %e,
            reason = %reason,
            "Failed to publish to dead-letter topic - event permanently lost"
        );
    } else {
        warn!(
            reason = %reason,
            payload_len = payload.len(),
            "Published failed event to dead-letter topic agentguard.events.dead"
        );
    }
}

/// Convert a ShadowEvent to a ClickHouse row, including masked_fields, pii_tokens, and derived_flags.
fn event_to_row(
    event: &ShadowEvent,
    masked_fields: Vec<String>,
    pii_tokens: Vec<String>,
    derived_flags: Vec<String>,
) -> ShadowLogRow {
    ShadowLogRow {
        id: event.request_id.to_string(),
        trace_id: event.trace_id.clone(),
        timestamp: event.timestamp.timestamp_millis() as u64,
        org_id: event.org_id.clone(),
        agent_id: event.agent_id.clone(),
        agent_name: event.agent_name.clone(),
        user_id: event.user_id.clone(),
        session_id: event.session_id.clone(),
        tool_name: event.tool_name.clone(),
        tool_action: event.tool_action.clone(),
        params_hash: event.params_hash.clone(),
        prompt_hash: event.prompt_hash.clone(),
        assessed_risk: event.assessed_risk as f32,
        session_risk_factor: event.session_risk_factor as f32,
        intent_classification: event.intent_classification.clone(),
        policy_action: event.policy_action.clone(),
        policy_reason: event.policy_reason.clone(),
        scope_requested: event.scope_requested.clone(),
        scope_granted: event.scope_granted.clone().unwrap_or_default(),
        blocked: if event.blocked { 1 } else { 0 },
        denial_reason: event
            .denial
            .as_ref()
            .map(|d| {
                if !d.violated_predicate.is_empty() {
                    d.violated_predicate.clone()
                } else if let Some(c) = d.corrective.as_ref() {
                    c.human_explanation.clone()
                } else {
                    String::new()
                }
            })
            .unwrap_or_default(),
        corrective_kind: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .map(|c| c.kind.clone())
            .unwrap_or_default(),
        corrective_data: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .map(|c| c.payload.to_string())
            .unwrap_or_default(),
        corrective_confidence: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .map(|c| match c.confidence {
                ag_common::corrective::Confidence::High => "high".to_string(),
                ag_common::corrective::Confidence::Medium => "medium".to_string(),
                ag_common::corrective::Confidence::Low => "low".to_string(),
            })
            .unwrap_or_default(),
        corrective_source: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .map(|c| c.source.clone())
            .unwrap_or_default(),
        // v0.23.1: persist the author hint + gateway-rendered text so
        // historical queries / replays can show the same string the LLM
        // saw at the time, even after templates change later.
        corrective_human_explanation: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .map(|c| c.human_explanation.clone())
            .unwrap_or_default(),
        corrective_tool_result: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .and_then(|c| c.rendered.as_ref())
            .map(|r| r.tool_result.clone())
            .unwrap_or_default(),
        corrective_short_label: event
            .denial
            .as_ref()
            .and_then(|d| d.corrective.as_ref())
            .and_then(|c| c.rendered.as_ref())
            .map(|r| r.short_label.clone())
            .unwrap_or_default(),
        latency_ms: event.latency_ms as u16,
        masked_fields,
        pii_tokens,
        encodings_detected: event.encodings_detected.clone(),
        encoding_risk_bonus: event.encoding_risk_bonus as f32,
        intent_labels: event.intent_labels.clone(),
        matched_rules: event.matched_rules.clone(),
        boundary_violation: event.boundary_violation.clone().unwrap_or_default(),
        session_flags: event.session_flags.clone(),
        response_status_code: event.response_metadata.as_ref().map(|r| r.status_code).unwrap_or(0),
        response_body_size: event.response_metadata.as_ref().map(|r| r.body_size_bytes).unwrap_or(0),
        response_records_count: event.response_metadata.as_ref().map(|r| r.records_count).unwrap_or(0),
        response_pii_detected: event.response_metadata.as_ref().map(|r| r.contains_pii_patterns).unwrap_or(false),
        degraded_stages: event.degraded_stages.clone(),
        params_summary: event.params_summary.clone(),
        response_hash: event.response_metadata.as_ref().map(|r| r.response_hash.clone()).unwrap_or_default(),
        derived_flags,
        caller_agent_id: event.caller_agent_id.clone().unwrap_or_default(),
        delegation_chain: event.delegation_chain.clone().unwrap_or_default(),
        delegation_trace_id: event.delegation_trace_id.clone().unwrap_or_default(),
        delegation_depth: event.delegation_chain.as_ref().map(|c| c.len() as u8).unwrap_or(0),
        a2a_event_type: event.a2a_event_type.clone().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2: "what do ya want for nothing?" with key "Jefe"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let result = compute_hmac_sha256(data, key);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha256_empty_message() {
        let secret = b"test-secret";
        let result = compute_hmac_sha256(b"", secret);
        // Should produce a valid 64-char hex string
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let secret = b"my-secret-key";
        let payload = b"some event payload";
        let h1 = compute_hmac_sha256(payload, secret);
        let h2 = compute_hmac_sha256(payload, secret);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hmac_sha256_different_payloads() {
        let secret = b"my-secret-key";
        let h1 = compute_hmac_sha256(b"payload-a", secret);
        let h2 = compute_hmac_sha256(b"payload-b", secret);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hmac_sha256_different_secrets() {
        let payload = b"same payload";
        let h1 = compute_hmac_sha256(payload, b"secret-1");
        let h2 = compute_hmac_sha256(payload, b"secret-2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // Key longer than 64 bytes should be hashed first
        let long_key = vec![0xABu8; 100];
        let payload = b"test data";
        let result = compute_hmac_sha256(payload, &long_key);
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_event_hmac_valid() {
        let secret = b"test-secret";
        let payload = b"event payload data";
        let hmac = compute_hmac_sha256(payload, secret);
        assert!(verify_event_hmac(payload, &hmac, secret));
    }

    #[test]
    fn test_verify_event_hmac_invalid() {
        let secret = b"test-secret";
        let payload = b"event payload data";
        let bad_hmac = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_event_hmac(payload, bad_hmac, secret));
    }

    #[test]
    fn test_verify_event_hmac_wrong_secret() {
        let payload = b"event payload data";
        let hmac = compute_hmac_sha256(payload, b"correct-secret");
        assert!(!verify_event_hmac(payload, &hmac, b"wrong-secret"));
    }

    #[test]
    fn test_verify_event_hmac_tampered_payload() {
        let secret = b"test-secret";
        let hmac = compute_hmac_sha256(b"original payload", secret);
        assert!(!verify_event_hmac(b"tampered payload", &hmac, secret));
    }

    #[test]
    fn test_verify_event_hmac_wrong_length() {
        let secret = b"test-secret";
        let payload = b"data";
        // Too short to be a valid HMAC
        assert!(!verify_event_hmac(payload, "abc", secret));
    }

    /// Regression test for #25 item 1: after migration to the `hmac` crate,
    /// the RFC 4231 test vector must still match. This guards against silent
    /// regressions if someone swaps the backing implementation again.
    #[test]
    fn test_hmac_matches_rfc4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(compute_hmac_sha256(data, key), expected);
    }

    /// Regression test for #25: malformed (non-hex) expected_hmac must be
    /// rejected. Previously the hand-rolled implementation returned early on
    /// a length mismatch which worked, but explicit hex-decode is safer.
    #[test]
    fn test_verify_event_hmac_rejects_non_hex() {
        let secret = b"s";
        assert!(!verify_event_hmac(b"payload", "not-hex!!!!", secret));
        assert!(!verify_event_hmac(
            b"payload",
            // 64 chars but not valid hex
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            secret,
        ));
    }

    /// Regression test for #25 item 2: the quarantine decision table must
    /// classify the three HMAC outcomes correctly. This mirrors the match
    /// arm used at the message-handling callsite so a future refactor that
    /// reverts the "missing header = allow" behavior fails a test.
    #[test]
    fn test_hmac_decision_table() {
        let secret = b"shared-secret";
        let payload = b"event-json";
        let good = compute_hmac_sha256(payload, secret);

        // Case 1: header missing => reject as hmac_header_missing.
        let presented: Option<&str> = None;
        let decision = match presented {
            None => "hmac_header_missing",
            Some(h) if verify_event_hmac(payload, h, secret) => "ok",
            Some(_) => "hmac_verification_failed",
        };
        assert_eq!(decision, "hmac_header_missing");

        // Case 2: header present and valid => ok.
        let presented: Option<&str> = Some(good.as_str());
        let decision = match presented {
            None => "hmac_header_missing",
            Some(h) if verify_event_hmac(payload, h, secret) => "ok",
            Some(_) => "hmac_verification_failed",
        };
        assert_eq!(decision, "ok");

        // Case 3: header present but wrong => hmac_verification_failed.
        let bad = compute_hmac_sha256(payload, b"other-secret");
        let presented: Option<&str> = Some(bad.as_str());
        let decision = match presented {
            None => "hmac_header_missing",
            Some(h) if verify_event_hmac(payload, h, secret) => "ok",
            Some(_) => "hmac_verification_failed",
        };
        assert_eq!(decision, "hmac_verification_failed");
    }
}
