use clickhouse::Row;
use serde::Serialize;
use std::time::{Duration, Instant};
use tracing::{debug, error, info};

/// A row in the ClickHouse shadow_logs table.
#[derive(Debug, Clone, Row, Serialize)]
pub struct ShadowLogRow {
    pub id: String,
    pub trace_id: String,
    pub timestamp: u64, // epoch millis
    pub org_id: String,
    pub agent_id: String,
    pub agent_name: String,
    pub user_id: String,
    pub session_id: String,
    pub tool_name: String,
    pub tool_action: String,
    pub params_hash: String,
    pub prompt_hash: String,
    pub assessed_risk: f32,
    pub session_risk_factor: f32,
    pub intent_classification: String,
    pub policy_action: String,
    pub policy_reason: String,
    pub scope_requested: String,
    pub scope_granted: String,
    pub blocked: u8,
    pub denial_reason: String,
    pub latency_ms: u16,
    /// Names of fields that were PII-masked before storage.
    pub masked_fields: Vec<String>,
    /// PII tokens generated for this event (for reversible de-tokenization).
    pub pii_tokens: Vec<String>,
    pub encodings_detected: Vec<String>,
    pub encoding_risk_bonus: f32,
    pub intent_labels: Vec<String>,
    pub matched_rules: Vec<String>,
    pub boundary_violation: String,
    pub session_flags: Vec<String>,
    pub response_status_code: u16,
    pub response_body_size: u64,
    pub response_records_count: u32,
    pub response_pii_detected: bool,
    pub degraded_stages: Vec<String>,
    pub params_summary: String,
    pub response_hash: String,
    pub derived_flags: Vec<String>,
    /// A2A delegation caller agent ID (empty if no delegation).
    pub caller_agent_id: String,
    /// A2A delegation chain as list of agent IDs.
    pub delegation_chain: Vec<String>,
    /// A2A delegation trace ID.
    pub delegation_trace_id: String,
    /// Delegation chain depth (0 = no delegation).
    pub delegation_depth: u8,
    /// A2A security event type (task_replay, contagion, cross_boundary, tool_restricted, killed_delegation).
    /// Empty string for regular tool call events.
    pub a2a_event_type: String,
}

/// Metrics for the last batch write operation.
#[derive(Debug, Clone, Default)]
pub struct BatchMetrics {
    /// Number of rows in the batch.
    pub batch_size: usize,
    /// Time from when the first event in the batch was buffered to when the flush completed.
    pub buffer_to_write_duration: Duration,
    /// Time the ClickHouse INSERT itself took.
    pub insert_duration: Duration,
}

/// Buffered batch writer for ClickHouse.
pub struct BatchWriter {
    client: clickhouse::Client,
    buffer: Vec<ShadowLogRow>,
    max_batch_size: usize,
    max_buffer_age: Duration,
    last_flush: Instant,
    /// Timestamp when the first event in the current batch was buffered.
    batch_start: Option<Instant>,
    /// Metrics from the last flush.
    last_metrics: Option<BatchMetrics>,
}

impl BatchWriter {
    pub fn new(
        client: clickhouse::Client,
        max_batch_size: usize,
        flush_interval_secs: u64,
    ) -> Self {
        Self {
            client,
            buffer: Vec::with_capacity(max_batch_size),
            max_batch_size,
            max_buffer_age: Duration::from_secs(flush_interval_secs),
            last_flush: Instant::now(),
            batch_start: None,
            last_metrics: None,
        }
    }

    /// Add a row to the buffer and flush if needed.
    pub async fn push(&mut self, row: ShadowLogRow) -> Result<(), String> {
        if self.batch_start.is_none() {
            self.batch_start = Some(Instant::now());
        }
        self.buffer.push(row);

        if self.buffer.len() >= self.max_batch_size
            || self.last_flush.elapsed() >= self.max_buffer_age
        {
            self.flush().await?;
        }

        Ok(())
    }

    /// Flush the buffer to ClickHouse.
    pub async fn flush(&mut self) -> Result<(), String> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let batch_size = self.buffer.len();
        let batch_start = self.batch_start.unwrap_or_else(Instant::now);
        let insert_start = Instant::now();

        match self.do_insert().await {
            Ok(()) => {
                let insert_duration = insert_start.elapsed();
                let buffer_to_write_duration = batch_start.elapsed();

                let metrics = BatchMetrics {
                    batch_size,
                    buffer_to_write_duration,
                    insert_duration,
                };

                info!(
                    batch_size,
                    insert_ms = insert_duration.as_millis() as u64,
                    buffer_age_ms = buffer_to_write_duration.as_millis() as u64,
                    "Flushed batch to ClickHouse"
                );

                debug!(
                    batch_size = metrics.batch_size,
                    insert_ms = metrics.insert_duration.as_millis() as u64,
                    buffer_age_ms = metrics.buffer_to_write_duration.as_millis() as u64,
                    "Batch write metrics"
                );

                self.last_metrics = Some(metrics);
                self.buffer.clear();
                self.last_flush = Instant::now();
                self.batch_start = None;
                Ok(())
            }
            Err(e) => {
                error!(batch_size, error = %e, "ClickHouse batch insert failed");
                Err(e)
            }
        }
    }

    async fn do_insert(&self) -> Result<(), String> {
        let mut insert = self
            .client
            .insert("shadow_logs")
            .map_err(|e| e.to_string())?;

        for row in &self.buffer {
            insert.write(row).await.map_err(|e| e.to_string())?;
        }

        insert.end().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Check if buffer should be flushed based on time.
    pub fn should_flush(&self) -> bool {
        !self.buffer.is_empty() && self.last_flush.elapsed() >= self.max_buffer_age
    }

    /// Update the max batch size dynamically (for backpressure adaptation).
    pub fn set_max_batch_size(&mut self, new_size: usize) {
        self.max_batch_size = new_size;
    }

    /// Update the flush interval dynamically (for backpressure adaptation).
    pub fn set_flush_interval(&mut self, interval: Duration) {
        self.max_buffer_age = interval;
    }

    /// Get metrics from the last flush operation.
    pub fn last_metrics(&self) -> Option<&BatchMetrics> {
        self.last_metrics.as_ref()
    }

    /// Get the current buffer size.
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Take ownership of buffered rows for retry purposes.
    pub fn take_buffer(&mut self) -> Vec<ShadowLogRow> {
        self.batch_start = None;
        std::mem::take(&mut self.buffer)
    }
}
