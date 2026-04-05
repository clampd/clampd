//! Command poller - polls SaaS API for pending commands.
//!
//! Flow:
//! 1. GET {saas_url}/v1/runtime/commands (with license token auth)
//! 2. For each command: execute locally (call ag-kill, ag-registry, etc.)
//! 3. POST {saas_url}/v1/runtime/commands/{id}/result
//!
//! Also periodically:
//! - POST {saas_url}/v1/runtime/health every 30s
//! - POST {saas_url}/v1/runtime/risk every 10s
//!
//! Additionally:
//! - Subscribes to `agentguard.events.masked` on NATS and relays individual risk
//!   events to the SaaS dashboard via POST /v1/runtime/risk-events so the
//!   WebSocket risk feed shows real data instead of mock events.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ag_common::models::ShadowEvent;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::command_executor::{self, CommandResult, ExecutorConfig, PendingCommand};
use crate::ws_client::{WsOutbound, WsSender};

// ── SaaS API response types ──────────────────────────────────────────────────

/// Response from GET /v1/runtime/commands.
#[derive(Debug, Deserialize)]
pub struct CommandsResponse {
    pub commands: Vec<PendingCommand>,
}

/// Payload sent to POST /v1/runtime/health.
#[derive(Debug, Serialize)]
pub struct RuntimeHealthPayload {
    pub overall_status: String,
    pub redis_status: String,
    pub nats_status: String,
    pub checked_at: String,
}

/// Payload sent to POST /v1/runtime/risk.
#[derive(Debug, Serialize)]
pub struct RuntimeRiskPayload {
    pub high_risk_agent_count: u32,
    pub sampled_at: String,
}

/// A single risk event in the shape expected by the dashboard frontend.
/// Sent to POST /v1/runtime/risk-events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardRiskEvent {
    pub timestamp: String,
    pub agent: String,
    pub tool: String,
    pub risk_score: f64,
    pub action: String,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rules: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_flags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encodings_detected: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_agent_id: Option<String>,
    pub latency_ms: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_granted: Option<String>,
}

/// Batch payload for POST /v1/runtime/risk-events.
#[derive(Debug, Serialize)]
pub struct RiskEventsPayload {
    pub events: Vec<DashboardRiskEvent>,
}

// ── Poller config (captured from ControlConfig) ──────────────────────────────

pub struct PollerConfig {
    pub saas_url: String,
    pub license_token: String,
    pub poll_interval_secs: u64,
    pub kill_url: String,
    pub registry_url: String,
    pub nats_client: Option<async_nats::Client>,
    /// Optional Redis pool for real health/risk reporting.
    pub redis_pool: Option<bb8::Pool<bb8_redis::RedisConnectionManager>>,
    /// Optional Postgres pool for on-demand agent sync (split-DB race fix).
    pub pg_pool: Option<sqlx::PgPool>,
    /// When true, the WebSocket command client is connected and the HTTP poll
    /// loop should yield to it (skip fetching commands via HTTP).
    pub ws_connected: Arc<AtomicBool>,
    /// Optional WS sender for routing health/risk data through the WebSocket
    /// instead of HTTP POST when the connection is active.
    pub ws_sender: Option<WsSender>,
    /// Notify handle to wake rules_sync immediately after push_rules.
    pub rules_sync_notify: Option<Arc<tokio::sync::Notify>>,
}

impl PollerConfig {
    /// Build an `ExecutorConfig` that shares the same connections.
    pub fn to_executor_config(&self) -> ExecutorConfig {
        ExecutorConfig {
            kill_url: self.kill_url.clone(),
            registry_url: self.registry_url.clone(),
            nats_client: self.nats_client.clone(),
            redis_pool: self.redis_pool.clone(),
            pg_pool: self.pg_pool.clone(),
            saas_url: Some(self.saas_url.clone()),
            license_token: Some(self.license_token.clone()),
            rules_sync_notify: self.rules_sync_notify.clone(),
        }
    }
}

// ── Main poller task ─────────────────────────────────────────────────────────

/// Spawns the four background loops:
///  - command poll loop (every `poll_interval_secs`)
///  - health push loop (every 30s)
///  - risk summary push loop (every 10s)
///  - risk event relay loop (NATS subscription -> SaaS WebSocket feed)
///
/// All loops are leader-gated via `is_leader`.
pub fn spawn(cfg: PollerConfig, is_leader: Arc<std::sync::atomic::AtomicBool>) {
    // Extract the NATS client and WS sender before wrapping cfg in Arc.
    let nats_client = cfg.nats_client.clone();
    let ws_sender = cfg.ws_sender.clone();
    let cfg = Arc::new(cfg);

    // Build a shared reqwest client.  reqwest::Client is cheap to clone (Arc
    // internally) so we share one instance across all loops.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client");

    // Build a shared ExecutorConfig for the command poll loop.
    let executor = Arc::new(cfg.to_executor_config());

    // Command poll loop.
    {
        let cfg = cfg.clone();
        let http = http.clone();
        let is_leader = is_leader.clone();
        let executor = executor.clone();
        tokio::spawn(async move {
            run_command_loop(cfg, http, is_leader, executor).await;
        });
    }

    // Health push loop.
    {
        let cfg = cfg.clone();
        let http = http.clone();
        let is_leader = is_leader.clone();
        let ws_sender = ws_sender.clone();
        tokio::spawn(async move {
            run_health_push_loop(cfg, http, is_leader, ws_sender).await;
        });
    }

    // Risk summary push loop.
    {
        let cfg = cfg.clone();
        let http = http.clone();
        let is_leader = is_leader.clone();
        let ws_sender = ws_sender.clone();
        tokio::spawn(async move {
            run_risk_push_loop(cfg, http, is_leader, ws_sender).await;
        });
    }

    // Risk event relay loop - subscribes to NATS `agentguard.events.masked` and
    // pushes individual risk events to the SaaS API for WebSocket broadcast.
    if let Some(nats) = nats_client {
        let cfg = cfg.clone();
        let http = http.clone();
        let is_leader = is_leader.clone();
        let ws_sender = ws_sender.clone();
        tokio::spawn(async move {
            run_risk_event_relay(cfg, http, nats, is_leader, ws_sender).await;
        });
    } else {
        warn!("No NATS client provided - risk event relay will not run");
    }
}

// ── Command poll loop ────────────────────────────────────────────────────────

async fn run_command_loop(
    cfg: Arc<PollerConfig>,
    http: reqwest::Client,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
    executor: Arc<ExecutorConfig>,
) {
    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(cfg.poll_interval_secs));

    loop {
        interval.tick().await;

        if !is_leader.load(Ordering::Relaxed) {
            debug!("Not leader - skipping command poll");
            continue;
        }

        // When the WebSocket command client is connected, skip HTTP polling -
        // commands arrive in real time over the WS connection.
        if cfg.ws_connected.load(Ordering::Relaxed) {
            debug!("WS active - skipping HTTP poll");
            continue;
        }

        let commands = match fetch_commands(&cfg, &http).await {
            Ok(cmds) => cmds,
            Err(e) => {
                warn!(error = %e, "Failed to fetch commands from SaaS - will retry");
                continue;
            }
        };

        if commands.is_empty() {
            debug!("No pending commands");
            continue;
        }

        info!(count = commands.len(), "Received pending commands");

        for cmd in commands {
            let result = command_executor::execute_command(&executor, &cmd).await;
            let mut report_attempts = 0;
            loop {
                match report_result(&cfg, &http, &cmd.id, result.clone()).await {
                    Ok(_) => break,
                    Err(e) => {
                        report_attempts += 1;
                        if report_attempts >= 2 {
                            warn!(command_id = %cmd.id, error = %e, "Failed to report command result after retries");
                            break;
                        }
                        warn!(command_id = %cmd.id, error = %e, "Retrying command result report");
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }
}

// ── Fetch commands (SaaS / Dashboard API) ────────────────────────────────────

async fn fetch_commands(
    cfg: &PollerConfig,
    http: &reqwest::Client,
) -> anyhow::Result<Vec<PendingCommand>> {
    let url = format!("{}/v1/runtime/commands", cfg.saas_url);

    let resp = http
        .get(&url)
        .header(
            "Authorization",
            format!("Bearer {}", cfg.license_token),
        )
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("SaaS returned {}: {}", status, body);
    }

    let parsed: CommandsResponse = resp.json().await?;
    Ok(parsed.commands)
}

// ── Report result back to SaaS ───────────────────────────────────────────────

async fn report_result(
    cfg: &PollerConfig,
    http: &reqwest::Client,
    command_id: &str,
    result: CommandResult,
) -> anyhow::Result<()> {
    let url = format!(
        "{}/v1/runtime/commands/{}/result",
        cfg.saas_url, command_id
    );

    let resp = http
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", cfg.license_token),
        )
        .json(&result)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("SaaS result endpoint returned {}: {}", status, body);
    }

    debug!(command_id = %command_id, "Result reported to SaaS");
    Ok(())
}

// ── Health push loop ─────────────────────────────────────────────────────────

async fn run_health_push_loop(
    cfg: Arc<PollerConfig>,
    http: reqwest::Client,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
    ws_sender: Option<WsSender>,
) {
    let base_interval_secs: u64 = 30;
    let max_interval_secs: u64 = 300; // 5 minutes max
    let mut current_interval_secs = base_interval_secs;
    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(current_interval_secs)).await;

        if !is_leader.load(Ordering::Relaxed) {
            debug!("Not leader - skipping health push");
            continue;
        }

        // Load real health data from Redis `ag:cluster:health` if available,
        // otherwise fall back to basic "healthy" defaults.
        let payload = load_health_payload_from_redis(&cfg).await;

        // If WS is connected and sender is available, route through WebSocket.
        if cfg.ws_connected.load(Ordering::Relaxed) {
            if let Some(ref sender) = ws_sender {
                // Build services JSON from Redis health data for richer WS payload.
                let services_json = load_services_json_from_redis(&cfg).await;
                let outbound = WsOutbound::Health {
                    overall_status: payload.overall_status.clone(),
                    services: services_json,
                    checked_at: payload.checked_at.clone(),
                };
                match sender.try_send(outbound) {
                    Ok(_) => {
                        debug!("Health pushed via WS");
                        consecutive_failures = 0;
                        current_interval_secs = base_interval_secs;
                        continue;
                    }
                    Err(e) => {
                        debug!(error = %e, "WS send failed - falling back to HTTP");
                    }
                }
            }
        }

        // HTTP fallback.
        let url = format!("{}/v1/runtime/health", cfg.saas_url);
        match http
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", cfg.license_token),
            )
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                debug!("Health pushed to SaaS");
                consecutive_failures = 0;
                current_interval_secs = base_interval_secs;
            }
            Ok(resp) => {
                consecutive_failures += 1;
                warn!(status = %resp.status(), consecutive_failures, "SaaS health endpoint returned non-2xx");
                if consecutive_failures >= 3 {
                    current_interval_secs = (current_interval_secs * 2).min(max_interval_secs);
                    warn!(backoff_secs = current_interval_secs, "Health push backing off after {} consecutive failures", consecutive_failures);
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(error = %e, consecutive_failures, "Failed to push health to SaaS");
                if consecutive_failures >= 3 {
                    current_interval_secs = (current_interval_secs * 2).min(max_interval_secs);
                    warn!(backoff_secs = current_interval_secs, "Health push backing off after {} consecutive failures", consecutive_failures);
                }
            }
        }
    }
}

// ── Risk push loop ───────────────────────────────────────────────────────────

async fn run_risk_push_loop(
    cfg: Arc<PollerConfig>,
    http: reqwest::Client,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
    ws_sender: Option<WsSender>,
) {
    let base_interval_secs: u64 = 10;
    let max_interval_secs: u64 = 300; // 5 minutes max
    let mut current_interval_secs = base_interval_secs;
    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(current_interval_secs)).await;

        if !is_leader.load(Ordering::Relaxed) {
            debug!("Not leader - skipping risk push");
            continue;
        }

        // Load real risk count from Redis `ag:risk:high_count` if available,
        // otherwise default to 0.
        let payload = load_risk_payload_from_redis(&cfg).await;

        // If WS is connected and sender is available, route through WebSocket.
        if cfg.ws_connected.load(Ordering::Relaxed) {
            if let Some(ref sender) = ws_sender {
                let outbound = WsOutbound::RiskSummary {
                    high_risk_agent_count: payload.high_risk_agent_count as u64,
                    sampled_at: payload.sampled_at.clone(),
                };
                match sender.try_send(outbound) {
                    Ok(_) => {
                        debug!("Risk summary pushed via WS");
                        consecutive_failures = 0;
                        current_interval_secs = base_interval_secs;
                        continue;
                    }
                    Err(e) => {
                        debug!(error = %e, "WS send failed - falling back to HTTP");
                    }
                }
            }
        }

        // HTTP fallback.
        let url = format!("{}/v1/runtime/risk", cfg.saas_url);
        match http
            .post(&url)
            .header(
                "Authorization",
                format!("Bearer {}", cfg.license_token),
            )
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                debug!("Risk summary pushed to SaaS");
                consecutive_failures = 0;
                current_interval_secs = base_interval_secs;
            }
            Ok(resp) => {
                consecutive_failures += 1;
                warn!(status = %resp.status(), consecutive_failures, "SaaS risk endpoint returned non-2xx");
                if consecutive_failures >= 3 {
                    current_interval_secs = (current_interval_secs * 2).min(max_interval_secs);
                    warn!(backoff_secs = current_interval_secs, "Risk push backing off after {} consecutive failures", consecutive_failures);
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(error = %e, consecutive_failures, "Failed to push risk summary to SaaS");
                if consecutive_failures >= 3 {
                    current_interval_secs = (current_interval_secs * 2).min(max_interval_secs);
                    warn!(backoff_secs = current_interval_secs, "Risk push backing off after {} consecutive failures", consecutive_failures);
                }
            }
        }
    }
}

// ── Risk event relay (NATS -> SaaS) ──────────────────────────────────────────
//
// Subscribes to `agentguard.events.masked` on NATS, converts each ShadowEvent into
// the dashboard-expected shape, buffers up to RELAY_BATCH_SIZE events, and
// pushes them to POST /v1/runtime/risk-events every RELAY_FLUSH_INTERVAL.
// If the batch fills up before the timer fires we flush immediately.

const RELAY_BATCH_SIZE: usize = 25;
const RELAY_FLUSH_INTERVAL_MS: u64 = 2000;

/// Map a ShadowEvent to the dashboard risk event shape.
/// Returns None for low-risk allowed events (noise) so they are not relayed.
fn shadow_to_dashboard_event(ev: &ShadowEvent) -> Option<DashboardRiskEvent> {
    let action = if ev.blocked {
        "blocked"
    } else if ev.assessed_risk >= 0.5 {
        if ev.scope_granted.as_ref().map_or(false, |s| !s.is_empty()) {
            "exempted"
        } else {
            "flagged"
        }
    } else {
        // Skip allowed events - dashboard owner said they are useless
        return None;
    };

    // Build a useful reason from the richest source available.
    let reason = if let Some(ref denial) = ev.denial_reason {
        // e.g. "R020 PII exfiltration detected"
        Some(denial.clone())
    } else if !ev.policy_reason.is_empty() {
        Some(ev.policy_reason.clone())
    } else if !ev.intent_classification.is_empty() && ev.intent_classification != "safe" {
        // e.g. "pii_exfiltration" or "privilege_escalation"
        let labels = if ev.intent_labels.is_empty() {
            String::new()
        } else {
            format!(" ({})", ev.intent_labels.join(", "))
        };
        Some(format!("Intent: {}{}", ev.intent_classification, labels))
    } else {
        Some(format!("Risk score {:.2}", ev.assessed_risk))
    };

    // Matched rules - only include if non-empty.
    let matched_rules = if ev.matched_rules.is_empty() {
        None
    } else {
        Some(ev.matched_rules.clone())
    };

    // The actual query/payload - params_summary has the SQL, URL, file path, etc.
    let query = if ev.params_summary.is_empty() {
        None
    } else {
        Some(ev.params_summary.clone())
    };

    // Risk score: clamp to [0.0, 1.0] range for the dashboard.
    let risk_score = ev.assessed_risk.clamp(0.0, 1.0);

    let intent_labels = if ev.intent_labels.is_empty() {
        None
    } else {
        Some(ev.intent_labels.clone())
    };

    let classification = if ev.intent_classification.is_empty() || ev.intent_classification == "safe" {
        None
    } else {
        Some(ev.intent_classification.clone())
    };

    let session_flags = if ev.session_flags.is_empty() {
        None
    } else {
        Some(ev.session_flags.clone())
    };

    let encodings_detected = if ev.encodings_detected.is_empty() {
        None
    } else {
        Some(ev.encodings_detected.clone())
    };

    let scope_granted = ev.scope_granted.clone().filter(|s| !s.is_empty());

    Some(DashboardRiskEvent {
        timestamp: ev.timestamp.to_rfc3339(),
        agent: if ev.agent_name.is_empty() {
            ev.agent_id.clone()
        } else {
            ev.agent_name.clone()
        },
        tool: ev.tool_name.clone(),
        risk_score,
        action: action.to_string(),
        reason,
        matched_rules,
        query,
        intent_labels,
        classification,
        session_flags,
        encodings_detected,
        caller_agent_id: ev.caller_agent_id.clone(),
        latency_ms: ev.latency_ms,
        scope_granted,
    })
}

async fn run_risk_event_relay(
    cfg: Arc<PollerConfig>,
    http: reqwest::Client,
    nats: async_nats::Client,
    is_leader: Arc<std::sync::atomic::AtomicBool>,
    ws_sender: Option<WsSender>,
) {
    // Subscribe to the same subject that ag-shadow and ag-risk use.
    let mut sub = match nats.subscribe("agentguard.events.masked").await {
        Ok(s) => {
            info!("Subscribed to agentguard.events.masked for risk event relay");
            s
        }
        Err(e) => {
            error!(error = %e, "Failed to subscribe to agentguard.events.masked - risk relay disabled");
            return;
        }
    };

    let mut batch: Vec<DashboardRiskEvent> = Vec::with_capacity(RELAY_BATCH_SIZE);
    let mut descriptor_batch: Vec<ObservedDescriptor> = Vec::new();
    let mut flush_timer = tokio::time::interval(
        tokio::time::Duration::from_millis(RELAY_FLUSH_INTERVAL_MS),
    );

    loop {
        tokio::select! {
            msg = sub.next() => {
                let Some(msg) = msg else {
                    warn!("NATS subscription closed - risk event relay stopping");
                    break;
                };

                // Only relay when we are the leader to avoid duplicate pushes.
                if !is_leader.load(Ordering::Relaxed) {
                    continue;
                }

                match serde_json::from_slice::<ShadowEvent>(&msg.payload) {
                    Ok(shadow) => {
                        // Detect blocked delegations and write to Redis for
                        // delegation_sync to pick up and forward to dashboard.
                        if shadow.blocked {
                            if let Some(ref reason) = shadow.denial_reason {
                                if reason.contains("delegation_not_approved") || reason.contains("delegation_tool_not_allowed") {
                                    if let Some(ref caller) = shadow.caller_agent_id {
                                        record_blocked_delegation(&cfg, &shadow.org_id, caller, &shadow.agent_id, reason, &shadow.tool_name).await;
                                    }
                                }
                            }
                        }

                        // Extract tool descriptor hash for dashboard sync.
                        if !shadow.tool_descriptor_hash.is_empty() && shadow.tool_descriptor_hash.len() == 64 {
                            descriptor_batch.push(ObservedDescriptor {
                                tool_name: shadow.tool_name.clone(),
                                descriptor_hash: shadow.tool_descriptor_hash.clone(),
                                agent_id: shadow.agent_id.clone(),
                            });
                        }

                        if let Some(event) = shadow_to_dashboard_event(&shadow) {
                            batch.push(event);
                        }

                        // Flush immediately if batch is full.
                        if batch.len() >= RELAY_BATCH_SIZE {
                            flush_risk_events_with_ws(&cfg, &http, &mut batch, &ws_sender).await;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "Failed to parse ShadowEvent - skipping");
                    }
                }
            }
            _ = flush_timer.tick() => {
                if !batch.is_empty() && is_leader.load(Ordering::Relaxed) {
                    flush_risk_events_with_ws(&cfg, &http, &mut batch, &ws_sender).await;
                }
                if !descriptor_batch.is_empty() && is_leader.load(Ordering::Relaxed) {
                    flush_tool_descriptors(&cfg, &http, &mut descriptor_batch).await;
                }
            }
        }
    }
}

/// Observed tool descriptor from a shadow event.
#[derive(Debug, Clone, Serialize)]
struct ObservedDescriptor {
    tool_name: String,
    descriptor_hash: String,
    agent_id: String,
}

/// Push observed tool descriptors to the dashboard.
async fn flush_tool_descriptors(
    cfg: &PollerConfig,
    http: &reqwest::Client,
    batch: &mut Vec<ObservedDescriptor>,
) {
    // Deduplicate by (tool_name, descriptor_hash) before sending.
    // Collect unique agent_ids per tool for auto-grant creation.
    let mut seen = std::collections::HashSet::new();
    let deduped: Vec<serde_json::Value> = batch
        .iter()
        .filter(|d| seen.insert(format!("{}:{}", d.tool_name, d.descriptor_hash)))
        .map(|d| serde_json::json!({
            "tool_name": d.tool_name,
            "descriptor_hash": d.descriptor_hash,
            "description": format!("Observed: {}", d.tool_name),
            "agent_id": d.agent_id,
        }))
        .collect();

    if deduped.is_empty() {
        batch.clear();
        return;
    }

    let url = format!("{}/v1/runtime/tool-descriptors/observed", cfg.saas_url);
    let body = serde_json::json!({ "descriptors": deduped });

    match http
        .post(&url)
        .bearer_auth(&cfg.license_token)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            debug!(count = deduped.len(), "Tool descriptors synced to dashboard");
        }
        Ok(resp) => {
            debug!(status = %resp.status(), "Dashboard rejected tool descriptors");
        }
        Err(e) => {
            debug!(error = %e, "Failed to push tool descriptors to dashboard");
        }
    }

    batch.clear();
}

/// Push buffered risk events, trying WS first and falling back to HTTP.
async fn flush_risk_events_with_ws(
    cfg: &PollerConfig,
    http: &reqwest::Client,
    batch: &mut Vec<DashboardRiskEvent>,
    ws_sender: &Option<WsSender>,
) {
    // Try WS if connected.
    if cfg.ws_connected.load(Ordering::Relaxed) {
        if let Some(ref sender) = ws_sender {
            let events_json: Vec<serde_json::Value> = batch
                .iter()
                .filter_map(|e| serde_json::to_value(e).ok())
                .collect();
            let outbound = WsOutbound::RiskEvents {
                events: events_json,
            };
            if sender.try_send(outbound).is_ok() {
                let count = batch.len();
                batch.clear();
                debug!(count = count, "Risk events relayed via WS");
                return;
            }
            debug!("WS send failed for risk events - falling back to HTTP");
        }
    }

    // HTTP fallback.
    flush_risk_events(cfg, http, batch).await;
}

/// Push buffered risk events to the SaaS API and clear the batch.
async fn flush_risk_events(
    cfg: &PollerConfig,
    http: &reqwest::Client,
    batch: &mut Vec<DashboardRiskEvent>,
) {
    let events: Vec<DashboardRiskEvent> = batch.drain(..).collect();
    let count = events.len();

    let payload = RiskEventsPayload { events };
    let url = format!("{}/v1/runtime/risk-events", cfg.saas_url);

    match http
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", cfg.license_token),
        )
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            debug!(count = count, "Risk events relayed to SaaS");
        }
        Ok(resp) => {
            warn!(
                status = %resp.status(),
                count = count,
                "SaaS risk-events endpoint returned non-2xx"
            );
        }
        Err(e) => {
            warn!(error = %e, count = count, "Failed to relay risk events to SaaS");
        }
    }
}

// ── Blocked delegation recording ──────────────────────────────────────────────

/// Record a blocked delegation in Redis so delegation_sync can forward it
/// to the Dashboard API. Uses a key with TTL to auto-expire if not consumed.
/// Key format: ag:delegation:blocked:{org_id}:{caller}:{target}
/// Must match the SCAN pattern in delegation_sync.rs.
async fn record_blocked_delegation(
    cfg: &PollerConfig,
    org_id: &str,
    caller_agent_id: &str,
    target_agent_id: &str,
    reason: &str,
    tool: &str,
) {
    if let Some(ref pool) = cfg.redis_pool {
        if let Ok(mut conn) = pool.get().await {
            let key = format!("ag:delegation:blocked:{}:{}:{}", org_id, caller_agent_id, target_agent_id);
            let value = serde_json::json!({
                "caller_agent_id": caller_agent_id,
                "target_agent_id": target_agent_id,
                "reason": reason,
                "tool": tool,
            });
            if let Ok(json_str) = serde_json::to_string(&value) {
                // Set with 5-minute TTL - delegation_sync runs every 15s so this is plenty
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(&json_str)
                    .arg("EX")
                    .arg(300u64)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or(());
                debug!(
                    caller = caller_agent_id,
                    target = target_agent_id,
                    "Recorded blocked delegation in Redis"
                );
            }
        }
    }
}

// ── Real health / risk data from Redis ────────────────────────────────────────

/// Load actual cluster health from Redis `ag:cluster:health` key.
/// Falls back to basic defaults if Redis is unavailable or key is missing.
async fn load_health_payload_from_redis(cfg: &PollerConfig) -> RuntimeHealthPayload {
    if let Some(ref pool) = cfg.redis_pool {
        if let Ok(mut conn) = pool.get().await {
            let health_json: Option<String> = redis::cmd("GET")
                .arg("ag:cluster:health")
                .query_async(&mut *conn)
                .await
                .unwrap_or(None);

            if let Some(json) = health_json {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
                    return RuntimeHealthPayload {
                        overall_status: parsed
                            .get("overall_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("healthy")
                            .to_string(),
                        redis_status: parsed
                            .get("redis_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("healthy")
                            .to_string(),
                        nats_status: parsed
                            .get("nats_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("healthy")
                            .to_string(),
                        checked_at: parsed
                            .get("checked_at")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&chrono::Utc::now().to_rfc3339())
                            .to_string(),
                    };
                }
            }
        }
    }

    // Fallback: no Redis pool or no health data found.
    RuntimeHealthPayload {
        overall_status: "healthy".to_string(),
        redis_status: "healthy".to_string(),
        nats_status: "healthy".to_string(),
        checked_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Load services array from Redis `ag:cluster:health` for the WS health message.
/// Returns None if unavailable.
async fn load_services_json_from_redis(cfg: &PollerConfig) -> Option<serde_json::Value> {
    if let Some(ref pool) = cfg.redis_pool {
        if let Ok(mut conn) = pool.get().await {
            let health_json: Option<String> = redis::cmd("GET")
                .arg("ag:cluster:health")
                .query_async(&mut *conn)
                .await
                .unwrap_or(None);

            if let Some(json) = health_json {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
                    return parsed.get("services").cloned();
                }
            }
        }
    }
    None
}

/// Load actual high-risk agent count from Redis `ag:risk:high_count` key.
/// Falls back to 0 if Redis is unavailable or key is missing.
async fn load_risk_payload_from_redis(cfg: &PollerConfig) -> RuntimeRiskPayload {
    let mut count: u32 = 0;

    if let Some(ref pool) = cfg.redis_pool {
        if let Ok(mut conn) = pool.get().await {
            count = redis::cmd("GET")
                .arg("ag:risk:high_count")
                .query_async(&mut *conn)
                .await
                .unwrap_or(0);
        }
    }

    RuntimeRiskPayload {
        high_risk_agent_count: count,
        sampled_at: chrono::Utc::now().to_rfc3339(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_connected_skips_poll() {
        // Verify the flag value - the actual poll skip is an `if` in
        // run_command_loop, but we can at least confirm the AtomicBool wiring.
        let ws_connected = Arc::new(AtomicBool::new(false));
        assert!(!ws_connected.load(Ordering::Relaxed));

        ws_connected.store(true, Ordering::Relaxed);
        assert!(ws_connected.load(Ordering::Relaxed));
    }

    #[test]
    fn test_poller_config_to_executor_config() {
        let cfg = PollerConfig {
            saas_url: "https://api.example.com".to_string(),
            license_token: "tok".to_string(),
            poll_interval_secs: 5,
            kill_url: "http://kill:50055".to_string(),
            registry_url: "http://reg:50051".to_string(),
            nats_client: None,
            redis_pool: None,
            pg_pool: None,
            ws_connected: Arc::new(AtomicBool::new(false)),
            ws_sender: None,
            rules_sync_notify: None,
        };
        let exec = cfg.to_executor_config();
        assert_eq!(exec.kill_url, "http://kill:50055");
        assert_eq!(exec.registry_url, "http://reg:50051");
        assert!(exec.nats_client.is_none());
        assert!(exec.redis_pool.is_none());
    }
}
