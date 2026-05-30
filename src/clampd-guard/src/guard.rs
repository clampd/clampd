/// Hot-path guard: called on every tool call by Claude Code / Cursor hooks.
///
/// Reads env vars → loads config → calls gateway → exits 0 (allow) or 2 (block).
/// Handles both PreToolUse (tool_input) and PostToolUse (tool_output).
///
/// Performance target: <10ms for cached JWT + config read. Total <100ms with network.

use crate::auth;
use crate::config::GuardConfig;
use crate::contract_hash::contract_hash;
use crate::scope;
use crate::sync::known_tool_description;

use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct ProxyResponse {
    #[allow(dead_code)]
    request_id: String,
    allowed: bool,
    #[allow(dead_code)]
    action: String,
    risk_score: f64,
    /// v0.20: typed denial from the gateway. Populated on Deny/Downscope.
    /// We render its `corrective` into the block message so the agent
    /// (Claude Code, Cursor, …) sees the suggested next action, not just
    /// "denied".
    #[serde(default)]
    denial: Option<ag_common::denial::StructuredDenialJson>,
    matched_rules: Vec<String>,
    reasoning: Option<String>,
    #[allow(dead_code)]
    latency_ms: u64,
}

/// Render the corrective hint for a Claude Code hook block message.
///
/// As of v0.23.1 the gateway pre-renders this string in
/// `corrective.rendered.tool_result`, so clampd-guard is a thin reader.
/// We keep a fall-back path (using `ag_common::denial::render::render`)
/// for pre-0.23.1 gateways that don't yet emit the `rendered` block —
/// that way an old gateway + new clampd-guard still shows the right
/// hint while rollouts overlap.
fn render_corrective(c: &ag_common::denial::CorrectiveActionJson) -> String {
    use ag_common::corrective::Confidence;
    if let Some(r) = c.rendered.as_ref() {
        return r.tool_result.clone();
    }
    // Fallback for pre-0.23.1 gateways that don't carry the pre-rendered
    // block. Uses the exact same templates the gateway would have used —
    // we call into the shared `render` module to guarantee parity instead
    // of inlining the templates here a fifth time.
    let conf = if c.confidence == Confidence::Low {
        Confidence::Low
    } else {
        c.confidence
    };
    ag_common::denial::render::render(&c.kind, &c.payload, &c.human_explanation, conf)
        .tool_result
}

/// Pick the best human-readable reason from the gateway's denial. Prefers
/// the rendered corrective over the raw violated_predicate so the agent
/// sees an actionable hint when one is available.
fn denial_reason(d: &ag_common::denial::StructuredDenialJson) -> String {
    if let Some(ref c) = d.corrective {
        let rendered = render_corrective(c);
        if !rendered.is_empty() {
            return rendered;
        }
    }
    if !d.violated_predicate.is_empty() {
        return d.violated_predicate.clone();
    }
    "Policy violation detected".to_string()
}

fn block(reason: &str) -> ! {
    let output = serde_json::json!({
        "decision": "block",
        "reason": reason,
    });
    print!("{}", output);
    std::process::exit(2);
}

fn allow() -> ! {
    std::process::exit(0);
}

/// JSON payload that Claude Code sends to hooks via stdin.
#[derive(Debug, Deserialize, Default)]
struct HookInput {
    #[serde(default)]
    hook_event_name: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: serde_json::Value,
    /// Present only on PostToolUse events.
    #[serde(default)]
    tool_response: Option<serde_json::Value>,
}

pub async fn run() {
    // Try reading hook payload from stdin (Claude Code protocol).
    // Fall back to env vars for backward compatibility (direct invocation).
    let hook = read_stdin_hook().unwrap_or_else(|| {
        let raw_input = std::env::var("CLAUDE_TOOL_INPUT").unwrap_or_default();
        let tool_input = serde_json::from_str(&raw_input)
            .unwrap_or_else(|_| serde_json::json!({ "raw": raw_input }));
        HookInput {
            hook_event_name: std::env::var("CLAUDE_HOOK_EVENT_NAME").unwrap_or_default(),
            tool_name: std::env::var("CLAUDE_TOOL_NAME").unwrap_or_default(),
            tool_input,
            tool_response: std::env::var("CLAUDE_TOOL_OUTPUT")
                .ok()
                .map(|s| serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({ "raw": s }))),
        }
    });

    // No tool name → nothing to guard
    if hook.tool_name.is_empty() {
        allow();
    }

    // Load config
    let config = match GuardConfig::load() {
        Ok(c) => c,
        Err(_) => allow(), // No config = not set up. Don't break the IDE.
    };

    // Skip low-risk tools if configured
    if config.skip_low_risk && scope::is_low_risk(&hook.tool_name) {
        allow();
    }

    // Determine mode: PreToolUse vs PostToolUse
    let is_post = hook.hook_event_name == "PostToolUse" || hook.tool_response.is_some();

    if is_post {
        let output = hook.tool_response
            .map(|v| v.to_string())
            .unwrap_or_default();
        handle_post(&config, &hook.tool_name, &output).await;
    } else {
        let input = serde_json::to_string(&hook.tool_input).unwrap_or_default();
        handle_pre(&config, &hook.tool_name, &input).await;
    }
}

/// Read and parse the JSON hook payload from stdin (non-blocking).
fn read_stdin_hook() -> Option<HookInput> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).ok()?;
    if buf.trim().is_empty() {
        return None;
    }
    serde_json::from_str(&buf).ok()
}

/// PreToolUse: verify tool call before execution via /v1/proxy.
async fn handle_pre(config: &GuardConfig, tool_name: &str, tool_input: &str) {
    let scope = scope::map_tool_to_scope(tool_name);

    let params: serde_json::Value = serde_json::from_str(tool_input)
        .unwrap_or_else(|_| serde_json::json!({ "raw": tool_input }));

    // Compute a canonical tool-descriptor hash that matches the one
    // `clampd-guard sync` publishes for the same tool, so gateway
    // rug-pull checks see a stable hash across discovery + invocation.
    // Description comes from the built-in catalog; parameters are left
    // as `{}` because the IDE hook does not forward the tool's schema.
    let description = known_tool_description(tool_name).unwrap_or("");
    let descriptor_hash = contract_hash(tool_name, description, &serde_json::json!({}));

    let body = serde_json::json!({
        "tool": tool_name,
        "params": params,
        "target_url": "",
        "prompt_context": format!("scope:{}", scope),
        "tool_descriptor_hash": descriptor_hash,
    });

    let endpoint = format!("{}/v1/proxy", config.gateway_url.trim_end_matches('/'));
    match call_gateway(config, &endpoint, &body).await {
        Ok(resp) => {
            if resp.allowed {
                allow();
            }
            let rules = if resp.matched_rules.is_empty() {
                String::new()
            } else {
                format!(" ({})", resp.matched_rules.join(", "))
            };
            let reason = resp
                .denial
                .as_ref()
                .map(denial_reason)
                .or(resp.reasoning)
                .unwrap_or_else(|| "Policy violation detected".into());
            block(&format!("{}{}. Risk: {:.2}", reason, rules, resp.risk_score));
        }
        Err(e) => {
            if config.fail_open {
                allow();
            }
            block(&format!("Gateway unreachable: {}", e));
        }
    }
}

/// PostToolUse: inspect tool output after execution via /v1/inspect.
async fn handle_post(config: &GuardConfig, tool_name: &str, tool_output: &str) {
    let response_data: serde_json::Value = serde_json::from_str(tool_output)
        .unwrap_or_else(|_| serde_json::json!({ "raw": tool_output }));

    let body = serde_json::json!({
        "tool": tool_name,
        "response_data": response_data,
    });

    let endpoint = format!("{}/v1/inspect", config.gateway_url.trim_end_matches('/'));
    match call_gateway(config, &endpoint, &body).await {
        Ok(resp) => {
            if resp.allowed {
                allow();
            }
            let reason = resp
                .denial
                .as_ref()
                .map(denial_reason)
                .unwrap_or_else(|| "Response inspection flagged violation".into());
            block(&reason);
        }
        Err(_) => {
            // PostToolUse: tool already ran. Always fail-open - blocking output
            // just hides it. Log the error but don't break UX.
            allow();
        }
    }
}

/// Call the Clampd gateway with auth headers and timeout.
async fn call_gateway(
    config: &GuardConfig,
    url: &str,
    body: &serde_json::Value,
) -> anyhow::Result<ProxyResponse> {
    // Prefer employee token, fall back to the enrolled agent's EdDSA JWT.
    let bearer = match auth::load_employee_token() {
        Some(t) => t,
        None => {
            let id = crate::enroll::get_identity(&config.gateway_url, &config.api_key, &config.agent_id).await?;
            auth::make_agent_jwt(&id.agent_id, &id.signing_key, 3600).unwrap_or_default()
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .build()?;

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", bearer))
        .header("X-AG-Key", &config.api_key)
        .json(body)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("Gateway returned {}", resp.status());
    }

    let proxy_resp: ProxyResponse = resp.json().await?;
    Ok(proxy_resp)
}
