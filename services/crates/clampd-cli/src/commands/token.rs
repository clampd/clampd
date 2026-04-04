use anyhow::Result;
use uuid::Uuid;
use crate::state::AppState;

/// Token operations routed through the Dashboard API.
/// The Dashboard enqueues runtime commands for ag-control, which forwards
/// to ag-token on the customer's network. The CLI polls for the result.

const POLL_INTERVAL_MS: u64 = 500;
const POLL_MAX_ATTEMPTS: u32 = 30; // 15 seconds max wait

/// Poll a runtime command until it completes or times out.
async fn poll_command_result(
    state: &AppState,
    org_id: &str,
    command_id: &str,
) -> Result<serde_json::Value> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/commands/{}", org_id, command_id);

    for _ in 0..POLL_MAX_ATTEMPTS {
        tokio::time::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS)).await;
        let cmd: serde_json::Value = client.get(&path).await?;
        let status = cmd["status"].as_str().unwrap_or("unknown");
        match status {
            "completed" => return Ok(cmd),
            "failed" => {
                let error = cmd["result"]["error"]
                    .as_str()
                    .unwrap_or("Unknown error from runtime");
                anyhow::bail!("Command failed: {}", error);
            }
            "expired" => {
                anyhow::bail!("Command expired — ag-control may be unreachable");
            }
            _ => continue, // pending or delivered — keep polling
        }
    }
    anyhow::bail!(
        "Timed out waiting for runtime response ({}s). \
         ag-control may be offline or slow to respond.",
        (POLL_INTERVAL_MS * POLL_MAX_ATTEMPTS as u64) / 1000
    )
}

pub async fn exchange(state: &AppState, agent_id: Uuid, scopes: Option<&str>) -> Result<()> {
    let client = state.api_client();
    let org_id = client.org_id().to_string();
    let path = format!("/v1/orgs/{}/tokens/exchange", org_id);

    let requested_scopes: Vec<String> = scopes
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    let body = serde_json::json!({
        "agent_id": agent_id.to_string(),
        "scopes": requested_scopes,
    });

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let command_id = resp["command_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing command_id in response"))?;

    println!("Token exchange dispatched (command: {command_id}), waiting for runtime...");

    let result = poll_command_result(state, &org_id, command_id).await?;
    let detail = &result["result"]["detail"];

    if detail.is_object() {
        println!("Token Exchange Successful:");
        if let Some(v) = detail["access_token"].as_str() {
            println!("  Access Token: {v}");
        }
        if let Some(v) = detail["token_type"].as_str() {
            println!("  Token Type:   {v}");
        }
        if let Some(v) = detail["expires_in"].as_u64() {
            println!("  Expires In:   {v}s");
        }
        if let Some(v) = detail["scope"].as_str() {
            println!("  Scope:        {v}");
        }
        if let Some(v) = detail["jti"].as_str() {
            println!("  JTI:          {v}");
        }
    } else {
        println!("Token exchange completed.");
        if let Some(msg) = result["result"].as_object() {
            println!("  Result: {}", serde_json::to_string_pretty(msg)?);
        }
    }
    Ok(())
}

pub async fn introspect(state: &AppState, token: &str) -> Result<()> {
    let client = state.api_client();
    let org_id = client.org_id().to_string();
    let path = format!("/v1/orgs/{}/tokens/introspect", org_id);

    let body = serde_json::json!({ "token": token });
    let resp: serde_json::Value = client.post(&path, &body).await?;
    let command_id = resp["command_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing command_id in response"))?;

    println!("Token introspect dispatched (command: {command_id}), waiting for runtime...");

    let result = poll_command_result(state, &org_id, command_id).await?;
    let detail = &result["result"]["detail"];

    if detail.is_object() {
        println!("Token Introspection:");
        if let Some(v) = detail["active"].as_bool() {
            println!("  Active:       {v}");
        }
        if let Some(v) = detail["sub"].as_str() {
            println!("  Subject:      {v}");
        }
        if let Some(v) = detail["scope"].as_str() {
            println!("  Scope:        {v}");
        }
        if let Some(v) = detail["exp"].as_u64() {
            println!("  Expires:      {v}");
        }
        if let Some(v) = detail["tool_binding"].as_str() {
            println!("  Tool Binding: {v}");
        }
    } else {
        println!("Token introspect completed.");
        if let Some(msg) = result["result"].as_object() {
            println!("  Result: {}", serde_json::to_string_pretty(msg)?);
        }
    }
    Ok(())
}

pub async fn revoke(state: &AppState, agent_id: Uuid) -> Result<()> {
    let client = state.api_client();
    let org_id = client.org_id().to_string();
    let path = format!(
        "/v1/orgs/{}/agents/{}/tokens/revoke",
        org_id, agent_id
    );

    let body = serde_json::json!({ "reason": "CLI token revoke" });
    let resp: serde_json::Value = client.post(&path, &body).await?;
    let command_id = resp["command_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing command_id in response"))?;

    println!("Token revoke dispatched (command: {command_id}), waiting for runtime...");

    let result = poll_command_result(state, &org_id, command_id).await?;
    let detail = &result["result"]["detail"];

    println!("Tokens revoked for agent {agent_id}");
    if let Some(v) = detail["tokens_revoked"].as_u64() {
        println!("  Tokens revoked:   {v}");
    }
    if let Some(v) = detail["sessions_revoked"].as_u64() {
        println!("  Sessions revoked: {v}");
    }
    Ok(())
}
