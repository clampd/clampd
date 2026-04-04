use anyhow::Result;
use uuid::Uuid;
use crate::state::AppState;

pub async fn kill_agent(state: &AppState, agent_id: Uuid, reason: Option<&str>) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}/kill", client.org_id(), agent_id);
    let body = serde_json::json!({
        "reason": reason.unwrap_or("CLI kill"),
    });
    let resp: serde_json::Value = client.post(&path, &body).await?;

    println!("Kill switch activated for agent {agent_id}");
    if let Some(msg) = resp["message"].as_str() {
        println!("  Status: {msg}");
    }
    if let Some(name) = resp["name"].as_str() {
        println!("  Name: {name}");
    }
    if let Some(killed_at) = resp["killed_at"].as_str() {
        println!("  Killed at: {killed_at}");
    }
    if let Some(cmd_id) = resp["command_id"].as_str() {
        println!("  Command ID: {cmd_id}");
    }
    Ok(())
}

pub async fn kill_all(state: &AppState, org_id: Uuid, reason: Option<&str>) -> Result<()> {
    // The dashboard API doesn't have a kill-all endpoint, so we list agents
    // and kill each one individually.
    let client = state.api_client();
    let agents_path = format!("/v1/orgs/{}/agents", org_id);
    let agents: Vec<serde_json::Value> = client.get(&agents_path).await?;

    let active_agents: Vec<&serde_json::Value> = agents.iter()
        .filter(|a| a["state"].as_str() == Some("active") || a["state"].as_str() == Some("suspended"))
        .collect();

    if active_agents.is_empty() {
        println!("No active agents to kill in org {org_id}.");
        return Ok(());
    }

    let kill_reason = reason.unwrap_or("CLI kill-all");
    let mut killed = 0u32;
    let mut failed = 0u32;

    for agent in &active_agents {
        if let Some(aid) = agent["id"].as_str() {
            let path = format!("/v1/orgs/{}/agents/{}/kill", org_id, aid);
            let body = serde_json::json!({ "reason": kill_reason });
            match client.post::<serde_json::Value>(&path, &body).await {
                Ok(_) => killed += 1,
                Err(e) => {
                    eprintln!("  Failed to kill agent {aid}: {e}");
                    failed += 1;
                }
            }
        }
    }

    println!("Kill-all activated for org {org_id}");
    println!("  Agents killed: {killed}");
    println!("  Agents failed: {failed}");
    Ok(())
}

pub async fn list(state: &AppState, org_id: Uuid) -> Result<()> {
    // List agents and filter for killed ones
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents", org_id);
    let agents: Vec<serde_json::Value> = client.get(&path).await?;

    let killed: Vec<&serde_json::Value> = agents.iter()
        .filter(|a| a["state"].as_str() == Some("killed"))
        .collect();

    if killed.is_empty() {
        println!("No killed agents found for org {org_id}.");
    } else {
        println!("{:<38} {:<25} {:<30} {}", "ID", "NAME", "KILL REASON", "KILLED AT");
        println!("{}", "-".repeat(120));
        for agent in &killed {
            println!("{:<38} {:<25} {:<30} {}",
                agent["id"].as_str().unwrap_or("-"),
                agent["name"].as_str().unwrap_or("-"),
                agent["killReason"].as_str().or(agent["kill_reason"].as_str()).unwrap_or("-"),
                agent["killedAt"].as_str().or(agent["killed_at"].as_str()).unwrap_or("-"),
            );
        }
        println!("\nTotal killed: {}", killed.len());
    }
    Ok(())
}

pub async fn status(state: &AppState, agent_id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}", client.org_id(), agent_id);
    let agent: serde_json::Value = client.get(&path).await?;

    let agent_state = agent["state"].as_str().unwrap_or("unknown");
    let is_killed = agent_state == "killed";
    let status_str = if is_killed { "KILLED" } else { "ALIVE" };

    println!("Agent {agent_id} kill status: {status_str}");
    println!("  State: {agent_state}");
    if is_killed {
        if let Some(reason) = agent["killReason"].as_str().or(agent["kill_reason"].as_str()) {
            println!("  Reason: {reason}");
        }
        if let Some(killed_at) = agent["killedAt"].as_str().or(agent["killed_at"].as_str()) {
            println!("  Killed at: {killed_at}");
        }
    }
    Ok(())
}
