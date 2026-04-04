use anyhow::Result;
use uuid::Uuid;
use crate::state::AppState;

pub async fn scores(state: &AppState) -> Result<()> {
    let client = state.api_client();
    let org_id = client.org_id();
    let path = format!("/v1/orgs/{}/risk-summary", org_id);

    match client.get::<serde_json::Value>(&path).await {
        Ok(summary) => {
            println!("Risk Summary:");
            let json = serde_json::to_string_pretty(&summary)?;
            println!("{json}");
        }
        Err(_) => {
            println!("No risk data available.");
            println!("Hint: ag-control pushes risk summaries to the dashboard periodically.");
            println!("      Ensure the cluster is running and has processed some requests.");
        }
    }
    Ok(())
}

pub async fn history(state: &AppState, agent_id: Uuid) -> Result<()> {
    // The dashboard API doesn't expose per-agent risk history directly.
    // Show the agent's audit trail filtered for risk-related events instead.
    let client = state.api_client();
    let org_id = client.org_id();
    let path = format!("/v1/orgs/{}/audit-trail?resource_type=agent&resource_id={}&limit=50", org_id, agent_id);

    match client.get::<serde_json::Value>(&path).await {
        Ok(resp) => {
            if let Some(entries) = resp["entries"].as_array() {
                if entries.is_empty() {
                    println!("No risk history for agent {agent_id}.");
                } else {
                    println!("Audit history for agent {agent_id}:");
                    let json = serde_json::to_string_pretty(entries)?;
                    println!("{json}");
                }
            } else {
                println!("No risk history for agent {agent_id}.");
            }
        }
        Err(_) => {
            println!("No risk history available for agent {agent_id}.");
        }
    }
    Ok(())
}
