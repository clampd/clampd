use anyhow::Result;
use crate::state::AppState;

pub async fn status(state: &AppState) -> Result<()> {
    let client = state.api_client();

    // First check dashboard API health
    match client.get::<serde_json::Value>(&client.health_path()).await {
        Ok(health) => {
            println!("Dashboard API: OK ({})", health["status"].as_str().unwrap_or("ok"));
        }
        Err(e) => {
            eprintln!("Dashboard API unreachable: {e}");
            eprintln!("Hint: Is the dashboard running? Check {}",
                client.base_url());
            return Ok(());
        }
    }

    // Then try to get cluster health from ag-control (via dashboard)
    let org_id = client.org_id();
    if !org_id.is_empty() {
        let health_path = format!("/v1/orgs/{}/cluster-health", org_id);
        match client.get::<serde_json::Value>(&health_path).await {
            Ok(health) => {
                println!("\nCluster Status: {}", health["overall_status"].as_str().unwrap_or("-"));
                if let Some(redis) = health["redis_status"].as_str() {
                    println!("  Redis:      {redis}");
                }
                if let Some(nats) = health["nats_status"].as_str() {
                    println!("  NATS:       {nats}");
                }
                if let Some(checked) = health["checked_at"].as_str() {
                    println!("  Checked At: {checked}");
                }
            }
            Err(_) => {
                println!("\nCluster health not available (ag-control may not be reporting yet).");
            }
        }
    } else {
        println!("\nSet --org-id to view cluster health from ag-control.");
    }

    Ok(())
}

pub async fn up(state: &AppState, detach: bool) -> Result<()> {
    let compose_file = &state.config.compose_file;
    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("compose").arg("-f").arg(compose_file).arg("up");
    if detach {
        cmd.arg("-d");
    }
    let status = cmd.status().await?;
    if !status.success() {
        anyhow::bail!("docker compose up failed");
    }
    Ok(())
}

pub async fn down(state: &AppState) -> Result<()> {
    let compose_file = &state.config.compose_file;
    let status = tokio::process::Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .arg("down")
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("docker compose down failed");
    }
    Ok(())
}
