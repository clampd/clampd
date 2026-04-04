use anyhow::Result;
use uuid::Uuid;
use crate::output::OutputFormat;
use crate::state::AppState;

pub async fn status(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/licenses/current", org_id);
    match client.get::<serde_json::Value>(&path).await {
        Ok(lic) => {
            println!("Active License:");
            match fmt {
                OutputFormat::Json | OutputFormat::Plain => {
                    let json = serde_json::to_string_pretty(&lic)?;
                    println!("{json}");
                }
                OutputFormat::Table => {
                    println!("  ID:        {}", lic["id"].as_str().unwrap_or("-"));
                    println!("  Tier:      {}", lic["tier"].as_str().unwrap_or("-"));
                    println!("  Status:    {}", lic["status"].as_str().unwrap_or("-"));
                    println!("  Expires:   {}", lic["expires_at"].as_str().unwrap_or("-"));
                    if let Some(features) = lic["features"].as_array() {
                        let f: Vec<&str> = features.iter().filter_map(|v| v.as_str()).collect();
                        println!("  Features:  {}", f.join(", "));
                    }
                }
            }
        }
        Err(_) => println!("No active license found for org {org_id}"),
    }
    Ok(())
}

pub async fn list(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/licenses", org_id);
    let licenses: Vec<serde_json::Value> = client.get(&path).await?;

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&licenses)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if licenses.is_empty() {
                println!("No licenses found.");
            } else {
                println!("{:<38} {:<8} {:<10} {:<24} {}", "ID", "TIER", "STATUS", "ISSUED", "EXPIRES");
                println!("{}", "-".repeat(110));
                for l in &licenses {
                    println!("{:<38} {:<8} {:<10} {:<24} {}",
                        l["id"].as_str().unwrap_or("-"),
                        l["tier"].as_str().unwrap_or("-"),
                        l["status"].as_str().unwrap_or("-"),
                        l["issuedAt"].as_str().or(l["issued_at"].as_str()).unwrap_or("-"),
                        l["expiresAt"].as_str().or(l["expires_at"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}
