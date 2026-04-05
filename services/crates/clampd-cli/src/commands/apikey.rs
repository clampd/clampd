use anyhow::Result;
use uuid::Uuid;
use crate::output::{OutputFormat, print_success};
use crate::state::AppState;

pub async fn list(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/api-keys", org_id);
    let keys: Vec<serde_json::Value> = client.get(&path).await?;

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&keys)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if keys.is_empty() {
                println!("No API keys found.");
            } else {
                println!("{:<38} {:<20} {:<12} {:<12} {:<24} {}", "ID", "NAME", "PREFIX", "ENV", "LAST USED", "CREATED");
                println!("{}", "-".repeat(130));
                for k in &keys {
                    println!("{:<38} {:<20} {:<12} {:<12} {:<24} {}",
                        k["id"].as_str().unwrap_or("-"),
                        k["name"].as_str().unwrap_or("-"),
                        k["prefix"].as_str().unwrap_or("-"),
                        k["environment"].as_str().unwrap_or("-"),
                        k["lastUsedAt"].as_str().or(k["last_used_at"].as_str()).unwrap_or("-"),
                        k["createdAt"].as_str().or(k["created_at"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn create(state: &AppState, org_id: Uuid, name: Option<&str>) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/api-keys", org_id);
    let body = serde_json::json!({
        "name": name.unwrap_or("Default"),
        "environment": "test",
    });

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let id = resp["id"].as_str().unwrap_or("unknown");
    print_success(&format!("API key created: {id}"));
    if let Some(key) = resp["key"].as_str() {
        println!("  Key: {key}");
        println!("  (Save this key - it won't be shown again)");
    }
    Ok(())
}

pub async fn revoke(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/api-keys/{}/revoke", client.org_id(), id);
    let _resp: serde_json::Value = client.post_empty(&path).await?;
    print_success(&format!("API key {id} revoked"));
    Ok(())
}
