use anyhow::Result;
use uuid::Uuid;
use crate::output::{OutputFormat, print_success};
use crate::state::AppState;

pub async fn list(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/webhooks", org_id);
    let webhooks: Vec<serde_json::Value> = client.get(&path).await?;

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&webhooks)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if webhooks.is_empty() {
                println!("No webhooks found.");
            } else {
                println!("{:<38} {:<50} {:<8} {:<8} {}", "ID", "URL", "ENABLED", "FAILS", "CREATED");
                println!("{}", "-".repeat(120));
                for w in &webhooks {
                    println!("{:<38} {:<50} {:<8} {:<8} {}",
                        w["id"].as_str().unwrap_or("-"),
                        w["url"].as_str().unwrap_or("-"),
                        w["enabled"].as_bool().map(|b| if b { "true" } else { "false" }).unwrap_or("-"),
                        w["failCount"].as_i64().or(w["fail_count"].as_i64()).unwrap_or(0),
                        w["createdAt"].as_str().or(w["created_at"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn create(state: &AppState, org_id: Uuid, url: &str, events: &str) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/webhooks", org_id);
    let event_list: Vec<String> = events.split(',').map(|s| s.trim().to_string()).collect();
    let body = serde_json::json!({
        "url": url,
        "events": event_list,
    });

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let id = resp["id"].as_str().unwrap_or("unknown");
    print_success(&format!("Webhook created: {id}"));
    if let Some(secret) = resp["secret"].as_str() {
        println!("  Secret: {secret}");
        println!("  (Save this secret — it won't be shown again)");
    }
    Ok(())
}

pub async fn delete(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/webhooks/{}", client.org_id(), id);
    let _resp: serde_json::Value = client.delete_json(&path).await?;
    print_success(&format!("Webhook {id} deleted"));
    Ok(())
}
