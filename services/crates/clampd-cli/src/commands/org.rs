use anyhow::Result;
use uuid::Uuid;
use crate::output::{OutputFormat, print_success};
use crate::state::AppState;

pub async fn list(state: &AppState, fmt: OutputFormat) -> Result<()> {
    // The dashboard API doesn't expose a list-all-orgs endpoint for CLI users.
    // Show the currently configured org instead.
    let client = state.api_client();
    let org_id = client.org_id();
    if org_id.is_empty() {
        println!("No organization configured. Set CLAMPD_ORG_ID or use --org-id.");
        return Ok(());
    }
    let path = format!("/v1/orgs/{}", org_id);
    match client.get::<serde_json::Value>(&path).await {
        Ok(org) => {
            match fmt {
                OutputFormat::Json | OutputFormat::Plain => {
                    let json = serde_json::to_string_pretty(&[&org])?;
                    println!("{json}");
                }
                OutputFormat::Table => {
                    println!("{:<38} {:<25} {:<12} {:<8} {}", "ID", "NAME", "SLUG", "TIER", "STATE");
                    println!("{}", "-".repeat(90));
                    println!("{:<38} {:<25} {:<12} {:<8} {}",
                        org["id"].as_str().unwrap_or("-"),
                        org["name"].as_str().unwrap_or("-"),
                        org["slug"].as_str().unwrap_or("-"),
                        org["tier"].as_str().unwrap_or("-"),
                        org["state"].as_str().unwrap_or("-"),
                    );
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to fetch org {org_id}: {e}");
        }
    }
    Ok(())
}

pub async fn create(state: &AppState, name: &str, slug: &str, billing_email: &str) -> Result<()> {
    let client = state.api_client();
    let body = serde_json::json!({
        "name": name,
        "slug": slug,
        "billingEmail": billing_email,
    });
    let resp: serde_json::Value = client.post("/v1/orgs", &body).await?;
    let id = resp["id"].as_str().unwrap_or("unknown");
    print_success(&format!("Organization created: {id}"));
    Ok(())
}

pub async fn update(state: &AppState, id: Uuid, name: &str, billing_email: &str) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}", id);
    let body = serde_json::json!({
        "name": name,
        "billingEmail": billing_email,
    });
    let _resp: serde_json::Value = client.patch(&path, &body).await?;
    print_success(&format!("Organization {id} updated"));
    Ok(())
}

pub async fn delete(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}", id);
    let _resp: serde_json::Value = client.delete_json(&path).await?;
    print_success(&format!("Organization {id} deleted"));
    Ok(())
}

pub async fn members(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/members", org_id);
    let members: Vec<serde_json::Value> = client.get(&path).await?;

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&members)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if members.is_empty() {
                println!("No members found.");
            } else {
                println!("{:<38} {:<30} {:<10} {}", "ID", "EMAIL", "ROLE", "ACCEPTED");
                println!("{}", "-".repeat(90));
                for m in &members {
                    println!("{:<38} {:<30} {:<10} {}",
                        m["id"].as_str().unwrap_or("-"),
                        m["email"].as_str().unwrap_or("-"),
                        m["role"].as_str().unwrap_or("-"),
                        m["acceptedAt"].as_str().or(m["accepted_at"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}
