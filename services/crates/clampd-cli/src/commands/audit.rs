use anyhow::Result;
use uuid::Uuid;
use crate::output::OutputFormat;
use crate::state::AppState;

pub async fn list(
    state: &AppState,
    agent: Option<Uuid>,
    action: Option<&str>,
    limit: u32,
    fmt: OutputFormat,
) -> Result<()> {
    let client = state.api_client();
    let org_id = client.org_id();
    let mut path = format!("/v1/orgs/{}/audit-trail?limit={}", org_id, limit);

    if let Some(aid) = agent {
        path.push_str(&format!("&resource_type=agent&resource_id={}", aid));
    }
    if let Some(act) = action {
        path.push_str(&format!("&action={}", act));
    }

    let resp: serde_json::Value = client.get(&path).await?;
    let entries = resp["entries"].as_array();

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&resp)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if let Some(entries) = entries {
                if entries.is_empty() {
                    println!("No audit events found.");
                } else {
                    println!("{:<24} {:<38} {:<25} {:<10} {}", "TIMESTAMP", "RESOURCE", "ACTION", "STATUS", "USER");
                    println!("{}", "-".repeat(110));
                    for e in entries {
                        println!("{:<24} {:<38} {:<25} {:<10} {}",
                            e["createdAt"].as_str().or(e["created_at"].as_str()).unwrap_or("-"),
                            e["resourceId"].as_str().or(e["resource_id"].as_str()).unwrap_or("-"),
                            e["action"].as_str().unwrap_or("-"),
                            e["statusCode"].as_i64().or(e["status_code"].as_i64()).map(|c| c.to_string()).unwrap_or("-".into()),
                            e["userId"].as_str().or(e["user_id"].as_str()).unwrap_or("-"),
                        );
                    }
                    if let Some(total) = resp["total"].as_i64() {
                        println!("\nShowing {}/{} entries", entries.len(), total);
                    }
                }
            } else {
                println!("No audit events found.");
            }
        }
    }
    Ok(())
}

pub async fn export(
    state: &AppState,
    format: &str,
    output: Option<&str>,
    limit: u32,
) -> Result<()> {
    let client = state.api_client();
    let org_id = client.org_id();
    let path = format!("/v1/orgs/{}/audit-trail?limit={}", org_id, limit);

    let resp: serde_json::Value = client.get(&path).await?;
    let entries = resp["entries"].as_array().cloned().unwrap_or_default();

    let content = match format {
        "csv" => {
            let mut wtr = csv::Writer::from_writer(Vec::new());
            // Write header
            wtr.write_record(["timestamp", "action", "resource_type", "resource_id", "user_id", "status_code"])?;
            for event in &entries {
                wtr.write_record([
                    event["createdAt"].as_str().or(event["created_at"].as_str()).unwrap_or(""),
                    event["action"].as_str().unwrap_or(""),
                    event["resourceType"].as_str().or(event["resource_type"].as_str()).unwrap_or(""),
                    event["resourceId"].as_str().or(event["resource_id"].as_str()).unwrap_or(""),
                    event["userId"].as_str().or(event["user_id"].as_str()).unwrap_or(""),
                    &event["statusCode"].as_i64().or(event["status_code"].as_i64()).map(|c| c.to_string()).unwrap_or_default(),
                ])?;
            }
            String::from_utf8(wtr.into_inner()?)?
        }
        _ => serde_json::to_string_pretty(&entries)?,
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            println!("Exported {} events to {path}", entries.len());
        }
        None => print!("{content}"),
    }
    Ok(())
}
