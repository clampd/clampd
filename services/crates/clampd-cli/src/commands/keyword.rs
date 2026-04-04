use anyhow::Result;
use uuid::Uuid;

use crate::output::{OutputFormat, print_success, print_warn};
use crate::state::AppState;

pub async fn list(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/keywords", org_id);
    let resp: serde_json::Value = client.get(&path).await?;

    // Handle paginated response {items, total, limit, offset}
    let keywords = if let Some(items) = resp.get("items") {
        items.as_array().cloned().unwrap_or_default()
    } else if let Some(arr) = resp.as_array() {
        arr.clone()
    } else {
        vec![]
    };

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&keywords)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if keywords.is_empty() {
                println!("No keywords found.");
            } else {
                println!(
                    "{:<38} {:<30} {:<20} {:<8} {:<6} {:<8} {}",
                    "ID", "KEYWORD", "CATEGORY", "WEIGHT", "LANG", "ENABLED", "SYNC"
                );
                println!("{}", "-".repeat(140));
                for k in &keywords {
                    let kw = k["keyword"].as_str().unwrap_or("-");
                    let display_kw = if kw.len() > 27 {
                        format!("{}...", &kw[..27])
                    } else {
                        kw.to_string()
                    };
                    println!(
                        "{:<38} {:<30} {:<20} {:<8} {:<6} {:<8} {}",
                        k["id"].as_str().unwrap_or("-"),
                        display_kw,
                        k["category"].as_str().unwrap_or("-"),
                        k["riskWeight"]
                            .as_str()
                            .or(k["risk_weight"].as_str())
                            .unwrap_or("-"),
                        k["lang"].as_str().unwrap_or("en"),
                        k["enabled"]
                            .as_bool()
                            .map(|b| if b { "true" } else { "false" })
                            .unwrap_or("-"),
                        k["syncStatus"]
                            .as_str()
                            .or(k["sync_status"].as_str())
                            .unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn add(
    state: &AppState,
    org_id: Uuid,
    keyword: &str,
    category: &str,
    risk_weight: f64,
    lang: &str,
) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/keywords", org_id);
    let body = serde_json::json!({
        "keyword": keyword,
        "category": category,
        "riskWeight": risk_weight,
        "lang": lang,
    });

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let id = resp["id"].as_str().unwrap_or("unknown");
    print_success(&format!("Keyword created: {id}"));
    Ok(())
}

pub async fn remove(state: &AppState, org_id: Uuid, keyword_id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/keywords/{}", org_id, keyword_id);
    let _resp: serde_json::Value = client.delete_json(&path).await?;
    print_success(&format!("Keyword {keyword_id} deleted"));
    Ok(())
}

pub async fn import_csv(state: &AppState, org_id: Uuid, file: &str) -> Result<()> {
    let csv = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read {file}: {e}"))?;

    let client = state.api_client();
    let path = format!("/v1/orgs/{}/keywords/import-csv", org_id);
    let body = serde_json::json!({ "csv": csv });

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let imported = resp["imported"].as_u64().unwrap_or(0);
    let errors = resp["errors"].as_u64().unwrap_or(0);

    print_success(&format!("Imported {imported} keywords ({errors} errors)"));

    if let Some(details) = resp["error_details"].as_array() {
        for err in details {
            if let Some(msg) = err.as_str() {
                print_warn(msg);
            }
        }
    }
    Ok(())
}

pub async fn import_rulepack(state: &AppState, org_id: Uuid, file: &str) -> Result<()> {
    let content = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read {file}: {e}"))?;

    // Validate it's valid JSON before sending
    let pack: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Invalid JSON in {file}: {e}"))?;

    let client = state.api_client();
    let path = format!("/v1/orgs/{}/import-rulepack", org_id);

    let resp: serde_json::Value = client.post(&path, &pack).await?;
    let rules = resp["rules_imported"].as_u64().unwrap_or(0);
    let kw = resp["keywords_imported"].as_u64().unwrap_or(0);

    print_success(&format!(
        "RulePack '{}' v{}: {rules} rules, {kw} keywords imported",
        resp["pack_name"].as_str().unwrap_or("unknown"),
        resp["pack_version"].as_str().unwrap_or("?"),
    ));

    for field in &["rules_errors", "keywords_errors"] {
        if let Some(errors) = resp[field].as_array() {
            for err in errors {
                if let Some(msg) = err.as_str() {
                    print_warn(msg);
                }
            }
        }
    }
    Ok(())
}
