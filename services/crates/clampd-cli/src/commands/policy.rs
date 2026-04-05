pub mod import;

use anyhow::Result;
use uuid::Uuid;
use crate::output::{OutputFormat, print_success};
use crate::state::AppState;

pub async fn list(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/policies", org_id);
    let policies: Vec<serde_json::Value> = client.get(&path).await?;

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&policies)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if policies.is_empty() {
                println!("No policies found.");
            } else {
                println!("{:<38} {:<25} {:<8} {:<10} {:<8} {}", "ID", "NAME", "MODE", "STATUS", "PRI", "CREATED");
                println!("{}", "-".repeat(110));
                for p in &policies {
                    println!("{:<38} {:<25} {:<8} {:<10} {:<8} {}",
                        p["id"].as_str().unwrap_or("-"),
                        p["name"].as_str().unwrap_or("-"),
                        p["mode"].as_str().unwrap_or("-"),
                        p["status"].as_str().unwrap_or("-"),
                        p["priority"].as_i64().unwrap_or(0),
                        p["createdAt"].as_str().or(p["created_at"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn create(
    state: &AppState,
    org_id: Uuid,
    name: &str,
    description: Option<&str>,
    mode: &str,
    source: &str,
) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/policies", org_id);
    let mut body = serde_json::json!({
        "name": name,
        "mode": mode,
        "source": source,
    });
    if let Some(d) = description {
        body["description"] = serde_json::Value::String(d.to_string());
    }

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let id = resp["id"].as_str().unwrap_or("unknown");
    print_success(&format!("Policy created: {id}"));
    Ok(())
}

pub async fn delete(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/policies/{}", client.org_id(), id);
    let _resp: serde_json::Value = client.delete_json(&path).await?;
    print_success(&format!("Policy {id} deleted"));
    Ok(())
}

pub async fn rules(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/rules", org_id);
    // API may return {total, items} or a flat array
    let rules: Vec<serde_json::Value> = match client.get::<serde_json::Value>(&path).await? {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Object(map) => {
            map.get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        }
        _ => vec![],
    };

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&rules)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if rules.is_empty() {
                println!("No rules found.");
            } else {
                println!("{:<38} {:<25} {:<40} {:<8} {:<10} {:<8} {}", "ID", "NAME", "PATTERN", "ACTION", "SEVERITY", "ENABLED", "SYNC");
                println!("{}", "-".repeat(140));
                for r in &rules {
                    let pattern = r["pattern"].as_str().unwrap_or("-");
                    let display_pattern = if pattern.len() > 37 {
                        format!("{}...", &pattern[..37])
                    } else {
                        pattern.to_string()
                    };
                    println!("{:<38} {:<25} {:<40} {:<8} {:<10} {:<8} {}",
                        r["id"].as_str().unwrap_or("-"),
                        r["name"].as_str().unwrap_or("-"),
                        display_pattern,
                        r["action"].as_str().unwrap_or("-"),
                        r["severity"].as_str().unwrap_or("-"),
                        r["enabled"].as_bool().map(|b| if b { "true" } else { "false" }).unwrap_or("-"),
                        r["syncStatus"].as_str().or(r["sync_status"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn import_rules(state: &AppState, org_id: Uuid, from: &str, file: &str) -> Result<()> {
    let content = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read {file}: {e}"))?;

    match from {
        "cedar" => import_cedar_policies(state, org_id, &content).await,
        "sigma" => import_sigma_rules(state, org_id, &content).await,
        other => anyhow::bail!("Unknown import format: {other}. Supported: cedar (policies), sigma (rules)"),
    }
}

/// Import Cedar policies → POST /v1/orgs/{}/policies (policy endpoint, not rules).
async fn import_cedar_policies(state: &AppState, org_id: Uuid, content: &str) -> Result<()> {
    let policies = import::cedar::parse(content)?;
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/policies", org_id);
    let mut created = 0;

    for policy in &policies {
        let body = serde_json::json!({
            "name": policy.name,
            "source": policy.pattern,
            "mode": "cedar",
            "description": policy.description,
            "cedarAction": policy.action,
            "cedarReason": policy.reason,
        });

        match client.post::<serde_json::Value>(&path, &body).await {
            Ok(_) => created += 1,
            Err(e) => crate::output::print_warn(&format!("Skipping policy '{}': {e}", policy.name)),
        }
    }

    print_success(&format!("Imported {created}/{} policies from cedar format", policies.len()));
    Ok(())
}

/// Import Sigma rules → POST /v1/orgs/{}/rules (rules endpoint).
async fn import_sigma_rules(state: &AppState, org_id: Uuid, content: &str) -> Result<()> {
    let imported = import::sigma::parse(content)?;
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/rules", org_id);
    let mut created = 0;

    for rule in &imported {
        let mut body = serde_json::json!({
            "name": rule.name,
            "pattern": rule.pattern,
            "action": rule.action,
            "severity": rule.severity,
        });
        if let Some(ref d) = rule.description {
            body["description"] = serde_json::Value::String(d.clone());
        }
        if let Some(ref r) = rule.reason {
            body["reason"] = serde_json::Value::String(r.clone());
        }
        if !rule.scope_patterns.is_empty() {
            body["scopePatterns"] = serde_json::json!(rule.scope_patterns);
        }

        match client.post::<serde_json::Value>(&path, &body).await {
            Ok(_) => created += 1,
            Err(e) => crate::output::print_warn(&format!("Skipping rule '{}': {e}", rule.name)),
        }
    }

    print_success(&format!("Imported {created}/{} rules from sigma format", imported.len()));
    Ok(())
}
