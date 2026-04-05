use anyhow::Result;
use regex::Regex;
use uuid::Uuid;
use std::sync::LazyLock;
use crate::output::{OutputFormat, print_success};
use crate::state::AppState;

static SCOPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z]+:[a-z_]+:[a-z_]+$").expect("valid scope regex")
});

pub async fn list(state: &AppState, org_id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents", org_id);
    let agents: Vec<serde_json::Value> = client.get(&path).await?;

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            let json = serde_json::to_string_pretty(&agents)?;
            println!("{json}");
        }
        OutputFormat::Table => {
            if agents.is_empty() {
                println!("No agents found.");
            } else {
                println!("{:<38} {:<25} {:<15} {:<12} {}", "ID", "NAME", "STATE", "FRAMEWORK", "CREATED");
                println!("{}", "-".repeat(100));
                for a in &agents {
                    println!("{:<38} {:<25} {:<15} {:<12} {}",
                        a["id"].as_str().unwrap_or("-"),
                        a["name"].as_str().unwrap_or("-"),
                        a["state"].as_str().unwrap_or("-"),
                        a["framework"].as_str().unwrap_or("-"),
                        a["createdAt"].as_str().or(a["created_at"].as_str()).unwrap_or("-"),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn get(state: &AppState, id: Uuid, _fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    // We need org_id to construct the path; use the client's configured org_id
    let path = format!("/v1/orgs/{}/agents/{}", client.org_id(), id);
    let agent: serde_json::Value = client.get(&path).await?;
    let json = serde_json::to_string_pretty(&agent)?;
    println!("{json}");
    Ok(())
}

pub async fn register(
    state: &AppState,
    org_id: Uuid,
    name: &str,
    description: Option<&str>,
    purpose: Option<&str>,
    framework: Option<&str>,
) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents", org_id);
    let mut body = serde_json::json!({ "name": name });
    if let Some(d) = description {
        body["description"] = serde_json::Value::String(d.to_string());
    }
    if let Some(p) = purpose {
        body["declaredPurpose"] = serde_json::Value::String(p.to_string());
    }
    if let Some(f) = framework {
        body["framework"] = serde_json::Value::String(f.to_string());
    }

    let resp: serde_json::Value = client.post(&path, &body).await?;
    let id = resp["id"].as_str().unwrap_or("unknown");
    print_success(&format!("Agent registered: {id}"));

    // Show agent secret if returned
    if let Some(secret) = resp["agent_secret"].as_str() {
        println!("  Agent Secret: {secret}");
        println!("  (Save this secret - it won't be shown again)");
    }
    Ok(())
}

pub async fn update(
    state: &AppState,
    id: Uuid,
    name: &str,
    description: Option<&str>,
    framework: Option<&str>,
) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}", client.org_id(), id);
    let mut body = serde_json::json!({ "name": name });
    if let Some(d) = description {
        body["description"] = serde_json::Value::String(d.to_string());
    }
    if let Some(f) = framework {
        body["framework"] = serde_json::Value::String(f.to_string());
    }

    let _resp: serde_json::Value = client.patch(&path, &body).await?;
    print_success(&format!("Agent {id} updated"));
    Ok(())
}

pub async fn delete(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}", client.org_id(), id);
    let resp: serde_json::Value = client.delete_json(&path).await?;
    let msg = resp["message"].as_str().unwrap_or("deleted");
    let cascade = resp["cascade"].as_str().unwrap_or("");
    print_success(&format!("Agent {id}: {msg}"));
    if !cascade.is_empty() {
        println!("  {cascade}");
    }
    Ok(())
}

pub async fn suspend(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}/suspend", client.org_id(), id);
    let resp: serde_json::Value = client.post_empty(&path).await?;
    let msg = resp["message"].as_str().unwrap_or("suspended");
    print_success(&format!("Agent {id}: {msg}"));
    Ok(())
}

pub async fn resume(state: &AppState, id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}/activate", client.org_id(), id);
    let resp: serde_json::Value = client.post_empty(&path).await?;
    let msg = resp["message"].as_str().unwrap_or("resumed");
    print_success(&format!("Agent {id}: {msg}"));
    Ok(())
}

pub async fn boundaries(state: &AppState, id: Uuid, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/agents/{}/boundaries", client.org_id(), id);
    let resp: serde_json::Value = client.get(&path).await?;

    if resp.get("message").is_some() {
        // No boundaries configured
        println!("No boundaries configured for agent {id}");
    } else {
        match fmt {
            OutputFormat::Json | OutputFormat::Plain => {
                let json = serde_json::to_string_pretty(&resp)?;
                println!("{json}");
            }
            OutputFormat::Table => {
                let json = serde_json::to_string_pretty(&resp)?;
                println!("{json}");
            }
        }
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<()> {
    if !SCOPE_RE.is_match(scope) {
        anyhow::bail!(
            "Invalid scope format: {scope:?}. Must match pattern category:subcategory:action (lowercase, e.g. data:pii:query)"
        );
    }
    Ok(())
}

pub async fn scopes(
    state: &AppState,
    id: Uuid,
    set: Option<&str>,
    add: Option<&str>,
    remove: Option<&str>,
) -> Result<()> {
    let client = state.api_client();
    let agent_path = format!("/v1/orgs/{}/agents/{}", client.org_id(), id);

    // Fetch agent to verify it exists and get current scopes
    let agent: serde_json::Value = client.get(&agent_path).await?;
    let current_scopes: Vec<String> = agent["allowedScopes"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if let Some(set_val) = set {
        // --set: replace all scopes
        let scopes: Vec<String> = if set_val.is_empty() {
            vec![]
        } else {
            set_val.split(',').map(|s| s.trim().to_string()).collect()
        };
        for s in &scopes {
            validate_scope(s)?;
        }
        let body = serde_json::json!({ "allowedScopes": scopes });
        let _resp: serde_json::Value = client.patch(&agent_path, &body).await?;
        print_success(&format!("Scopes set for agent {id}: {}", scopes.join(", ")));
    } else if let Some(add_val) = add {
        // --add: append a scope
        let scope = add_val.trim().to_string();
        validate_scope(&scope)?;
        if current_scopes.contains(&scope) {
            println!("Scope {scope:?} already present on agent {id}");
        } else {
            let mut new_scopes = current_scopes;
            new_scopes.push(scope.clone());
            let body = serde_json::json!({ "allowedScopes": new_scopes });
            let _resp: serde_json::Value = client.patch(&agent_path, &body).await?;
            print_success(&format!("Scope {scope:?} added to agent {id}"));
        }
    } else if let Some(remove_val) = remove {
        // --remove: remove a scope
        let scope = remove_val.trim().to_string();
        validate_scope(&scope)?;
        let before_len = current_scopes.len();
        let new_scopes: Vec<String> = current_scopes.into_iter().filter(|s| s != &scope).collect();
        if new_scopes.len() == before_len {
            println!("Scope {scope:?} not found on agent {id}");
        } else {
            let body = serde_json::json!({ "allowedScopes": new_scopes });
            let _resp: serde_json::Value = client.patch(&agent_path, &body).await?;
            print_success(&format!("Scope {scope:?} removed from agent {id}"));
        }
    } else {
        // No flags: list current scopes
        if current_scopes.is_empty() {
            println!("No scopes configured for agent {id}");
        } else {
            println!("Scopes for agent {id}:");
            for s in &current_scopes {
                println!("  {s}");
            }
        }
    }

    Ok(())
}

// ── Delegation (A2A) ────────────────────────────────────

pub async fn delegation_graph(state: &AppState, org_id: Uuid, agent: Option<Uuid>, fmt: OutputFormat) -> Result<()> {
    let client = state.api_client();
    let path = match agent {
        Some(id) => format!("/v1/orgs/{}/delegation/relationships/{}", org_id, id),
        None => format!("/v1/orgs/{}/delegation/graph", org_id),
    };
    let resp: serde_json::Value = client.get(&path).await?;

    let edges = resp.get("edges").and_then(|v| v.as_array())
        .or_else(|| resp.as_array());

    match fmt {
        OutputFormat::Json | OutputFormat::Plain => {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        OutputFormat::Table => {
            if let Some(enforcement) = resp.get("enforcement_mode") {
                let mode = if enforcement.as_bool().unwrap_or(false) { "ENFORCEMENT" } else { "LEARNING" };
                println!("Mode: {mode}\n");
            }
            if let Some(arr) = edges {
                if arr.is_empty() {
                    println!("No delegation relationships found.");
                } else {
                    println!("{:<38} {:<38} {:<12} {:<10} {:<20} {:<6}",
                        "PARENT", "CHILD", "CONFIDENCE", "STATUS", "TOOLS", "COUNT");
                    println!("{}", "-".repeat(126));
                    for rel in arr {
                        let tools = rel["allowed_tools"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
                            .unwrap_or_else(|| "*".to_string());
                        let tools_display = if tools.is_empty() { "*" } else { &tools };
                        println!("{:<38} {:<38} {:<12} {:<10} {:<20} {:<6}",
                            rel["parent_agent_id"].as_str().unwrap_or("-"),
                            rel["child_agent_id"].as_str().unwrap_or("-"),
                            rel["confidence"].as_str().unwrap_or("-"),
                            rel["status"].as_str().unwrap_or("-"),
                            tools_display,
                            rel["observation_count"].as_u64().unwrap_or(0),
                        );
                    }
                }
            } else {
                println!("No delegation data.");
            }
        }
    }
    Ok(())
}

pub async fn delegation_link(
    state: &AppState,
    org_id: Uuid,
    parent: Uuid,
    child: Uuid,
    tools: Option<&str>,
    max_depth: u32,
) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/delegation/link", org_id);
    let allowed_tools: Vec<&str> = tools
        .map(|t| t.split(',').map(|s| s.trim()).collect())
        .unwrap_or_default();
    let body = serde_json::json!({
        "parent_agent_id": parent,
        "child_agent_id": child,
        "allowed_tools": allowed_tools,
        "max_delegation_depth": max_depth,
        "confidence": "declared",
        "status": "approved",
    });
    let _resp: serde_json::Value = client.post(&path, &body).await?;
    let tools_display = tools.unwrap_or("*");
    print_success(&format!("Linked {parent} → {child} (tools: {tools_display}, max_depth: {max_depth})"));
    Ok(())
}

pub async fn delegation_unlink(state: &AppState, org_id: Uuid, parent: Uuid, child: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/delegation/unlink", org_id);
    let body = serde_json::json!({ "parent_agent_id": parent, "child_agent_id": child });
    let _resp: serde_json::Value = client.post(&path, &body).await?;
    print_success(&format!("Unlinked {parent} → {child}"));
    Ok(())
}

pub async fn delegation_approve(state: &AppState, org_id: Uuid, parent: Uuid, child: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/delegation/approve", org_id);
    let body = serde_json::json!({ "parent_agent_id": parent, "child_agent_id": child });
    let _resp: serde_json::Value = client.post(&path, &body).await?;
    print_success(&format!("Approved: {parent} → {child}"));
    Ok(())
}

pub async fn delegation_lock_graph(state: &AppState, org_id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/delegation/lock-graph", org_id);
    let resp: serde_json::Value = client.post(&path, &serde_json::json!({})).await?;
    let count = resp.get("approved_count").and_then(|v| v.as_u64()).unwrap_or(0);
    print_success(&format!("Graph locked. {count} relationships approved. New delegations will be blocked."));
    Ok(())
}

pub async fn delegation_unlock_graph(state: &AppState, org_id: Uuid) -> Result<()> {
    let client = state.api_client();
    let path = format!("/v1/orgs/{}/delegation/unlock-graph", org_id);
    let _resp: serde_json::Value = client.post(&path, &serde_json::json!({})).await?;
    print_success("Graph unlocked. Learning mode active.");
    Ok(())
}
