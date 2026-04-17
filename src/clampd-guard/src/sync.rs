//! Tool sync - discovers available tools from Claude Code / Cursor configs
//! and MCP servers, then sends a ping request per tool through /v1/proxy
//! to trigger the existing tool descriptor discovery pipeline.
//!
//! MCP discovery: starts each configured MCP server, sends `tools/list`
//! JSON-RPC over stdio, parses the tool catalog, then shuts down.
//!
//! Flow: clampd-guard sync → discover tools → /v1/proxy (ping per tool)
//!       → shadow event → ag-control → dashboard → category assignment

use crate::auth;
use crate::config::GuardConfig;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Claude Code built-in tools.
const CLAUDE_CODE_TOOLS: &[(&str, &str)] = &[
    ("Bash", "Execute shell commands"),
    ("Read", "Read file contents"),
    ("Write", "Write file contents"),
    ("Edit", "Edit file contents"),
    ("Glob", "Search for files by pattern"),
    ("Grep", "Search file contents"),
    ("WebFetch", "Fetch URL content"),
    ("WebSearch", "Search the web"),
    ("Agent", "Spawn sub-agent"),
    ("NotebookEdit", "Edit Jupyter notebook"),
];

/// Cursor built-in tools.
const CURSOR_TOOLS: &[(&str, &str)] = &[
    ("terminal", "Execute shell commands"),
    ("readFile", "Read file contents"),
    ("writeFile", "Write file contents"),
    ("editFile", "Edit file contents"),
    ("listFiles", "List directory contents"),
    ("searchFiles", "Search file contents"),
];

fn descriptor_hash(name: &str, description: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"|");
    hasher.update(description.as_bytes());
    hasher.update(b"|");
    format!("{:x}", hasher.finalize())
}

/// MCP server config from Claude Code / Cursor settings.
#[derive(Debug, serde::Deserialize)]
struct McpServerConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

/// Query a single MCP server for its tool list via stdio JSON-RPC.
async fn query_mcp_tools(server_name: &str, config: &McpServerConfig) -> Vec<(String, String)> {
    let mut cmd = tokio::process::Command::new(&config.command);
    cmd.args(&config.args)
        .envs(&config.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  [{}] Failed to start: {}", server_name, e);
            return vec![];
        }
    };

    let stdin = child.stdin.as_mut().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Send MCP initialize request
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "clampd-guard", "version": "0.1.0" }
        }
    });
    let init_msg = format!("{}\n", serde_json::to_string(&init_req).unwrap());
    if stdin.write_all(init_msg.as_bytes()).await.is_err() {
        let _ = child.kill().await;
        return vec![];
    }

    // Read initialize response (with timeout)
    let mut line = String::new();
    let read_result = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await;
    if read_result.is_err() || read_result.unwrap().is_err() {
        eprintln!("  [{}] Timeout waiting for initialize response", server_name);
        let _ = child.kill().await;
        return vec![];
    }

    // Send initialized notification
    let initialized = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let notif_msg = format!("{}\n", serde_json::to_string(&initialized).unwrap());
    let _ = stdin.write_all(notif_msg.as_bytes()).await;

    // Send tools/list request
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let tools_msg = format!("{}\n", serde_json::to_string(&tools_req).unwrap());
    if stdin.write_all(tools_msg.as_bytes()).await.is_err() {
        let _ = child.kill().await;
        return vec![];
    }

    // Read tools/list response
    let mut tools_line = String::new();
    let read_result = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut tools_line)).await;
    let _ = child.kill().await;

    if read_result.is_err() || read_result.unwrap().is_err() {
        eprintln!("  [{}] Timeout waiting for tools/list response", server_name);
        return vec![];
    }

    // Parse the response
    let response: serde_json::Value = match serde_json::from_str(tools_line.trim()) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("  [{}] Invalid JSON response", server_name);
            return vec![];
        }
    };

    let tools = response["result"]["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    tools.iter().filter_map(|t| {
        let name = t["name"].as_str()?;
        let desc = t["description"].as_str().unwrap_or("");
        // Use the Claude Code MCP naming convention: mcp__server__tool
        let full_name = format!("mcp__{}_{}__{}", "claude_ai", server_name, name);
        Some((full_name, desc.to_string()))
    }).collect()
}

/// Discover MCP servers from Claude Code / Cursor config and query each for tools.
async fn discover_mcp_tools() -> Vec<(String, String)> {
    let home = dirs::home_dir().unwrap_or_default();
    let mut servers: HashMap<String, McpServerConfig> = HashMap::new();

    // Check Claude Code settings
    let settings_paths = vec![
        home.join(".claude").join("settings.json"),
        home.join(".claude").join("settings.local.json"),
    ];

    for path in &settings_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(mcp) = json.get("mcpServers").and_then(|s| s.as_object()) {
                    for (name, config) in mcp {
                        if let Ok(cfg) = serde_json::from_value::<McpServerConfig>(config.clone()) {
                            servers.entry(name.clone()).or_insert(cfg);
                        }
                    }
                }
            }
        }
    }

    // Check Cursor MCP config
    let cursor_mcp = home.join(".cursor").join("mcp.json");
    if let Ok(content) = std::fs::read_to_string(&cursor_mcp) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(mcp) = json.get("mcpServers").and_then(|s| s.as_object()) {
                for (name, config) in mcp {
                    if let Ok(cfg) = serde_json::from_value::<McpServerConfig>(config.clone()) {
                        servers.entry(name.clone()).or_insert(cfg);
                    }
                }
            }
        }
    }

    if servers.is_empty() {
        return vec![];
    }

    eprintln!("[clampd] Querying {} MCP servers for tool lists...", servers.len());

    let mut all_tools = Vec::new();
    for (name, config) in &servers {
        eprint!("  [{}] ", name);
        let tools = query_mcp_tools(name, config).await;
        eprintln!("{} tools", tools.len());
        all_tools.extend(tools);
    }

    all_tools
}

/// Run the sync command.
pub async fn run(target: &str) {
    let config = match GuardConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[clampd] No config found: {}. Run `clampd-guard setup` first.", e);
            std::process::exit(1);
        }
    };

    // Collect built-in tools based on target
    let mut tools: Vec<(String, String)> = Vec::new();

    match target {
        "claude-code" | "claude" | "cc" => {
            tools.extend(CLAUDE_CODE_TOOLS.iter().map(|(n, d)| (n.to_string(), d.to_string())));
        }
        "cursor" => {
            tools.extend(CURSOR_TOOLS.iter().map(|(n, d)| (n.to_string(), d.to_string())));
        }
        "all" => {
            tools.extend(CLAUDE_CODE_TOOLS.iter().map(|(n, d)| (n.to_string(), d.to_string())));
            tools.extend(CURSOR_TOOLS.iter().map(|(n, d)| (n.to_string(), d.to_string())));
        }
        _ => {
            eprintln!("[clampd] Unknown target '{}'. Use: claude-code, cursor, or all", target);
            std::process::exit(1);
        }
    }

    // Discover MCP tools by querying each configured server
    let mcp_tools = discover_mcp_tools().await;
    if !mcp_tools.is_empty() {
        eprintln!("[clampd] Discovered {} MCP tools total", mcp_tools.len());
        tools.extend(mcp_tools);
    }

    if tools.is_empty() {
        eprintln!("[clampd] No tools to sync.");
        return;
    }

    eprintln!("[clampd] Syncing {} tools to gateway...", tools.len());

    let bearer = auth::load_employee_token()
        .unwrap_or_else(|| {
            auth::get_cached_jwt(&config.agent_id, &config.secret)
                .unwrap_or_default()
        });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let endpoint = format!("{}/v1/proxy", config.gateway_url.trim_end_matches('/'));
    let mut synced = 0;
    let mut failed = 0;

    for (name, description) in &tools {
        let hash = descriptor_hash(name, description);
        let body = serde_json::json!({
            "tool": name,
            "params": { "_sync": true, "description": description },
            "target_url": "",
            "prompt_context": "scope:sync",
            "tool_descriptor_hash": hash,
        });

        match client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", bearer))
            .header("X-AG-Key", &config.api_key)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() || status.as_u16() == 403 {
                    // 403 = blocked by rules, but tool was still registered via shadow event
                    synced += 1;
                    eprint!(".");
                } else {
                    failed += 1;
                    eprint!("x");
                }
            }
            Err(_) => {
                failed += 1;
                eprint!("x");
            }
        }
    }

    eprintln!();
    eprintln!("[clampd] Synced: {} | Failed: {} | Total: {}", synced, failed, tools.len());
    eprintln!("[clampd] Tools will appear in the dashboard for category assignment.");

    if failed > 0 {
        std::process::exit(1);
    }
}
