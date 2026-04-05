use anyhow::{Context, Result};
use uuid::Uuid;
use sha2::{Digest, Sha256};
use crate::output::OutputFormat;
use crate::state::AppState;

/// Default path for the activation file.
const DEFAULT_ACTIVATION_PATH: &str = "/var/lib/clampd/activation.json";

/// Return the activation file path from env or default.
fn activation_path() -> String {
    std::env::var("CLAMPD_ACTIVATION_PATH")
        .unwrap_or_else(|_| DEFAULT_ACTIVATION_PATH.to_string())
}

/// Ensure the parent directory of the activation file exists.
fn ensure_activation_dir() -> Result<()> {
    let path = activation_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }
    Ok(())
}

// ── Fingerprint helpers (mirrors ag-common::fingerprint) ─────

struct MachineFingerprint {
    hash: String,
    machine_id: String,
    hostname: String,
}

fn get_machine_id() -> String {
    if let Ok(id) = std::env::var("CLAMPD_MACHINE_ID") {
        if !id.is_empty() {
            return id;
        }
    }
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "no-machine-id".to_string())
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn total_memory_gb() -> u64 {
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb / 1_048_576;
                    }
                }
            }
        }
    }
    0
}

/// Get the primary MAC address (first non-loopback, non-virtual interface).
fn get_mac_address() -> String {
    // Try /sys/class/net/*/address (Linux)
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut macs: Vec<(String, String)> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip loopback and common virtual interfaces
            if name == "lo" || name.starts_with("veth") || name.starts_with("docker")
                || name.starts_with("br-") || name.starts_with("virbr")
            {
                continue;
            }
            if let Ok(mac) = std::fs::read_to_string(entry.path().join("address")) {
                let mac = mac.trim().to_string();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    macs.push((name, mac));
                }
            }
        }
        // Sort by name for deterministic ordering (e.g. eth0 before wlan0)
        macs.sort_by(|a, b| a.0.cmp(&b.0));
        if let Some((_, mac)) = macs.first() {
            return mac.clone();
        }
    }
    // Windows: try ipconfig /all parsing via env (fallback)
    "no-mac".to_string()
}

/// Get the root disk serial/UUID (Linux: /sys/block/*/serial or lsblk).
fn get_disk_id() -> String {
    // Try DMI product UUID (most reliable, works on VMs too)
    if let Ok(id) = std::fs::read_to_string("/sys/class/dmi/id/product_uuid") {
        let id = id.trim().to_string();
        if !id.is_empty() && id != "Not Settable" {
            return id;
        }
    }
    // Try root disk serial via /sys/block/sda/serial or /sys/block/nvme0n1/serial
    for disk in &["sda", "nvme0n1", "vda", "xvda"] {
        let path = format!("/sys/block/{}/serial", disk);
        if let Ok(serial) = std::fs::read_to_string(&path) {
            let serial = serial.trim().to_string();
            if !serial.is_empty() {
                return serial;
            }
        }
    }
    // Fallback: root filesystem UUID
    if let Ok(output) = std::process::Command::new("findmnt")
        .args(["-no", "UUID", "/"])
        .output()
    {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() {
            return uuid;
        }
    }
    "no-disk-id".to_string()
}

fn generate_fingerprint() -> MachineFingerprint {
    let machine_id = get_machine_id();
    let hostname = get_hostname();
    let cpus = num_cpus().to_string();
    let mem_gb = total_memory_gb().to_string();
    let mac = get_mac_address();
    let disk_id = get_disk_id();

    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"|");
    hasher.update(hostname.as_bytes());
    hasher.update(b"|");
    hasher.update(cpus.as_bytes());
    hasher.update(b"|");
    hasher.update(mem_gb.as_bytes());
    hasher.update(b"|");
    hasher.update(mac.as_bytes());
    hasher.update(b"|");
    hasher.update(disk_id.as_bytes());

    let hash = format!("{:x}", hasher.finalize());

    MachineFingerprint {
        hash,
        machine_id,
        hostname,
    }
}

// ── Installation ID ──────────────────────────────────────────

fn installation_id_path() -> String {
    let act_path = activation_path();
    let parent = std::path::Path::new(&act_path)
        .parent()
        .unwrap_or(std::path::Path::new("/var/lib/clampd"));
    parent.join("installation_id").to_string_lossy().to_string()
}

fn get_or_create_installation_id() -> Result<String> {
    let path = installation_id_path();
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let id = Uuid::new_v4().to_string();
    ensure_activation_dir()?;
    std::fs::write(&path, &id)
        .with_context(|| format!("Failed to write installation ID to {path}"))?;
    Ok(id)
}

// ── Existing commands ────────────────────────────────────────

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

// ── New activation commands ──────────────────────────────────

pub async fn fingerprint() -> Result<()> {
    let fp = generate_fingerprint();
    let installation_id = get_or_create_installation_id()?;

    println!("Machine Fingerprint:");
    println!("  Hash:            {}", fp.hash);
    println!("  Installation ID: {}", installation_id);
    println!("  Hostname:        {}", fp.hostname);
    println!();
    println!("For air-gapped activation, copy this to the license portal.");

    Ok(())
}

pub async fn activate_machine(license: &str, server: &str) -> Result<()> {
    let fp = generate_fingerprint();
    let installation_id = get_or_create_installation_id()?;

    // Hash the hostname for privacy
    let hostname_hash = {
        let mut h = Sha256::new();
        h.update(fp.hostname.as_bytes());
        format!("{:x}", h.finalize())
    };

    let body = serde_json::json!({
        "fingerprint_hash": fp.hash,
        "installation_id": installation_id,
        "hostname_hash": hostname_hash,
        "fingerprint_components": {
            "machine_id": fp.machine_id,
            "hostname": fp.hostname,
        }
    });

    let url = format!("{}/v1/activate", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", license))
        .json(&body)
        .send()
        .await
        .context("Failed to reach license service")?;

    let status_code = resp.status();
    if status_code == reqwest::StatusCode::CONFLICT {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "This license is already activated on a machine. \
             Deactivate first with: clampd license deactivate\n\
             Server response: {text}"
        );
    }

    if !status_code.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Activation failed (HTTP {status_code}): {text}");
    }

    let resp_body: serde_json::Value = resp.json().await
        .context("Failed to parse activation response")?;

    let activation = serde_json::json!({
        "license_jwt": license,
        "activation_token": resp_body["activation_token"].as_str().unwrap_or(""),
        "activated_at": resp_body["activated_at"].as_str().unwrap_or(""),
        "installation_id": installation_id,
    });

    ensure_activation_dir()?;
    let act_path = activation_path();
    let json = serde_json::to_string_pretty(&activation)?;
    std::fs::write(&act_path, &json)
        .with_context(|| format!("Failed to write activation file to {act_path}"))?;

    println!("License activated successfully!");
    println!("  Activation saved to: {act_path}");
    if let Some(at) = resp_body["activated_at"].as_str() {
        println!("  Activated at:        {at}");
    }

    Ok(())
}

pub async fn activate_offline(activation_token: &str, license: &str) -> Result<()> {
    let installation_id = get_or_create_installation_id()?;
    let now = chrono::Utc::now().to_rfc3339();

    let activation = serde_json::json!({
        "license_jwt": license,
        "activation_token": activation_token,
        "activated_at": now,
        "installation_id": installation_id,
    });

    ensure_activation_dir()?;
    let act_path = activation_path();
    let json = serde_json::to_string_pretty(&activation)?;
    std::fs::write(&act_path, &json)
        .with_context(|| format!("Failed to write activation file to {act_path}"))?;

    println!("License activated offline successfully!");
    println!("  Activation saved to: {act_path}");
    println!("  Installation ID:     {installation_id}");

    Ok(())
}

pub async fn deactivate(server: &str) -> Result<()> {
    let act_path = activation_path();
    let content = std::fs::read_to_string(&act_path)
        .with_context(|| format!("No activation file found at {act_path}. Nothing to deactivate."))?;

    let activation: serde_json::Value = serde_json::from_str(&content)
        .context("Failed to parse activation file")?;

    let license_jwt = activation["license_jwt"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Activation file missing license_jwt field"))?;
    let installation_id = activation["installation_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Activation file missing installation_id field"))?;

    let fp = generate_fingerprint();

    let body = serde_json::json!({
        "installation_id": installation_id,
        "fingerprint_hash": fp.hash,
    });

    let url = format!("{}/v1/deactivate", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", license_jwt))
        .json(&body)
        .send()
        .await
        .context("Failed to reach license service")?;

    let status_code = resp.status();
    if !status_code.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Deactivation failed (HTTP {status_code}): {text}");
    }

    std::fs::remove_file(&act_path)
        .with_context(|| format!("Failed to remove activation file at {act_path}"))?;

    println!("License deactivated successfully.");
    println!("  Removed: {act_path}");

    Ok(())
}

pub async fn activation_status() -> Result<()> {
    // Check license key
    let license_key = std::env::var("CLAMPD_LICENSE_KEY").ok().filter(|s| !s.is_empty());
    println!("License Activation Status:");
    println!();

    if let Some(ref key) = license_key {
        println!("  CLAMPD_LICENSE_KEY: set");
        // Decode JWT claims for display
        if let Some(claims) = decode_jwt_claims(key) {
            if let Some(tier) = claims["tier"].as_str() {
                println!("  License Tier:      {tier}");
            }
            if let Some(org) = claims["org_id"].as_str().or(claims["sub"].as_str()) {
                println!("  Org ID:            {org}");
            }
            if let Some(exp) = claims["exp"].as_i64() {
                let dt = chrono::DateTime::from_timestamp(exp, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| exp.to_string());
                println!("  Expires:           {dt}");
            }
        }
    } else {
        println!("  CLAMPD_LICENSE_KEY: not set");
    }

    println!();

    // Check activation file
    let act_path = activation_path();
    match std::fs::read_to_string(&act_path) {
        Ok(content) => {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(activation) => {
                    println!("  Activation File:   {act_path}");
                    if let Some(at) = activation["activated_at"].as_str() {
                        println!("  Activated At:      {at}");
                    }
                    if let Some(iid) = activation["installation_id"].as_str() {
                        println!("  Installation ID:   {iid}");
                    }
                    if activation["activation_token"].as_str().is_some() {
                        println!("  Activation Token:  present");
                    }

                    // Decode the stored license JWT for tier/org info
                    if let Some(jwt) = activation["license_jwt"].as_str() {
                        if let Some(claims) = decode_jwt_claims(jwt) {
                            if let Some(tier) = claims["tier"].as_str() {
                                println!("  License Tier:      {tier}");
                            }
                            if let Some(org) = claims["org_id"].as_str().or(claims["sub"].as_str()) {
                                println!("  Org ID:            {org}");
                            }
                            if let Some(exp) = claims["exp"].as_i64() {
                                let dt = chrono::DateTime::from_timestamp(exp, 0)
                                    .map(|d| d.to_rfc3339())
                                    .unwrap_or_else(|| exp.to_string());
                                println!("  Expires:           {dt}");
                            }
                        }
                    }

                    // Check fingerprint match
                    let fp = generate_fingerprint();
                    let installation_id = get_or_create_installation_id().ok();
                    let stored_iid = activation["installation_id"].as_str();
                    let fp_match = match (installation_id.as_deref(), stored_iid) {
                        (Some(current), Some(stored)) => current == stored,
                        _ => false,
                    };
                    println!("  Fingerprint Match: {}", if fp_match { "yes" } else { "no" });
                    println!("  Current FP Hash:   {}", fp.hash);
                }
                Err(e) => {
                    println!("  Activation File:   {act_path} (corrupt: {e})");
                }
            }
        }
        Err(_) => {
            println!("  Activation:        Not activated");
            println!("  Expected Path:     {act_path}");
        }
    }

    Ok(())
}

/// Decode JWT payload claims without verifying signature (display only).
fn decode_jwt_claims(token: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = engine
        .decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[1]))
        .ok()?;
    serde_json::from_slice(&payload).ok()
}
