//! Per-agent Ed25519 identity + gateway enrollment for clampd-guard.
//!
//! Mirrors the SDK's enrollment: generate an Ed25519 keypair on first run,
//! persist it under `~/.clampd` (0600), enroll the public key with the gateway
//! (which assigns the agent UUID), and cache the UUID alongside the key so
//! subsequent hook invocations reuse the identity. The private key never leaves
//! the machine; no shared secret.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

pub struct Identity {
    pub signing_key: SigningKey,
    pub agent_id: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    seed_hex: String,
    agent_id: Option<String>,
}

fn slot(api_key: &str, name: &str) -> PathBuf {
    let org = hex::encode(Sha256::digest(api_key.as_bytes()));
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".clampd")
        .join("agents")
        .join(&org[..16])
        .join(format!("{}.json", name.replace('/', "_")))
}

fn load_or_create(api_key: &str, name: &str) -> Result<(SigningKey, Option<String>)> {
    let path = slot(api_key, name);
    if let Ok(content) = std::fs::read_to_string(&path) {
        if let Ok(stored) = serde_json::from_str::<StoredIdentity>(&content) {
            let seed = hex::decode(&stored.seed_hex).context("bad stored key")?;
            let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| anyhow!("bad seed length"))?;
            return Ok((SigningKey::from_bytes(&seed), stored.agent_id));
        }
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    save(&path, &key, None)?;
    Ok((key, None))
}

fn save(path: &PathBuf, key: &SigningKey, agent_id: Option<&str>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let stored = StoredIdentity {
        seed_hex: hex::encode(key.to_bytes()),
        agent_id: agent_id.map(String::from),
    };
    std::fs::write(path, serde_json::to_string(&stored)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn public_key_b64(key: &SigningKey) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())
}

fn gather_attestation() -> (String, String) {
    // A re-key token takes precedence: it re-binds a new keypair to an existing
    // agent (used after losing the local key). Minted in the dashboard.
    if let Ok(tok) = std::env::var("CLAMPD_REBIND_TOKEN") {
        if !tok.is_empty() {
            return ("rekey_token".into(), tok);
        }
    }
    // An explicit, admin-minted enroll token (org-wide) is the next choice.
    if let Ok(tok) = std::env::var("CLAMPD_ENROLL_TOKEN") {
        if !tok.is_empty() {
            return ("enroll_token".into(), tok);
        }
    }
    // Workload OIDC attestation: a verified, STABLE per-workload identity
    // (k8s ServiceAccount / OIDC `sub`). The gateway verifies the projected
    // token against the org's trusted issuers and derives the agent's stable
    // attestation id — enabling idempotent auto-recovery. Preferred.
    let tok = workload_token();
    if !tok.is_empty() {
        return ("oidc".into(), tok);
    }
    ("none".into(), String::new())
}

/// Locate a workload OIDC/k8s ServiceAccount token for attestation. Order:
/// explicit raw token, explicit file, the recommended clampd-audience
/// projected token, then the default k8s ServiceAccount token as a fallback.
/// Returns an empty string when none is present.
fn workload_token() -> String {
    if let Ok(tok) = std::env::var("CLAMPD_WORKLOAD_TOKEN") {
        let tok = tok.trim().to_string();
        if !tok.is_empty() {
            return tok;
        }
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("CLAMPD_WORKLOAD_TOKEN_FILE") {
        if !path.is_empty() {
            candidates.push(PathBuf::from(path));
        }
    }
    candidates.push(PathBuf::from("/var/run/secrets/clampd.io/token"));
    candidates.push(PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token"));
    for path in candidates {
        if let Ok(s) = std::fs::read_to_string(&path) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}

/// Return an enrolled identity, enrolling with the gateway if the cached
/// identity has no assigned agent UUID yet. When `CLAMPD_REBIND_TOKEN` is set,
/// a re-key is forced even if a cached identity exists: a fresh keypair is
/// generated and bound to the existing agent (same UUID), mirroring the SDK.
pub async fn get_identity(gateway_url: &str, api_key: &str, name: &str) -> Result<Identity> {
    let rebinding = std::env::var("CLAMPD_REBIND_TOKEN")
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    let key = if rebinding {
        // Force a fresh keypair — the old private key is gone or being rotated.
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        save(&slot(api_key, name), &key, None)?;
        key
    } else {
        let (key, cached_agent_id) = load_or_create(api_key, name)?;
        if let Some(agent_id) = cached_agent_id {
            return Ok(Identity { signing_key: key, agent_id });
        }
        key
    };

    let (att_type, attestation) = gather_attestation();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let resp = client
        .post(format!("{}/v1/enroll", gateway_url.trim_end_matches('/')))
        .header("X-AG-Key", api_key)
        .json(&serde_json::json!({
            "public_key": public_key_b64(&key),
            "attestation_type": att_type,
            "attestation": attestation,
            "name": name,
        }))
        .send()
        .await
        .context("enrollment request failed")?;

    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("enrollment rejected: {} {}", code, body));
    }
    let agent_id = resp
        .json::<serde_json::Value>()
        .await?
        .get("agent_id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| anyhow!("enrollment response missing agent_id"))?;

    save(&slot(api_key, name), &key, Some(&agent_id))?;
    Ok(Identity { signing_key: key, agent_id })
}
