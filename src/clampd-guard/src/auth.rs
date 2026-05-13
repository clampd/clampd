/// JWT creation and caching for Clampd gateway authentication.
///
/// Reuses the same HMAC-SHA256 pattern as the TypeScript/Python/Go SDKs.
/// `ags_` prefix secrets get SHA-256 hashed before HMAC (matches server-side credential_hash).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

fn b64url(data: &[u8]) -> String {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(table[((triple >> 18) & 0x3F) as usize] as char);
        result.push(table[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(table[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(table[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }
    result
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Create a JWT with HMAC-SHA256 signing.
pub fn make_agent_jwt(agent_id: &str, secret: &str, ttl_seconds: u64) -> anyhow::Result<String> {
    if secret.is_empty() {
        anyhow::bail!("No signing secret available");
    }

    // Derive signing key: ags_ prefix → SHA-256 hash
    let signing_key = if secret.starts_with("ags_") {
        use sha2::Digest;
        let hash = Sha256::digest(secret.as_bytes());
        hex::encode(hash)
    } else {
        secret.to_string()
    };

    let now = now_unix();
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let payload = format!(
        r#"{{"sub":"{}","iss":"clampd-guard","iat":{},"exp":{}}}"#,
        agent_id,
        now,
        now + ttl_seconds
    );

    let header_b64 = b64url(header.as_bytes());
    let payload_b64 = b64url(payload.as_bytes());
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
    mac.update(signing_input.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = b64url(&sig);

    Ok(format!("{}.{}", signing_input, sig_b64))
}

// ── JWT Cache ────────────────────────────────────────────

struct CachedJwt {
    token: String,
    exp: u64,
}

static JWT_CACHE: Mutex<Option<CachedJwt>> = Mutex::new(None);

/// Get a JWT, using in-process cache if still valid.
pub fn get_cached_jwt(agent_id: &str, secret: &str) -> anyhow::Result<String> {
    let now = now_unix();
    let ttl: u64 = 3600;

    if let Ok(guard) = JWT_CACHE.lock() {
        if let Some(ref cached) = *guard {
            if cached.exp > now + 60 {
                return Ok(cached.token.clone());
            }
        }
    }

    let token = make_agent_jwt(agent_id, secret, ttl)?;

    if let Ok(mut guard) = JWT_CACHE.lock() {
        *guard = Some(CachedJwt {
            token: token.clone(),
            exp: now + ttl,
        });
    }

    Ok(token)
}

/// Read employee token from ~/.clampd/token.json if it exists and is not expired.
pub fn load_employee_token() -> Option<String> {
    let path = dirs::home_dir()?.join(".clampd").join("token.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;

    let expires_at = parsed.get("expires_at")?.as_u64()?;
    if now_unix() + 60 >= expires_at {
        return None; // expired
    }

    parsed.get("access_token")?.as_str().map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_has_three_parts() {
        let jwt = make_agent_jwt("test-agent", "test-secret", 3600).unwrap();
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn jwt_fails_without_secret() {
        assert!(make_agent_jwt("test-agent", "", 3600).is_err());
    }

    #[test]
    fn ags_prefix_produces_different_signature() {
        let jwt1 = make_agent_jwt("agent", "ags_test_key", 3600).unwrap();
        let jwt2 = make_agent_jwt("agent", "plain_key", 3600).unwrap();
        assert_ne!(jwt1, jwt2);
    }

    #[test]
    fn cache_returns_same_token() {
        let t1 = get_cached_jwt("cache-agent", "cache-secret").unwrap();
        let t2 = get_cached_jwt("cache-agent", "cache-secret").unwrap();
        assert_eq!(t1, t2);
    }
}
