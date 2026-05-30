//! EdDSA JWT signing for Clampd gateway authentication.
//!
//! The guard signs JWTs with its enrolled Ed25519 private key; the gateway
//! verifies against the registered public key. No shared secret.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use std::time::{SystemTime, UNIX_EPOCH};

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Create an EdDSA-signed JWT with `sub` = *agent_id*.
pub fn make_agent_jwt(agent_id: &str, signing_key: &SigningKey, ttl_seconds: u64) -> anyhow::Result<String> {
    let now = now_unix();
    let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
    let payload = format!(
        r#"{{"sub":"{}","iss":"clampd-sdk","aud":"ag-gateway","iat":{},"exp":{}}}"#,
        agent_id,
        now,
        now + ttl_seconds
    );
    let signing_input = format!("{}.{}", b64url(header.as_bytes()), b64url(payload.as_bytes()));
    let sig = signing_key.sign(signing_input.as_bytes());
    Ok(format!("{}.{}", signing_input, b64url(&sig.to_bytes())))
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

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn jwt_has_three_parts() {
        let jwt = make_agent_jwt("test-agent", &test_key(), 3600).unwrap();
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn jwt_header_is_eddsa() {
        let jwt = make_agent_jwt("a", &test_key(), 3600).unwrap();
        let header_b64 = jwt.split('.').next().unwrap();
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .unwrap();
        assert!(String::from_utf8_lossy(&header).contains("EdDSA"));
    }

    #[test]
    fn signature_verifies_with_public_key() {
        use ed25519_dalek::Verifier;
        let key = test_key();
        let jwt = make_agent_jwt("agent-x", &key, 3600).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        assert!(key.verifying_key().verify(signing_input.as_bytes(), &sig).is_ok());
    }
}
