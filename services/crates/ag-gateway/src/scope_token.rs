//! Scope token minting and verification.
//!
//! Scope tokens are Ed25519-signed proofs that a specific tool call was authorized.
//! Format: `base64url(json_payload).base64url(ed25519_signature)`
//!
//! The gateway mints tokens after an ALLOW decision. Tools verify them using
//! the public key from `GET /.well-known/jwks.json`.
//!
//! Extracted from proxy.rs for testability — pure crypto, no I/O.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Claims embedded in a scope token.
#[derive(Debug, Clone)]
pub struct ScopeTokenClaims {
    /// Agent ID (subject).
    pub sub: String,
    /// Granted scope string (e.g., "data:pii:query").
    pub scope: Option<String>,
    /// Tool name the scope was granted for.
    pub tool: String,
    /// SHA-256 binding of tool+params at grant time.
    pub binding: String,
    /// Expiry timestamp (Unix epoch seconds).
    pub exp: i64,
    /// Request ID linking back to the original proxy call.
    pub rid: String,
}

/// Inputs for minting a scope token.
pub struct MintInput<'a> {
    pub agent_id: &'a str,
    pub scope_granted: &'a str,
    pub tool_name: &'a str,
    pub params_hash: &'a str,
    pub request_id: &'a str,
    pub ttl_secs: i64,
    pub now: i64,
}

/// Mint a scope token: sign a JSON payload with Ed25519.
///
/// Returns the token string: `base64url(payload).base64url(signature)`.
pub fn mint(signing_key: &SigningKey, input: &MintInput) -> String {
    let binding = hex::encode(Sha256::digest(
        format!("{}{}", input.tool_name, input.params_hash).as_bytes(),
    ));
    let payload = serde_json::json!({
        "sub": input.agent_id,
        "scope": input.scope_granted,
        "tool": input.tool_name,
        "binding": binding,
        "exp": input.now + input.ttl_secs,
        "rid": input.request_id,
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let signature = signing_key.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("{}.{}", payload_b64, sig_b64)
}

/// Verify a scope token's Ed25519 signature and expiry.
///
/// Returns the decoded claims on success, or a reason string on failure.
pub fn verify(token: &str, verifying_key: &VerifyingKey, now: i64) -> Result<ScopeTokenClaims, String> {
    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err("malformed scope token: expected payload.signature".to_string());
    }

    let payload_b64 = parts[0];
    let sig_b64 = parts[1];

    // Decode and verify Ed25519 signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("signature decode error: {}", e))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("invalid signature format: {}", e))?;

    verifying_key
        .verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| "invalid Ed25519 signature".to_string())?;

    // Decode base64url payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("base64 decode error: {}", e))?;
    let payload_str =
        String::from_utf8(payload_bytes).map_err(|e| format!("utf8 error: {}", e))?;
    let claims: serde_json::Value =
        serde_json::from_str(&payload_str).map_err(|e| format!("json parse error: {}", e))?;

    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if now > exp {
        return Err(format!("token expired (exp={}, now={})", exp, now));
    }

    Ok(ScopeTokenClaims {
        sub: claims.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        scope: claims.get("scope").and_then(|v| v.as_str()).map(|s| s.to_string()),
        tool: claims.get("tool").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        binding: claims.get("binding").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        exp,
        rid: claims.get("rid").and_then(|v| v.as_str()).unwrap_or("").to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn default_mint_input() -> MintInput<'static> {
        MintInput {
            agent_id: "agent-123",
            scope_granted: "db:query:read",
            tool_name: "database.query",
            params_hash: "abc123def456",
            request_id: "req-001",
            ttl_secs: 300,
            now: 1_700_000_000,
        }
    }

    // ── Mint + Verify roundtrip ──

    #[test]
    fn positive_mint_verify_roundtrip() {
        let (sk, vk) = test_keypair();
        let input = default_mint_input();
        let token = mint(&sk, &input);
        let claims = verify(&token, &vk, input.now).unwrap();

        assert_eq!(claims.sub, "agent-123");
        assert_eq!(claims.scope.as_deref(), Some("db:query:read"));
        assert_eq!(claims.tool, "database.query");
        assert_eq!(claims.rid, "req-001");
        assert_eq!(claims.exp, 1_700_000_300); // now + 300s TTL
        assert!(!claims.binding.is_empty(), "Binding hash should be non-empty");
    }

    // ── Expiry ──

    #[test]
    fn negative_expired_token_rejected() {
        let (sk, vk) = test_keypair();
        let input = default_mint_input();
        let token = mint(&sk, &input);
        // Verify 600 seconds later (token TTL is 300s)
        let result = verify(&token, &vk, input.now + 600);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn positive_token_valid_just_before_expiry() {
        let (sk, vk) = test_keypair();
        let input = default_mint_input();
        let token = mint(&sk, &input);
        // Verify at exactly exp time (300s later) — should still be valid (exp == now, not now > exp)
        let result = verify(&token, &vk, input.now + 300);
        assert!(result.is_ok(), "Token should be valid at exactly exp time");
    }

    // ── Tampered payload ──

    #[test]
    fn negative_tampered_payload_rejected() {
        let (sk, vk) = test_keypair();
        let input = default_mint_input();
        let token = mint(&sk, &input);

        // Tamper: replace first char of payload
        let mut chars: Vec<char> = token.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();

        let result = verify(&tampered, &vk, input.now);
        assert!(result.is_err(), "Tampered payload must be rejected");
    }

    // ── Wrong key ──

    #[test]
    fn negative_wrong_key_rejected() {
        let (sk, _) = test_keypair();
        let (_, wrong_vk) = test_keypair(); // different key pair
        let input = default_mint_input();
        let token = mint(&sk, &input);

        let result = verify(&token, &wrong_vk, input.now);
        assert!(result.is_err(), "Wrong verifying key must reject");
        assert!(result.unwrap_err().contains("signature"));
    }

    // ── Malformed token ──

    #[test]
    fn negative_missing_dot_separator() {
        let (_, vk) = test_keypair();
        let result = verify("no-dot-here", &vk, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("malformed"));
    }

    #[test]
    fn negative_empty_token() {
        let (_, vk) = test_keypair();
        let result = verify("", &vk, 0);
        assert!(result.is_err());
    }

    // ── Binding hash ──

    #[test]
    fn binding_changes_with_params() {
        let (sk, vk) = test_keypair();
        let input1 = default_mint_input();
        let mut input2 = default_mint_input();
        input2.params_hash = "different_hash";

        let token1 = mint(&sk, &input1);
        let token2 = mint(&sk, &input2);

        let claims1 = verify(&token1, &vk, input1.now).unwrap();
        let claims2 = verify(&token2, &vk, input2.now).unwrap();

        assert_ne!(claims1.binding, claims2.binding,
            "Different params_hash must produce different binding");
    }

    #[test]
    fn binding_is_sha256_hex() {
        let (sk, vk) = test_keypair();
        let token = mint(&sk, &default_mint_input());
        let claims = verify(&token, &vk, 1_700_000_000).unwrap();
        assert_eq!(claims.binding.len(), 64, "Binding must be 64-char hex (SHA-256)");
        assert!(claims.binding.chars().all(|c| c.is_ascii_hexdigit()),
            "Binding must be hex: {}", claims.binding);
    }
}
