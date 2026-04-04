use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Ed25519 key manager for micro-token signing.
pub struct SigningKeyManager {
    kid: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SigningKeyManager {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let kid = format!("key-{}", chrono::Utc::now().format("%Y-%m"));
        Self {
            kid,
            signing_key,
            verifying_key,
        }
    }

    /// Construct from a 32-byte seed (deterministic, for key rotation via NATS).
    pub fn from_seed(seed: &[u8; 32], kid: String) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            kid,
            signing_key,
            verifying_key,
        }
    }

    /// Return the raw seed bytes (for backup / rotation handoff).
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn active_kid(&self) -> &str {
        &self.kid
    }

    /// Encrypt the seed bytes for safe storage in Redis.
    /// Uses SHA-256(encryption_key) as a 32-byte XOR mask.
    /// Returns hex-encoded encrypted seed.
    ///
    /// If no encryption key is provided (empty/absent), returns plaintext hex
    /// with a warning prefix "PLAIN:" so callers can detect unencrypted seeds.
    pub fn encrypt_seed_for_storage(&self, encryption_key: &str) -> String {
        let seed = self.seed_bytes();
        if encryption_key.is_empty() {
            return format!("PLAIN:{}", hex::encode(seed));
        }
        let mask = sha2::Sha256::digest(encryption_key.as_bytes());
        let encrypted: Vec<u8> = seed.iter().zip(mask.iter()).map(|(s, m)| s ^ m).collect();
        format!("ENC1:{}", hex::encode(encrypted))
    }

    /// Decrypt a seed from Redis storage. Handles both encrypted ("ENC1:...")
    /// and legacy plaintext ("PLAIN:..." or raw hex) formats.
    pub fn decrypt_seed_from_storage(stored: &str, encryption_key: &str) -> Result<[u8; 32], String> {
        let (prefix, hex_data) = if let Some(rest) = stored.strip_prefix("ENC1:") {
            ("ENC1", rest)
        } else if let Some(rest) = stored.strip_prefix("PLAIN:") {
            ("PLAIN", rest)
        } else {
            // Legacy format: raw hex, no prefix
            ("PLAIN", stored)
        };

        let raw_bytes = hex::decode(hex_data).map_err(|e| format!("hex decode: {}", e))?;
        if raw_bytes.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", raw_bytes.len()));
        }

        let seed = if prefix == "ENC1" && !encryption_key.is_empty() {
            let mask = sha2::Sha256::digest(encryption_key.as_bytes());
            let decrypted: Vec<u8> = raw_bytes.iter().zip(mask.iter()).map(|(s, m)| s ^ m).collect();
            decrypted
        } else {
            if prefix == "ENC1" {
                return Err("Seed is encrypted but AG_TOKEN_ENCRYPTION_KEY is not set".to_string());
            }
            raw_bytes
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed);
        Ok(arr)
    }

    /// Sign a micro-token payload and return a compact JWT.
    pub fn sign_token(&self, claims: &MicroTokenPayload) -> Result<String, String> {
        let header = JwtHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
            kid: self.kid.clone(),
        };

        let header_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).map_err(|e| e.to_string())?);
        let payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(claims).map_err(|e| e.to_string())?);

        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Verify a micro-token JWT signature.
    pub fn verify_token(&self, token: &str) -> Result<MicroTokenPayload, String> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".to_string());
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("Invalid signature: {}", e))?;

        use ed25519_dalek::Verifier;
        self.verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| format!("Signature verification failed: {}", e))?;

        let payload_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| format!("Invalid payload encoding: {}", e))?;

        serde_json::from_slice(&payload_json).map_err(|e| format!("Invalid payload: {}", e))
    }

    /// Return JWKS JSON for the public key.
    #[allow(dead_code)]
    pub fn jwks_json(&self) -> serde_json::Value {
        let pub_key_bytes = self.verifying_key.to_bytes();
        let x = URL_SAFE_NO_PAD.encode(pub_key_bytes);
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": self.kid,
                "x": x,
                "use": "sig",
                "alg": "EdDSA"
            }]
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroTokenPayload {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub scope: String,
    pub jti: String,
    #[serde(rename = "ag:tool_binding")]
    pub tool_binding: String,
    #[serde(rename = "ag:request_id", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "ag:session_id", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "ag:trust_level", skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let km = SigningKeyManager::generate();
        let claims = MicroTokenPayload {
            sub: "agent-123".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 30,
            scope: "db:read".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            tool_binding: "abc123".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };

        let token = km.sign_token(&claims).unwrap();
        let verified = km.verify_token(&token).unwrap();
        assert_eq!(verified.sub, "agent-123");
        assert_eq!(verified.scope, "db:read");
    }

    #[test]
    fn test_tampered_token_fails() {
        let km = SigningKeyManager::generate();
        let claims = MicroTokenPayload {
            sub: "agent-123".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 30,
            scope: "db:read".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            tool_binding: "abc123".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };

        let token = km.sign_token(&claims).unwrap();
        // Tamper by re-encoding the payload with different claims but keeping original signature
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut tampered_claims = claims.clone();
        tampered_claims.sub = "agent-999".to_string();
        let tampered_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&tampered_claims).unwrap());
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);
        assert!(km.verify_token(&tampered_token).is_err());
    }

    #[test]
    fn test_wrong_key_verification_fails() {
        let km1 = SigningKeyManager::generate();
        let km2 = SigningKeyManager::generate();
        let claims = MicroTokenPayload {
            sub: "agent-123".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 30,
            scope: "db:read".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            tool_binding: "abc".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };
        let token = km1.sign_token(&claims).unwrap();
        assert!(km2.verify_token(&token).is_err(), "Different key should reject");
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [42u8; 32];
        let km1 = SigningKeyManager::from_seed(&seed, "key-test".to_string());
        let km2 = SigningKeyManager::from_seed(&seed, "key-test".to_string());
        let claims = MicroTokenPayload {
            sub: "agent-1".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: 1700000000,
            scope: "db:read".to_string(),
            jti: "fixed-jti".to_string(),
            tool_binding: "bind".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };
        let token1 = km1.sign_token(&claims).unwrap();
        // Same seed should be able to verify each other's tokens
        let verified = km2.verify_token(&token1).unwrap();
        assert_eq!(verified.sub, "agent-1");
    }

    #[test]
    fn test_seed_bytes_roundtrip() {
        let km = SigningKeyManager::generate();
        let seed = km.seed_bytes();
        let kid = km.active_kid().to_string();
        let km2 = SigningKeyManager::from_seed(&seed, kid);
        let claims = MicroTokenPayload {
            sub: "agent-rt".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 30,
            scope: "all".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            tool_binding: "bind".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };
        let token = km.sign_token(&claims).unwrap();
        assert!(km2.verify_token(&token).is_ok(), "Seed roundtrip should preserve key");
    }

    #[test]
    fn test_jwks_json_structure() {
        let km = SigningKeyManager::generate();
        let jwks = km.jwks_json();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["use"], "sig");
        assert!(keys[0]["x"].as_str().unwrap().len() > 0);
        assert_eq!(keys[0]["kid"].as_str().unwrap(), km.active_kid());
    }

    #[test]
    fn test_kid_format() {
        let km = SigningKeyManager::generate();
        let kid = km.active_kid();
        assert!(kid.starts_with("key-"), "kid should start with 'key-'");
        assert!(kid.len() >= 11, "kid should be at least key-YYYY-MM (11 chars)");
    }

    #[test]
    fn test_invalid_jwt_format() {
        let km = SigningKeyManager::generate();
        assert!(km.verify_token("not-a-jwt").is_err());
        assert!(km.verify_token("only.two").is_err());
        assert!(km.verify_token("").is_err());
    }

    #[test]
    fn test_garbage_signature_rejected() {
        let km = SigningKeyManager::generate();
        let claims = MicroTokenPayload {
            sub: "agent-1".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 30,
            scope: "db:read".to_string(),
            jti: "jti-1".to_string(),
            tool_binding: "bind".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };
        let token = km.sign_token(&claims).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let bad_token = format!("{}.{}.AAAA", parts[0], parts[1]);
        assert!(km.verify_token(&bad_token).is_err());
    }

    #[test]
    fn test_full_claims_roundtrip() {
        let km = SigningKeyManager::generate();
        let claims = MicroTokenPayload {
            sub: "agent-full".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 60,
            scope: "db:read db:write".to_string(),
            jti: "jti-full-test".to_string(),
            tool_binding: "sha256:abc123".to_string(),
            request_id: Some("req-001".to_string()),
            session_id: Some("sess-001".to_string()),
            trust_level: Some("high".to_string()),
        };
        let token = km.sign_token(&claims).unwrap();
        let verified = km.verify_token(&token).unwrap();
        assert_eq!(verified.sub, "agent-full");
        assert_eq!(verified.iss, "agentguard");
        assert_eq!(verified.aud, "tool-service");
        assert_eq!(verified.scope, "db:read db:write");
        assert_eq!(verified.jti, "jti-full-test");
        assert_eq!(verified.tool_binding, "sha256:abc123");
        assert_eq!(verified.request_id.as_deref(), Some("req-001"));
        assert_eq!(verified.session_id.as_deref(), Some("sess-001"));
        assert_eq!(verified.trust_level.as_deref(), Some("high"));
    }

    #[test]
    fn test_token_is_three_part_jwt() {
        let km = SigningKeyManager::generate();
        let claims = MicroTokenPayload {
            sub: "agent-1".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: chrono::Utc::now().timestamp() + 30,
            scope: "db:read".to_string(),
            jti: "jti-1".to_string(),
            tool_binding: "bind".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };
        let token = km.sign_token(&claims).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");
        // Header should decode to EdDSA
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: JwtHeader = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header.alg, "EdDSA");
        assert_eq!(header.typ, "JWT");
    }

    #[test]
    fn test_optional_fields_omitted_when_none() {
        let claims = MicroTokenPayload {
            sub: "agent-1".to_string(),
            iss: "agentguard".to_string(),
            aud: "tool-service".to_string(),
            exp: 1700000000,
            scope: "db:read".to_string(),
            jti: "jti-1".to_string(),
            tool_binding: "bind".to_string(),
            request_id: None,
            session_id: None,
            trust_level: None,
        };
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("ag:request_id"), "None fields should be omitted");
        assert!(!json.contains("ag:session_id"));
        assert!(!json.contains("ag:trust_level"));
    }

    #[test]
    fn test_payload_serde_custom_field_names() {
        let claims = MicroTokenPayload {
            sub: "a".to_string(),
            iss: "b".to_string(),
            aud: "c".to_string(),
            exp: 100,
            scope: "d".to_string(),
            jti: "e".to_string(),
            tool_binding: "f".to_string(),
            request_id: Some("r".to_string()),
            session_id: Some("s".to_string()),
            trust_level: Some("t".to_string()),
        };
        let json = serde_json::to_value(&claims).unwrap();
        // Check custom serde rename attributes
        assert!(json.get("ag:tool_binding").is_some());
        assert!(json.get("ag:request_id").is_some());
        assert!(json.get("ag:session_id").is_some());
        assert!(json.get("ag:trust_level").is_some());
    }
}
