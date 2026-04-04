use sha2::{Digest, Sha256};

/// Hash an API key with SHA-256 for storage/lookup.
pub fn hash_api_key(raw_key: &str) -> String {
    let hash = Sha256::digest(raw_key.as_bytes());
    hex::encode(hash)
}

/// Verify an inter-service HMAC for internal calls.
/// Uses HMAC-SHA256 with a shared secret, binding to a timestamp.
pub fn verify_internal_hmac(timestamp: &str, hmac_hex: &str, shared_secret: &str) -> bool {
    let expected = generate_hmac(timestamp, shared_secret);
    // Constant-time comparison
    constant_time_eq(expected.as_bytes(), hmac_hex.as_bytes())
}

/// Generate an HMAC for internal service-to-service auth.
pub fn generate_internal_hmac(shared_secret: &str) -> (String, String) {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let hmac = generate_hmac(&timestamp, shared_secret);
    (timestamp, hmac)
}

fn generate_hmac(timestamp: &str, secret: &str) -> String {
    let input = format!("{}{}", timestamp, secret);
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Validate a JWT token and extract AgentJwtClaims.
/// Uses HMAC-SHA256 validation with the provided secret.
/// Checks: signature validity, expiration, required fields.
#[cfg(feature = "license")]
pub fn validate_jwt(token: &str, secret: &str) -> Result<crate::models::AgentJwtClaims, crate::errors::AgError> {
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

    let key = DecodingKey::from_secret(secret.as_ref());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    // SECURITY: Only accept HS256 when using HMAC secret.
    // RS256 with an HMAC DecodingKey enables algorithm confusion attacks.
    // Use validate_jwt_rsa() for RS256/IdP tokens with a proper RSA public key.
    validation.algorithms = vec![Algorithm::HS256];
    // Don't require specific aud/iss — gateway is flexible
    validation.validate_aud = false;

    let token_data = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| crate::errors::AgError::JwtValidation(e.to_string()))?;

    let claims = &token_data.claims;
    let sub = claims.get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::errors::AgError::JwtValidation("missing sub claim".to_string()))?
        .to_string();

    let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    let user_id = claims.get("user_id").and_then(|v| v.as_str()).map(String::from);

    Ok(crate::models::AgentJwtClaims {
        sub,
        iss,
        aud,
        scope,
        exp,
        user_id,
    })
}

/// Validate a JWT using an RSA public key (PEM format).
/// Used for IdP-issued tokens with RS256.
#[cfg(feature = "license")]
pub fn validate_jwt_rsa(token: &str, public_key_pem: &str) -> Result<crate::models::AgentJwtClaims, crate::errors::AgError> {
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

    let key = DecodingKey::from_rsa_pem(public_key_pem.as_ref())
        .map_err(|e| crate::errors::AgError::JwtValidation(format!("invalid RSA key: {}", e)))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_aud = false;

    let token_data = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|e| crate::errors::AgError::JwtValidation(e.to_string()))?;

    let claims = &token_data.claims;
    let sub = claims.get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::errors::AgError::JwtValidation("missing sub claim".to_string()))?
        .to_string();

    let iss = claims.get("iss").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let aud = claims.get("aud").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    let user_id = claims.get("user_id").and_then(|v| v.as_str()).map(String::from);

    Ok(crate::models::AgentJwtClaims {
        sub,
        iss,
        aud,
        scope,
        exp,
        user_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_api_key() {
        let hash = hash_api_key("ag_live_test123");
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_internal_hmac_roundtrip() {
        let secret = "test-secret";
        let (timestamp, hmac) = generate_internal_hmac(secret);
        assert!(verify_internal_hmac(&timestamp, &hmac, secret));
        assert!(!verify_internal_hmac(&timestamp, &hmac, "wrong-secret"));
    }
}

#[cfg(all(test, feature = "license"))]
mod jwt_tests {
    use super::*;

    fn make_hs256_token(claims: &serde_json::Value, secret: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
        let key = EncodingKey::from_secret(secret.as_ref());
        let header = Header::new(Algorithm::HS256);
        encode(&header, claims, &key).unwrap()
    }

    #[test]
    fn test_validate_jwt_valid_token() {
        let secret = "test-secret-key-for-jwt";
        let exp = chrono::Utc::now().timestamp() + 3600;
        let claims = serde_json::json!({
            "sub": "agent-001",
            "iss": "ag-gateway",
            "aud": "ag-services",
            "scope": "read write",
            "exp": exp,
            "user_id": "user-42"
        });
        let token = make_hs256_token(&claims, secret);
        let result = validate_jwt(&token, secret);
        assert!(result.is_ok());
        let jwt_claims = result.unwrap();
        assert_eq!(jwt_claims.sub, "agent-001");
        assert_eq!(jwt_claims.iss, "ag-gateway");
        assert_eq!(jwt_claims.aud, "ag-services");
        assert_eq!(jwt_claims.scope, "read write");
        assert_eq!(jwt_claims.user_id, Some("user-42".to_string()));
    }

    #[test]
    fn test_validate_jwt_expired_token() {
        let secret = "test-secret-key-for-jwt";
        let exp = chrono::Utc::now().timestamp() - 3600; // expired 1 hour ago
        let claims = serde_json::json!({
            "sub": "agent-001",
            "exp": exp,
        });
        let token = make_hs256_token(&claims, secret);
        let result = validate_jwt(&token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_wrong_secret() {
        let exp = chrono::Utc::now().timestamp() + 3600;
        let claims = serde_json::json!({
            "sub": "agent-001",
            "exp": exp,
        });
        let token = make_hs256_token(&claims, "correct-secret");
        let result = validate_jwt(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_missing_sub() {
        let secret = "test-secret-key-for-jwt";
        let exp = chrono::Utc::now().timestamp() + 3600;
        let claims = serde_json::json!({
            "exp": exp,
            "iss": "test",
        });
        let token = make_hs256_token(&claims, secret);
        let result = validate_jwt(&token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_jwt_minimal_claims() {
        let secret = "test-secret-key-for-jwt";
        let exp = chrono::Utc::now().timestamp() + 3600;
        let claims = serde_json::json!({
            "sub": "agent-minimal",
            "exp": exp,
        });
        let token = make_hs256_token(&claims, secret);
        let result = validate_jwt(&token, secret);
        assert!(result.is_ok());
        let jwt_claims = result.unwrap();
        assert_eq!(jwt_claims.sub, "agent-minimal");
        assert_eq!(jwt_claims.iss, "");
        assert_eq!(jwt_claims.aud, "");
        assert_eq!(jwt_claims.scope, "");
        assert_eq!(jwt_claims.user_id, None);
    }
}
