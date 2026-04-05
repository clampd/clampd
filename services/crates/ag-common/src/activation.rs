//! Activation token validation - offline validation for self-hosted deployments.
//!
//! After a one-time online activation, the activation token is stored locally
//! at `/var/lib/clampd/activation.json`. On every service startup, this module
//! validates the token OFFLINE using the embedded RSA-4096 public key (the same
//! key used for license JWT validation).
//!
//! The activation token is an RS256 JWT containing:
//! - org_id, license_id, installation_id
//! - fingerprint_hash (binds to this machine)
//! - expiry (activation tokens have a long TTL but still expire)
//!
//! No network call required - pure offline crypto, same as license_guard.

use crate::fingerprint;
use rsa::pkcs8::DecodePublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

/// The activation file stored on disk after successful online activation.
#[derive(Debug, Deserialize)]
pub struct ActivationFile {
    /// The original license JWT (passed through to PlanGuard).
    pub license_jwt: String,
    /// The activation token JWT (RS256, signed by the license server).
    pub activation_token: String,
    /// ISO-8601 timestamp of when activation occurred.
    pub activated_at: String,
    /// Unique installation identifier for this deployment.
    pub installation_id: String,
}

/// Claims embedded in the activation token JWT.
#[derive(Debug, Clone, Deserialize)]
pub struct ActivationClaims {
    /// Issuer - must be "license.clampd.dev".
    pub iss: String,
    /// Subject - the org_id.
    pub sub: String,
    /// Token type - must be "activation".
    pub typ: String,
    /// The license ID this activation is bound to.
    pub license_id: String,
    /// Installation ID - must match the activation file.
    pub installation_id: String,
    /// SHA-256 hash of the machine fingerprint at activation time.
    pub fingerprint_hash: String,
    /// Expiry (Unix timestamp).
    pub exp: u64,
    /// Issued-at (Unix timestamp).
    pub iat: u64,
}

/// Errors that can occur during activation validation.
#[derive(Debug)]
pub enum ActivationError {
    /// The activation file does not exist at the expected path.
    FileNotFound,
    /// Failed to parse the activation file or JWT payload.
    ParseError(String),
    /// RSA signature verification failed - token may be forged.
    InvalidSignature,
    /// The activation token has expired.
    Expired,
    /// Machine fingerprint does not match the activation token.
    FingerprintMismatch { expected: String, actual: String },
    /// Installation ID in the JWT does not match the file.
    InstallationIdMismatch,
    /// Token type is not "activation".
    InvalidType,
}

impl std::fmt::Display for ActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivationError::FileNotFound => write!(f, "activation file not found"),
            ActivationError::ParseError(msg) => write!(f, "parse error: {}", msg),
            ActivationError::InvalidSignature => write!(f, "invalid RSA signature"),
            ActivationError::Expired => write!(f, "activation token expired"),
            ActivationError::FingerprintMismatch { expected, actual } => {
                write!(
                    f,
                    "fingerprint mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            ActivationError::InstallationIdMismatch => {
                write!(f, "installation ID mismatch between file and JWT")
            }
            ActivationError::InvalidType => {
                write!(f, "token type is not 'activation'")
            }
        }
    }
}

/// Embedded RSA-4096 public key - same key as license_guard.rs.
/// Compiled into the binary, not configurable at runtime.
const LICENSE_RSA_PUBLIC_KEY_PEM: &str = include_str!("../keys/license_pub.pem");

/// Load and validate an activation token from disk.
///
/// Reads the activation file, verifies the RS256 JWT signature using the
/// embedded public key, checks expiry, fingerprint binding, and installation ID.
///
/// Returns the license_jwt (for PlanGuard) and the validated claims on success.
pub fn load_and_validate(path: &str) -> Result<(String, ActivationClaims), ActivationError> {
    // Read the activation file
    let contents = std::fs::read_to_string(path).map_err(|_| ActivationError::FileNotFound)?;

    // Parse as ActivationFile
    let activation_file: ActivationFile = serde_json::from_str(&contents)
        .map_err(|e| ActivationError::ParseError(format!("invalid activation file JSON: {}", e)))?;

    // Split the activation token JWT
    let token = &activation_file.activation_token;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ActivationError::ParseError(
            "activation token is not a valid JWT (expected 3 parts)".to_string(),
        ));
    }

    // Verify RSA-4096 signature before trusting any claims
    if !verify_rsa_signature(&format!("{}.{}", parts[0], parts[1]), parts[2]) {
        return Err(ActivationError::InvalidSignature);
    }

    // Decode and parse the payload
    let payload_bytes = base64url_decode(parts[1]).ok_or_else(|| {
        ActivationError::ParseError("activation token payload has invalid base64url encoding".to_string())
    })?;

    let claims: ActivationClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| ActivationError::ParseError(format!("invalid activation claims: {}", e)))?;

    // Check token type
    if claims.typ != "activation" {
        return Err(ActivationError::InvalidType);
    }

    // Check issuer
    if claims.iss != "license.clampd.dev" {
        return Err(ActivationError::InvalidSignature);
    }

    // Check expiry
    let now = chrono::Utc::now().timestamp() as u64;
    if claims.exp < now {
        return Err(ActivationError::Expired);
    }

    // Generate current machine fingerprint and compare
    let current_fp = fingerprint::generate();
    let mut hasher = Sha256::new();
    hasher.update(current_fp.hash.as_bytes());
    let current_fp_hash = format!("{:x}", hasher.finalize());

    if claims.fingerprint_hash != current_fp_hash {
        return Err(ActivationError::FingerprintMismatch {
            expected: claims.fingerprint_hash.clone(),
            actual: current_fp_hash,
        });
    }

    // Verify installation_id matches between the file and the JWT
    if claims.installation_id != activation_file.installation_id {
        return Err(ActivationError::InstallationIdMismatch);
    }

    Ok((activation_file.license_jwt, claims))
}

/// Get the default path for the activation file.
///
/// Checks `CLAMPD_ACTIVATION_PATH` env var first, falls back to
/// `/var/lib/clampd/activation.json`.
pub fn default_activation_path() -> String {
    std::env::var("CLAMPD_ACTIVATION_PATH")
        .unwrap_or_else(|_| "/var/lib/clampd/activation.json".to_string())
}

/// Read an existing installation ID or create a new one.
///
/// Looks for `{dir}/installation_id` file. If it exists, reads and returns
/// the contents. Otherwise, generates a UUID v4, writes it to the file,
/// and returns it.
pub fn read_or_create_installation_id(dir: &str) -> String {
    let path = format!("{}/installation_id", dir);

    // Try to read existing
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }

    // Generate new UUID v4
    let id = uuid::Uuid::new_v4().to_string();

    // Ensure directory exists
    let _ = std::fs::create_dir_all(dir);

    // Write to file (best-effort - if this fails, the ID is still usable)
    if let Err(e) = std::fs::write(&path, &id) {
        warn!("Failed to write installation_id to {}: {}", path, e);
    }

    id
}

/// Verify RSA-4096 signature on a JWT.
///
/// Uses RSASSA-PKCS1-v1_5 with SHA-256 (RS256). Same algorithm and key
/// as license_guard.rs.
fn verify_rsa_signature(signing_input: &str, signature_b64: &str) -> bool {
    let sig_bytes = match base64url_decode(signature_b64) {
        Some(bytes) => bytes,
        None => {
            warn!("Activation token signature has invalid base64url encoding");
            return false;
        }
    };

    let public_key = match rsa::RsaPublicKey::from_public_key_pem(LICENSE_RSA_PUBLIC_KEY_PEM) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Failed to parse embedded license public key: {}", e);
            return false;
        }
    };

    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    let verifying_key = VerifyingKey::<sha2::Sha256>::new(public_key);
    let signature = match rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            warn!("Activation token signature has invalid RSA format");
            return false;
        }
    };

    match verifying_key.verify(signing_input.as_bytes(), &signature) {
        Ok(()) => true,
        Err(_) => {
            warn!("Activation token RSA signature verification failed - token may be forged");
            false
        }
    }
}

/// Base64url decode (no padding).
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut s = input.replace('-', "+").replace('_', "/");
    match s.len() % 4 {
        2 => s.push_str("=="),
        3 => s.push('='),
        _ => {}
    }
    base64_decode(&s)
}

/// Simple base64 decode using standard alphabet.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let table: [u8; 256] = {
        let mut t = [255u8; 256];
        for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .iter()
            .enumerate()
        {
            t[c as usize] = i as u8;
        }
        t[b'=' as usize] = 0;
        t
    };

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let a = table[chunk[0] as usize];
        let b = table[chunk[1] as usize];
        let c = table[chunk[2] as usize];
        let d = table[chunk[3] as usize];
        if a == 255 || b == 255 || c == 255 || d == 255 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_activation_path_no_env() {
        std::env::remove_var("CLAMPD_ACTIVATION_PATH");
        assert_eq!(
            default_activation_path(),
            "/var/lib/clampd/activation.json"
        );
    }

    #[test]
    fn test_default_activation_path_with_env() {
        std::env::set_var("CLAMPD_ACTIVATION_PATH", "/tmp/test-activation.json");
        assert_eq!(default_activation_path(), "/tmp/test-activation.json");
        std::env::remove_var("CLAMPD_ACTIVATION_PATH");
    }

    #[test]
    fn test_load_and_validate_file_not_found() {
        let result = load_and_validate("/nonexistent/path/activation.json");
        assert!(matches!(result, Err(ActivationError::FileNotFound)));
    }

    #[test]
    fn test_load_and_validate_invalid_json() {
        let dir = std::env::temp_dir().join("clampd-test-activation");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let result = load_and_validate(path.to_str().unwrap());
        assert!(matches!(result, Err(ActivationError::ParseError(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_and_validate_invalid_jwt_format() {
        let dir = std::env::temp_dir().join("clampd-test-activation-jwt");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad-jwt.json");
        let file = serde_json::json!({
            "license_jwt": "a.b.c",
            "activation_token": "not-a-jwt",
            "activated_at": "2025-01-01T00:00:00Z",
            "installation_id": "test-id"
        });
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        let result = load_and_validate(path.to_str().unwrap());
        assert!(matches!(result, Err(ActivationError::ParseError(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_or_create_installation_id_new() {
        let dir = std::env::temp_dir().join("clampd-test-install-id");
        let _ = std::fs::remove_dir_all(&dir);
        let id = read_or_create_installation_id(dir.to_str().unwrap());
        // Should be a valid UUID v4
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        // Should persist
        let id2 = read_or_create_installation_id(dir.to_str().unwrap());
        assert_eq!(id, id2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_or_create_installation_id_existing() {
        let dir = std::env::temp_dir().join("clampd-test-install-id-existing");
        let _ = std::fs::create_dir_all(&dir);
        let expected = "my-custom-install-id";
        std::fs::write(dir.join("installation_id"), expected).unwrap();
        let id = read_or_create_installation_id(dir.to_str().unwrap());
        assert_eq!(id, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_base64url_decode_valid() {
        let result = base64url_decode("eyJ0ZXN0IjoxfQ");
        assert!(result.is_some());
        let decoded = String::from_utf8(result.unwrap()).unwrap();
        assert_eq!(decoded, r#"{"test":1}"#);
    }

    #[test]
    fn test_activation_error_display() {
        let err = ActivationError::FileNotFound;
        assert_eq!(format!("{}", err), "activation file not found");

        let err = ActivationError::Expired;
        assert_eq!(format!("{}", err), "activation token expired");

        let err = ActivationError::FingerprintMismatch {
            expected: "abc".to_string(),
            actual: "def".to_string(),
        };
        assert!(format!("{}", err).contains("abc"));
    }
}
