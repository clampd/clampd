//! Parameter normalization integration for the proxy pipeline.
//!
//! Wraps `ag_common::normalizer::normalize()` with gateway-specific logic:
//! - Computes hashes for both raw and normalized params
//! - Tracks detected encodings for risk scoring (+0.15 per encoding type)
//! - Provides the encoding risk bonus for the intent classifier
//!
//! This module is called in Stage 3 (NORMALIZE + EXTRACT) of the pipeline,
//! after extracting the ToolCall from the request body and before passing
//! params to the intent classifier.

use sha2::{Digest, Sha256};

/// Result of parameter normalization for the pipeline.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// Normalized parameters (decoded, stripped of obfuscation).
    pub normalized_params: serde_json::Value,
    /// JSON string of normalized params (for gRPC ClassifyRequest).
    pub normalized_params_json: String,
    /// SHA-256 hash of the normalized params (for micro-token binding).
    pub params_hash: String,
    /// SHA-256 hash of the raw (pre-normalization) params.
    pub params_raw_hash: String,
    /// Encoding types detected during normalization (e.g., "base64", "url_encoding").
    pub encodings_detected: Vec<String>,
    /// Risk bonus from detected encodings: +0.15 per encoding type.
    pub encoding_risk_bonus: f64,
}

/// Risk bonus per detected encoding type (spec: +0.15).
const ENCODING_RISK_BONUS: f64 = 0.15;

/// Normalize parameters and compute pipeline-relevant metadata.
///
/// Calls `ag_common::normalizer::normalize()` on the raw params,
/// then computes hashes and encoding risk bonus.
///
/// # Arguments
/// * `raw_params` - Original parameters from the request body.
/// * `raw_params_json` - Pre-serialized JSON string of raw params (avoids re-serialization).
pub fn normalize_params(
    raw_params: &serde_json::Value,
    raw_params_json: &str,
) -> NormalizationResult {
    // Call ag-common normalizer.
    let (normalized_params, encodings_detected) = ag_common::normalizer::normalize(raw_params);

    // Serialize normalized params for gRPC.
    let normalized_params_json =
        serde_json::to_string(&normalized_params).unwrap_or_else(|_| raw_params_json.to_string());

    // Compute hashes.
    let params_hash = sha256_hex(&normalized_params_json);
    let params_raw_hash = sha256_hex(raw_params_json);

    // Compute encoding risk bonus.
    let encoding_risk_bonus = encodings_detected.len() as f64 * ENCODING_RISK_BONUS;

    NormalizationResult {
        normalized_params,
        normalized_params_json,
        params_hash,
        params_raw_hash,
        encodings_detected,
        encoding_risk_bonus,
    }
}

/// SHA-256 hash of a string, returned as lowercase hex.
fn sha256_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Clean input passthrough ──

    #[test]
    fn test_clean_params_no_encodings() {
        let params = json!({"query": "SELECT * FROM users"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.is_empty());
        assert!((result.encoding_risk_bonus - 0.0).abs() < f64::EPSILON);
        assert_eq!(result.normalized_params, params);
    }

    // ── Encoding detection and risk bonus ──

    #[test]
    fn test_base64_encoding_detected() {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "DROP TABLE users CASCADE",
        );
        let params = json!({"query": encoded});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.contains(&"base64".to_string()));
        assert!(result.encoding_risk_bonus >= ENCODING_RISK_BONUS);
    }

    #[test]
    fn test_url_encoding_detected() {
        let params = json!({"path": "/etc/%2e%2e/%2e%2e/etc/passwd"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.contains(&"url_encoding".to_string()));
        assert!(result.encoding_risk_bonus >= ENCODING_RISK_BONUS);
    }

    #[test]
    fn test_multiple_encodings_increase_risk_bonus() {
        // SQL comment + whitespace abuse
        let params = json!({"sql": "SELECT/*bypass*/1 FROM users"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        // sql_comment should be detected
        assert!(result.encodings_detected.contains(&"sql_comment".to_string()));
        // Risk bonus should be >= 0.15 per encoding type
        assert!(result.encoding_risk_bonus >= ENCODING_RISK_BONUS);
    }

    // ── Hash computation ──

    #[test]
    fn test_hashes_are_sha256_hex() {
        let params = json!({"key": "value"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert_eq!(result.params_hash.len(), 64);
        assert!(result.params_hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(result.params_raw_hash.len(), 64);
        assert!(result
            .params_raw_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_raw_hash_differs_from_normalized_when_encodings_present() {
        let params = json!({"sql": "SELECT/*comment*/1 FROM t-- trailing"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        if !result.encodings_detected.is_empty() {
            // When normalization actually changed the params, hashes should differ.
            assert_ne!(result.params_hash, result.params_raw_hash);
        }
    }

    #[test]
    fn test_raw_hash_equals_normalized_when_clean() {
        let params = json!({"key": "clean value"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        // When no encoding detected, normalized == raw, so hashes match.
        assert_eq!(result.params_hash, result.params_raw_hash);
    }

    // ── Deterministic output ──

    #[test]
    fn test_normalization_is_deterministic() {
        let params = json!({"query": "SELECT * FROM users"});
        let params_json = serde_json::to_string(&params).unwrap();

        let r1 = normalize_params(&params, &params_json);
        let r2 = normalize_params(&params, &params_json);

        assert_eq!(r1.params_hash, r2.params_hash);
        assert_eq!(r1.params_raw_hash, r2.params_raw_hash);
        assert_eq!(r1.normalized_params, r2.normalized_params);
        assert_eq!(r1.encodings_detected, r2.encodings_detected);
    }

    // ── Edge cases ──

    #[test]
    fn test_empty_params() {
        let params = json!({});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.is_empty());
        assert!((result.encoding_risk_bonus - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_null_params() {
        let params = json!(null);
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.is_empty());
    }

    #[test]
    fn test_nested_params() {
        let params = json!({
            "outer": {
                "inner": {
                    "sql": "SELECT/*nested*/1 FROM t"
                }
            }
        });
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.contains(&"sql_comment".to_string()));
    }

    // ── sha256_hex tests ──

    #[test]
    fn test_sha256_hex_known_value() {
        // SHA-256 of empty string is well-known.
        let hash = sha256_hex("");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_different_inputs_different_hashes() {
        let h1 = sha256_hex("hello");
        let h2 = sha256_hex("world");
        assert_ne!(h1, h2);
    }

    // ── Risk bonus calculation ──

    #[test]
    fn test_encoding_risk_bonus_constant() {
        assert!((ENCODING_RISK_BONUS - 0.15).abs() < f64::EPSILON);
    }

    #[test]
    fn test_html_entity_encoding_risk_bonus() {
        let params = json!({"query": "value &lt; 5 AND name = &apos;admin&apos;"});
        let params_json = serde_json::to_string(&params).unwrap();
        let result = normalize_params(&params, &params_json);

        assert!(result.encodings_detected.contains(&"html_entity".to_string()));
        assert!(result.encoding_risk_bonus >= ENCODING_RISK_BONUS);
    }
}
