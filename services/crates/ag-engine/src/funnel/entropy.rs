//! Shannon entropy calculation for binary content analysis.
//! High entropy (>7.5) indicates encrypted or compressed data.

// ── Entropy thresholds ───────────────────────────────────────────

/// Entropy above this indicates encrypted/compressed data.
const ENCRYPTED_ENTROPY_THRESHOLD: f64 = 7.5;
/// Minimum data length to attempt encrypted-data detection.
const MIN_ENCRYPTED_DETECT_LEN: usize = 32;
/// Entropy above this is almost certainly AES (not XOR).
const AES_ENTROPY_THRESHOLD: f64 = 7.9;
/// Minimum data length to attempt XOR detection.
const MIN_XOR_DETECT_LEN: usize = 64;
/// Maximum distinct byte values for XOR-encrypted data.
const XOR_MAX_DISTINCT_BYTES: usize = 120;
/// Alpha ratio above which text looks like normal readable text (not XOR'd).
const TEXT_ALPHA_RATIO: f64 = 0.5;
/// Minimum entropy for XOR-encrypted data (below this is too regular).
const XOR_MIN_ENTROPY: f64 = 2.0;

/// Calculate Shannon entropy of a byte slice.
/// Returns a value between 0.0 (all same byte) and 8.0 (perfectly random).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if data is likely encrypted (entropy > 7.5).
pub fn is_likely_encrypted(data: &[u8]) -> bool {
    if data.len() < MIN_ENCRYPTED_DETECT_LEN {
        return false;
    }
    shannon_entropy(data) > ENCRYPTED_ENTROPY_THRESHOLD
}

/// Distinguish XOR-encrypted from AES-encrypted data.
/// Single-byte XOR has slightly lower entropy (~7.5-7.8) with
/// characteristic byte frequency patterns.
/// True random (AES) has entropy ~7.99.
pub fn is_likely_xor(data: &[u8]) -> bool {
    if data.len() < MIN_XOR_DETECT_LEN {
        return false;
    }

    let entropy = shannon_entropy(data);

    // True random (AES) has entropy ~7.99 for large data.
    // If entropy is very high, it's likely AES, not XOR.
    if entropy > AES_ENTROPY_THRESHOLD {
        return false;
    }

    // XOR with a single byte preserves the frequency distribution of the plaintext
    // but shifts all byte values. This means:
    // 1. The most frequent byte in XOR'd text = key XOR most_common_plaintext_byte (usually space=0x20)
    // 2. The frequency distribution looks like shifted English, not uniform random
    //
    // Heuristic: count how many distinct byte values appear.
    // English text uses ~60-80 distinct bytes. XOR preserves this.
    // True random uses all 256. Compressed uses ~200-256.
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let distinct_bytes = freq.iter().filter(|&&c| c > 0).count();

    // XOR'd English text: 40-100 distinct bytes (same as plaintext)
    // True random: 200+ distinct bytes
    // Plain English: 40-100 distinct bytes
    // We also need it to NOT look like plain ASCII
    let is_ascii = data.iter().all(|&b| b.is_ascii());

    // XOR'd text has limited distinct byte values (like English, ~30-100)
    // but doesn't look like normal readable text (low ratio of common ASCII letters)
    let alpha_count = data.iter().filter(|&&b| b.is_ascii_alphabetic()).count();
    let alpha_ratio = alpha_count as f64 / data.len() as f64;

    // Normal English text: ~70-80% alphabetic
    // XOR'd English: much lower alphabetic ratio (shifted bytes)
    // True random: ~40% alphabetic (26*2/128)
    let looks_like_text = alpha_ratio > TEXT_ALPHA_RATIO;

    !looks_like_text && distinct_bytes < XOR_MAX_DISTINCT_BYTES && entropy > XOR_MIN_ENTROPY && entropy < ENCRYPTED_ENTROPY_THRESHOLD
}
