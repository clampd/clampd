//! Tier 2 decoders: gzip, hex string, XOR single-byte brute force.
//! These activate when Tier 1 (normalize.rs) produces further-encoded output.

use flate2::read::GzDecoder;
use std::io::Read;

/// Try to decompress gzip/deflate content. Returns decoded bytes or None.
pub fn try_gzip_decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 || data[0] != 0x1F || data[1] != 0x8B {
        return None;
    }

    let mut decoder = GzDecoder::new(data);
    let mut output = Vec::new();

    // Cap at 1MB to prevent decompression bombs
    match decoder.by_ref().take(1_048_576).read_to_end(&mut output) {
        Ok(_) if !output.is_empty() => Some(output),
        _ => None,
    }
}

/// Try to decode a hex string like "44524f50205441424c45" → "DROP TABLE".
/// Returns decoded bytes if input looks like a hex string.
pub fn try_hex_string_decode(data: &str) -> Option<Vec<u8>> {
    let trimmed = data.trim();

    // Must be even length, all hex chars, and reasonably long
    if trimmed.len() < 4 || trimmed.len() % 2 != 0 {
        return None;
    }

    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    hex::decode(trimmed).ok()
}

/// Try XOR single-byte brute force. Tests all 256 keys.
/// Returns (decoded_bytes, key) if decoded output is mostly printable ASCII.
pub fn try_xor_single_byte(data: &[u8]) -> Option<(Vec<u8>, u8)> {
    if data.len() < 8 {
        return None;
    }

    // Try each possible key
    for key in 1..=255u8 {
        let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();

        // Check if result looks like real text:
        // 1. >95% printable ASCII
        // 2. Contains spaces (real text has spaces)
        // 3. No null bytes
        let printable = decoded
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
            .count();
        let has_spaces = decoded.iter().any(|&b| b == b' ');
        let has_nulls = decoded.iter().any(|&b| b == 0);

        let ratio = printable as f64 / decoded.len() as f64;
        if ratio > 0.95 && has_spaces && !has_nulls {
            return Some((decoded, key));
        }
    }

    None
}
