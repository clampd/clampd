//! L0: Decode funnel + binary inspection.
//!
//! Peels encoding layers iteratively (up to depth 6, 5ms budget).
//! At every decoded layer, feeds text to L1-L3.
//! Binary inspection via magic bytes, entropy analysis, and yara-x.

pub mod magic;
pub mod entropy;
pub mod decoders;
pub mod depth;
#[cfg(feature = "yara")]
pub mod yara;

use std::time::Instant;

// ── Funnel detection thresholds ──────────────────────────────────

/// Ratio of printable ASCII chars above which text is "mostly printable"
/// (skip XOR brute-force on already-readable text).
const PRINTABLE_TEXT_RATIO: f64 = 0.90;
/// Minimum ratio of base64-alphabet chars for a string to look like base64.
const BASE64_CHAR_RATIO: f64 = 0.95;
/// Minimum string length to attempt hex/base64 heuristic decoding.
const MIN_ENCODING_DETECT_LEN: usize = 8;

/// Configuration for the decode funnel.
#[derive(Debug, Clone)]
pub struct FunnelConfig {
    /// Maximum decode depth (default: 6).
    pub max_depth: u8,
    /// Time budget in milliseconds (default: 5).
    pub time_budget_ms: u64,
    /// Maximum decoded output size in bytes (default: 1MB).
    pub max_output_size: usize,
}

impl Default for FunnelConfig {
    fn default() -> Self {
        Self {
            max_depth: 6,
            time_budget_ms: 5,
            max_output_size: 1_048_576,
        }
    }
}

/// Result of the decode funnel processing.
#[derive(Debug, Clone)]
pub struct FunnelResult {
    /// Final decoded text (may have gone through multiple layers).
    pub decoded_text: String,
    /// Number of encoding layers peeled.
    pub depth: u8,
    /// Which encodings were peeled, in order.
    pub encodings: Vec<String>,
    /// Whether the funnel hit its time budget.
    pub timed_out: bool,
    /// Binary content if decoding produced non-text bytes.
    pub binary_content: Option<Vec<u8>>,
    /// Risk score contribution from encoding depth.
    pub depth_score: f64,
}

/// The decode funnel — peels encoding layers iteratively.
pub struct DecodeFunnel {
    config: FunnelConfig,
}

impl DecodeFunnel {
    pub fn new(config: FunnelConfig) -> Self {
        Self { config }
    }

    /// Decode a byte slice, peeling encoding layers.
    pub fn decode(&self, input: &[u8]) -> FunnelResult {
        let start = Instant::now();
        let mut current = input.to_vec();
        let mut depth: u8 = 0;
        let mut encodings = Vec::new();
        let mut timed_out = false;
        let mut binary_content: Option<Vec<u8>> = None;

        for _ in 0..self.config.max_depth {
            // Check time budget
            if start.elapsed().as_millis() as u64 >= self.config.time_budget_ms {
                timed_out = true;
                break;
            }

            let mut decoded_this_round = false;

            // Tier 1: Try standard text decodings on string representation
            if let Ok(text) = std::str::from_utf8(&current) {
                // Tier 2: Hex string decode — check BEFORE base64 because
                // pure hex strings are also valid base64 but hex is the intended decode
                if is_pure_hex_string(text) {
                    if let Some(decoded) = decoders::try_hex_string_decode(text) {
                        current = decoded;
                        encodings.push("hex_string".to_string());
                        depth += 1;
                        decoded_this_round = true;
                        continue;
                    }
                }

                // Base64 decode
                if looks_like_base64(text) {
                    if let Ok(decoded) = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        text.trim(),
                    ) {
                        if !decoded.is_empty() && decoded != current {
                            // Check if decoded is binary
                            let m = magic::detect(&decoded);
                            if m != magic::MagicType::Unknown {
                                binary_content = Some(decoded.clone());
                            }
                            current = decoded;
                            encodings.push("base64".to_string());
                            depth += 1;
                            decoded_this_round = true;
                            continue;
                        }
                    }
                }

                // URL decode — only if string contains %XX hex sequences
                if has_url_encoded_chars(text) {
                    if let Some(decoded) = try_url_decode(text) {
                        if decoded.as_bytes() != current.as_slice() {
                            current = decoded.into_bytes();
                            encodings.push("url_decode".to_string());
                            depth += 1;
                            decoded_this_round = true;
                            continue;
                        }
                    }
                }

            }

            // Tier 2: Gzip decode (binary)
            if let Some(decoded) = decoders::try_gzip_decode(&current) {
                current = decoded;
                encodings.push("gzip".to_string());
                depth += 1;
                decoded_this_round = true;
                continue;
            }

            // Tier 2: XOR single-byte brute force — only on non-text content
            // (text that's already readable shouldn't be XOR-decoded)
            if !is_mostly_printable_text(&current) {
                if let Some((decoded, key)) = decoders::try_xor_single_byte(&current) {
                    current = decoded;
                    encodings.push(format!("xor_0x{:02x}", key));
                    depth += 1;
                    decoded_this_round = true;
                    continue;
                }
            }

            if !decoded_this_round {
                break; // No more layers to peel
            }
        }

        // Check size cap
        if current.len() > self.config.max_output_size {
            current.truncate(self.config.max_output_size);
        }

        // If we haven't detected binary yet, check final output
        if binary_content.is_none() {
            let magic = magic::detect(&current);
            if magic != magic::MagicType::Unknown {
                binary_content = Some(current.clone());
            }
        }

        let decoded_text = String::from_utf8(current)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).to_string());

        FunnelResult {
            decoded_text,
            depth,
            encodings,
            timed_out,
            binary_content,
            depth_score: depth::depth_score(depth),
        }
    }

    /// Decode a string, peeling encoding layers.
    pub fn decode_str(&self, input: &str) -> FunnelResult {
        self.decode(input.as_bytes())
    }
}

/// Check if text is mostly printable (>90% printable ASCII + spaces).
/// Used to avoid XOR-decoding already readable text.
fn is_mostly_printable_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let printable = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    printable as f64 / data.len() as f64 > PRINTABLE_TEXT_RATIO
}

/// Check if a string contains %XX URL-encoded hex sequences.
fn has_url_encoded_chars(s: &str) -> bool {
    let bytes = s.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == b'%'
            && bytes.get(i + 1).map_or(false, |b| b.is_ascii_hexdigit())
            && bytes.get(i + 2).map_or(false, |b| b.is_ascii_hexdigit())
        {
            return true;
        }
    }
    false
}

/// Check if the ENTIRE string is a hex-encoded byte sequence.
fn is_pure_hex_string(s: &str) -> bool {
    let trimmed = s.trim();
    trimmed.len() >= MIN_ENCODING_DETECT_LEN
        && trimmed.len() % 2 == 0
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check if a string looks like base64 (heuristic).
fn looks_like_base64(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < MIN_ENCODING_DETECT_LEN {
        return false;
    }
    // Must be mostly base64 chars
    let b64_chars = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    let ratio = b64_chars as f64 / trimmed.len() as f64;
    ratio > BASE64_CHAR_RATIO && trimmed.len() % 4 <= 1
}

/// Try URL decoding. Returns None if no %XX sequences found.
fn try_url_decode(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }

    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    if result == s {
        None
    } else {
        Some(result)
    }
}
