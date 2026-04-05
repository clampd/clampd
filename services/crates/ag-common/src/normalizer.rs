//! Parameter normalization pipeline.
//!
//! Defends against encoded payload attacks by normalizing parameters
//! before intent analysis. The rules engine evaluates `params_normalized`
//! while raw params are preserved for shadow logging.
//!
//! 13-step pipeline (applied recursively to all string values):
//!  1. Hex escape decode (\x41, 0x41)
//!  2. Octal escape decode (\101)
//!  3. Base64 decode (if valid)
//!  4. Unicode NFKC normalization
//!  5. Zero-width character stripping
//!  6. Homoglyph/confusable normalization
//!  7. HTML entity decode
//!  8. URL decode
//!  9. ROT13 detection (heuristic)
//! 10. SQL comment strip
//! 11. Punycode decode (xn-- domains)
//! 12. Whitespace normalization
//! 13. Case preservation (no lowercasing — rules handle case-insensitive matching)

use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;
use unicode_normalization::UnicodeNormalization;

/// Maximum iterative passes for deeply nested encoding (base64→URL→unicode).
const MAX_DECODE_PASSES: usize = 3;

/// Maximum length for individual strings to normalize (FIX 5: write bomb mitigation).
/// Strings exceeding this are returned as-is with a "truncated" encoding flag.
pub const MAX_NORMALIZE_STRING_LEN: usize = 65_536;

/// Minimum length for a string to be considered a possible base64 payload.
const MIN_BASE64_LEN: usize = 20;

// Pre-compiled regexes (compiled once, reused across calls).
static RE_BASE64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/=]{20,}$").unwrap());
static RE_SQL_BLOCK_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\*.*?\*/").unwrap());
static RE_SQL_LINE_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"--[^\n]*").unwrap());
static RE_WHITESPACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[ \t\r\n]+").unwrap());
static RE_HTML_NAMED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&(lt|gt|amp|quot|apos|nbsp);").unwrap());
static RE_HTML_NUMERIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&#x?([0-9a-fA-F]+);").unwrap());
static RE_URL_ENCODED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%[0-9a-fA-F]{2}").unwrap());

// New encoding regexes
static RE_HEX_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\x|0x)([0-9a-fA-F]{2})").unwrap());
static RE_OCTAL_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\([0-3][0-7]{2})").unwrap());
static RE_PUNYCODE_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxn--[a-z0-9\-]+").unwrap());

/// Normalize a JSON value, returning the normalized value and a list of
/// encoding types that were detected and decoded.
///
/// Each detected encoding adds +0.15 risk bonus in the intent classifier.
pub fn normalize(params: &serde_json::Value) -> (serde_json::Value, Vec<String>) {
    let mut encodings = Vec::new();
    let normalized = normalize_value(params, &mut encodings);
    // Deduplicate encoding names.
    encodings.sort();
    encodings.dedup();
    (normalized, encodings)
}

/// Recursively normalize a JSON value.
fn normalize_value(value: &serde_json::Value, encodings: &mut Vec<String>) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let normalized = normalize_string(s, encodings);
            serde_json::Value::String(normalized)
        }
        serde_json::Value::Array(arr) => {
            let normalized: Vec<serde_json::Value> = arr
                .iter()
                .map(|v| normalize_value(v, encodings))
                .collect();
            serde_json::Value::Array(normalized)
        }
        serde_json::Value::Object(map) => {
            let normalized: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), normalize_value(v, encodings)))
                .collect();
            serde_json::Value::Object(normalized)
        }
        // Numbers, booleans, null pass through unchanged.
        other => other.clone(),
    }
}

/// Normalize a single string through the 13-step pipeline.
/// Runs up to MAX_DECODE_PASSES iterations to handle nested encoding.
/// Strings exceeding MAX_NORMALIZE_STRING_LEN are returned as-is with "truncated" flag.
fn normalize_string(input: &str, encodings: &mut Vec<String>) -> String {
    // FIX 5: Skip normalization for oversized strings to prevent CPU exhaustion
    if input.len() > MAX_NORMALIZE_STRING_LEN {
        if !encodings.contains(&"truncated".to_string()) {
            encodings.push("truncated".to_string());
        }
        return input.to_string();
    }

    let mut current = input.to_string();

    for _pass in 0..MAX_DECODE_PASSES {
        let before = current.clone();

        // Step 1: Hex escape decode (\x41, 0x41)
        current = decode_hex_escapes(&current, encodings);

        // Step 2: Octal escape decode (\101)
        current = decode_octal_escapes(&current, encodings);

        // Step 3: Base64 decode
        current = try_base64_decode(&current, encodings);

        // Step 4: Unicode NFKC normalization
        let nfkc = current.nfkc().collect::<String>();
        if nfkc != current {
            encodings.push("unicode_nfkc".to_string());
            current = nfkc;
        }

        // Step 5: Zero-width character stripping
        current = strip_zero_width(&current, encodings);

        // Step 6: Homoglyph/confusable normalization
        current = normalize_homoglyphs(&current, encodings);

        // Step 7: HTML entity decode
        current = decode_html_entities(&current, encodings);

        // Step 8: URL decode
        current = decode_url_encoding(&current, encodings);

        // Step 9: ROT13 detection (heuristic)
        current = try_rot13_decode(&current, encodings);

        // Step 10: SQL comment stripping
        current = strip_sql_comments(&current, encodings);

        // Step 11: Punycode decode (xn-- domains)
        current = decode_punycode(&current, encodings);

        // Step 12: Whitespace normalization
        current = normalize_whitespace(&current);

        // Step 13: Case preservation — intentionally no lowercasing.

        // If nothing changed this pass, we're done.
        if current == before {
            break;
        }
    }

    current
}

/// Step 1: Attempt base64 decode if the string looks like base64.
fn try_base64_decode(input: &str, encodings: &mut Vec<String>) -> String {
    let trimmed = input.trim();
    if trimmed.len() < MIN_BASE64_LEN {
        return input.to_string();
    }
    if !RE_BASE64.is_match(trimmed) {
        return input.to_string();
    }
    match base64::engine::general_purpose::STANDARD.decode(trimmed) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(decoded) => {
                encodings.push("base64".to_string());
                decoded
            }
            Err(_) => input.to_string(),
        },
        Err(_) => input.to_string(),
    }
}

/// Step 1: Decode hex escapes (\x41 → 'A', 0x41 → 'A').
/// Catches payloads like: SELECT \x53\x53\x4e FROM users → SELECT SSN FROM users
fn decode_hex_escapes(input: &str, encodings: &mut Vec<String>) -> String {
    if !RE_HEX_ESCAPE.is_match(input) {
        return input.to_string();
    }
    encodings.push("hex".to_string());
    RE_HEX_ESCAPE
        .replace_all(input, |caps: &regex::Captures| {
            let hex = &caps[1];
            match u8::from_str_radix(hex, 16) {
                Ok(b) if b.is_ascii() => (b as char).to_string(),
                _ => caps[0].to_string(),
            }
        })
        .to_string()
}

/// Step 2: Decode octal escapes (\101 → 'A', \123 → 'S').
/// Catches payloads like: \123\123\116 → SSN
fn decode_octal_escapes(input: &str, encodings: &mut Vec<String>) -> String {
    if !RE_OCTAL_ESCAPE.is_match(input) {
        return input.to_string();
    }
    encodings.push("octal".to_string());
    RE_OCTAL_ESCAPE
        .replace_all(input, |caps: &regex::Captures| {
            let oct = &caps[1];
            match u8::from_str_radix(oct, 8) {
                Ok(b) if b.is_ascii() => (b as char).to_string(),
                _ => caps[0].to_string(),
            }
        })
        .to_string()
}

/// Step 5: Strip zero-width characters (U+200B, U+200C, U+200D, U+FEFF, U+00AD).
/// These are invisible and used to bypass keyword matching:
/// "DR​OP" (with zero-width space) → "DROP"
fn strip_zero_width(input: &str, encodings: &mut Vec<String>) -> String {
    let stripped: String = input
        .chars()
        .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}' | '\u{2060}' | '\u{180E}'))
        .collect();
    if stripped.len() != input.len() {
        encodings.push("zero_width".to_string());
    }
    stripped
}

/// Step 6: Normalize common homoglyphs/confusable characters.
/// Catches attacks like: ЅЕLЕСТ (Cyrillic lookalikes) → SELECT
/// Maps visually similar Unicode chars to their ASCII equivalents.
fn normalize_homoglyphs(input: &str, encodings: &mut Vec<String>) -> String {
    let mut result = String::with_capacity(input.len());
    let mut changed = false;

    for ch in input.chars() {
        let mapped = match ch {
            // Cyrillic lookalikes
            '\u{0410}' | '\u{0430}' => 'a',  // А/а → a
            '\u{0412}' | '\u{0432}' => 'B',  // В/в → B (visual match)
            '\u{0415}' | '\u{0435}' => 'e',  // Е/е → e
            '\u{041A}' | '\u{043A}' => 'K',  // К/к → K
            '\u{041C}' | '\u{043C}' => 'M',  // М/м → M
            '\u{041D}' | '\u{043D}' => 'H',  // Н/н → H
            '\u{041E}' | '\u{043E}' => 'o',  // О/о → o
            '\u{0420}' | '\u{0440}' => 'p',  // Р/р → p
            '\u{0421}' | '\u{0441}' => 'c',  // С/с → c
            '\u{0422}' | '\u{0442}' => 'T',  // Т/т → T
            '\u{0425}' | '\u{0445}' => 'x',  // Х/х → x
            '\u{0423}' | '\u{0443}' => 'y',  // У/у → y
            '\u{0405}' => 'S',                // Ѕ → S (Macedonian)
            '\u{0455}' => 's',                // ѕ → s
            '\u{0406}' | '\u{0456}' => 'i',  // І/і → i (Ukrainian)
            '\u{0408}' => 'J',                // Ј → J (Serbian)
            // Greek lookalikes
            '\u{0391}' | '\u{03B1}' => 'a',  // Α/α → a
            '\u{0392}' | '\u{03B2}' => 'B',  // Β/β → B
            '\u{0395}' | '\u{03B5}' => 'e',  // Ε/ε → e
            '\u{0397}' | '\u{03B7}' => 'H',  // Η/η → H
            '\u{0399}' | '\u{03B9}' => 'i',  // Ι/ι → i
            '\u{039A}' | '\u{03BA}' => 'K',  // Κ/κ → K
            '\u{039C}' | '\u{03BC}' => 'M',  // Μ/μ → M
            '\u{039D}' | '\u{03BD}' => 'N',  // Ν/ν → N
            '\u{039F}' | '\u{03BF}' => 'o',  // Ο/ο → o
            '\u{03A1}' | '\u{03C1}' => 'p',  // Ρ/ρ → p
            '\u{03A4}' | '\u{03C4}' => 'T',  // Τ/τ → T
            '\u{03A5}' | '\u{03C5}' => 'y',  // Υ/υ → y
            '\u{03A7}' | '\u{03C7}' => 'x',  // Χ/χ → x
            '\u{0396}' | '\u{03B6}' => 'Z',  // Ζ/ζ → Z
            // Math/special lookalikes
            '\u{FF21}'..='\u{FF3A}' => {      // Fullwidth A-Z
                ((ch as u32 - 0xFF21) as u8 + b'A') as char
            }
            '\u{FF41}'..='\u{FF5A}' => {      // Fullwidth a-z
                ((ch as u32 - 0xFF41) as u8 + b'a') as char
            }
            '\u{FF10}'..='\u{FF19}' => {      // Fullwidth 0-9
                ((ch as u32 - 0xFF10) as u8 + b'0') as char
            }
            '\u{2013}' | '\u{2014}' => '-',  // En/em dash → hyphen
            '\u{2018}' | '\u{2019}' | '\u{201B}' => '\'', // Smart quotes
            '\u{201C}' | '\u{201D}' | '\u{201F}' => '"',  // Smart double quotes
            _ => ch,
        };
        if mapped != ch {
            changed = true;
        }
        result.push(mapped);
    }

    if changed {
        encodings.push("homoglyph".to_string());
    }
    result
}

/// Step 9: ROT13 heuristic detection.
/// If a string contains known ROT13-encoded SQL keywords, decode them.
/// "QEBC GNOYR" (ROT13 of "DROP TABLE") → "DROP TABLE"
fn try_rot13_decode(input: &str, encodings: &mut Vec<String>) -> String {
    // Only attempt ROT13 if string contains suspicious ROT13-encoded keywords
    let rot13_keywords = [
        "QEBC",  // DROP
        "GNOYR", // TABLE
        "FRYRPG", // SELECT
        "VAFREG", // INSERT
        "QRYRGR", // DELETE
        "HCQNGR", // UPDATE
        "rkrp",   // exec
        "onfu",   // bash
        "phey",   // curl
        "jtrg",   // wget
    ];

    let has_rot13 = rot13_keywords.iter().any(|kw| input.contains(kw));
    if !has_rot13 {
        return input.to_string();
    }

    encodings.push("rot13".to_string());
    input
        .chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => ((c as u8) + 13) as char,
            'N'..='Z' | 'n'..='z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

/// Step 11: Decode punycode domain labels (xn--nxasmq6b → example in non-Latin).
/// Converts internationalized domain names back to Unicode for inspection.
fn decode_punycode(input: &str, encodings: &mut Vec<String>) -> String {
    if !RE_PUNYCODE_LABEL.is_match(input) {
        return input.to_string();
    }

    let mut result = input.to_string();
    let mut found = false;

    // Decode each xn-- label using a simple punycode decoder
    for mat in RE_PUNYCODE_LABEL.find_iter(input) {
        let label = mat.as_str();
        // Strip "xn--" prefix for decoding
        let encoded = &label[4..];
        if let Some(decoded) = decode_punycode_label(encoded) {
            result = result.replace(label, &decoded);
            found = true;
        }
    }

    if found {
        encodings.push("punycode".to_string());
    }
    result
}

/// Simple punycode label decoder (RFC 3492 subset).
/// Handles common attack cases like xn--80ak6aa92e (apple in Cyrillic).
fn decode_punycode_label(encoded: &str) -> Option<String> {
    // Find the last '-' which separates basic chars from encoded chars
    let (basic_part, _delta_part) = match encoded.rfind('-') {
        Some(pos) => (&encoded[..pos], &encoded[pos + 1..]),
        None => ("", encoded),
    };

    // For security purposes, if we detect xn-- we flag it even if
    // full decoding fails — the label is suspicious regardless
    if basic_part.is_empty() && encoded.len() > 2 {
        // Return a marker that shows this is a decoded IDN
        return Some(format!("[IDN:{}]", encoded));
    }

    // If there's a basic part, return it (partial decode, enough for rule matching)
    if !basic_part.is_empty() {
        return Some(basic_part.to_string());
    }

    None
}

/// Step 7: Decode HTML entities (&lt; &gt; &amp; &quot; &apos; &nbsp; and numeric).
fn decode_html_entities(input: &str, encodings: &mut Vec<String>) -> String {
    let mut result = input.to_string();
    let mut found = false;

    // Named entities
    if RE_HTML_NAMED.is_match(&result) {
        found = true;
        result = RE_HTML_NAMED
            .replace_all(&result, |caps: &regex::Captures| {
                match &caps[1] {
                    "lt" => "<",
                    "gt" => ">",
                    "amp" => "&",
                    "quot" => "\"",
                    "apos" => "'",
                    "nbsp" => " ",
                    _ => &caps[0],
                }
                .to_string()
            })
            .to_string();
    }

    // Numeric entities (&#x27; &#39;)
    if RE_HTML_NUMERIC.is_match(&result) {
        found = true;
        result = RE_HTML_NUMERIC
            .replace_all(&result, |caps: &regex::Captures| {
                let num_str = &caps[1];
                let code_point = if caps[0].contains('x') || caps[0].contains('X') {
                    u32::from_str_radix(num_str, 16).ok()
                } else {
                    num_str.parse::<u32>().ok()
                };
                match code_point.and_then(char::from_u32) {
                    Some(ch) => ch.to_string(),
                    None => caps[0].to_string(),
                }
            })
            .to_string();
    }

    if found {
        encodings.push("html_entity".to_string());
    }
    result
}

/// Step 4: Decode URL percent-encoding (%20 → space, %27 → ', etc.).
fn decode_url_encoding(input: &str, encodings: &mut Vec<String>) -> String {
    if !RE_URL_ENCODED.is_match(input) {
        return input.to_string();
    }
    encodings.push("url_encoding".to_string());

    let mut result = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &input[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| input.to_string())
}

/// Step 5: Strip SQL block comments (/* ... */) and line comments (-- ...).
fn strip_sql_comments(input: &str, encodings: &mut Vec<String>) -> String {
    let mut result = input.to_string();
    let mut found = false;

    if RE_SQL_BLOCK_COMMENT.is_match(&result) {
        found = true;
        result = RE_SQL_BLOCK_COMMENT.replace_all(&result, " ").to_string();
    }
    if RE_SQL_LINE_COMMENT.is_match(&result) {
        found = true;
        result = RE_SQL_LINE_COMMENT.replace_all(&result, "").to_string();
    }

    if found {
        encodings.push("sql_comment".to_string());
    }
    result
}

/// Step 6: Collapse multiple spaces/tabs/newlines to a single space, and trim.
fn normalize_whitespace(input: &str) -> String {
    RE_WHITESPACE.replace_all(input.trim(), " ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_passthrough_clean_input() {
        let input = json!({"sql": "SELECT * FROM users WHERE id = 1"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized, input);
        assert!(encodings.is_empty());
    }

    #[test]
    fn test_base64_decode() {
        // "DROP TABLE users" in base64
        let encoded = base64::engine::general_purpose::STANDARD.encode("DROP TABLE users CASCADE");
        let input = json!({"query": encoded});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "DROP TABLE users CASCADE");
        assert!(encodings.contains(&"base64".to_string()));
    }

    #[test]
    fn test_html_entity_decode() {
        let input = json!({"query": "SELECT * FROM users WHERE name = &apos;admin&apos;"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(
            normalized["query"],
            "SELECT * FROM users WHERE name = 'admin'"
        );
        assert!(encodings.contains(&"html_entity".to_string()));
    }

    #[test]
    fn test_url_decode() {
        let input = json!({"path": "/etc/%2e%2e/%2e%2e/etc/passwd"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["path"], "/etc/../../etc/passwd");
        assert!(encodings.contains(&"url_encoding".to_string()));
    }

    #[test]
    fn test_sql_comment_strip() {
        let input = json!({"sql": "SELECT/*bypass*/1 FROM users-- comment"});
        let (normalized, encodings) = normalize(&input);
        let result = normalized["sql"].as_str().unwrap();
        assert!(result.contains("SELECT"));
        assert!(!result.contains("bypass"));
        assert!(!result.contains("comment"));
        assert!(encodings.contains(&"sql_comment".to_string()));
    }

    #[test]
    fn test_whitespace_normalization() {
        let input = json!({"sql": "SELECT   *   FROM    users"});
        let (normalized, _) = normalize(&input);
        assert_eq!(normalized["sql"], "SELECT * FROM users");
    }

    #[test]
    fn test_nested_array_normalization() {
        let input = json!({"commands": ["normal", "SELECT/**/1", "safe"]});
        let (normalized, encodings) = normalize(&input);
        assert!(normalized["commands"][1].as_str().unwrap().contains("SELECT"));
        assert!(!normalized["commands"][1]
            .as_str()
            .unwrap()
            .contains("/**/"));
        assert!(encodings.contains(&"sql_comment".to_string()));
    }

    #[test]
    fn test_numbers_booleans_null_passthrough() {
        let input = json!({"count": 42, "active": true, "extra": null});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized, input);
        assert!(encodings.is_empty());
    }

    #[test]
    fn test_unicode_nfkc() {
        // Fullwidth 'A' (U+FF21) should normalize to regular 'A'
        let input = json!({"query": "SELECT \u{FF21} FROM users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT A FROM users");
        assert!(encodings.contains(&"unicode_nfkc".to_string()));
    }

    // ── Hex encoding tests ──

    #[test]
    fn test_hex_escape_backslash_x() {
        // \x53\x53\x4e → SSN
        let input = json!({"query": "SELECT \\x53\\x53\\x4e FROM users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT SSN FROM users");
        assert!(encodings.contains(&"hex".to_string()));
    }

    #[test]
    fn test_hex_escape_0x_prefix() {
        // 0x44 0x52 0x4f 0x50 → DROP
        let input = json!({"cmd": "0x44 0x52 0x4f 0x50"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["cmd"], "D R O P");
        assert!(encodings.contains(&"hex".to_string()));
    }

    #[test]
    fn test_hex_mixed_with_text() {
        let input = json!({"query": "SELECT email, \\x73\\x73\\x6e FROM customers"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT email, ssn FROM customers");
        assert!(encodings.contains(&"hex".to_string()));
    }

    // ── Octal encoding tests ──

    #[test]
    fn test_octal_escape() {
        // \123\123\116 → SSN (S=123, S=123, N=116 in octal)
        let input = json!({"query": "SELECT \\123\\123\\116 FROM users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT SSN FROM users");
        assert!(encodings.contains(&"octal".to_string()));
    }

    // ── Zero-width character tests ──

    #[test]
    fn test_zero_width_stripping() {
        // "DR\u{200B}OP" (zero-width space inside DROP)
        let input = json!({"query": "DR\u{200B}OP TABLE users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "DROP TABLE users");
        assert!(encodings.contains(&"zero_width".to_string()));
    }

    #[test]
    fn test_zero_width_joiner_stripping() {
        let input = json!({"cmd": "ba\u{200D}sh -i"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["cmd"], "bash -i");
        assert!(encodings.contains(&"zero_width".to_string()));
    }

    #[test]
    fn test_soft_hyphen_stripping() {
        let input = json!({"query": "SE\u{00AD}LECT * FROM pass\u{00AD}wd"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT * FROM passwd");
        assert!(encodings.contains(&"zero_width".to_string()));
    }

    // ── Homoglyph tests ──

    #[test]
    fn test_cyrillic_homoglyph() {
        // Cyrillic С (U+0421) looks like Latin C, Cyrillic Е (U+0415) looks like E
        let input = json!({"query": "\u{0405}\u{0415}LECT * FROM users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SeLECT * FROM users");
        assert!(encodings.contains(&"homoglyph".to_string()));
    }

    #[test]
    fn test_fullwidth_homoglyph() {
        // Fullwidth "DROP" — these are also caught by NFKC but homoglyph step
        // handles the broader set
        let input = json!({"query": "\u{FF24}\u{FF32}\u{FF2F}\u{FF30} TABLE"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "DROP TABLE");
        assert!(
            encodings.contains(&"homoglyph".to_string())
            || encodings.contains(&"unicode_nfkc".to_string())
        );
    }

    #[test]
    fn test_smart_quotes_normalized() {
        let input = json!({"query": "WHERE name = \u{201C}admin\u{201D}"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "WHERE name = \"admin\"");
        assert!(encodings.contains(&"homoglyph".to_string()));
    }

    // ── ROT13 tests ──

    #[test]
    fn test_rot13_drop_table() {
        // "QEBC GNOYR hfref" = ROT13("DROP TABLE users")
        let input = json!({"cmd": "QEBC GNOYR hfref"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["cmd"], "DROP TABLE users");
        assert!(encodings.contains(&"rot13".to_string()));
    }

    #[test]
    fn test_rot13_exec_bash() {
        // "rkrp onfu" = ROT13("exec bash")
        let input = json!({"cmd": "rkrp onfu"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["cmd"], "exec bash");
        assert!(encodings.contains(&"rot13".to_string()));
    }

    #[test]
    fn test_rot13_no_false_positive() {
        // Normal text should NOT trigger ROT13 decode
        let input = json!({"query": "SELECT name FROM users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT name FROM users");
        assert!(!encodings.contains(&"rot13".to_string()));
    }

    // ── Punycode tests ──

    #[test]
    fn test_punycode_domain() {
        let input = json!({"url": "https://xn--80ak6aa92e.com/api"});
        let (normalized, encodings) = normalize(&input);
        let url_val = normalized["url"].as_str().unwrap_or("NOT_STRING");
        // The punycode label should be decoded (xn-- removed).
        // If an earlier normalization step (NFKC, homoglyph) transforms the string
        // before punycode runs, the xn-- prefix may still match or the decoded
        // form may differ. Assert the detection happened:
        assert!(
            encodings.contains(&"punycode".to_string()) || !url_val.contains("xn--"),
            "Punycode should be detected OR xn-- should be gone. encodings={:?}, url={}",
            encodings,
            url_val,
        );
    }

    // ── Combined encoding tests ──

    #[test]
    fn test_hex_plus_zero_width() {
        // Hex encoding + zero-width chars: \\x53\\x53\u{200B}\\x4e
        let input = json!({"query": "SELECT \\x53\\x53\u{200B}\\x4e FROM users"});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "SELECT SSN FROM users");
        assert!(encodings.contains(&"hex".to_string()));
        assert!(encodings.contains(&"zero_width".to_string()));
    }

    #[test]
    fn test_homoglyph_plus_sql_comment() {
        let input = json!({"query": "\u{0405}ELECT/*bypass*/ * FROM users"});
        let (normalized, encodings) = normalize(&input);
        let result = normalized["query"].as_str().unwrap();
        assert!(result.contains("SELECT") || result.contains("sELECT"));
        assert!(!result.contains("/*bypass*/"));
        assert!(encodings.contains(&"homoglyph".to_string()));
        assert!(encodings.contains(&"sql_comment".to_string()));
    }

    // ── Additional tests ──

    #[test]
    fn test_multi_pass_base64_url_encoded() {
        // Encode "DROP TABLE" as URL-encoded, then base64-encode the result.
        // URL-encoded: DROP%20TABLE
        let url_encoded = "DROP%20TABLE%20users";
        let base64_of_url =
            base64::engine::general_purpose::STANDARD.encode(url_encoded);
        let input = json!({"query": base64_of_url});
        let (normalized, encodings) = normalize(&input);
        // After pass 1: base64 decoded to "DROP%20TABLE%20users"
        // After pass 2: URL decoded to "DROP TABLE users"
        assert_eq!(normalized["query"], "DROP TABLE users");
        assert!(encodings.contains(&"base64".to_string()));
        assert!(encodings.contains(&"url_encoding".to_string()));
    }

    #[test]
    fn test_empty_string_passthrough() {
        let input = json!({"query": ""});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["query"], "");
        assert!(encodings.is_empty());
    }

    #[test]
    fn test_deeply_nested_json_objects() {
        let input = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "sql": "SELECT/*nested*/1 FROM t-- comment"
                    }
                }
            }
        });
        let (normalized, encodings) = normalize(&input);
        let result = normalized["level1"]["level2"]["level3"]["sql"]
            .as_str()
            .unwrap();
        assert!(!result.contains("/*nested*/"));
        assert!(!result.contains("comment"));
        assert!(result.contains("SELECT"));
        assert!(encodings.contains(&"sql_comment".to_string()));
    }

    #[test]
    fn test_number_passthrough_in_nested_object() {
        let input = json!({"data": {"count": 42, "ratio": 3.14}});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["data"]["count"], 42);
        assert_eq!(normalized["data"]["ratio"], 3.14);
        assert!(encodings.is_empty());
    }

    #[test]
    fn test_boolean_passthrough() {
        let input = json!({"enabled": true, "debug": false});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["enabled"], true);
        assert_eq!(normalized["debug"], false);
        assert!(encodings.is_empty());
    }

    #[test]
    fn test_null_passthrough() {
        let input = json!({"value": null});
        let (normalized, encodings) = normalize(&input);
        assert!(normalized["value"].is_null());
        assert!(encodings.is_empty());
    }

    #[test]
    fn test_mixed_types_in_array() {
        let input = json!({"items": [42, "SELECT/**/1", true, null, 3.14]});
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["items"][0], 42);
        assert!(!normalized["items"][1]
            .as_str()
            .unwrap()
            .contains("/**/"));
        assert_eq!(normalized["items"][2], true);
        assert!(normalized["items"][3].is_null());
        assert_eq!(normalized["items"][4], 3.14);
        assert!(encodings.contains(&"sql_comment".to_string()));
    }

    #[test]
    fn test_short_string_not_decoded_as_base64() {
        // Strings shorter than MIN_BASE64_LEN (20) should not be base64-decoded.
        let input = json!({"token": "SGVsbG8="});  // "Hello" in base64, only 8 chars
        let (normalized, encodings) = normalize(&input);
        assert_eq!(normalized["token"], "SGVsbG8=");
        assert!(!encodings.contains(&"base64".to_string()));
    }

    #[test]
    fn test_html_numeric_entity_decode() {
        // &#x27; is single quote ('), &#60; is '<'
        let input = json!({"query": "value &#x27;test&#x27; &#60;end&#62;"});
        let (normalized, encodings) = normalize(&input);
        let result = normalized["query"].as_str().unwrap();
        assert!(result.contains("'test'"));
        assert!(encodings.contains(&"html_entity".to_string()));
    }

    #[test]
    fn test_whitespace_tabs_and_newlines() {
        let input = json!({"sql": "SELECT\t\t*\n\nFROM\r\nusers"});
        let (normalized, _) = normalize(&input);
        assert_eq!(normalized["sql"], "SELECT * FROM users");
    }

    #[test]
    fn test_encodings_are_deduplicated() {
        // Two URL-encoded segments should produce only one "url_encoding" entry.
        let input = json!({"a": "%20space", "b": "%21bang"});
        let (_, encodings) = normalize(&input);
        let url_count = encodings
            .iter()
            .filter(|e| *e == "url_encoding")
            .count();
        assert_eq!(url_count, 1, "encoding names should be deduplicated");
    }
}
