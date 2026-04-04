//! Input normalization layer (L4).
//!
//! Pre-processes text before rule evaluation to defeat encoding evasion.
//! Runs on BOTH the original and normalized variants; score = max(original, normalized).
//!
//! Steps:
//! 1. URL-decode (%2e → .)
//! 2. HTML entity decode (&lt; → <)
//! 3. Hex escape decode (\x41 → A)
//! 4. Octal escape decode (\143 → c)
//! 5. Strip zero-width Unicode (U+200B, U+200C, U+200D, U+FEFF, U+2060)
//! 6. Strip BIDI override chars (U+202A–U+202E, U+200E–U+200F, U+2066–U+2069)
//! 7. Normalize Unicode spaces to ASCII space (U+00A0, U+2000–U+200A, U+202F, U+205F, U+3000)
//! 8. NFKC-normalize (fullwidth Ａ → A)
//! 9. Strip Unicode tag chars (U+E0001–U+E007F)
//! 10. Try base64 decode (heuristic)

use regex::Regex;
use std::sync::LazyLock;
use tracing::warn;

/// Maximum recursive decode depth (prevents encoding bombs).
const MAX_DECODE_DEPTH: u8 = 3;

/// P2-11: Maximum size per variant to prevent memory exhaustion on large payloads.
const MAX_VARIANT_SIZE: usize = 256 * 1024; // 256KB per variant

// ── Normalization tuning constants ───────────────────────────────

/// Minimum input length to attempt char-separator stripping (a.b.c.d pattern).
const MIN_CHAR_SEPARATOR_LEN: usize = 7;
/// Minimum input length to attempt dominant-separator detection.
const MIN_DOMINANT_SEP_LEN: usize = 5;
/// Minimum occurrences for a separator to be considered dominant.
const MIN_DOMINANT_SEP_COUNT: usize = 2;
/// Minimum alpha-only variant length to add as variant.
const MIN_ALPHA_ONLY_LEN: usize = 4;
/// Minimum stripped ratio for alpha-only variant (avoids near-duplicates).
const MIN_ALPHA_STRIPPED_RATIO: f64 = 0.10;
/// Minimum result length after dominant separator stripping.
const MIN_DOMINANT_STRIPPED_LEN: usize = 4;
/// Minimum input length to attempt ROT13 decode.
const MIN_ROT13_LEN: usize = 8;
/// Minimum suspicious keyword matches for ROT13 to return a variant.
const MIN_ROT13_KEYWORD_MATCHES: usize = 1;
/// Minimum word count for fragmentation detection.
const MIN_FRAGMENT_WORD_COUNT: usize = 4;
/// Maximum word length to count as "short" for fragmentation heuristic.
const SHORT_WORD_MAX_LEN: usize = 4;
/// Minimum accumulated buffer length before flushing a merged word.
const MERGE_FLUSH_MIN_LEN: usize = 4;
/// Maximum accumulated merge buffer before forced flush.
const MERGE_FLUSH_MAX_LEN: usize = 12;

// ── Compiled patterns ──────────────────────────────────────────────

static RE_URL_ENCODED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"%([0-9A-Fa-f]{2})").unwrap());

static RE_HTML_ENTITY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"&(amp|lt|gt|quot|apos|#(\d{1,5})|#x([0-9A-Fa-f]{1,4}));").unwrap());

static RE_HEX_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\x([0-9A-Fa-f]{2})").unwrap());

static RE_OCTAL_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\([0-3][0-7]{2})").unwrap());

static RE_UNICODE_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\u\{?([0-9A-Fa-f]{4,6})\}?").unwrap());

static RE_BASE64_CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap());

/// Matches short evasion comments like /**/ or /* */ (empty or whitespace-only body).
/// These are used to split keywords: DR/**/OP → DROP
static RE_SQL_EVASION_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\*\s*\*/").unwrap());

/// Matches block comments with actual content: /* real comment */
static RE_SQL_BLOCK_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\*.+?\*/").unwrap());

static RE_SQL_LINE_COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"--[^\n]*").unwrap());

// ── Public API ─────────────────────────────────────────────────────

/// Normalize a single pass: URL-decode → HTML entities → hex/unicode escapes
/// → strip zero-width → NFKC → strip tag chars.
pub fn normalize(text: &str) -> String {
    // Phase A: Regex-based decoders (5 allocations — unavoidable)
    let mut out = decode_url_encoding(text);
    out = decode_html_entities(&out);
    out = decode_hex_escapes(&out);
    out = decode_octal_escapes(&out);
    out = decode_unicode_escapes(&out);
    // Phase B: Combined char-level filters + maps (1 allocation instead of 6)
    out = char_level_normalize(&out);
    // Phase C: Regex-based SQL comment stripping (1 allocation)
    out = strip_sql_comments(&out);
    // Phase D: Strip character-level obfuscation separators
    // "I.g.n.o.r.e" or "I-g-n-o-r-e" or "I G N O R E" → "Ignore"
    // Only applies when single chars are separated by consistent delimiters
    out = strip_char_separators(&out);
    out
}

/// Strip single-character obfuscation: "I.g.n.o.r.e" → "Ignore"
/// Detects when single alpha chars are separated by a consistent delimiter.
/// Works for: . - / _ | + ~ :
fn strip_char_separators(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < MIN_CHAR_SEPARATOR_LEN {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut i = 0;

    while i < chars.len() {
        // Check: alpha + separator + alpha + same_separator + alpha + same_separator + alpha
        if i + 6 <= chars.len()
            && chars[i].is_alphabetic()
            && is_obfusc_sep(chars[i + 1])
            && chars[i + 2].is_alphabetic()
            && chars[i + 3] == chars[i + 1]
            && chars[i + 4].is_alphabetic()
            && chars[i + 5] == chars[i + 1]
            && chars[i + 6].is_alphabetic()
        {
            let sep = chars[i + 1];
            // Consume the entire char-separated run
            result.push(chars[i]);
            i += 1;
            while i + 1 < chars.len() && chars[i] == sep && chars[i + 1].is_alphabetic() {
                result.push(chars[i + 1]);
                i += 2;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

fn is_obfusc_sep(c: char) -> bool {
    matches!(c, '.' | '-' | '/' | '_' | '|' | '+' | '~' | ':')
}

/// Find the most frequent non-alnum character that appears between single alpha chars,
/// then strip ONLY that character. Preserves structural separators.
///
/// Algorithm:
/// 1. For each non-alnum char, count how many times it appears between single alpha chars
/// 2. The char with highest count is the obfuscation separator
/// 3. Strip only that char, leave everything else intact
fn strip_dominant_separator(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() < MIN_DOMINANT_SEP_LEN {
        return None;
    }

    // Count separator frequency between single alpha chars
    let mut sep_counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for i in 1..chars.len().saturating_sub(1) {
        if !chars[i].is_alphanumeric() && !chars[i].is_whitespace() {
            // Check if it's between alpha chars
            let prev_alpha = chars[..i].iter().rev()
                .take_while(|c| !c.is_whitespace())
                .filter(|c| c.is_alphabetic())
                .count();
            let next_alpha = chars[i+1..].iter()
                .take_while(|c| !c.is_whitespace())
                .filter(|c| c.is_alphabetic())
                .count();
            // If surrounding context has single chars separated by this separator
            if prev_alpha <= 2 && next_alpha >= 1 {
                *sep_counts.entry(chars[i]).or_insert(0) += 1;
            }
        }
    }

    if sep_counts.is_empty() {
        return None;
    }

    // Find the dominant separator (most frequent)
    let (&dominant_sep, &count) = sep_counts.iter().max_by_key(|(_, &v)| v)?;

    // Must appear at least N times to be considered obfuscation
    if count < MIN_DOMINANT_SEP_COUNT {
        return None;
    }

    // Strip only the dominant separator
    let result: String = chars.iter()
        .filter(|&&c| c != dominant_sep)
        .collect();

    if result == text {
        return None;
    }

    Some(result)
}

/// Combined char-level normalization: strip + map in a single pass.
/// Fuses strip_zero_width_chars, strip_bidi_chars, strip_unicode_spaces,
/// normalize_nfkc, normalize_homoglyphs, and strip_unicode_tags into one
/// `.chars().filter_map().collect()` — 1 allocation instead of 6.
/// Output is byte-for-byte identical to the sequential 6-function chain.
fn char_level_normalize(text: &str) -> String {
    text.chars()
        .filter_map(|c| {
            // Step 1: Filter — strip zero-width chars
            if matches!(c,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{00AD}'
            ) {
                return None;
            }
            // Step 2: Filter — strip BIDI overrides
            if matches!(c,
                '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
                | '\u{200E}' | '\u{200F}'
                | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
            ) {
                return None;
            }
            // Step 3: Filter — strip Unicode tag chars (U+E0001–U+E007F)
            let cp = c as u32;
            if (0xE0001..=0xE007F).contains(&cp) {
                return None;
            }
            // Step 4: Map — normalize Unicode spaces to ASCII space
            let c = match c {
                '\u{00A0}' | '\u{2000}' | '\u{2001}' | '\u{2002}' | '\u{2003}'
                | '\u{2004}' | '\u{2005}' | '\u{2006}' | '\u{2007}' | '\u{2008}'
                | '\u{2009}' | '\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => ' ',
                _ => c,
            };
            // Step 5: Map — NFKC fullwidth ASCII (U+FF01–U+FF5E → U+0021–U+007E)
            let cp = c as u32;
            let c = if (0xFF01..=0xFF5E).contains(&cp) {
                char::from_u32(cp - 0xFF01 + 0x0021).unwrap_or(c)
            } else {
                c
            };
            // Step 6: Map — homoglyph normalization (Cyrillic/Greek → Latin)
            let c = match c {
                // Cyrillic uppercase → Latin
                '\u{0410}' => 'a', '\u{0412}' => 'b', '\u{0421}' => 'c', '\u{0415}' => 'e',
                '\u{041D}' => 'h', '\u{0406}' => 'i', '\u{041A}' => 'k', '\u{041C}' => 'm',
                '\u{041E}' => 'o', '\u{0420}' => 'p', '\u{0422}' => 't', '\u{0425}' => 'x',
                '\u{0423}' => 'y',
                // Cyrillic lowercase → Latin
                '\u{0430}' => 'a', '\u{0432}' => 'b', '\u{0441}' => 'c', '\u{0435}' => 'e',
                '\u{043D}' => 'h', '\u{0456}' => 'i', '\u{043A}' => 'k', '\u{043C}' => 'm',
                '\u{043E}' => 'o', '\u{0440}' => 'p', '\u{0442}' => 't', '\u{0445}' => 'x',
                '\u{0443}' => 'y',
                // Greek uppercase → Latin
                '\u{0391}' => 'a', '\u{0392}' => 'b', '\u{0395}' => 'e', '\u{0397}' => 'h',
                '\u{0399}' => 'i', '\u{039A}' => 'k', '\u{039C}' => 'm', '\u{039D}' => 'n',
                '\u{039F}' => 'o', '\u{03A1}' => 'p', '\u{03A4}' => 't', '\u{03A7}' => 'x',
                '\u{03A5}' => 'y', '\u{0396}' => 'z',
                // Greek lowercase → Latin
                '\u{03B1}' => 'a', '\u{03B2}' => 'b', '\u{03B5}' => 'e', '\u{03B7}' => 'h',
                '\u{03B9}' => 'i', '\u{03BA}' => 'k', '\u{03BC}' => 'm', '\u{03BD}' => 'n',
                '\u{03BF}' => 'o', '\u{03C1}' => 'p', '\u{03C4}' => 't', '\u{03C7}' => 'x',
                '\u{03C5}' => 'y', '\u{03B6}' => 'z',
                _ => c,
            };
            Some(c)
        })
        .collect()
}

/// Produce all decode variants (original + up to MAX_DECODE_DEPTH rounds).
/// Also tries base64 decode if the input looks like base64.
pub fn normalize_variants(text: &str) -> Vec<String> {
    let mut variants = Vec::with_capacity(4);

    // P2-11: Cap input size to prevent memory exhaustion on large payloads
    if text.len() > MAX_VARIANT_SIZE {
        warn!("Input exceeds {}KB — truncating for normalization", MAX_VARIANT_SIZE / 1024);
        variants.push(text[..MAX_VARIANT_SIZE].to_string());
        return variants;
    }

    variants.push(text.to_string());

    let mut current = text.to_string();
    for _ in 0..MAX_DECODE_DEPTH {
        let decoded = normalize(&current);
        if decoded == current {
            break; // fixed point
        }
        // P2-11: Don't add variant if it exceeds size cap (e.g., base64 expansion)
        if decoded.len() > MAX_VARIANT_SIZE {
            warn!("Decoded variant exceeds size cap — skipping");
            break;
        }
        variants.push(decoded.clone());
        current = decoded;
    }

    // Try base64 decode on the original (heuristic: long alnum+/= block)
    if let Some(decoded) = try_base64_decode(text) {
        // Only include if it decoded to valid UTF-8 with printable chars
        if decoded.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
            variants.push(decoded);
        }
    }

    // Try ROT13 decode — only add variant if decoded text contains suspicious keywords
    if let Some(decoded) = try_rot13_decode(text) {
        variants.push(decoded);
    }

    // Try space-collapse for fragmented-word evasion (e.g., "Ig nore prev ious")
    if let Some(rejoined) = rejoin_fragmented_words(text) {
        variants.push(rejoined);
    }

    // Also try full collapse (all whitespace removed) — catches heavily fragmented text
    // Only if text has many short words (same heuristic as rejoin)
    if let Some(collapsed) = try_full_collapse(text) {
        variants.push(collapsed);
    }

    // Alpha-only variant: the simplest and most powerful deobfuscation.
    // Strip EVERYTHING except letters. No heuristics, no thresholds.
    //
    // "I g n o r e"         → "Ignore"          (any separator)
    // "I.g.n.o.r.e"         → "Ignore"          (dots)
    // "D-R-O-P T-A-B-L-E"  → "DROPTABLE"        (dashes + spaces)
    // "/e.t.c/p.a.s.s.w.d" → "etcpasswd"        (dots + slashes)
    // "r.m -r.f /"          → "rmrf"             (dots + dashes)
    // "Ig nore prev ious"   → "Ignoreprevious"   (word fragments)
    //
    // R143 matches dangerous concatenations: ignoreprevious, droptable, rmrf, etc.
    // Safe text like "SELECT FROM users" → "SELECTFROMusers" does NOT match R143.
    let alpha_only: String = text.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha_only.len() >= MIN_ALPHA_ONLY_LEN && alpha_only.len() < text.len() {
        // Only add if stripping actually removed something (avoids duplicate of plain text)
        let stripped_ratio = 1.0 - (alpha_only.len() as f64 / text.len() as f64);
        if stripped_ratio > MIN_ALPHA_STRIPPED_RATIO {
            variants.push(alpha_only);
        }
    }

    // Also keep dominant-separator stripping for structural preservation
    // "/e.t.c/p.a.s.s.w.d" → "/etc/passwd" (preserves path structure for R008)
    if let Some(stripped) = strip_dominant_separator(text) {
        if stripped != text && stripped.len() >= MIN_DOMINANT_STRIPPED_LEN {
            variants.push(stripped);
        }
    }

    variants
}

// ── Decoders ───────────────────────────────────────────────────────

fn decode_url_encoding(text: &str) -> String {
    RE_URL_ENCODED
        .replace_all(text, |caps: &regex::Captures| {
            let hex = &caps[1];
            match u8::from_str_radix(hex, 16) {
                Ok(byte) if byte.is_ascii() => String::from(byte as char),
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

fn decode_html_entities(text: &str) -> String {
    RE_HTML_ENTITY
        .replace_all(text, |caps: &regex::Captures| {
            match &caps[1] {
                "amp" => "&".to_string(),
                "lt" => "<".to_string(),
                "gt" => ">".to_string(),
                "quot" => "\"".to_string(),
                "apos" => "'".to_string(),
                _ => {
                    // Numeric entity: &#123; or &#x1A;
                    if let Some(dec) = caps.get(2) {
                        if let Ok(n) = dec.as_str().parse::<u32>() {
                            if let Some(c) = char::from_u32(n) {
                                return c.to_string();
                            }
                        }
                    }
                    if let Some(hex) = caps.get(3) {
                        if let Ok(n) = u32::from_str_radix(hex.as_str(), 16) {
                            if let Some(c) = char::from_u32(n) {
                                return c.to_string();
                            }
                        }
                    }
                    caps[0].to_string()
                }
            }
        })
        .into_owned()
}

fn decode_hex_escapes(text: &str) -> String {
    RE_HEX_ESCAPE
        .replace_all(text, |caps: &regex::Captures| {
            match u8::from_str_radix(&caps[1], 16) {
                Ok(byte) if byte.is_ascii() => String::from(byte as char),
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

/// Decode octal escapes: \NNN (where N is 0-7) → ASCII character.
/// Catches payloads like: /bin/sh -c '\143\141\164 /etc/passwd' → cat /etc/passwd
fn decode_octal_escapes(text: &str) -> String {
    RE_OCTAL_ESCAPE
        .replace_all(text, |caps: &regex::Captures| {
            match u8::from_str_radix(&caps[1], 8) {
                Ok(byte) if byte.is_ascii() => String::from(byte as char),
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

fn decode_unicode_escapes(text: &str) -> String {
    RE_UNICODE_ESCAPE
        .replace_all(text, |caps: &regex::Captures| {
            match u32::from_str_radix(&caps[1], 16) {
                Ok(n) => match char::from_u32(n) {
                    Some(c) => c.to_string(),
                    None => caps[0].to_string(),
                },
                Err(_) => caps[0].to_string(),
            }
        })
        .into_owned()
}

fn strip_zero_width_chars(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(
            *c,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}'
            | '\u{00AD}'  // soft hyphen
        ))
        .collect()
}

/// Strip Unicode bidirectional override and isolate characters.
/// These can visually reorder displayed text to hide malicious content.
fn strip_bidi_chars(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(
            *c,
            '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}'
            | '\u{200E}' | '\u{200F}'
            | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
        ))
        .collect()
}

/// Strip Unicode space characters that bypass \s regex matching.
/// Standard ASCII space (U+0020) is preserved — only exotic spaces replaced.
fn strip_unicode_spaces(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{00A0}' // non-breaking space
            | '\u{2000}' // en quad
            | '\u{2001}' // em quad
            | '\u{2002}' // en space
            | '\u{2003}' // em space
            | '\u{2004}' // three-per-em space
            | '\u{2005}' // four-per-em space
            | '\u{2006}' // six-per-em space
            | '\u{2007}' // figure space
            | '\u{2008}' // punctuation space
            | '\u{2009}' // thin space
            | '\u{200A}' // hair space
            | '\u{202F}' // narrow no-break space
            | '\u{205F}' // medium mathematical space
            | '\u{3000}' // ideographic space
            => ' ', // Replace with standard ASCII space
            _ => c,
        })
        .collect()
}

/// Normalize visual homoglyphs (Cyrillic/Greek lookalikes) to ASCII equivalents.
/// NFKC does NOT handle these because they are distinct Unicode codepoints.
/// Example: Cyrillic 'О' (U+041E) looks identical to Latin 'O' (U+004F).
fn normalize_homoglyphs(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            // Cyrillic uppercase → Latin lowercase
            '\u{0410}' => 'a', // А
            '\u{0412}' => 'b', // В (looks like B)
            '\u{0421}' => 'c', // С
            '\u{0415}' => 'e', // Е
            '\u{041D}' => 'h', // Н (looks like H)
            '\u{0406}' => 'i', // І (Ukrainian)
            '\u{041A}' => 'k', // К
            '\u{041C}' => 'm', // М
            '\u{041E}' => 'o', // О
            '\u{0420}' => 'p', // Р (looks like P)
            '\u{0422}' => 't', // Т
            '\u{0425}' => 'x', // Х (looks like X)
            '\u{0423}' => 'y', // У (looks like Y)
            // Cyrillic lowercase → Latin lowercase
            '\u{0430}' => 'a', // а
            '\u{0432}' => 'b', // в
            '\u{0441}' => 'c', // с
            '\u{0435}' => 'e', // е
            '\u{043D}' => 'h', // н
            '\u{0456}' => 'i', // і
            '\u{043A}' => 'k', // к
            '\u{043C}' => 'm', // м
            '\u{043E}' => 'o', // о
            '\u{0440}' => 'p', // р
            '\u{0442}' => 't', // т
            '\u{0445}' => 'x', // х
            '\u{0443}' => 'y', // у
            // Greek uppercase → Latin lowercase
            '\u{0391}' => 'a', // Α (Alpha)
            '\u{0392}' => 'b', // Β (Beta)
            '\u{0395}' => 'e', // Ε (Epsilon)
            '\u{0397}' => 'h', // Η (Eta)
            '\u{0399}' => 'i', // Ι (Iota)
            '\u{039A}' => 'k', // Κ (Kappa)
            '\u{039C}' => 'm', // Μ (Mu)
            '\u{039D}' => 'n', // Ν (Nu)
            '\u{039F}' => 'o', // Ο (Omicron)
            '\u{03A1}' => 'p', // Ρ (Rho)
            '\u{03A4}' => 't', // Τ (Tau)
            '\u{03A7}' => 'x', // Χ (Chi)
            '\u{03A5}' => 'y', // Υ (Upsilon)
            '\u{0396}' => 'z', // Ζ (Zeta)
            // Greek lowercase → Latin lowercase
            '\u{03B1}' => 'a', // α
            '\u{03B2}' => 'b', // β
            '\u{03B5}' => 'e', // ε
            '\u{03B7}' => 'h', // η
            '\u{03B9}' => 'i', // ι
            '\u{03BA}' => 'k', // κ
            '\u{03BC}' => 'm', // μ
            '\u{03BD}' => 'n', // ν
            '\u{03BF}' => 'o', // ο
            '\u{03C1}' => 'p', // ρ
            '\u{03C4}' => 't', // τ
            '\u{03C7}' => 'x', // χ
            '\u{03C5}' => 'y', // υ
            '\u{03B6}' => 'z', // ζ
            _ => c,
        })
        .collect()
}

/// NFKC normalization: fullwidth → ASCII, compatibility decomposition.
/// Manual mapping for the most common attack vectors (fullwidth ASCII range FF01-FF5E).
fn normalize_nfkc(text: &str) -> String {
    text.chars()
        .map(|c| {
            let cp = c as u32;
            // Fullwidth ASCII variants: U+FF01 (！) → U+0021 (!), ... U+FF5E (～) → U+007E (~)
            if (0xFF01..=0xFF5E).contains(&cp) {
                char::from_u32(cp - 0xFF01 + 0x0021).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

fn strip_unicode_tags(text: &str) -> String {
    text.chars()
        .filter(|c| {
            let cp = *c as u32;
            // Unicode Tags block: U+E0001–U+E007F
            !(0xE0001..=0xE007F).contains(&cp)
        })
        .collect()
}

/// Strip SQL comments: `/* ... */` block comments and `--` line comments.
/// Short evasion comments (/**/) are removed entirely so DR/**/OP → DROP.
/// Long block comments (/* real comment */) are replaced with space.
fn strip_sql_comments(input: &str) -> String {
    // Phase 1: Remove evasion comments (empty/whitespace body) → join split keywords
    let result = RE_SQL_EVASION_COMMENT.replace_all(input, "");
    // Phase 2: Replace substantive block comments with space
    let result = RE_SQL_BLOCK_COMMENT.replace_all(&result, " ");
    // Phase 3: Replace line comments with space
    RE_SQL_LINE_COMMENT.replace_all(&result, " ").to_string()
}

fn try_base64_decode(text: &str) -> Option<String> {
    // Only try if the text looks like a base64 blob
    let trimmed = text.trim();
    if !RE_BASE64_CANDIDATE.is_match(trimmed) {
        return None;
    }

    let bytes = base64_decode(trimmed)?;
    String::from_utf8(bytes).ok()
}

/// Simple base64 decoder (no external crate dependency).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let chunks = bytes.chunks(4);

    for chunk in chunks {
        let vals: Vec<u8> = chunk.iter().filter_map(|&b| val(b)).collect();
        if vals.len() < 2 {
            return None;
        }
        output.push((vals[0] << 2) | (vals[1] >> 4));
        if vals.len() > 2 {
            output.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if vals.len() > 3 {
            output.push((vals[2] << 6) | vals[3]);
        }
    }

    Some(output)
}

/// Try ROT13 decode. Only returns Some if the decoded text contains
/// at least 2 suspicious keywords — prevents false positives since
/// every ASCII text has a valid ROT13 encoding.
fn try_rot13_decode(input: &str) -> Option<String> {
    // Only try on mostly-ASCII text with enough length
    if input.len() < MIN_ROT13_LEN {
        return None;
    }

    let decoded: String = input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect();

    // Heuristic: only return if decoded contains suspicious keywords.
    // Comprehensive list covering SQL, shell, filesystem, network, and injection terms.
    static SUSPICIOUS_WORDS: &[&str] = &[
        // SQL
        "drop", "select", "table", "delete", "exec", "from", "insert",
        "update", "union", "where", "grant", "truncate", "alter",
        // Shell commands
        "bash", "shell", "sudo", "chmod", "chown", "cat", "rm", "mv", "cp",
        "wget", "curl", "nc", "ncat", "python", "perl", "ruby", "php",
        "whoami", "uname", "ifconfig", "nslookup", "dig", "nmap", "ssh",
        "scp", "rsync", "tar", "gzip", "unzip", "crontab", "kill",
        "pkill", "nohup", "screen", "tmux", "awk", "sed", "grep",
        "find", "xargs", "eval", "source", "export", "env", "printenv",
        // Filesystem paths
        "etc", "passwd", "shadow", "proc", "sys", "dev", "tmp", "var",
        "home", "root", "bin", "sbin", "usr",
        // Sensitive files
        "password", "admin", "secret", "token", "credential", "key",
        "config", "htpasswd", "authorized_keys", "id_rsa",
        // Prompt injection
        "ignore", "previous", "instructions", "system", "prompt",
        "override", "bypass", "disable", "jailbreak",
        // Network/exfil
        "http", "https", "ftp", "dns", "smtp", "connect", "listen",
        "bind", "socket", "pipe", "redirect", "proxy", "tunnel",
        // File operations
        "remove", "file", "write", "read", "open", "create", "append",
    ];
    let lower = decoded.to_lowercase();
    let matches = SUSPICIOUS_WORDS.iter().filter(|w| lower.contains(**w)).count();

    // 1 keyword is enough — if someone ROT13-encodes text containing
    // "passwd", "rm", "cat", etc., that's already suspicious
    if matches >= MIN_ROT13_KEYWORD_MATCHES {
        Some(decoded)
    } else {
        None
    }
}

/// Rejoin words fragmented by space insertion (e.g., "Ig nore prev ious" → "Ignore previous").
/// Heuristic: if >50% of whitespace-separated tokens are 1-3 chars, greedily merge short tokens
/// into groups, inserting spaces between groups when the accumulated length reaches a plausible
/// word length (>= 4 chars and the next token starts a new "word").
fn rejoin_fragmented_words(input: &str) -> Option<String> {
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() < MIN_FRAGMENT_WORD_COUNT {
        return None;
    }

    let short_count = words.iter().filter(|w| w.len() <= SHORT_WORD_MAX_LEN).count();
    if short_count < words.len() / 2 {
        return None; // Not fragmented
    }

    // Greedily merge consecutive short tokens. When accumulated buffer reaches
    // MERGE_FLUSH_MIN_LEN and next token starts an uppercase letter or the buffer
    // would exceed MERGE_FLUSH_MAX_LEN, flush with a space.
    let mut result = String::new();
    let mut buf = String::new();

    for (i, word) in words.iter().enumerate() {
        if word.len() > SHORT_WORD_MAX_LEN {
            // Long word — flush buffer, add space, add this word
            if !buf.is_empty() {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(&buf);
                buf.clear();
            }
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(word);
        } else {
            // Short word — accumulate
            let new_len = buf.len() + word.len();
            // Flush buffer if it's already word-length and this starts a new word boundary
            if buf.len() >= MERGE_FLUSH_MIN_LEN && (new_len > MERGE_FLUSH_MAX_LEN || (i > 0 && word.chars().next().map_or(false, |c| c.is_uppercase()))) {
                if !result.is_empty() {
                    result.push(' ');
                }
                result.push_str(&buf);
                buf.clear();
            }
            buf.push_str(word);
        }
    }
    // Flush remaining buffer
    if !buf.is_empty() {
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(&buf);
    }

    let rejoined = result.trim().to_string();
    if rejoined == input {
        return None;
    }
    Some(rejoined)
}

/// Full space collapse — removes all whitespace when text appears heavily fragmented.
/// Produces a single blob like "ignorepreviousinstructions" that can match rules
/// with `\s*` patterns (e.g., DROP\s*TABLE).
fn try_full_collapse(input: &str) -> Option<String> {
    let words: Vec<&str> = input.split_whitespace().collect();
    if words.len() < MIN_FRAGMENT_WORD_COUNT {
        return None;
    }
    let short_count = words.iter().filter(|w| w.len() <= SHORT_WORD_MAX_LEN).count();
    if short_count < words.len() / 2 {
        return None;
    }
    let collapsed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if collapsed == input {
        return None;
    }
    Some(collapsed)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(decode_url_encoding("%2e%2e%2f"), "../");
        assert_eq!(decode_url_encoding("%2E%2E%5C"), "..\\");
        assert_eq!(decode_url_encoding("hello%20world"), "hello world");
    }

    #[test]
    fn test_double_url_encode() {
        // %252e → first pass: %2e → second pass: .
        let first = decode_url_encoding("%252e%252e%252f");
        assert_eq!(first, "%2e%2e%2f");
        let second = decode_url_encoding(&first);
        assert_eq!(second, "../");
    }

    #[test]
    fn test_html_entities() {
        assert_eq!(decode_html_entities("&lt;script&gt;"), "<script>");
        assert_eq!(decode_html_entities("&amp;"), "&");
        assert_eq!(decode_html_entities("&#60;"), "<"); // numeric
        assert_eq!(decode_html_entities("&#x3C;"), "<"); // hex
    }

    #[test]
    fn test_hex_escapes() {
        // \x44\x52\x4f\x50 = DROP
        assert_eq!(decode_hex_escapes("\\x44\\x52\\x4f\\x50"), "DROP");
        assert_eq!(decode_hex_escapes("\\x53\\x53\\x4e"), "SSN");
    }

    #[test]
    fn test_unicode_escapes() {
        assert_eq!(decode_unicode_escapes("\\u0041"), "A");
        assert_eq!(decode_unicode_escapes("\\u{0041}"), "A");
    }

    #[test]
    fn test_strip_zero_width() {
        // D + ZWS + R + ZWS + O + ZWS + P
        let input = "D\u{200B}R\u{200B}O\u{200B}P";
        assert_eq!(strip_zero_width_chars(input), "DROP");
    }

    #[test]
    fn test_nfkc_fullwidth() {
        // Fullwidth ＤＲＯＰ
        let input = "\u{FF24}\u{FF32}\u{FF2F}\u{FF30}";
        assert_eq!(normalize_nfkc(input), "DROP");

        let input2 = "\u{FF33}\u{FF25}\u{FF2C}\u{FF25}\u{FF23}\u{FF34}";
        assert_eq!(normalize_nfkc(input2), "SELECT");
    }

    #[test]
    fn test_strip_unicode_tags() {
        // Tag characters mixed in: D + tag_D + R + tag_R
        let input = format!("D{}R{}OP", '\u{E0044}', '\u{E0052}');
        assert_eq!(strip_unicode_tags(&input), "DROP");
    }

    #[test]
    fn test_base64_decode() {
        // "DROP TABLE users" = RFJPUCBUQUJMRSB1c2Vycw==
        let encoded = "RFJPUCBUQUJMRSB1c2Vycw==";
        let decoded = try_base64_decode(encoded);
        assert_eq!(decoded, Some("DROP TABLE users".to_string()));
    }

    #[test]
    fn test_base64_short_string_ignored() {
        // Short strings should NOT be decoded
        assert_eq!(try_base64_decode("hello"), None);
        assert_eq!(try_base64_decode("abc"), None);
    }

    #[test]
    fn test_normalize_full_pipeline() {
        // URL-encoded path traversal
        assert_eq!(normalize("%2e%2e%2fetc%2fpasswd"), "../etc/passwd");

        // Hex-encoded DROP
        assert_eq!(normalize("\\x44\\x52\\x4f\\x50 TABLE users"), "DROP TABLE users");

        // Zero-width char insertion
        assert_eq!(normalize("D\u{200B}R\u{200B}O\u{200B}P TABLE"), "DROP TABLE");

        // Fullwidth
        assert_eq!(
            normalize("\u{FF24}\u{FF32}\u{FF2F}\u{FF30} TABLE"),
            "DROP TABLE"
        );
    }

    #[test]
    fn test_normalize_variants() {
        let variants = normalize_variants("%252e%252e%252f");
        // Original, first decode (%2e%2e%2f), second decode (../)
        assert!(variants.len() >= 3);
        assert!(variants.contains(&"../".to_string()));
    }

    #[test]
    fn test_normalize_passthrough_clean() {
        // Clean text should come through unchanged
        let clean = "SELECT name, email FROM users WHERE id = 5";
        assert_eq!(normalize(clean), clean);
    }

    #[test]
    fn test_normalize_variants_base64_attack() {
        // Base64-encoded "DROP TABLE users"
        let variants = normalize_variants("RFJPUCBUQUJMRSB1c2Vycw==");
        assert!(variants.iter().any(|v| v.contains("DROP TABLE")));
    }

    #[test]
    fn test_mixed_encoding_attack() {
        // HTML entity + hex escape in one string
        let input = "&lt;script&gt;\\x61lert(1)";
        let normalized = normalize(input);
        assert_eq!(normalized, "<script>alert(1)");
    }

    // ── Octal escape tests ──────────────────────────────────────────

    #[test]
    fn test_octal_escapes_basic() {
        // \123\123\116 = SSN
        assert_eq!(decode_octal_escapes("\\123\\123\\116"), "SSN");
    }

    #[test]
    fn test_octal_escapes_cat_etc_passwd() {
        // \143\141\164 = cat
        assert_eq!(decode_octal_escapes("\\143\\141\\164"), "cat");
    }

    #[test]
    fn test_octal_escapes_shell_bypass() {
        let input = "/bin/sh -c '\\143\\141\\164 /etc/passwd'";
        let decoded = decode_octal_escapes(input);
        assert_eq!(decoded, "/bin/sh -c 'cat /etc/passwd'");
    }

    #[test]
    fn test_octal_escapes_space() {
        // \040 = space
        assert_eq!(decode_octal_escapes("hello\\040world"), "hello world");
    }

    #[test]
    fn test_octal_escapes_drop() {
        // \104\122\117\120 = DROP
        assert_eq!(decode_octal_escapes("\\104\\122\\117\\120"), "DROP");
    }

    #[test]
    fn test_octal_no_false_positive() {
        let clean = "SELECT name FROM users WHERE id = 5";
        assert_eq!(decode_octal_escapes(clean), clean);
    }

    #[test]
    fn test_octal_invalid_range_ignored() {
        // \400 is not matched by regex (first digit must be 0-3)
        let input = "\\400";
        assert_eq!(decode_octal_escapes(input), input);
    }

    // ── BIDI stripping tests ────────────────────────────────────────

    #[test]
    fn test_strip_bidi_lro_rlo() {
        let input = format!("{}DROP TABLE{}", '\u{202D}', '\u{202E}');
        assert_eq!(strip_bidi_chars(&input), "DROP TABLE");
    }

    #[test]
    fn test_strip_bidi_lre_rle_pdf() {
        let input = format!("{}SELECT{}{}", '\u{202A}', '\u{202B}', '\u{202C}');
        assert_eq!(strip_bidi_chars(&input), "SELECT");
    }

    #[test]
    fn test_strip_bidi_directional_marks() {
        let input = format!("rm{} -rf{} /", '\u{200E}', '\u{200F}');
        assert_eq!(strip_bidi_chars(&input), "rm -rf /");
    }

    #[test]
    fn test_strip_bidi_isolates() {
        let input = format!("{}rm{} -rf{} /{}", '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}');
        assert_eq!(strip_bidi_chars(&input), "rm -rf /");
    }

    #[test]
    fn test_strip_bidi_no_false_positive() {
        let clean = "SELECT name FROM users";
        assert_eq!(strip_bidi_chars(clean), clean);
    }

    #[test]
    fn test_strip_bidi_all_chars() {
        // All 11 BIDI chars in one string
        let input = format!(
            "{}{}{}{}{}{}{}{}{}{}{}test",
            '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}',
            '\u{200E}', '\u{200F}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}'
        );
        assert_eq!(strip_bidi_chars(&input), "test");
    }

    // ── Combined pipeline tests ─────────────────────────────────────

    #[test]
    fn test_octal_in_full_pipeline() {
        // Octal-encoded "cat /etc/passwd" should be decoded in the pipeline
        let normalized = normalize("/bin/sh -c '\\143\\141\\164 /etc/passwd'");
        assert!(normalized.contains("cat /etc/passwd"));
    }

    #[test]
    fn test_bidi_in_full_pipeline() {
        let input = format!("{}DROP TABLE users{}", '\u{202D}', '\u{202E}');
        let normalized = normalize(&input);
        assert_eq!(normalized, "DROP TABLE users");
    }

    // ── Unicode space stripping tests ─────────────────────────────────

    #[test]
    fn test_strip_unicode_spaces_nbsp() {
        assert_eq!(strip_unicode_spaces("DROP\u{00A0}TABLE"), "DROP TABLE");
    }

    #[test]
    fn test_strip_unicode_spaces_ideographic() {
        assert_eq!(strip_unicode_spaces("SELECT\u{3000}*\u{3000}FROM"), "SELECT * FROM");
    }

    #[test]
    fn test_strip_unicode_spaces_preserves_ascii() {
        assert_eq!(strip_unicode_spaces("DROP TABLE users"), "DROP TABLE users");
    }

    // ── SQL comment stripping tests ─────────────────────────────────

    #[test]
    fn test_strip_sql_block_comments() {
        // Evasion comments (empty body) are removed entirely to rejoin split keywords
        assert_eq!(strip_sql_comments("DR/**/OP/**/TA/**/BLE/**/users"), "DROPTABLEusers");
    }

    #[test]
    fn test_strip_sql_line_comments() {
        assert_eq!(strip_sql_comments("DROP TABLE users -- this is a comment"), "DROP TABLE users  ");
    }

    #[test]
    fn test_strip_sql_comments_mixed() {
        // "/*comment*/" has content so it becomes space; "--" line comment becomes space
        assert_eq!(
            strip_sql_comments("SEL/*comment*/ECT * FROM users -- get all"),
            "SEL ECT * FROM users  "
        );
    }

    #[test]
    fn test_strip_sql_comments_no_false_positive() {
        let clean = "SELECT name FROM users WHERE id = 5";
        assert_eq!(strip_sql_comments(clean), clean);
    }

    #[test]
    fn test_sql_comment_evasion_in_full_pipeline() {
        // DR/**/OP/**/TABLE evasion comments removed entirely → keywords rejoin
        let normalized = normalize("DR/**/OP/**/TA/**/BLE/**/users");
        assert!(normalized.contains("DROPTABLE"),
            "SQL evasion comment stripping should rejoin keywords, got: {}", normalized);
    }

    #[test]
    fn test_sql_long_comment_replaced_with_space() {
        // Long block comments (with content) replaced with space
        // "SELECT /* user query */ name" → "SELECT " + " " + " name" (space around comment preserved)
        let normalized = normalize("SELECT /* user query */ name FROM users");
        assert!(normalized.contains("SELECT") && normalized.contains("name FROM users"),
            "Long SQL comment should be replaced with space, got: {}", normalized);
    }
}
