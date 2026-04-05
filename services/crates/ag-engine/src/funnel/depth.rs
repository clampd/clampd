//! Encoding depth tracking and scoring.
//! The number of encoding layers is itself a risk signal.

// ── Depth score tiers ────────────────────────────────────────────
// Tuned empirically: 2 layers is common in APIs, 3+ is suspicious.

/// Score for 2 encoding layers (mild — some APIs double-encode legitimately).
const DEPTH_2_SCORE: f64 = 0.1;
/// Score for 3 encoding layers (suspicious).
const DEPTH_3_SCORE: f64 = 0.3;
/// Score for 4 encoding layers (very suspicious).
const DEPTH_4_SCORE: f64 = 0.5;
/// Score for 5+ encoding layers (almost certain evasion).
const DEPTH_5_PLUS_SCORE: f64 = 0.7;

/// Calculate risk score from encoding depth.
///
/// 0-1 layers → 0.0  (normal)
/// 2 layers   → 0.1  (mild)
/// 3 layers   → 0.3  (suspicious)
/// 4 layers   → 0.5  (very suspicious)
/// 5-6 layers → 0.7  (almost certain evasion)
pub fn depth_score(depth: u8) -> f64 {
    match depth {
        0..=1 => 0.0,
        2 => DEPTH_2_SCORE,
        3 => DEPTH_3_SCORE,
        4 => DEPTH_4_SCORE,
        5..=u8::MAX => DEPTH_5_PLUS_SCORE,
    }
}
