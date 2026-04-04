// Copyright (c) 2026 Clampd Inc. - BUSL-1.1
//! Aho-Corasick keyword dictionary (L2 detection layer).
//! Single-pass O(n) scan over input text.

use aho_corasick::{AhoCorasick, MatchKind};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

// ── Types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    PromptInjection,
    GoalHijack,
    SecurityDisable,
    DataExfil,
    PiiField,
    DangerousOp,
    InfraTarget,
    ExfilDestination,
    Compliance,
}

/// Owned version of DictEntry for loading from external files and internal storage.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DictEntryOwned {
    pub keyword: String,
    pub category: String,      // "prompt_injection", "pii_field", etc.
    pub risk_weight: f64,
    pub lang: String,
}

/// Internal entry with parsed Category enum for efficient matching.
#[derive(Debug, Clone)]
struct DictEntryInternal {
    pub keyword: String,
    pub category: Category,
    pub risk_weight: f64,
}

#[derive(Debug, Clone)]
pub struct DictResult {
    pub matched_count: usize,
    pub max_risk: f64,
    pub category_risks: HashMap<Category, f64>,
    pub matched_keywords: Vec<(Category, f64, String)>,
}

impl DictResult {
    pub fn empty() -> Self {
        Self {
            matched_count: 0,
            max_risk: 0.0,
            category_risks: HashMap::new(),
            matched_keywords: Vec::new(),
        }
    }
}

// ── Global dictionary ──────────────────────────────────────────────

/// Global swappable dictionary. Use `DICTIONARY.load()` to read, `reload_dictionary()` to swap.
pub static DICTIONARY: LazyLock<ArcSwap<KeywordDictionary>> = LazyLock::new(|| {
    let dict = match std::env::var("CLAMPD_DICTIONARY_PATH") {
        Ok(path) if !path.is_empty() => {
            match KeywordDictionary::from_file_merged(&path) {
                Ok(dict) => {
                    tracing::info!(path = %path, entries = dict.entry_count(), "Loaded merged keyword dictionary");
                    dict
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to load external dictionary, using built-ins only");
                    KeywordDictionary::built_in()
                }
            }
        }
        _ => KeywordDictionary::built_in(),
    };
    ArcSwap::from_pointee(dict)
});

/// Hot-reload: rebuild dictionary from built-ins + new external keywords.
/// Called by RulesLoader when keywords are updated via Redis/NATS.
pub fn reload_dictionary(extra_keywords: Vec<DictEntryOwned>) -> Result<usize, String> {
    let mut entries = build_entries();

    for ext in extra_keywords {
        let category = parse_category(&ext.category)
            .ok_or_else(|| format!("Unknown category: {}", ext.category))?;
        entries.push(DictEntryInternal {
            keyword: ext.keyword,
            category,
            risk_weight: ext.risk_weight.clamp(0.0, 1.0),
        });
    }

    let count = entries.len();
    let patterns: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
    let automaton = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .ascii_case_insensitive(true)
        .build(&patterns)
        .map_err(|e| format!("Aho-Corasick rebuild failed: {}", e))?;

    let new_dict = KeywordDictionary { automaton, entries };
    DICTIONARY.store(Arc::new(new_dict));

    tracing::info!(entries = count, "Dictionary hot-reloaded");
    Ok(count)
}

pub struct KeywordDictionary {
    automaton: AhoCorasick,
    entries: Vec<DictEntryInternal>,
}

impl KeywordDictionary {
    fn built_in() -> Self {
        let entries = build_entries();
        let patterns: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("aho-corasick build failed");
        Self { automaton, entries }
    }

    /// Load additional keywords from a JSON file and merge with built-ins.
    /// File format: array of `{"keyword": "...", "category": "prompt_injection", "risk_weight": 0.9, "lang": "en"}`
    ///
    /// Environment variable: `CLAMPD_DICTIONARY_PATH` - if set, loads and merges on startup.
    pub fn from_file_merged(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read dictionary file {}: {}", path, e))?;
        let external: Vec<DictEntryOwned> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse dictionary JSON: {}", e))?;

        let mut entries = build_entries();

        for ext in external {
            let category = parse_category(&ext.category)
                .ok_or_else(|| format!("Unknown category: {}", ext.category))?;
            entries.push(DictEntryInternal {
                keyword: ext.keyword,
                category,
                risk_weight: ext.risk_weight.clamp(0.0, 1.0),
            });
        }

        let patterns: Vec<&str> = entries.iter().map(|e| e.keyword.as_str()).collect();
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| format!("Aho-Corasick build failed: {}", e))?;

        Ok(Self { automaton, entries })
    }

    /// O(n) scan - finds all matching keywords in a single pass.
    /// Returns per-category risk using formula: 1 - Π(1 - weight_i)
    pub fn scan(&self, text: &str) -> DictResult {
        if text.is_empty() {
            return DictResult::empty();
        }

        let mut cat_weights: HashMap<Category, Vec<f64>> = HashMap::new();
        let mut matched: Vec<(Category, f64, String)> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for mat in self.automaton.find_iter(text) {
            let idx = mat.pattern().as_usize();
            let entry = &self.entries[idx];
            if seen.insert(idx) {
                cat_weights
                    .entry(entry.category)
                    .or_default()
                    .push(entry.risk_weight);
                matched.push((entry.category, entry.risk_weight, entry.keyword.clone()));
            }
        }

        if matched.is_empty() {
            return DictResult::empty();
        }

        // Per-category combined risk: 1 - Π(1 - w_i)
        let mut category_risks = HashMap::new();
        let mut max_risk = 0.0_f64;
        for (cat, weights) in &cat_weights {
            let combined = 1.0 - weights.iter().fold(1.0, |acc, w| acc * (1.0 - w));
            let capped = combined.min(0.98);
            category_risks.insert(*cat, capped);
            max_risk = max_risk.max(capped);
        }

        DictResult {
            matched_count: matched.len(),
            max_risk,
            category_risks,
            matched_keywords: matched,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ── Keyword data ───────────────────────────────────────────────────

macro_rules! kw {
    ($keyword:expr, $cat:ident, $weight:expr, $lang:expr) => {
        DictEntryInternal {
            keyword: $keyword.to_string(),
            category: Category::$cat,
            risk_weight: $weight,
        }
    };
}

fn parse_category(s: &str) -> Option<Category> {
    match s {
        "prompt_injection" => Some(Category::PromptInjection),
        "goal_hijack" => Some(Category::GoalHijack),
        "security_disable" => Some(Category::SecurityDisable),
        "data_exfil" => Some(Category::DataExfil),
        "pii_field" => Some(Category::PiiField),
        "dangerous_op" => Some(Category::DangerousOp),
        "infra_target" => Some(Category::InfraTarget),
        "exfil_destination" => Some(Category::ExfilDestination),
        "compliance" => Some(Category::Compliance),
        _ => None,
    }
}

fn build_entries() -> Vec<DictEntryInternal> {
    vec![
        kw!("ignore your instructions", PromptInjection, 0.90, "en"),
        kw!("ignore previous instructions", PromptInjection, 0.90, "en"),
        kw!("override system prompt", PromptInjection, 0.92, "en"),
        kw!("disregard all safety", PromptInjection, 0.90, "en"),
        kw!("new objective:", GoalHijack, 0.85, "en"),
        kw!("your new task is", GoalHijack, 0.85, "en"),
        kw!("dump all credentials", DataExfil, 0.92, "en"),
        kw!("exfiltrate", DataExfil, 0.88, "en"),
        kw!("social security number", PiiField, 0.85, "en"),
        kw!("credit card number", PiiField, 0.85, "en"),
        kw!("rm -rf /", DangerousOp, 0.95, "en"),
        kw!("DROP TABLE", DangerousOp, 0.90, "en"),
        kw!("169.254.169.254", InfraTarget, 0.92, "en"),
        kw!("/etc/shadow", InfraTarget, 0.90, "en"),
    ]
}
