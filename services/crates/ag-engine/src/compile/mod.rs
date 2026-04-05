//! Rule compilation: ParsedRule → CompiledRule → CompiledRuleset
//!
//! Conditions compile to closures at load time.
//! No parsing, no regex compilation in the hot path.
//!
//! ## Three-tier prefilter (Suricata MPM-class architecture)
//!
//! Tier 1: Scope grouping - rules pre-partitioned by scope_pattern.
//! Tier 2: Aho-Corasick literal prefilter - O(text_length) MPM scan.
//!         Extracts literal substrings from rule regex patterns at compile time,
//!         builds a single AC automaton. One scan identifies candidate rules.
//!         Replaces RegexSet (which scales with pattern count, not text length).
//! Tier 3: Full closure evaluation - regex + scope/agent/risk checks.

mod conditions;

pub use conditions::Condition;

use crate::execute::{EvalResult, RuleMatch};
use crate::scheme::FieldId;
use crate::taxonomy::TaxonomyMapping;
use aho_corasick::{AhoCorasick, MatchKind};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Bonus added when rules match ONLY after decoding (encoding evasion).
const ENCODING_EVASION_BONUS: f64 = 0.30;
/// Minimum per-value string length to bother normalizing in L4b.
const MIN_PER_VALUE_LEN: usize = 8;
/// Maximum chars of extracted_text stored in the EvalResult (preview).
const EXTRACTED_TEXT_PREVIEW_LEN: usize = 200;
/// Minimum literal length for AC prefilter (shorter literals cause too many false hits).
const MIN_LITERAL_LEN: usize = 3;

/// Action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Pass,
    Flag,
    Block,
}

impl RuleAction {
    /// Returns severity ordering: Pass=0, Flag=1, Block=2.
    pub fn severity(self) -> u8 {
        match self {
            RuleAction::Pass => 0,
            RuleAction::Flag => 1,
            RuleAction::Block => 2,
        }
    }
}

/// A compiled detection rule - ready for execution.
/// The condition is a pre-compiled closure tree.
pub struct CompiledRule {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub risk_score: f64,
    pub action: RuleAction,
    pub priority: u8,
    pub labels: Arc<[Arc<str>]>,
    pub exemptable: bool,
    pub condition: Box<dyn Fn(&crate::execute::ExecutionContext) -> bool + Send + Sync>,
    pub taxonomy: TaxonomyMapping,
}

impl std::fmt::Debug for CompiledRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRule")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("risk_score", &self.risk_score)
            .field("action", &self.action)
            .finish()
    }
}

/// A compiled ruleset with three-tier pre-filtering (Suricata MPM-class architecture).
///
/// Tier 1: Scope grouping - rules pre-partitioned by scope_pattern at compile time.
///         Only rules matching the request's scope are checked. (210 → ~50 rules)
/// Tier 2: Aho-Corasick literal prefilter - O(text_length) multi-pattern match.
///         Extracts literal substrings from rule regex at compile time. One AC scan
///         identifies candidate rules. Cost: O(text_length) regardless of rule count.
///         At 5000 rules: same ~10μs as at 200 rules. (Replaces RegexSet.)
/// Tier 3: Full closure evaluation - only candidates get full regex/agent/risk check.
///
/// This reduces per-request rule checks from O(N) to O(K) where K << N.
/// Scales to 30,000+ rules (same architecture as Suricata IDS).
pub struct CompiledRuleset {
    pub version: u64,
    pub checksum: [u8; 32],
    pub rules: Vec<CompiledRule>,

    // ── Tier 1: Scope-based rule grouping ──
    scope_groups: std::collections::HashMap<String, Vec<usize>>,
    wildcard_rules: Vec<usize>,

    // ── Tier 2: Aho-Corasick literal prefilter (MPM) ──
    literal_prefilter: LiteralPrefilter,
}

/// Aho-Corasick multi-pattern matching prefilter.
/// Extracts literal substrings from rule regex at compile time.
/// One O(text_length) scan identifies which rules COULD match.
struct LiteralPrefilter {
    /// AC automaton built from all extracted literals (case-insensitive).
    automaton: AhoCorasick,
    /// Maps AC pattern index → rule indices that contain this literal.
    /// Multiple rules can share the same literal; one rule can have multiple literals.
    pattern_to_rules: Vec<Vec<usize>>,
    /// Rules with no extractable literals - must always be evaluated (the 8%).
    no_literal_rules: Vec<usize>,
}

impl LiteralPrefilter {
    /// Scan text and return a hit bitset: hits[rule_idx] = true if rule is a candidate.
    fn scan_candidates(&self, text: &str, rule_count: usize) -> Vec<bool> {
        let mut hits = vec![false; rule_count];

        // No-literal rules always pass prefilter
        for &idx in &self.no_literal_rules {
            hits[idx] = true;
        }

        // One AC scan - O(text_length) regardless of pattern count
        for mat in self.automaton.find_overlapping_iter(text) {
            let pat_idx = mat.pattern().as_usize();
            for &rule_idx in &self.pattern_to_rules[pat_idx] {
                hits[rule_idx] = true;
            }
        }

        hits
    }

    /// Union scan across multiple texts - candidate if ANY text contains the literal.
    fn scan_candidates_union(&self, texts: &[Arc<str>], rule_count: usize) -> Vec<bool> {
        let mut hits = vec![false; rule_count];

        for &idx in &self.no_literal_rules {
            hits[idx] = true;
        }

        for text in texts {
            for mat in self.automaton.find_overlapping_iter(text.as_ref()) {
                let pat_idx = mat.pattern().as_usize();
                for &rule_idx in &self.pattern_to_rules[pat_idx] {
                    hits[rule_idx] = true;
                }
            }
        }

        hits
    }
}

/// Check if a scope matches a colon-separated pattern with `*` wildcard.
///
/// Pre-compiled at load time (wirefilter pattern) - the pattern parts are
/// captured into the closure, so evaluation is pure string comparison.
///
/// `db:*`          matches `db:query:read`
/// `db:query:*`    matches `db:query:read`, `db:query:search`
/// `db:query:read` exact match only
/// `*`             matches everything
fn scope_pattern_matches(pattern: &str, scope: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pat_parts: Vec<&str> = pattern.split(':').collect();
    let scope_parts: Vec<&str> = scope.split(':').collect();
    for (i, pat) in pat_parts.iter().enumerate() {
        if *pat == "*" {
            return true;
        }
        match scope_parts.get(i) {
            Some(s) if *pat == *s => {}
            _ => return false,
        }
    }
    pat_parts.len() == scope_parts.len()
}

/// Check if a tool name matches a glob-style pattern.
/// Supports `*` as wildcard. `database.*` matches `database.query`.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        // No wildcard - exact match
        return pattern == text;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(found) => {
                // First part must match at start
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }
    // Last part must match at end
    if let Some(last) = parts.last() {
        if !last.is_empty() && !text.ends_with(last) {
            return false;
        }
    }
    true
}

impl CompiledRuleset {
    /// Compile a set of parsed rules into an optimized ruleset.
    pub fn compile(
        rules: Vec<crate::parse::ParsedRule>,
        _scheme: &crate::scheme::Scheme,
    ) -> Result<Self, CompileError> {
        // Compute SHA-256 checksum of serialized rules
        let serialized = serde_json::to_vec(&rules).unwrap_or_default();
        let checksum: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&serialized);
            hasher.finalize().into()
        };

        let mut compiled_rules = Vec::with_capacity(rules.len());

        for parsed in &rules {
            // Compile all regex patterns for this rule
            let mut compiled_regexes: Vec<Arc<regex::Regex>> = Vec::new();
            let mut pattern_fields: Vec<Option<String>> = Vec::new();

            for pat in &parsed.patterns {
                let re = regex::Regex::new(&pat.regex).map_err(|e| {
                    CompileError::InvalidRegex(format!("{}: {}", pat.regex, e))
                })?;

                compiled_regexes.push(Arc::new(re));
                pattern_fields.push(pat.field.clone());
            }

            // Capture values for the closure - no allocation at eval time
            let tool_pattern = parsed.tool_pattern.clone();
            let scope_patterns = parsed.scope_pattern.clone();
            let exempt_agents: Arc<[Arc<str>]> = parsed
                .exempt_agents
                .iter()
                .map(|s| Arc::from(s.as_str()))
                .collect();
            let risk_above = parsed.risk_above;
            let regexes = compiled_regexes;
            let fields = pattern_fields;

            // Build condition closure
            let condition: Box<dyn Fn(&crate::execute::ExecutionContext) -> bool + Send + Sync> =
                Box::new(move |ctx| {
                    // 1. Scope/tool filter
                    // Tier 1 (scope grouping) owns scope-based rule selection at eval time.
                    // The closure only handles the no-scope fallback to tool_pattern.
                    // Do NOT re-check scope here - it kills cross-category detection
                    // via related_scopes (e.g., R008 fs:* selected for exec:shell:run).
                    if scope_patterns.is_empty() {
                        // Legacy: no scope_pattern declared → use tool_pattern glob
                        if let Some(ref pat) = tool_pattern {
                            let tool_name = ctx.get_str(FieldId(0));
                            if !glob_matches(pat, tool_name) {
                                return false;
                            }
                        }
                    } else {
                        let scope_str = ctx.get_str(FieldId(22));
                        if scope_str.is_empty() {
                            // No scope set at runtime → fall back to tool_pattern
                            if let Some(ref pat) = tool_pattern {
                                let tool_name = ctx.get_str(FieldId(0));
                                if !glob_matches(pat, tool_name) {
                                    return false;
                                }
                            }
                        }
                        // When scope IS set: Tier 1 already selected this rule via
                        // primary or related scope groups. No re-check needed.
                    }

                    // 2. agent_not_in check (agent.id, FieldId(5))
                    if !exempt_agents.is_empty() {
                        let agent_id = ctx.get_str(FieldId(5));
                        if exempt_agents.iter().any(|ea| ea.as_ref() == agent_id) {
                            return false;
                        }
                    }

                    // 3. risk_above check (agent.risk_score, FieldId(6))
                    if let Some(threshold) = risk_above {
                        let risk = ctx.get_float(FieldId(6));
                        if risk <= threshold {
                            return false;
                        }
                    }

                    // 4. ALL patterns must match (AND logic)
                    for (i, re) in regexes.iter().enumerate() {
                        let matched = match &fields[i] {
                            None => {
                                // No field: match against tool.args_text (FieldId(4)), then all_text
                                let args_text = ctx.get_str(FieldId(4));
                                if !args_text.is_empty() && re.is_match(args_text) {
                                    true
                                } else {
                                    re.is_match(ctx.all_text())
                                }
                            }
                            Some(field_name) => {
                                // Field-specific: extract the named field from JSON params (FieldId 2)
                                // and match regex ONLY against that field's value.
                                // No fallback - if field is missing, rule does not match.
                                if let crate::scheme::FieldValue::Json(json) = ctx.get(FieldId(2)) {
                                    if let Some(val) = json.get(field_name.as_str()) {
                                        let field_text = match val {
                                            serde_json::Value::String(s) => s.as_str().to_string(),
                                            other => other.to_string(),
                                        };
                                        re.is_match(&field_text)
                                    } else {
                                        false // field not in JSON → no match
                                    }
                                } else {
                                    false // no JSON params → field-specific rule cannot match
                                }
                            }
                        };
                        if !matched {
                            return false;
                        }
                    }

                    true
                });

            let labels: Arc<[Arc<str>]> = parsed
                .labels
                .iter()
                .map(|s| Arc::from(s.as_str()))
                .collect();

            compiled_rules.push(CompiledRule {
                id: Arc::from(parsed.id.as_str()),
                name: Arc::from(parsed.name.as_str()),
                risk_score: parsed.risk_score,
                action: parsed.action,
                priority: parsed.priority,
                labels,
                exemptable: parsed.exemptable,
                condition,
                taxonomy: parsed.taxonomy.clone(),
            });
        }

        // ── Tier 1: Scope-based rule grouping ──
        // Partition rules by scope prefix at compile time.
        // At eval time, only rules matching the request's scope are checked.
        let mut scope_groups: std::collections::HashMap<String, Vec<usize>> = std::collections::HashMap::new();
        let mut wildcard_rules: Vec<usize> = Vec::new();

        for (idx, parsed) in rules.iter().enumerate() {
            if parsed.scope_pattern.is_empty() || parsed.scope_pattern.iter().any(|p| p == "*") {
                wildcard_rules.push(idx);
            } else {
                // Add rule to EACH scope group it declares.
                // e.g., scope_pattern = ["db:*", "exec:*"] → added to both "db" and "exec" groups.
                for pat in &parsed.scope_pattern {
                    let prefix = pat.split(':').next().unwrap_or(pat);
                    scope_groups.entry(prefix.to_string())
                        .or_default()
                        .push(idx);
                }
            }
        }

        let scoped_count: usize = scope_groups.values().map(|v| v.len()).sum();
        tracing::info!(
            wildcard = wildcard_rules.len(),
            scoped = scoped_count,
            groups = scope_groups.len(),
            "Tier 1: Scope-based rule grouping built"
        );

        // ── Tier 2: Aho-Corasick literal prefilter (MPM) ──
        // Extract literal substrings from each rule's regex patterns.
        // Build one AC automaton. At eval time: one O(text_length) scan
        // identifies candidate rules. Scales to 30,000+ rules.
        let literal_prefilter = {
            let mut all_literals: Vec<String> = Vec::new();
            let mut pattern_to_rules: Vec<Vec<usize>> = Vec::new();
            let mut no_literal_rules: Vec<usize> = Vec::new();
            let mut literal_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

            for (idx, parsed) in rules.iter().enumerate() {
                let mut rule_has_literal = false;
                let mut rule_fully_covered = true;

                for pat in &parsed.patterns {
                    let result = extract_literals_from_regex(&pat.regex);
                    if !result.all_branches_covered {
                        rule_fully_covered = false;
                    }
                    for lit in result.literals {
                        let key = lit.to_lowercase();
                        if key.len() < MIN_LITERAL_LEN { continue; }
                        rule_has_literal = true;
                        if let Some(&lit_idx) = literal_index.get(&key) {
                            let rules_for_lit = &mut pattern_to_rules[lit_idx];
                            if !rules_for_lit.contains(&idx) {
                                rules_for_lit.push(idx);
                            }
                        } else {
                            let lit_idx = all_literals.len();
                            literal_index.insert(key, lit_idx);
                            all_literals.push(lit);
                            pattern_to_rules.push(vec![idx]);
                        }
                    }
                }

                // Rule goes to no_literal if it has no literals at all,
                // OR if any alternation branch lacks a literal (the regex
                // can match text without any of the extracted literals).
                if !rule_has_literal || !rule_fully_covered {
                    no_literal_rules.push(idx);
                }
            }

            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::Standard)
                .build(&all_literals)
                .expect("AC literal prefilter build failed");

            tracing::info!(
                literals = all_literals.len(),
                no_literal = no_literal_rules.len(),
                "Tier 2: AC literal prefilter built (MPM)"
            );

            LiteralPrefilter {
                automaton,
                pattern_to_rules,
                no_literal_rules,
            }
        };

        Ok(CompiledRuleset {
            version: 1,
            checksum,
            rules: compiled_rules,
            scope_groups,
            wildcard_rules,
            literal_prefilter,
        })
    }

    /// Number of rules in this ruleset.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Related scope prefixes - cross-category attack detection.
    /// A shell tool can read files, an HTTP tool can execute commands, etc.
    fn related_scopes(prefix: &str) -> &'static [&'static str] {
        match prefix {
            "exec" => &["fs", "net"],       // shell reads files, fetches URLs
            "net"  => &["exec"],            // HTTP params can contain commands
            "fs"   => &["exec"],            // file paths can contain command injection
            "db"   => &["fs"],              // SQL can read files (LOAD_FILE)
            "llm"  => &["exec", "net"],     // LLM output can contain commands/URLs
            _ => &[],
        }
    }

    /// Collect rule indices to evaluate based on scope (Tier 1).
    /// Returns wildcard rules + primary scope rules + related scope rules.
    fn rules_for_scope(&self, scope: &str) -> Vec<usize> {
        let mut indices = self.wildcard_rules.clone();
        if !scope.is_empty() {
            let prefix = scope.split(':').next().unwrap_or(scope);

            // Primary scope group
            if let Some(group) = self.scope_groups.get(prefix) {
                indices.extend_from_slice(group);
            }

            // Related scope groups (cross-category detection)
            for related in Self::related_scopes(prefix) {
                if let Some(group) = self.scope_groups.get(*related) {
                    indices.extend_from_slice(group);
                }
            }
        } else {
            // No scope → check ALL rules (safe fallback)
            indices.clear();
            indices.extend(0..self.rules.len());
        }
        indices
    }

    /// Three-tier rule evaluation:
    /// Tier 1: Scope grouping → only rules matching request scope
    /// Tier 2: AC literal prefilter → O(text_length) MPM scan
    /// Tier 3: Full closure evaluation → regex/agent/risk checks
    pub fn evaluate(&self, ctx: &crate::execute::ExecutionContext) -> EvalResult {
        let mut rule_matches = Vec::new();
        let mut assessed_risk: f64 = 0.0;
        let mut max_action = RuleAction::Pass;
        let mut has_non_exemptable_block = false;

        // Tier 1: Scope-based rule selection
        let scope = ctx.get_str(FieldId(22));
        let candidate_indices = self.rules_for_scope(scope);

        // Tier 2: AC literal prefilter - O(text_length)
        let prefilter_hits = self.literal_prefilter.scan_candidates(
            ctx.all_text(), self.rules.len()
        );

        // Tier 3: Full closure evaluation on candidates only
        for idx in &candidate_indices {
            let idx = *idx;
            // Tier 2 gate: skip if AC prefilter excludes this rule
            if !prefilter_hits[idx] {
                continue;
            }
            let rule = &self.rules[idx];
            if (rule.condition)(ctx) {
                if rule.risk_score > assessed_risk {
                    assessed_risk = rule.risk_score;
                }
                if rule.action.severity() > max_action.severity() {
                    max_action = rule.action;
                }
                if rule.action == RuleAction::Block && !rule.exemptable {
                    has_non_exemptable_block = true;
                }

                rule_matches.push(RuleMatch {
                    rule_id: rule.id.to_string(),
                    risk_score: rule.risk_score,
                    action: rule.action,
                    priority: rule.priority,
                    labels: rule.labels.iter().map(|l| l.to_string()).collect(),
                    reasoning: format!("Rule {} ({}) matched", rule.id, rule.name),
                    exemptable: rule.exemptable,
                    taxonomy: rule.taxonomy.clone(),
                });
            }
        }

        EvalResult {
            rule_matches,
            assessed_risk,
            action: max_action,
            has_non_exemptable_block,
            decode_depth: 0,
            decode_encodings: vec![],
            decode_depth_score: 0.0,
            dict_risk: 0.0,
            dict_matched_count: 0,
            signal_risk: 0.0,
            signal_count: 0,
            matched_signals: vec![],
            extracted_text: String::new(),
            normalization_variant_count: 0,
        }
    }

    /// Full 5-layer evaluation pipeline (single-pass architecture).
    ///
    /// Input: `ctx.all_text()` = raw params_json (may be JSON or plain text).
    ///
    /// Pipeline:
    /// 1. **Prepare**: Parse JSON → extract string values → join as `extracted_text`
    /// 2. **L0**: Decode funnel on extracted_text (base64, gzip, hex, XOR)
    /// 3. **L4**: Normalize extracted_text (URL decode, hex escapes, NFKC, etc.)
    /// 4. **L1**: Single-pass rule evaluation across ALL text variants
    /// 5. **L2**: Aho-Corasick dictionary on extracted + normalized text
    /// 6. **L3**: Compound signals on extracted text
    /// 7. **Combine**: assessed_risk = max(L0_depth, L1, L2, L3)
    ///
    /// Single-pass architecture (Suricata-inspired):
    /// - Collects all text variants upfront (original, extracted, normalized, decoded)
    /// - One Tier 1 scope selection (not N times)
    /// - Union RegexSet pre-filter across all variants (one bitset)
    /// - One loop over candidates - tries each variant per rule, breaks on first match
    /// - Zero evaluate() calls - everything inline
    pub fn evaluate_full(
        &self,
        ctx: &crate::execute::ExecutionContext,
    ) -> EvalResult {
        use crate::scheme::{FieldId, FieldValue, clampd_scheme};

        let tool_name = ctx.get_str(FieldId(0));
        let raw_params = ctx.all_text(); // raw params_json (may be JSON)

        // ── PREPARE: Extract text from JSON ──────────────────────────
        let (extracted_text, per_value_strings) = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(raw_params) {
            let mut strings = Vec::new();
            collect_strings_recursive(&parsed, &mut strings);
            let joined = strings.join(" ");
            let extracted = if joined.is_empty() { raw_params.to_string() } else { joined };
            (extracted, strings)
        } else {
            (raw_params.to_string(), vec![raw_params.to_string()])
        };

        // ── L0: Decode funnel ────────────────────────────────────────
        let funnel = crate::funnel::DecodeFunnel::new(crate::funnel::FunnelConfig::default());
        let funnel_result = funnel.decode_str(&extracted_text);
        let decode_depth = funnel_result.depth;
        let depth_score = funnel_result.depth_score;

        // ── L4: Normalize extracted text ─────────────────────────────
        let variants = crate::normalize::normalize_variants(&extracted_text);

        // ── COLLECT ALL VARIANT TEXTS ────────────────────────────────
        // Original texts first (index < original_count), decoded/normalized after.
        // Rules that match ONLY on decoded variants get the encoding evasion bonus.
        let mut all_variants: Vec<Arc<str>> = Vec::new();
        let mut seen_texts = std::collections::HashSet::new();

        // Original forms (no evasion bonus)
        all_variants.push(Arc::from(raw_params));
        seen_texts.insert(raw_params.to_string());
        if extracted_text != raw_params {
            if seen_texts.insert(extracted_text.clone()) {
                all_variants.push(Arc::from(extracted_text.as_str()));
            }
        }
        let original_count = all_variants.len();

        // Decoded/normalized forms (evasion bonus candidates)
        for v in &variants {
            if seen_texts.insert(v.clone()) {
                all_variants.push(Arc::from(v.as_str()));
            }
        }
        if funnel_result.depth > 0 {
            if seen_texts.insert(funnel_result.decoded_text.clone()) {
                all_variants.push(Arc::from(funnel_result.decoded_text.as_str()));
            }
        }
        // Per-value normalization variants
        for raw_str in &per_value_strings {
            if raw_str.len() < MIN_PER_VALUE_LEN { continue; }
            let str_variants = crate::normalize::normalize_variants(raw_str);
            for v in &str_variants[1..] {
                if v != raw_str {
                    if seen_texts.insert(v.clone()) {
                        all_variants.push(Arc::from(v.as_str()));
                    }
                }
            }
        }
        drop(seen_texts); // free memory before hot loop

        // ── L1: SINGLE-PASS RULE EVALUATION ──────────────────────────
        // One Tier 1 selection, one RegexSet union, one candidate loop.

        // Cache scheme as static
        static CACHED_SCHEME: std::sync::LazyLock<crate::scheme::Scheme> =
            std::sync::LazyLock::new(|| clampd_scheme());
        let scheme = &*CACHED_SCHEME;

        // Tier 1: One scope selection (was N times in multi-call approach)
        let scope = ctx.get_str(FieldId(22));
        let candidate_indices = self.rules_for_scope(scope);

        // Tier 2: AC literal prefilter - union scan across ALL variants.
        // One O(text_length) AC scan per variant, results unioned into one bitset.
        let prefilter_hits = self.literal_prefilter.scan_candidates_union(
            &all_variants, self.rules.len(),
        );

        // Tier 3: Single-pass - one reusable context, try variants per rule.
        let mut tctx = crate::execute::ExecutionContext::new(scheme);
        tctx.set(FieldId(0), FieldValue::String(Arc::from(tool_name)));
        tctx.set(FieldId(5), ctx.get(FieldId(5)).clone());
        tctx.set(FieldId(6), ctx.get(FieldId(6)).clone());
        tctx.set(FieldId(22), ctx.get(FieldId(22)).clone());

        let mut all_matches: Vec<RuleMatch> = Vec::new();
        let mut has_evasion_only_match = false;
        let mut assessed_risk: f64 = 0.0;
        let mut max_action = RuleAction::Pass;
        let mut has_non_exemptable_block = false;

        for &idx in &candidate_indices {
            // Tier 2 gate: skip if AC prefilter excludes this rule on ALL variants
            if !prefilter_hits[idx] { continue; }

            let rule = &self.rules[idx];

            // Try each variant - break on first match (original texts tried first)
            for (vi, variant) in all_variants.iter().enumerate() {
                tctx.set(FieldId(4), FieldValue::String(variant.clone()));
                tctx.set_all_text(variant.clone());

                if (rule.condition)(&tctx) {
                    // Evasion detection: matched only on decoded variant, not original
                    if vi >= original_count {
                        has_evasion_only_match = true;
                    }

                    if rule.risk_score > assessed_risk {
                        assessed_risk = rule.risk_score;
                    }
                    if rule.action.severity() > max_action.severity() {
                        max_action = rule.action;
                    }
                    if rule.action == RuleAction::Block && !rule.exemptable {
                        has_non_exemptable_block = true;
                    }

                    all_matches.push(RuleMatch {
                        rule_id: rule.id.to_string(),
                        risk_score: rule.risk_score,
                        action: rule.action,
                        priority: rule.priority,
                        labels: rule.labels.iter().map(|l| l.to_string()).collect(),
                        reasoning: format!("Rule {} ({}) matched", rule.id, rule.name),
                        exemptable: rule.exemptable,
                        taxonomy: rule.taxonomy.clone(),
                    });
                    break; // First matching variant wins - no duplicate checks
                }
            }
        }

        // ── L2: Aho-Corasick dictionary scan ─────────────────────────
        let dict = crate::dictionary::DICTIONARY.load();
        let dict_scan = dict.scan(&extracted_text);
        let mut dict_risk = dict_scan.max_risk;
        let dict_matched_count = dict_scan.matched_count;
        for variant in &variants {
            let vr = dict.scan(variant).max_risk;
            if vr > dict_risk { dict_risk = vr; }
        }

        // ── L3: Compound signal scoring ──────────────────────────────
        let signal_result = crate::signals::compound_score(tool_name, &extracted_text);
        let mut signal_risk = signal_result.score;
        if extracted_text != raw_params {
            let raw_sig = crate::signals::compound_score(tool_name, raw_params).score;
            if raw_sig > signal_risk { signal_risk = raw_sig; }
        }

        // ── ENCODING EVASION BONUS ───────────────────────────────────
        // Rules matched ONLY on decoded text → intentional evasion.
        let encoding_evasion_bonus = if has_evasion_only_match
            && (variants.len() > 1 || funnel_result.depth > 0)
        {
            ENCODING_EVASION_BONUS
        } else {
            0.0
        };

        // ── COMBINE ──────────────────────────────────────────────────
        let l1_risk = assessed_risk;
        let assessed_risk = (l1_risk + encoding_evasion_bonus)
            .max(dict_risk)
            .max(signal_risk)
            .max(depth_score)
            .min(1.0);

        EvalResult {
            rule_matches: all_matches,
            assessed_risk,
            action: max_action,
            has_non_exemptable_block,
            decode_depth,
            decode_encodings: funnel_result.encodings.clone(),
            decode_depth_score: depth_score,
            dict_risk,
            dict_matched_count,
            signal_risk,
            signal_count: signal_result.signal_count,
            matched_signals: signal_result.matched_signals.iter().map(|s| s.to_string()).collect(),
            extracted_text: extracted_text.chars().take(EXTRACTED_TEXT_PREVIEW_LEN).collect(),
            normalization_variant_count: all_variants.len(),
        }
    }
}

/// Recursively collect all string values from a JSON value.
fn collect_strings_recursive(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for v in arr { collect_strings_recursive(v, out); }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() { collect_strings_recursive(v, out); }
        }
        _ => {}
    }
}

// ── Literal extraction for AC prefilter (Suricata "fast_pattern" approach) ──

/// Result of literal extraction from a regex pattern.
struct LiteralExtractionResult {
    /// All literal substrings ≥ MIN_LITERAL_LEN found in the pattern.
    literals: Vec<String>,
    /// True if ALL alternation branches have at least one extractable literal.
    /// If false, the regex can match text without any of the extracted literals
    /// (e.g., `(1=1|DROP TABLE)` - the `1=1` branch has no 3-char literal).
    /// Rules with uncovered branches must go to no_literal_rules.
    all_branches_covered: bool,
}

/// Extract literal substrings from a regex pattern for Aho-Corasick prefiltering.
///
/// Returns literals AND whether all alternation branches are covered.
/// If any branch lacks a literal, the rule must be in no_literal_rules
/// (always evaluated) because AC can't guarantee the branch won't match.
///
/// Examples:
///   `(?i)(DROP\s+TABLE|TRUNCATE)` → lits=["DROP","TABLE","TRUNCATE"], covered=true
///   `(?i)(1\s*=\s*1|OR\s+true)` → lits=["true"], covered=false (1=1 branch has no literal)
///   `(?i)https?://(evil|attacker)\.[a-z]` → lits=["http","evil","attacker"], covered=true
fn extract_literals_from_regex(regex: &str) -> LiteralExtractionResult {
    // Strip (?i), (?s), (?m) flags and outer capture group
    let mut s = regex.to_string();
    while s.starts_with("(?") {
        if let Some(end) = s[2..].find(')') {
            let flag_content = &s[2..2 + end];
            if flag_content.chars().all(|c| "ismxUu".contains(c)) {
                s = s[3 + end..].to_string();
                continue;
            }
        }
        break;
    }
    // Strip outermost (...) if it wraps the entire expression
    let s = strip_outer_group(&s);

    let branches = split_top_level_alternation(s);
    let mut all_literals = Vec::new();
    let mut all_branches_covered = true;

    for branch in &branches {
        let branch_lits = extract_literals_from_branch(branch);
        if branch_lits.is_empty() {
            all_branches_covered = false;
        }
        all_literals.extend(branch_lits);
    }

    LiteralExtractionResult {
        literals: all_literals,
        all_branches_covered,
    }
}

/// Strip outermost parentheses if they wrap the entire expression.
fn strip_outer_group(s: &str) -> &str {
    let trimmed = s.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return trimmed;
    }
    let chars: Vec<char> = trimmed.chars().collect();
    let mut depth = 0;
    let mut in_escape = false;
    let mut in_class = false;
    for (i, &ch) in chars.iter().enumerate() {
        if in_escape { in_escape = false; continue; }
        if ch == '\\' { in_escape = true; continue; }
        if in_class {
            if ch == ']' { in_class = false; }
            continue;
        }
        match ch {
            '[' => { in_class = true; }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i < chars.len() - 1 {
                    return trimmed; // First ( closes before end - not a wrapper
                }
            }
            _ => {}
        }
    }
    &trimmed[1..trimmed.len() - 1]
}

/// Split a regex on top-level `|` (alternation outside parentheses).
/// Respects paren/bracket nesting.
fn split_top_level_alternation(regex: &str) -> Vec<String> {
    let mut branches = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = regex.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut paren_depth = 0;
    let mut in_class = false;

    while i < len {
        let ch = chars[i];

        if ch == '\\' && i + 1 < len {
            current.push(ch);
            current.push(chars[i + 1]);
            i += 2;
            continue;
        }

        match ch {
            '[' if !in_class => { in_class = true; current.push(ch); }
            ']' if in_class => { in_class = false; current.push(ch); }
            '(' if !in_class => { paren_depth += 1; current.push(ch); }
            ')' if !in_class => { paren_depth -= 1; current.push(ch); }
            '|' if !in_class && paren_depth == 0 => {
                branches.push(current.clone());
                current.clear();
            }
            _ => { current.push(ch); }
        }
        i += 1;
    }
    if !current.is_empty() {
        branches.push(current);
    }
    // If no alternation found, return the whole regex as one branch
    if branches.is_empty() {
        branches.push(regex.to_string());
    }
    branches
}

/// Extract literal runs from a single regex branch (no top-level alternation).
fn extract_literals_from_branch(branch: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = branch.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut in_class = false;

    while i < len {
        let ch = chars[i];

        // Handle escape sequences
        if ch == '\\' && i + 1 < len {
            let next = chars[i + 1];
            match next {
                's' | 'S' | 'w' | 'W' | 'd' | 'D' | 'b' | 'B'
                | 'A' | 'Z' | 'z' | 'r' | 'n' | 't' => {
                    flush_literal(&mut current, &mut literals);
                    i += 2;
                    continue;
                }
                'x' | 'u' | 'p' | 'P' => {
                    flush_literal(&mut current, &mut literals);
                    i += 2;
                    while i < len && (chars[i].is_ascii_hexdigit()
                        || chars[i] == '{' || chars[i] == '}') {
                        i += 1;
                    }
                    continue;
                }
                _ => {
                    if !in_class { current.push(next); }
                    i += 2;
                    continue;
                }
            }
        }

        // Skip flag groups (?i), (?:...)
        if ch == '(' && i + 1 < len && chars[i + 1] == '?' {
            flush_literal(&mut current, &mut literals);
            let mut j = i + 2;
            while j < len && chars[j] != ')' && chars[j] != ':' { j += 1; }
            i = j + 1;
            continue;
        }

        if ch == '[' && !in_class {
            flush_literal(&mut current, &mut literals);
            in_class = true;
            i += 1;
            continue;
        }
        if ch == ']' && in_class {
            in_class = false;
            i += 1;
            continue;
        }
        if in_class { i += 1; continue; }

        match ch {
            '(' | ')' | '.' | '^' | '$' | '+' => {
                flush_literal(&mut current, &mut literals);
            }
            '|' => {
                // Nested alternation inside parens - flush
                flush_literal(&mut current, &mut literals);
            }
            '*' | '?' => {
                if !current.is_empty() { current.pop(); }
                flush_literal(&mut current, &mut literals);
            }
            '{' => {
                flush_literal(&mut current, &mut literals);
                while i < len && chars[i] != '}' { i += 1; }
            }
            _ => { current.push(ch); }
        }
        i += 1;
    }

    flush_literal(&mut current, &mut literals);
    literals
}

/// Flush a literal accumulator into the output vec if long enough.
fn flush_literal(current: &mut String, literals: &mut Vec<String>) {
    let trimmed = current.trim().to_string();
    if trimmed.len() >= MIN_LITERAL_LEN {
        literals.push(trimmed);
    }
    current.clear();
}

/// Error during rule compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
    #[error("Unknown field '{0}' in condition")]
    UnknownField(String),
    #[error("Type mismatch: field '{field}' is {expected:?}, got {actual:?}")]
    TypeMismatch {
        field: String,
        expected: crate::scheme::FieldType,
        actual: String,
    },
}

#[cfg(test)]
mod literal_extraction_tests {
    use super::*;

    #[test]
    fn extract_sql_alternation() {
        let r = extract_literals_from_regex(r"(?i)(DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM)");
        assert!(r.literals.contains(&"DROP".to_string()));
        assert!(r.literals.contains(&"TABLE".to_string()));
        assert!(r.literals.contains(&"TRUNCATE".to_string()));
        assert!(r.all_branches_covered, "all branches have 3+ char literals");
    }

    #[test]
    fn extract_path_literals() {
        let r = extract_literals_from_regex(r"(?i)(\/etc\/passwd|\/etc\/shadow|\/proc\/|\/sys\/)");
        assert!(r.literals.contains(&"/etc/passwd".to_string()));
        assert!(r.literals.contains(&"/etc/shadow".to_string()));
        assert!(r.all_branches_covered);
    }

    #[test]
    fn extract_secret_prefixes() {
        let r = extract_literals_from_regex(r"(AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{20,})");
        assert!(r.literals.contains(&"AKIA".to_string()));
        assert!(r.literals.contains(&"ghp_".to_string()));
        assert!(r.all_branches_covered);
    }

    #[test]
    fn extract_url_domains() {
        let r = extract_literals_from_regex(r"(?i)https?://(evil|attacker|malicious)\.[a-z]{2,6}");
        assert!(r.literals.contains(&"http".to_string()));
        assert!(r.literals.contains(&"evil".to_string()));
        assert!(r.literals.contains(&"attacker".to_string()));
        assert!(r.all_branches_covered);
    }

    #[test]
    fn tautology_has_uncovered_branches() {
        // R005: 1=1 branch has no 3-char literal → not fully covered
        let r = extract_literals_from_regex(
            r"(?i)(\b1\s*=\s*1\b|\bOR\s+true\b|;\s*DROP)"
        );
        assert!(!r.all_branches_covered, "1=1 branch has no literal");
        // But "true" and "DROP" are still extracted from other branches
        assert!(r.literals.contains(&"true".to_string()));
        assert!(r.literals.contains(&"DROP".to_string()));
    }

    #[test]
    fn extract_escaped_dots() {
        let r = extract_literals_from_regex(r"\.burpcollaborator\.net");
        assert!(r.literals.contains(&".burpcollaborator.net".to_string()));
        assert!(r.all_branches_covered);
    }

    #[test]
    fn all_short_branches_not_covered() {
        // All branches are short → no literals, not covered
        let r = extract_literals_from_regex(r"(ab|cd|ef)");
        assert!(r.literals.is_empty());
        assert!(!r.all_branches_covered);
    }
}
