use std::sync::Arc;

use regex::Regex;
use tracing::debug;

use crate::ner::NerDetector;
use crate::tokenizer::PiiTokenizer;

/// Result of masking a single string field.
#[derive(Debug, Clone)]
pub struct MaskResult {
    /// The masked string.
    pub text: String,
    /// Number of PII patterns found and masked.
    pub pii_count: usize,
    /// Tokens generated during masking (empty if tokenization disabled).
    pub tokens: Vec<String>,
    /// Number of NER-detected entities in this field.
    pub ner_count: usize,
}

/// Stateless PII masker with pre-compiled regex patterns, optional NER detection,
/// and optional tokenization vault.
///
/// Detects and masks email addresses, SSN-like patterns, credit card numbers,
/// phone numbers, IP addresses, and JWT tokens in freeform text fields.
/// When NER is enabled, also detects person names, addresses, organizations,
/// medical IDs, zip codes, and financial accounts.
/// When tokenization is enabled, PII is replaced with reversible tokens
/// instead of irreversible masks.
pub struct PiiMasker {
    email_re: Regex,
    ssn_re: Regex,
    credit_card_re: Regex,
    phone_re: Regex,
    ip_re: Regex,
    jwt_re: Regex,
    /// AWS access key IDs (AKIA + 16 alphanumeric chars).
    aws_key_re: Regex,
    /// Generic high-entropy secrets (40+ char base64-like strings after keywords).
    generic_secret_re: Regex,
    /// Private key headers (BEGIN RSA/EC/DSA PRIVATE KEY).
    private_key_re: Regex,
    ner_detector: Option<NerDetector>,
    tokenizer: Option<Arc<PiiTokenizer>>,
}

/// Summary of masking applied to an event.
#[derive(Debug, Clone, Default)]
pub struct MaskSummary {
    /// Total PII patterns found and replaced across all fields.
    pub total_pii_found: usize,
    /// Names of fields that were modified.
    pub masked_fields: Vec<String>,
    /// Number of tokens generated (0 when tokenization disabled).
    pub tokens_created: usize,
    /// Number of NER-detected entities across all fields.
    pub ner_detections: usize,
    /// All tokens generated during masking.
    pub pii_tokens: Vec<String>,
}

impl PiiMasker {
    /// Create a new PiiMasker with pre-compiled regex patterns (no NER, no tokenization).
    pub fn new() -> Self {
        Self {
            email_re: Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
                .expect("email regex"),
            ssn_re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex"),
            credit_card_re: Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
                .expect("credit card regex"),
            phone_re: Regex::new(
                r"\b\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
            )
            .expect("phone regex"),
            ip_re: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("ip regex"),
            jwt_re: Regex::new(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+")
                .expect("jwt regex"),
            aws_key_re: Regex::new(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
                .expect("aws key regex"),
            generic_secret_re: Regex::new(
                r#"(?i)(?:secret|password|token|key|credential|auth)[_\s:=]*['"]?([A-Za-z0-9+/=_\-]{20,})"#
            ).expect("generic secret regex"),
            private_key_re: Regex::new(r"-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----")
                .expect("private key regex"),
            ner_detector: None,
            tokenizer: None,
        }
    }

    /// Create a PiiMasker with optional NER and tokenizer.
    pub fn new_with_ner(ner_enabled: bool, tokenizer: Option<Arc<PiiTokenizer>>) -> Self {
        let mut masker = Self::new();
        if ner_enabled {
            masker.ner_detector = Some(NerDetector::new());
        }
        masker.tokenizer = tokenizer;
        masker
    }

    /// Mask all PII patterns in a string, returning the masked text and count of patterns found.
    ///
    /// If the input is valid JSON, nested string values are individually masked
    /// to catch PII embedded inside structured payloads.
    pub fn mask_string(&self, input: &str) -> MaskResult {
        // Try to parse as JSON and mask nested string values first.
        // If the input is valid JSON, recurse into all string leaves.
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(input) {
            let count = self.mask_json_value(&mut value);
            if count > 0 {
                return MaskResult {
                    text: value.to_string(),
                    pii_count: count,
                    tokens: Vec::new(),
                    ner_count: 0,
                };
            }
        }

        // Fall back to flat string masking for non-JSON input
        self.mask_flat_string(input)
    }

    /// Recursively mask PII in all string values within a JSON structure.
    /// Returns the total number of PII patterns found and replaced.
    fn mask_json_value(&self, value: &mut serde_json::Value) -> usize {
        match value {
            serde_json::Value::String(s) => {
                let result = self.mask_flat_string(s);
                if result.pii_count > 0 {
                    *s = result.text;
                }
                result.pii_count
            }
            serde_json::Value::Object(map) => {
                let mut total = 0;
                for v in map.values_mut() {
                    total += self.mask_json_value(v);
                }
                total
            }
            serde_json::Value::Array(arr) => {
                let mut total = 0;
                for v in arr.iter_mut() {
                    total += self.mask_json_value(v);
                }
                total
            }
            _ => 0,
        }
    }

    /// Mask PII in a flat string (regex + NER, no JSON recursion).
    /// This is the core masking logic extracted so `mask_json_value` can call it
    /// without re-entering the JSON parsing path.
    ///
    /// Collects all regex matches first, deduplicates overlapping ranges (keeping
    /// the longer match), then applies replacements from right to left to preserve
    /// byte indices. This prevents a JWT match from consuming an embedded email.
    fn mask_flat_string(&self, input: &str) -> MaskResult {
        let text = input.to_string();

        // Collect all regex matches with their ranges and replacement strings.
        // Uses owned Strings so NER-generated replacements don't require Box::leak.
        // (start, end, replacement)
        let mut all_matches: Vec<(usize, usize, String)> = Vec::new();

        for m in self.jwt_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "[REDACTED_TOKEN]".to_string()));
        }
        for m in self.email_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "***@***".to_string()));
        }
        for m in self.ssn_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "***-**-****".to_string()));
        }
        for m in self.credit_card_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "****-****-****-****".to_string()));
        }
        for m in self.phone_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "***-***-****".to_string()));
        }
        for m in self.ip_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "***.***.***.***".to_string()));
        }
        // Secret patterns
        for m in self.aws_key_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "[REDACTED_AWS_KEY]".to_string()));
        }
        for caps in self.generic_secret_re.captures_iter(&text) {
            if let Some(secret_match) = caps.get(1) {
                all_matches.push((secret_match.start(), secret_match.end(), "[REDACTED_SECRET]".to_string()));
            }
        }
        for m in self.private_key_re.find_iter(&text) {
            all_matches.push((m.start(), m.end(), "[REDACTED_PRIVATE_KEY]".to_string()));
        }

        // NER matches
        let ner_count = if let Some(ref ner) = self.ner_detector {
            let ner_matches = ner.detect(&text);
            let count = ner_matches.len();
            for m in &ner_matches {
                let replacement = format!("[REDACTED_{}]", m.entity_type.as_str().to_uppercase());
                all_matches.push((m.start, m.end, replacement));
            }
            count
        } else {
            0
        };

        // Sort by start position descending (for right-to-left replacement)
        all_matches.sort_by(|a, b| b.0.cmp(&a.0));

        // Deduplicate overlapping ranges — keep longer match (same logic as tokenized path)
        let mut deduped: Vec<&(usize, usize, String)> = Vec::new();
        for find in &all_matches {
            if deduped.iter().all(|d| find.1 <= d.0 || find.0 >= d.1) {
                deduped.push(find);
            }
        }
        deduped.sort_by(|a, b| b.0.cmp(&a.0));

        let pii_count = deduped.len();

        // Apply replacements from right to left to preserve byte indices
        let mut result = text;
        for (start, end, replacement) in &deduped {
            result.replace_range(*start..*end, replacement);
        }

        MaskResult {
            text: result,
            pii_count,
            tokens: Vec::new(),
            ner_count,
        }
    }

    /// Mask a string with tokenization (async). If tokenizer is enabled, PII values
    /// are replaced with reversible tokens instead of irreversible masks.
    pub async fn mask_string_tokenized(&self, input: &str) -> MaskResult {
        let tokenizer = match &self.tokenizer {
            Some(t) if t.is_enabled() => t,
            _ => return self.mask_string(input),
        };

        let mut text = input.to_string();
        let mut tokens = Vec::new();

        // Collect regex PII matches with their types (process from most specific first)
        let mut pii_finds: Vec<(usize, usize, &str)> = Vec::new(); // (start, end, type)

        for m in self.jwt_re.find_iter(&text) {
            pii_finds.push((m.start(), m.end(), "jwt"));
        }
        for m in self.email_re.find_iter(&text) {
            pii_finds.push((m.start(), m.end(), "email"));
        }
        for m in self.ssn_re.find_iter(&text) {
            pii_finds.push((m.start(), m.end(), "ssn"));
        }
        for m in self.credit_card_re.find_iter(&text) {
            pii_finds.push((m.start(), m.end(), "credit_card"));
        }
        for m in self.phone_re.find_iter(&text) {
            pii_finds.push((m.start(), m.end(), "phone"));
        }
        for m in self.ip_re.find_iter(&text) {
            pii_finds.push((m.start(), m.end(), "ip"));
        }

        // NER matches
        let ner_count = if let Some(ref ner) = self.ner_detector {
            let ner_matches = ner.detect(&text);
            let count = ner_matches.len();
            for m in &ner_matches {
                pii_finds.push((m.start, m.end, m.entity_type.as_str()));
            }
            count
        } else {
            0
        };

        // Sort by start position descending to replace from end
        pii_finds.sort_by(|a, b| b.0.cmp(&a.0));

        // Deduplicate overlapping ranges (keep longer/earlier match)
        let mut deduped: Vec<(usize, usize, &str)> = Vec::new();
        for find in &pii_finds {
            if deduped.iter().all(|d| find.1 <= d.0 || find.0 >= d.1) {
                deduped.push(*find);
            }
        }
        deduped.sort_by(|a, b| b.0.cmp(&a.0));

        let pii_count = deduped.len();

        // Replace each PII occurrence with a token
        for (start, end, entity_type) in &deduped {
            let original = &text[*start..*end];
            match tokenizer.tokenize(original, entity_type).await {
                Ok(result) => {
                    let replacement = format!("[PII:{}]", result.token);
                    text.replace_range(*start..*end, &replacement);
                    tokens.push(result.token);
                }
                Err(e) => {
                    // Fallback to irreversible mask on tokenization failure
                    debug!(error = %e, "Tokenization failed, using irreversible mask");
                    let replacement = format!("[REDACTED_{}]", entity_type.to_uppercase());
                    text.replace_range(*start..*end, &replacement);
                }
            }
        }

        MaskResult {
            text,
            pii_count,
            tokens,
            ner_count,
        }
    }

    /// Mask PII in a ShadowEvent's mutable string fields (in-place via references).
    ///
    /// Returns a MaskSummary containing the total PII found and which fields were modified.
    /// This masks: params_summary, tool_action, policy_reason, denial_reason,
    /// boundary_violation, agent_name, user_id, scope_requested, intent_labels,
    /// and session_flags.
    ///
    /// Fields NOT masked: params_hash, prompt_hash, trace_id, org_id, agent_id,
    /// session_id, request_id (these are UUIDs/hashes, not freeform text).
    pub fn mask_event(&self, event: &mut ag_common::models::ShadowEvent) -> MaskSummary {
        let mut summary = MaskSummary::default();

        // Helper closure to mask a field and track it
        macro_rules! mask_field {
            ($field:expr, $name:expr) => {
                let result = self.mask_string($field);
                if result.pii_count > 0 {
                    summary.total_pii_found += result.pii_count;
                    summary.ner_detections += result.ner_count;
                    summary.masked_fields.push($name.to_string());
                    *$field = result.text;
                }
            };
        }

        // Mask freeform string fields that may contain user data
        mask_field!(&mut event.params_summary, "params_summary");
        mask_field!(&mut event.tool_action, "tool_action");
        mask_field!(&mut event.policy_reason, "policy_reason");
        mask_field!(&mut event.agent_name, "agent_name");
        mask_field!(&mut event.user_id, "user_id");
        mask_field!(&mut event.scope_requested, "scope_requested");

        // Optional string fields
        if let Some(ref mut granted) = event.scope_granted {
            let result = self.mask_string(granted);
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.masked_fields.push("scope_granted".to_string());
                *granted = result.text;
            }
        }

        if let Some(ref mut reason) = event.denial_reason {
            let result = self.mask_string(reason);
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.masked_fields.push("denial_reason".to_string());
                *reason = result.text;
            }
        }

        if let Some(ref mut violation) = event.boundary_violation {
            let result = self.mask_string(violation);
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.masked_fields.push("boundary_violation".to_string());
                *violation = result.text;
            }
        }

        // Vec<String> fields
        let mut labels_modified = false;
        for label in event.intent_labels.iter_mut() {
            let result = self.mask_string(label);
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                labels_modified = true;
                *label = result.text;
            }
        }
        if labels_modified {
            summary.masked_fields.push("intent_labels".to_string());
        }

        let mut flags_modified = false;
        for flag in event.session_flags.iter_mut() {
            let result = self.mask_string(flag);
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                flags_modified = true;
                *flag = result.text;
            }
        }
        if flags_modified {
            summary.masked_fields.push("session_flags".to_string());
        }

        if summary.total_pii_found > 0 {
            debug!(
                pii_found = summary.total_pii_found,
                ner_detections = summary.ner_detections,
                tokens_created = summary.tokens_created,
                fields = ?summary.masked_fields,
                "PII masked in event"
            );
        }

        summary
    }

    /// Async version of mask_event that uses tokenization when enabled.
    pub async fn mask_event_tokenized(
        &self,
        event: &mut ag_common::models::ShadowEvent,
    ) -> MaskSummary {
        // If tokenizer is not enabled, fall back to sync version
        let tokenizer_enabled = self
            .tokenizer
            .as_ref()
            .map(|t| t.is_enabled())
            .unwrap_or(false);

        if !tokenizer_enabled {
            return self.mask_event(event);
        }

        let mut summary = MaskSummary::default();

        // Helper: mask a single field with tokenization
        macro_rules! mask_field_async {
            ($field:expr, $name:expr) => {
                let result = self.mask_string_tokenized($field).await;
                if result.pii_count > 0 {
                    summary.total_pii_found += result.pii_count;
                    summary.ner_detections += result.ner_count;
                    summary.tokens_created += result.tokens.len();
                    summary.pii_tokens.extend(result.tokens);
                    summary.masked_fields.push($name.to_string());
                    *$field = result.text;
                }
            };
        }

        mask_field_async!(&mut event.params_summary, "params_summary");
        mask_field_async!(&mut event.tool_action, "tool_action");
        mask_field_async!(&mut event.policy_reason, "policy_reason");
        mask_field_async!(&mut event.agent_name, "agent_name");
        mask_field_async!(&mut event.user_id, "user_id");
        mask_field_async!(&mut event.scope_requested, "scope_requested");

        if let Some(ref mut granted) = event.scope_granted {
            let result = self.mask_string_tokenized(granted).await;
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.tokens_created += result.tokens.len();
                summary.pii_tokens.extend(result.tokens);
                summary.masked_fields.push("scope_granted".to_string());
                *granted = result.text;
            }
        }

        if let Some(ref mut reason) = event.denial_reason {
            let result = self.mask_string_tokenized(reason).await;
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.tokens_created += result.tokens.len();
                summary.pii_tokens.extend(result.tokens);
                summary.masked_fields.push("denial_reason".to_string());
                *reason = result.text;
            }
        }

        if let Some(ref mut violation) = event.boundary_violation {
            let result = self.mask_string_tokenized(violation).await;
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.tokens_created += result.tokens.len();
                summary.pii_tokens.extend(result.tokens);
                summary.masked_fields.push("boundary_violation".to_string());
                *violation = result.text;
            }
        }

        let mut labels_modified = false;
        for label in event.intent_labels.iter_mut() {
            let result = self.mask_string_tokenized(label).await;
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.tokens_created += result.tokens.len();
                summary.pii_tokens.extend(result.tokens);
                labels_modified = true;
                *label = result.text;
            }
        }
        if labels_modified {
            summary.masked_fields.push("intent_labels".to_string());
        }

        let mut flags_modified = false;
        for flag in event.session_flags.iter_mut() {
            let result = self.mask_string_tokenized(flag).await;
            if result.pii_count > 0 {
                summary.total_pii_found += result.pii_count;
                summary.ner_detections += result.ner_count;
                summary.tokens_created += result.tokens.len();
                summary.pii_tokens.extend(result.tokens);
                flags_modified = true;
                *flag = result.text;
            }
        }
        if flags_modified {
            summary.masked_fields.push("session_flags".to_string());
        }

        if summary.total_pii_found > 0 {
            debug!(
                pii_found = summary.total_pii_found,
                ner_detections = summary.ner_detections,
                tokens_created = summary.tokens_created,
                fields = ?summary.masked_fields,
                "PII masked in event (tokenized)"
            );
        }

        summary
    }
}

impl Default for PiiMasker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_test_event() -> ag_common::models::ShadowEvent {
        ag_common::models::ShadowEvent {
            request_id: Uuid::new_v4(),
            trace_id: Uuid::new_v4().to_string(),
            org_id: "org-123".to_string(),
            agent_id: Uuid::new_v4().to_string(),
            agent_name: "test-agent".to_string(),
            user_id: "user:test".to_string(),
            tool_name: "db.query".to_string(),
            tool_action: "SELECT".to_string(),
            params_hash: "sha256:abc123".to_string(),
            params_summary: "SELECT name FROM users".to_string(),
            prompt_hash: "sha256:def456".to_string(),
            encodings_detected: vec![],
            encoding_risk_bonus: 0.0,
            assessed_risk: 0.1,
            session_risk_factor: 0.0,
            intent_classification: "Safe".to_string(),
            intent_labels: vec![],
            matched_rules: vec![],
            policy_action: "allow".to_string(),
            policy_reason: "scope ok".to_string(),
            boundary_violation: None,
            scope_requested: "db:read".to_string(),
            scope_granted: Some("db:read".to_string()),
            blocked: false,
            denial_reason: None,
            session_id: "sess-123".to_string(),
            session_flags: vec![],
            response_metadata: None,
            degraded_stages: vec![],
            latency_ms: 10,
            timestamp: Utc::now(),
            caller_agent_id: None,
            delegation_chain: None,
            delegation_trace_id: None,
            tool_descriptor_hash: String::new(),
            tool_description: String::new(),
            tool_params_schema: String::new(),
            active_hours_start: 0,
            active_hours_end: 0,
            rejection_type: ag_common::models::RejectionType::None,
        }
    }

    #[test]
    fn test_mask_email() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Contact john.doe@example.com for details");
        assert_eq!(result.text, "Contact ***@*** for details");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_multiple_emails() {
        let masker = PiiMasker::new();
        let result =
            masker.mask_string("From alice@acme.com to bob@corp.io about project");
        assert_eq!(result.text, "From ***@*** to ***@*** about project");
        assert_eq!(result.pii_count, 2);
    }

    #[test]
    fn test_mask_ssn() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("SSN is 123-45-6789");
        assert_eq!(result.text, "SSN is ***-**-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_credit_card_with_spaces() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Card: 4111 1111 1111 1111");
        assert_eq!(result.text, "Card: ****-****-****-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_credit_card_with_dashes() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Card: 4111-1111-1111-1111");
        assert_eq!(result.text, "Card: ****-****-****-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_credit_card_no_separator() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Card: 4111111111111111");
        assert_eq!(result.text, "Card: ****-****-****-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_phone_us_format() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Call (555) 123-4567");
        assert_eq!(result.text, "Call***-***-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_phone_with_country_code() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Call +15551234567");
        assert_eq!(result.text, "Call +***-***-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_ip_address() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Source IP: 192.168.1.100");
        assert_eq!(result.text, "Source IP: ***.***.***.***");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_jwt_token() {
        let masker = PiiMasker::new();
        let result = masker.mask_string(
            "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        );
        assert_eq!(result.text, "Token: [REDACTED_TOKEN]");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_mixed_pii() {
        let masker = PiiMasker::new();
        let result = masker.mask_string(
            "User john@acme.com from 10.0.0.1 with SSN 111-22-3333",
        );
        assert!(result.text.contains("***@***"));
        assert!(result.text.contains("***.***.***.***"));
        assert!(result.text.contains("***-**-****"));
        assert_eq!(result.pii_count, 3);
    }

    #[test]
    fn test_mask_no_pii() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Normal text without PII");
        assert_eq!(result.text, "Normal text without PII");
        assert_eq!(result.pii_count, 0);
    }

    #[test]
    fn test_mask_empty_string() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("");
        assert_eq!(result.text, "");
        assert_eq!(result.pii_count, 0);
    }

    #[test]
    fn test_mask_event_no_pii() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 0);
        assert!(summary.masked_fields.is_empty());
    }

    #[test]
    fn test_mask_event_pii_in_policy_reason() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.policy_reason = "Denied for user john@example.com".to_string();
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary.masked_fields.contains(&"policy_reason".to_string()));
        assert_eq!(event.policy_reason, "Denied for user ***@***");
    }

    #[test]
    fn test_mask_event_pii_in_denial_reason() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.denial_reason = Some("Agent accessed SSN 123-45-6789".to_string());
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary.masked_fields.contains(&"denial_reason".to_string()));
        assert_eq!(
            event.denial_reason.as_deref(),
            Some("Agent accessed SSN ***-**-****")
        );
    }

    #[test]
    fn test_mask_event_pii_in_user_id() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.user_id = "user:alice@corp.com".to_string();
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary.masked_fields.contains(&"user_id".to_string()));
        assert_eq!(event.user_id, "user:***@***");
    }

    #[test]
    fn test_mask_event_pii_in_intent_labels() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.intent_labels = vec![
            "normal_label".to_string(),
            "user_data:bob@evil.net".to_string(),
        ];
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary.masked_fields.contains(&"intent_labels".to_string()));
        assert_eq!(event.intent_labels[0], "normal_label");
        assert_eq!(event.intent_labels[1], "user_data:***@***");
    }

    #[test]
    fn test_mask_event_pii_in_boundary_violation() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.boundary_violation =
            Some("IP 10.20.30.40 accessed forbidden resource".to_string());
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary
            .masked_fields
            .contains(&"boundary_violation".to_string()));
        let violation = event.boundary_violation.unwrap();
        // IP should be masked to ***.***.***.***
        assert!(!violation.contains("10.20.30.40"), "IP should be masked");
        assert!(violation.contains("accessed forbidden resource"));
        assert!(violation.starts_with("IP "));
    }

    #[test]
    fn test_mask_event_pii_in_tool_action() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.tool_action =
            r#"SELECT * WHERE email='test@domain.com'"#.to_string();
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary.masked_fields.contains(&"tool_action".to_string()));
        assert!(event.tool_action.contains("***@***"));
    }

    #[test]
    fn test_mask_event_multiple_fields_with_pii() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.policy_reason = "User admin@corp.com allowed".to_string();
        event.tool_action = "Query from 192.168.0.1".to_string();
        event.denial_reason = Some("SSN 999-88-7777 detected".to_string());
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 3);
        assert_eq!(summary.masked_fields.len(), 3);
    }

    #[test]
    fn test_mask_event_session_flags_with_pii() {
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.session_flags = vec![
            "suspicious_activity".to_string(),
            "from_ip:172.16.0.1".to_string(),
        ];
        let summary = masker.mask_event(&mut event);
        assert_eq!(summary.total_pii_found, 1);
        assert!(summary.masked_fields.contains(&"session_flags".to_string()));
        assert_eq!(event.session_flags[1], "from_ip:***.***.***.***");
    }

    #[test]
    fn test_mask_email_in_url() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("https://example.com/user?email=test@domain.com&action=view");
        assert!(result.text.contains("***@***"));
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_ssn_in_json() {
        let masker = PiiMasker::new();
        let result =
            masker.mask_string(r#"{"ssn":"123-45-6789","name":"John"}"#);
        assert!(result.text.contains("***-**-****"));
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_jwt_in_reason_string() {
        let masker = PiiMasker::new();
        let result = masker.mask_string(
            "Auth failed with token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZ2VudCJ9 and was denied",
        );
        assert!(result.text.contains("[REDACTED_TOKEN]"));
        assert!(!result.text.contains("eyJ"));
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_mask_phone_dot_separated() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Phone: 555.123.4567");
        assert_eq!(result.text, "Phone: ***-***-****");
        assert_eq!(result.pii_count, 1);
    }

    #[test]
    fn test_params_hash_not_masked() {
        // Hashes should NOT be masked (they contain dots but are not IPs/emails)
        let masker = PiiMasker::new();
        let mut event = make_test_event();
        event.params_hash = "sha256:a1b2c3d4e5f6".to_string();
        event.prompt_hash = "sha256:f6e5d4c3b2a1".to_string();
        let summary = masker.mask_event(&mut event);
        // params_hash and prompt_hash are not passed through masking
        assert_eq!(event.params_hash, "sha256:a1b2c3d4e5f6");
        assert_eq!(event.prompt_hash, "sha256:f6e5d4c3b2a1");
        assert_eq!(summary.total_pii_found, 0);
    }

    // NER-specific tests

    #[test]
    fn test_ner_enabled_detects_person_name() {
        let masker = PiiMasker::new_with_ner(true, None);
        let result = masker.mask_string("Contact Dr. John Smith about the case");
        assert!(result.ner_count > 0);
        assert!(result.text.contains("[REDACTED_PERSON_NAME]"));
    }

    #[test]
    fn test_ner_enabled_detects_organization() {
        let masker = PiiMasker::new_with_ner(true, None);
        let result = masker.mask_string("Working with Acme Corp on the deal");
        assert!(result.ner_count > 0);
        assert!(result.text.contains("[REDACTED_ORGANIZATION]"));
    }

    #[test]
    fn test_ner_disabled_no_extra_detections() {
        let masker = PiiMasker::new();
        let result = masker.mask_string("Contact Dr. John Smith about the case");
        assert_eq!(result.ner_count, 0);
        // Should not contain NER-specific redactions
        assert!(!result.text.contains("[REDACTED_PERSON_NAME]"));
    }

    #[test]
    fn test_new_with_ner_constructor() {
        let masker = PiiMasker::new_with_ner(true, None);
        assert!(masker.ner_detector.is_some());
        assert!(masker.tokenizer.is_none());
    }

    #[test]
    fn test_mask_summary_new_fields_default() {
        let summary = MaskSummary::default();
        assert_eq!(summary.tokens_created, 0);
        assert_eq!(summary.ner_detections, 0);
        assert!(summary.pii_tokens.is_empty());
    }
}
