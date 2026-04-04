//! Test corpus: record, replay, and validate rulesets against known test cases.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::compile::{CompiledRuleset, RuleAction};
use crate::execute::ExecutionContext;
use crate::scheme::{clampd_scheme, FieldId, FieldValue};

/// A single test case in the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub tool_name: String,
    pub params_json: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub agent_risk_score: f64,
    pub expected_action: RuleAction,
    #[serde(default)]
    pub expected_min_risk: Option<f64>,
    #[serde(default)]
    pub expected_rules: Vec<String>,
}

/// Result of running the corpus against a ruleset.
#[derive(Debug)]
pub struct CorpusResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<CorpusFailure>,
}

/// A single test case failure.
#[derive(Debug)]
pub struct CorpusFailure {
    pub test_name: String,
    pub reason: String,
}

/// A collection of test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCorpus {
    cases: Vec<TestCase>,
}

impl TestCorpus {
    pub fn new() -> Self {
        Self { cases: Vec::new() }
    }

    pub fn add(&mut self, case: TestCase) {
        self.cases.push(case);
    }

    pub fn len(&self) -> usize {
        self.cases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    pub fn cases(&self) -> &[TestCase] {
        &self.cases
    }

    /// Run all test cases against a compiled ruleset.
    pub fn run(&self, ruleset: &CompiledRuleset) -> CorpusResult {
        let scheme = clampd_scheme();
        let mut passed = 0;
        let mut failures = Vec::new();

        for case in &self.cases {
            let mut ctx = ExecutionContext::new(&scheme);
            ctx.set(FieldId(0), FieldValue::String(Arc::from(case.tool_name.as_str())));
            ctx.set(FieldId(5), FieldValue::String(Arc::from(case.agent_id.as_str())));
            ctx.set(FieldId(6), FieldValue::Float(case.agent_risk_score));
            ctx.set(FieldId(4), FieldValue::String(Arc::from(case.params_json.as_str())));
            ctx.set_all_text(Arc::from(case.params_json.as_str()));

            let result = ruleset.evaluate(&ctx);

            // Check action
            if result.action != case.expected_action {
                failures.push(CorpusFailure {
                    test_name: case.name.clone(),
                    reason: format!(
                        "Expected action {:?}, got {:?} (risk={:.3})",
                        case.expected_action, result.action, result.assessed_risk
                    ),
                });
                continue;
            }

            // Check min risk
            if let Some(min_risk) = case.expected_min_risk {
                if result.assessed_risk < min_risk {
                    failures.push(CorpusFailure {
                        test_name: case.name.clone(),
                        reason: format!(
                            "Expected risk >= {:.3}, got {:.3}",
                            min_risk, result.assessed_risk
                        ),
                    });
                    continue;
                }
            }

            // Check expected rules
            for expected_rule in &case.expected_rules {
                if !result.rule_matches.iter().any(|m| m.rule_id == *expected_rule) {
                    failures.push(CorpusFailure {
                        test_name: case.name.clone(),
                        reason: format!(
                            "Expected rule {} to match, but it didn't. Matched: {:?}",
                            expected_rule,
                            result.rule_matches.iter().map(|m| &m.rule_id).collect::<Vec<_>>()
                        ),
                    });
                    continue;
                }
            }

            passed += 1;
        }

        CorpusResult {
            total: self.cases.len(),
            passed,
            failed: failures.len(),
            failures,
        }
    }
}

impl Default for TestCorpus {
    fn default() -> Self {
        Self::new()
    }
}
