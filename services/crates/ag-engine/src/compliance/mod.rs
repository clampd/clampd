// Copyright (c) 2026 Clampd Inc. - BUSL-1.1

use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataClassification {
    Restricted,
    Confidential,
    Internal,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Regulation {
    Hipaa,
    Gdpr,
    PciDss,
    Ccpa,
    Soc2,
    EuAiAct,
    NistAiRmf,
}

#[derive(Debug, Clone)]
pub struct ComplianceMapping {
    pub regulations: Vec<Regulation>,
    pub classification: DataClassification,
    pub phi_identifiers: Vec<&'static str>,
}

pub static HIPAA_PHI_IDENTIFIERS: &[&str] = &[
    "name", "address", "dates", "phone", "fax", "email",
    "ssn", "mrn", "health_plan_id", "account_number",
    "certificate_license", "vehicle_id", "device_id", "url",
    "ip_address", "biometric", "photo", "other_unique_id",
];

pub static RULE_COMPLIANCE: LazyLock<HashMap<&'static str, ComplianceMapping>> =
    LazyLock::new(|| HashMap::new());

pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u8> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u16 = digits.iter().rev().enumerate().map(|(i, &d)| {
        if i % 2 == 1 {
            let doubled = d * 2;
            (if doubled > 9 { doubled - 9 } else { doubled }) as u16
        } else {
            d as u16
        }
    }).sum();
    sum % 10 == 0
}

pub fn find_valid_cards(text: &str) -> Vec<String> {
    let _ = text;
    Vec::new()
}

pub fn get_phi_coverage(rule_id: &str) -> Vec<&'static str> {
    RULE_COMPLIANCE.get(rule_id)
        .map(|m| m.phi_identifiers.clone())
        .unwrap_or_default()
}

pub fn get_classification(rule_id: &str) -> DataClassification {
    RULE_COMPLIANCE.get(rule_id)
        .map(|m| m.classification)
        .unwrap_or(DataClassification::Public)
}

pub fn get_regulations(rule_id: &str) -> Vec<Regulation> {
    RULE_COMPLIANCE.get(rule_id)
        .map(|m| m.regulations.clone())
        .unwrap_or_default()
}
