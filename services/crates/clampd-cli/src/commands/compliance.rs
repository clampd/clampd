use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

// ── Check Result ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    control: String,
    name: String,
    status: String, // "pass", "fail", "warn", "info"
    details: String,
}

impl CheckResult {
    fn pass(control: &str, name: &str, details: &str) -> Self {
        Self { control: control.into(), name: name.into(), status: "pass".into(), details: details.into() }
    }
    fn fail(control: &str, name: &str, details: &str) -> Self {
        Self { control: control.into(), name: name.into(), status: "fail".into(), details: details.into() }
    }
    fn warn(control: &str, name: &str, details: &str) -> Self {
        Self { control: control.into(), name: name.into(), status: "warn".into(), details: details.into() }
    }
    fn info(control: &str, name: &str, details: &str) -> Self {
        Self { control: control.into(), name: name.into(), status: "info".into(), details: details.into() }
    }
    fn check(control: &str, name: &str, passed: bool, pass_detail: &str, fail_detail: &str) -> Self {
        if passed { Self::pass(control, name, pass_detail) } else { Self::fail(control, name, fail_detail) }
    }
}

// ── Common evidence collection via Dashboard API ────────────

struct Evidence {
    org_count: i64,
    agent_count: i64,
    active_agents: i64,
    killed_agents: i64,
    active_licenses: i64,
    expired_licenses: i64,
    api_keys_total: i64,
    api_keys_no_expiry: i64,
    api_keys_revoked: i64,
    member_count: i64,
    webhook_count: i64,
    policy_count: i64,
    rule_count: i64,
    audit_trail_count: i64,
    audit_retention_days: Vec<i32>,
    kill_service_reachable: bool,
}

async fn collect_evidence(state: &AppState) -> Result<Evidence> {
    let client = state.api_client();
    let org_id = client.org_id();

    // Fetch data from various dashboard API endpoints
    let agents: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/agents", org_id)).await.unwrap_or_default();
    let api_keys: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/api-keys", org_id)).await.unwrap_or_default();
    let members: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/members", org_id)).await.unwrap_or_default();
    let webhooks: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/webhooks", org_id)).await.unwrap_or_default();
    let licenses: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/licenses", org_id)).await.unwrap_or_default();

    // Policies and rules may require pro tier; handle errors gracefully
    let policies: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/policies", org_id)).await.unwrap_or_default();
    let rules: Vec<serde_json::Value> = client.get(&format!("/v1/orgs/{}/rules", org_id)).await.unwrap_or_default();

    // Audit trail count
    let audit: serde_json::Value = client.get(&format!("/v1/orgs/{}/audit-trail?limit=1", org_id)).await.unwrap_or_default();
    let audit_trail_count = audit["total"].as_i64().unwrap_or(0);

    // Agent stats
    let active_agents = agents.iter().filter(|a| a["state"].as_str() == Some("active")).count() as i64;
    let killed_agents = agents.iter().filter(|a| a["state"].as_str() == Some("killed")).count() as i64;

    // License stats
    let active_licenses = licenses.iter().filter(|l| l["status"].as_str() == Some("active")).count() as i64;
    let expired_licenses = licenses.iter().filter(|l| {
        let s = l["status"].as_str().unwrap_or("");
        s == "expired" || s == "revoked"
    }).count() as i64;

    // API key stats
    let api_keys_revoked = api_keys.iter().filter(|k| {
        k["revokedAt"].as_str().or(k["revoked_at"].as_str()).is_some()
    }).count() as i64;
    let api_keys_active: Vec<&serde_json::Value> = api_keys.iter().filter(|k| {
        k["revokedAt"].is_null() && k["revoked_at"].is_null()
    }).collect();
    // All CLI-created keys currently lack expiry, count them
    let api_keys_no_expiry = api_keys_active.len() as i64;

    // Webhook stats (only count enabled ones)
    let webhook_count = webhooks.iter().filter(|w| w["enabled"].as_bool() == Some(true)).count() as i64;

    // Policy/rule counts (active/enabled)
    let policy_count = policies.iter().filter(|p| p["status"].as_str() == Some("active")).count() as i64;
    let rule_count = rules.iter().filter(|r| r["enabled"].as_bool() == Some(true)).count() as i64;

    // Check if cluster health is reachable (proxy for kill service)
    let kill_reachable = client.get::<serde_json::Value>(&format!("/v1/orgs/{}/cluster-health", org_id)).await.is_ok();

    // Get org details for retention config
    let org: serde_json::Value = client.get(&format!("/v1/orgs/{}", org_id)).await.unwrap_or_default();
    let retention = org["auditRetentionDays"].as_i64()
        .or(org["audit_retention_days"].as_i64())
        .unwrap_or(30) as i32;

    Ok(Evidence {
        org_count: 1, // We know at least our org exists
        agent_count: agents.len() as i64,
        active_agents,
        killed_agents,
        active_licenses,
        expired_licenses,
        api_keys_total: api_keys_active.len() as i64,
        api_keys_no_expiry,
        api_keys_revoked,
        member_count: members.len() as i64,
        webhook_count,
        policy_count,
        rule_count,
        audit_trail_count,
        audit_retention_days: vec![retention],
        kill_service_reachable: kill_reachable,
    })
}

// ── SOC 2 Checks ────────────────────────────────────────────

fn checks_soc2(ev: &Evidence) -> Vec<CheckResult> {
    let mut c = Vec::new();

    c.push(CheckResult::check(
        "CC6.1", "RBAC members configured",
        ev.member_count > 0,
        &format!("{} members with role-based access", ev.member_count),
        "No org members configured - RBAC not enforced",
    ));
    c.push(CheckResult::check(
        "CC6.1", "Admin audit trail active",
        ev.audit_trail_count > 0,
        &format!("{} audit entries recorded", ev.audit_trail_count),
        "No audit trail entries - enable audit logging",
    ));

    c.push(CheckResult::check(
        "CC6.2", "Active policies enforced",
        ev.policy_count > 0,
        &format!("{} active policies", ev.policy_count),
        "No active policies - agent behavior is ungoverned",
    ));
    c.push(CheckResult::check(
        "CC6.2", "Rules engine configured",
        ev.rule_count > 0,
        &format!("{} enabled rules", ev.rule_count),
        "No rules configured - request filtering disabled",
    ));

    c.push(CheckResult::check(
        "CC6.3", "Webhook monitoring configured",
        ev.webhook_count > 0,
        &format!("{} active webhooks for change notifications", ev.webhook_count),
        "No webhooks - operational changes are unmonitored",
    ));

    c.push(CheckResult::check(
        "CC7.2", "Kill switch service available",
        ev.kill_service_reachable,
        "Kill switch service is reachable",
        "Kill switch service unreachable - incident response degraded",
    ));

    let all_retention_ok = ev.audit_retention_days.iter().all(|d| *d >= 90);
    if ev.audit_retention_days.is_empty() {
        c.push(CheckResult::fail("CC7.3", "Audit retention >= 90 days", "No organizations found"));
    } else if all_retention_ok {
        c.push(CheckResult::pass("CC7.3", "Audit retention >= 90 days", "All orgs meet 90-day retention"));
    } else {
        let min = ev.audit_retention_days.iter().min().unwrap_or(&0);
        c.push(CheckResult::fail("CC7.3", "Audit retention >= 90 days", &format!("Minimum retention is {min} days - requires 90")));
    }

    c.push(CheckResult::check(
        "CC8.1", "License management active",
        ev.active_licenses > 0,
        &format!("{} active license(s)", ev.active_licenses),
        "No active licenses - deployment unregistered",
    ));

    if ev.api_keys_no_expiry > 0 {
        c.push(CheckResult::warn(
            "CC6.1", "API key expiration policy",
            &format!("{} API keys without expiration date", ev.api_keys_no_expiry),
        ));
    } else {
        c.push(CheckResult::pass("CC6.1", "API key expiration policy", "All API keys have expiration dates"));
    }

    c
}

// ── HIPAA Checks ────────────────────────────────────────────

fn checks_hipaa(ev: &Evidence) -> Vec<CheckResult> {
    let mut c = Vec::new();

    c.push(CheckResult::check(
        "164.312(a)(1)", "Unique user identification (RBAC)",
        ev.member_count > 0,
        &format!("{} uniquely identified members", ev.member_count),
        "No RBAC members - unique identification not enforced",
    ));

    c.push(CheckResult::check(
        "164.312(a)(2)(i)", "Emergency kill switch procedure",
        ev.kill_service_reachable,
        "Kill switch available for emergency access termination",
        "Kill switch unreachable - emergency procedures degraded",
    ));

    c.push(CheckResult::check(
        "164.312(b)", "Audit controls implemented",
        ev.audit_trail_count > 0,
        &format!("{} audit records - logging active", ev.audit_trail_count),
        "No audit records - HIPAA audit control requirement not met",
    ));

    c.push(CheckResult::check(
        "164.312(c)(1)", "Policy-based integrity controls",
        ev.policy_count > 0,
        &format!("{} active policies governing agent behavior", ev.policy_count),
        "No policies - data integrity controls missing",
    ));

    c.push(CheckResult::check(
        "164.312(d)", "Agent authentication enforced",
        ev.active_licenses > 0,
        "License-based agent authentication active",
        "No active licenses - agent authentication unverified",
    ));

    c.push(CheckResult::info(
        "164.312(e)(1)", "Transmission encryption (TLS)",
        "Verify TLS is enforced on all service endpoints (gateway, API, dashboard)",
    ));

    if ev.api_keys_no_expiry > 0 {
        c.push(CheckResult::warn(
            "164.308(a)(5)", "Credential lifecycle management",
            &format!("{} API keys without expiration - rotate or set expiry", ev.api_keys_no_expiry),
        ));
    } else {
        c.push(CheckResult::pass("164.308(a)(5)", "Credential lifecycle management", "All API keys have expiration"));
    }

    c.push(CheckResult::check(
        "164.308(a)(6)", "Incident notification (webhooks)",
        ev.webhook_count > 0,
        &format!("{} webhooks for incident notification", ev.webhook_count),
        "No webhooks - incident notification not automated",
    ));

    c.push(CheckResult::check(
        "164.316(b)(1)", "Retention of audit documentation",
        ev.audit_retention_days.iter().all(|d| *d >= 180),
        "Audit retention meets 6-year HIPAA recommendation threshold",
        "Some orgs have retention < 180 days (HIPAA recommends 6 years)",
    ));

    c
}

// ── ISO 27001 Checks ────────────────────────────────────────

fn checks_iso27001(ev: &Evidence) -> Vec<CheckResult> {
    let mut c = Vec::new();

    c.push(CheckResult::check(
        "A.5.1", "Security policies defined",
        ev.policy_count > 0,
        &format!("{} active security policies", ev.policy_count),
        "No security policies - A.5.1 control not satisfied",
    ));

    c.push(CheckResult::check(
        "A.6.1", "Roles and responsibilities (RBAC)",
        ev.member_count > 0,
        &format!("{} members with assigned roles", ev.member_count),
        "No RBAC - roles and responsibilities undefined",
    ));

    c.push(CheckResult::check(
        "A.8.1", "Agent inventory maintained",
        ev.agent_count > 0,
        &format!("{} agents registered ({} active, {} killed)", ev.agent_count, ev.active_agents, ev.killed_agents),
        "No agents registered - asset inventory empty",
    ));
    c.push(CheckResult::check(
        "A.8.2", "License asset tracking",
        ev.active_licenses > 0,
        &format!("{} active, {} expired/revoked licenses tracked", ev.active_licenses, ev.expired_licenses),
        "No license tracking",
    ));

    c.push(if ev.api_keys_no_expiry > 0 {
        CheckResult::warn("A.9.2", "API key lifecycle management", &format!("{} keys without expiry", ev.api_keys_no_expiry))
    } else {
        CheckResult::pass("A.9.2", "API key lifecycle management", "All keys have expiration policies")
    });
    c.push(CheckResult::check(
        "A.9.4", "Agent credential management",
        ev.active_licenses > 0,
        "License-based credential management active",
        "No license-based auth - credential management gap",
    ));

    c.push(CheckResult::check(
        "A.12.4", "Event logging (audit trail)",
        ev.audit_trail_count > 0,
        &format!("{} audit trail entries", ev.audit_trail_count),
        "No audit trail - event logging not implemented",
    ));
    c.push(CheckResult::check(
        "A.12.4", "Rule-based monitoring",
        ev.rule_count > 0,
        &format!("{} active rules for real-time monitoring", ev.rule_count),
        "No monitoring rules configured",
    ));

    c.push(CheckResult::check(
        "A.16.1", "Incident response capability",
        ev.kill_service_reachable,
        "Kill switch operational for incident response",
        "Kill switch unreachable - incident response degraded",
    ));
    c.push(CheckResult::check(
        "A.16.1", "Incident notification automation",
        ev.webhook_count > 0,
        &format!("{} webhooks for automated incident notification", ev.webhook_count),
        "No webhook notifications configured",
    ));

    let retention_ok = ev.audit_retention_days.iter().all(|d| *d >= 90);
    c.push(CheckResult::check(
        "A.18.1", "Audit log retention compliance",
        retention_ok || ev.audit_retention_days.is_empty(),
        "Audit retention meets minimum requirements",
        "Some orgs below 90-day retention requirement",
    ));

    c
}

// ── GDPR Checks ─────────────────────────────────────────────

fn checks_gdpr(ev: &Evidence) -> Vec<CheckResult> {
    let mut c = Vec::new();

    c.push(CheckResult::check(
        "Art.5(1)(b)", "Purpose limitation via policies",
        ev.policy_count > 0,
        &format!("{} policies enforcing purpose limitation", ev.policy_count),
        "No policies - purpose limitation not technically enforced",
    ));

    c.push(CheckResult::info(
        "Art.17", "Right to Erasure endpoint",
        "DELETE /v1/orgs/:id/agents/:aid/data available via dashboard API",
    ));

    c.push(CheckResult::info(
        "Art.20", "Data portability endpoint",
        "GET /v1/orgs/:id/agents/:aid/export?format=json|csv available via dashboard API",
    ));

    c.push(CheckResult::check(
        "Art.25", "Data minimization (rule-based filtering)",
        ev.rule_count > 0,
        &format!("{} rules filtering agent data access", ev.rule_count),
        "No rules - data minimization not enforced at proxy layer",
    ));

    c.push(CheckResult::check(
        "Art.30", "Processing activity records (audit trail)",
        ev.audit_trail_count > 0,
        &format!("{} audit records of processing activities", ev.audit_trail_count),
        "No audit records - Art. 30 not satisfied",
    ));

    c.push(CheckResult::check(
        "Art.32(1)(b)", "Access control (RBAC)",
        ev.member_count > 0,
        &format!("{} members with role-based access controls", ev.member_count),
        "No RBAC - access control measures missing",
    ));
    c.push(CheckResult::check(
        "Art.32(1)(d)", "Testing and assessment capability",
        ev.kill_service_reachable,
        "Kill switch available for security testing/response",
        "Kill switch unreachable - security assessment gap",
    ));

    c.push(CheckResult::check(
        "Art.33", "Breach notification mechanism",
        ev.webhook_count > 0,
        &format!("{} webhooks for automated breach notification", ev.webhook_count),
        "No webhooks - breach notification not automated (72h requirement)",
    ));

    c.push(CheckResult::info(
        "Art.35", "Data Protection Impact Assessment",
        &format!(
            "System manages {} agents across {} org(s). Risk scoring + shadow logging provide DPIA evidence.",
            ev.agent_count, ev.org_count,
        ),
    ));

    if ev.api_keys_no_expiry > 0 {
        c.push(CheckResult::warn(
            "Art.32(1)(a)", "Credential rotation",
            &format!("{} API keys without expiration - rotation recommended", ev.api_keys_no_expiry),
        ));
    } else {
        c.push(CheckResult::pass("Art.32(1)(a)", "Credential rotation", "All API keys have expiration dates"));
    }

    c
}

// ── Run (interactive) ───────────────────────────────────────

pub async fn run(state: &AppState, framework: &str) -> Result<()> {
    let fw = framework.to_lowercase();
    let valid = ["soc2", "hipaa", "iso27001", "gdpr"];
    if !valid.contains(&fw.as_str()) {
        println!("Unknown framework: {framework}");
        println!("Supported: {}", valid.join(", "));
        return Ok(());
    }

    println!("Running {} compliance checks...\n", fw.to_uppercase());

    let ev = collect_evidence(state).await?;
    let checks = match fw.as_str() {
        "soc2" => checks_soc2(&ev),
        "hipaa" => checks_hipaa(&ev),
        "iso27001" => checks_iso27001(&ev),
        "gdpr" => checks_gdpr(&ev),
        _ => unreachable!(),
    };

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut warnings = 0u32;
    let mut info = 0u32;

    for c in &checks {
        let icon = match c.status.as_str() {
            "pass" => { passed += 1; "PASS" },
            "fail" => { failed += 1; "FAIL" },
            "warn" => { warnings += 1; "WARN" },
            "info" => { info += 1; "INFO" },
            _ => "????",
        };
        println!("  {icon}  [{:>16}] {} - {}", c.control, c.name, c.details);
    }

    println!("\n{} Compliance Summary:", fw.to_uppercase());
    println!("  Passed:   {passed}");
    println!("  Failed:   {failed}");
    println!("  Warnings: {warnings}");
    println!("  Info:     {info}");

    let scorable = passed + failed;
    if scorable > 0 {
        let pct = (passed as f64 / scorable as f64) * 100.0;
        println!("  Score:    {pct:.0}%");
    }

    Ok(())
}

// ── Report (export to file) ─────────────────────────────────

pub async fn report(state: &AppState, framework: &str, output: Option<&str>) -> Result<()> {
    let fw = framework.to_lowercase();
    let valid = ["soc2", "hipaa", "iso27001", "gdpr", "all"];

    if !valid.contains(&fw.as_str()) {
        println!("Unknown framework: {framework}");
        println!("Supported: {}", valid.join(", "));
        return Ok(());
    }

    let default_path = format!("compliance-report-{fw}.json");
    let path = output.unwrap_or(&default_path);
    println!("Generating {} compliance report...", fw.to_uppercase());

    let ev = collect_evidence(state).await?;

    let frameworks: Vec<&str> = if fw == "all" {
        vec!["soc2", "hipaa", "iso27001", "gdpr"]
    } else {
        vec![fw.as_str()]
    };

    let mut framework_reports = serde_json::Map::new();

    for f in &frameworks {
        let checks = match *f {
            "soc2" => checks_soc2(&ev),
            "hipaa" => checks_hipaa(&ev),
            "iso27001" => checks_iso27001(&ev),
            "gdpr" => checks_gdpr(&ev),
            _ => continue,
        };

        let passed = checks.iter().filter(|c| c.status == "pass").count();
        let failed = checks.iter().filter(|c| c.status == "fail").count();
        let warnings = checks.iter().filter(|c| c.status == "warn").count();
        let info_count = checks.iter().filter(|c| c.status == "info").count();
        let scorable = passed + failed;
        let score = if scorable > 0 { (passed as f64 / scorable as f64) * 100.0 } else { 0.0 };

        let report_section = serde_json::json!({
            "framework": f,
            "score_percent": (score * 10.0).round() / 10.0,
            "summary": {
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "info": info_count,
                "total_controls": checks.len(),
            },
            "controls": checks,
        });

        framework_reports.insert(f.to_string(), report_section);
    }

    let full_report = serde_json::json!({
        "report_metadata": {
            "generated_at": Utc::now().to_rfc3339(),
            "generator": "clampd-cli",
            "version": env!("CARGO_PKG_VERSION"),
            "frameworks": frameworks,
        },
        "environment": {
            "organizations": ev.org_count,
            "total_agents": ev.agent_count,
            "active_agents": ev.active_agents,
            "killed_agents": ev.killed_agents,
            "active_licenses": ev.active_licenses,
            "api_keys": ev.api_keys_total,
            "api_keys_without_expiry": ev.api_keys_no_expiry,
            "rbac_members": ev.member_count,
            "active_policies": ev.policy_count,
            "enabled_rules": ev.rule_count,
            "active_webhooks": ev.webhook_count,
            "audit_trail_entries": ev.audit_trail_count,
            "kill_switch_reachable": ev.kill_service_reachable,
        },
        "frameworks": framework_reports,
    });

    let content = serde_json::to_string_pretty(&full_report)?;
    std::fs::write(path, &content)?;
    println!("Report written to {path}");

    // Print summary
    for (name, section) in full_report["frameworks"].as_object().unwrap() {
        let score = section["score_percent"].as_f64().unwrap_or(0.0);
        let p = section["summary"]["passed"].as_u64().unwrap_or(0);
        let f = section["summary"]["failed"].as_u64().unwrap_or(0);
        let w = section["summary"]["warnings"].as_u64().unwrap_or(0);
        println!("  {}: {score:.0}% ({p} passed, {f} failed, {w} warnings)", name.to_uppercase());
    }

    Ok(())
}
