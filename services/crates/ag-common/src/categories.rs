//! Tool category taxonomy for AgentGuard.
//!
//! Maps tool names to security categories and defense tiers, so that
//! downstream services (ag-engine, ag-policy) know which enforcement
//! layer is responsible for a given tool call.
//!
//! Classification flow:
//!   raw tool name → `tool_names::canonicalize()` → prefix matching → `ToolCategory`

use crate::tool_names::canonicalize;

// ── Defense tier ────────────────────────────────────────────────────

/// Which defense layer handles enforcement for a given category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefenseTier {
    /// Must go through ag-engine for payload inspection.
    Rules,
    /// Scope enforcement only — default-deny, no payload inspection needed.
    Policy,
    /// Both: ag-engine for payload + ag-policy for scope.
    Hybrid,
}

// ── Category enum ──────────────────────────────────────────────────

/// High-level security category for a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Shell,
    FilesystemRead,
    FilesystemWrite,
    DatabaseQuery,
    DatabaseMutate,
    HttpOutbound,
    HttpInbound,
    AuthSecrets,
    EmailMessaging,
    CodeEval,
    NetworkDns,
    CloudInfra,
    GitVcs,
    BrowserScraping,
    AgentDelegation,
    LlmInput,
    LlmOutput,
    /// AP2 payment operations (future — extension point for payment guardrails).
    Payment,
    Unknown,
}

impl Category {
    /// Human-readable category label.
    pub fn name(&self) -> &'static str {
        match self {
            Category::Shell => "Shell / Process Execution",
            Category::FilesystemRead => "Filesystem Read",
            Category::FilesystemWrite => "Filesystem Write",
            Category::DatabaseQuery => "Database Query",
            Category::DatabaseMutate => "Database Mutation",
            Category::HttpOutbound => "HTTP Outbound",
            Category::HttpInbound => "HTTP Inbound",
            Category::AuthSecrets => "Auth / Secrets",
            Category::EmailMessaging => "Email / Messaging",
            Category::CodeEval => "Code Evaluation",
            Category::NetworkDns => "Network / DNS",
            Category::CloudInfra => "Cloud Infrastructure",
            Category::GitVcs => "Git / VCS",
            Category::BrowserScraping => "Browser / Scraping",
            Category::AgentDelegation => "Agent Delegation",
            Category::LlmInput => "LLM Input",
            Category::LlmOutput => "LLM Output",
            Category::Payment => "Payment / Financial",
            Category::Unknown => "Unknown",
        }
    }

    /// Which defense tier handles this category.
    pub fn defense_tier(&self) -> DefenseTier {
        match self {
            // Rules — payload inspection required
            Category::Shell => DefenseTier::Rules,
            Category::FilesystemRead => DefenseTier::Rules,
            Category::FilesystemWrite => DefenseTier::Rules,
            Category::DatabaseQuery => DefenseTier::Rules,
            Category::DatabaseMutate => DefenseTier::Rules,
            Category::HttpOutbound => DefenseTier::Rules,
            Category::CodeEval => DefenseTier::Rules,
            Category::NetworkDns => DefenseTier::Rules,
            Category::LlmInput => DefenseTier::Rules,
            Category::LlmOutput => DefenseTier::Rules,

            // Policy — scope enforcement only (no payload rules)
            Category::HttpInbound => DefenseTier::Policy,
            // Payment — Hybrid (rules for amount/vendor + Cedar for spend limits)
            Category::Payment => DefenseTier::Hybrid,

            // Hybrid — payload inspection + scope enforcement
            // (moved from Policy after adding R178-R182, R188-R192, R074-R086)
            Category::CloudInfra => DefenseTier::Hybrid,
            Category::BrowserScraping => DefenseTier::Hybrid,
            Category::AgentDelegation => DefenseTier::Hybrid,
            // Unknown tools MUST be scanned — we don't know what they do.
            // Default-deny philosophy: if we can't categorize it, inspect it.
            Category::Unknown => DefenseTier::Rules,

            // Hybrid — both payload + scope
            Category::AuthSecrets => DefenseTier::Hybrid,
            Category::EmailMessaging => DefenseTier::Hybrid,
            Category::GitVcs => DefenseTier::Hybrid,
        }
    }
}

// ── ToolCategory result ────────────────────────────────────────────

/// The result of classifying a tool name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCategory {
    /// High-level security category.
    pub category: Category,
    /// The full canonical name after normalization.
    pub canonical_name: String,
}

// ── Classification ─────────────────────────────────────────────────

/// Classify a tool name into a security category.
///
/// The tool name is first canonicalized via `tool_names::canonicalize()`
/// (e.g. `db.query` → `database.query`) and then matched by prefix.
pub fn classify_tool(tool_name: &str) -> ToolCategory {
    let canonical = canonicalize(tool_name);
    let category = classify_canonical(&canonical);
    ToolCategory {
        category,
        canonical_name: canonical,
    }
}

/// Classify an already-canonical tool name by prefix matching.
fn classify_canonical(name: &str) -> Category {
    // Shell / Process
    if name.starts_with("shell.") || name.starts_with("process.") {
        return Category::Shell;
    }

    // Filesystem — distinguish read vs write
    if name.starts_with("filesystem.") {
        return classify_filesystem(name);
    }

    // Database — distinguish query vs mutate
    if name.starts_with("database.") {
        return classify_database(name);
    }

    // HTTP — distinguish outbound vs inbound
    if name.starts_with("http.") {
        return classify_http(name);
    }

    // Auth / Secrets
    if name.starts_with("auth.")
        || name.starts_with("secret.")
        || name.starts_with("credential.")
        || name.starts_with("token.")
        || name.starts_with("oauth.")
    {
        return Category::AuthSecrets;
    }

    // Email / Messaging
    if name.starts_with("email.")
        || name.starts_with("slack.")
        || name.starts_with("messaging.")
        || name.starts_with("sms.")
        || name.starts_with("notification.")
    {
        return Category::EmailMessaging;
    }

    // Code evaluation
    if name.starts_with("code.")
        || name.starts_with("eval.")
        || name.starts_with("python.")
        || name.starts_with("interpret.")
    {
        return Category::CodeEval;
    }

    // Network / DNS
    if name.starts_with("network.")
        || name.starts_with("dns.")
        || name.starts_with("socket.")
        || name.starts_with("connect.")
    {
        return Category::NetworkDns;
    }

    // Cloud / Infra
    if name.starts_with("cloud.")
        || name.starts_with("infra.")
        || name.starts_with("deploy.")
        || name.starts_with("kubernetes.")
        || name.starts_with("k8s.")
    {
        return Category::CloudInfra;
    }

    // Git / VCS
    if name.starts_with("git.") || name.starts_with("vcs.") {
        return Category::GitVcs;
    }

    // Browser / Scraping
    if name.starts_with("browser.")
        || name.starts_with("scrape.")
        || name.starts_with("navigate.")
        || name.starts_with("screenshot.")
    {
        return Category::BrowserScraping;
    }

    // Agent delegation
    if name.starts_with("agent.")
        || name.starts_with("delegate.")
        || name.starts_with("handoff.")
        || name.starts_with("spawn.")
        || name.starts_with("a2a.")
    {
        return Category::AgentDelegation;
    }

    // LLM — distinguish input vs output
    if name.starts_with("llm.") {
        return classify_llm(name);
    }

    // ── Extended tool mappings ──────────────────────────────────────
    // Common MCP tool patterns that don't match the primary prefixes.

    // Function execution / invocation → CodeEval (arbitrary code risk)
    if name.starts_with("function.")
        || name.starts_with("invoke.")
        || name.starts_with("call.")
        || name.starts_with("execute.")
        || name.starts_with("run.")
        || name.starts_with("lambda.")
    {
        return Category::CodeEval;
    }

    // API / webhook / endpoint → HttpOutbound (external calls)
    if name.starts_with("api.")
        || name.starts_with("webhook.")
        || name.starts_with("endpoint.")
        || name.starts_with("fetch.")
        || name.starts_with("request.")
    {
        return Category::HttpOutbound;
    }

    // Payment / billing → Payment (AP2 financial guardrails)
    if name.starts_with("payment.")
        || name.starts_with("billing.")
        || name.starts_with("stripe.")
        || name.starts_with("checkout.")
        || name.starts_with("invoice.")
        || name.starts_with("refund.")
    {
        return Category::Payment;
    }

    // User / account / role management → AuthSecrets
    if name.starts_with("user.")
        || name.starts_with("account.")
        || name.starts_with("role.")
        || name.starts_with("permission.")
        || name.starts_with("iam.")
    {
        return Category::AuthSecrets;
    }

    // Config / settings / env → AuthSecrets (can expose secrets, escalate)
    if name.starts_with("config.")
        || name.starts_with("settings.")
        || name.starts_with("env.")
    {
        return Category::AuthSecrets;
    }

    // Cloud storage / providers → CloudInfra
    if name.starts_with("s3.")
        || name.starts_with("gcs.")
        || name.starts_with("azure.")
        || name.starts_with("aws.")
        || name.starts_with("storage.")
    {
        return Category::CloudInfra;
    }

    // Messaging platforms → EmailMessaging
    if name.starts_with("discord.")
        || name.starts_with("teams.")
        || name.starts_with("telegram.")
        || name.starts_with("whatsapp.")
        || name.starts_with("chat.")
    {
        return Category::EmailMessaging;
    }

    // MCP tools — strip `mcp.` prefix and re-classify the inner tool.
    // e.g., "mcp.github.push" → "github.push" → GitVcs
    if name.starts_with("mcp.") {
        let inner = &name[4..];
        if !inner.is_empty() && inner != name {
            let inner_category = classify_canonical(inner);
            if inner_category != Category::Unknown {
                return inner_category;
            }
        }
    }

    // Fallback — unknown tools still get scanned (DefenseTier::Rules)
    Category::Unknown
}

/// Sub-classify filesystem tools.
fn classify_filesystem(name: &str) -> Category {
    match name {
        "filesystem.read" | "filesystem.list" => Category::FilesystemRead,
        "filesystem.write" | "filesystem.delete" | "filesystem.create" => Category::FilesystemWrite,
        _ => Category::FilesystemRead, // conservative default
    }
}

/// Sub-classify database tools.
fn classify_database(name: &str) -> Category {
    match name {
        "database.query" | "database.search" | "database.select" => Category::DatabaseQuery,
        "database.mutate"
        | "database.execute"
        | "database.insert"
        | "database.update"
        | "database.delete"
        | "database.create"
        | "database.drop"
        | "database.alter" => Category::DatabaseMutate,
        _ => Category::DatabaseQuery, // conservative default
    }
}

/// Sub-classify HTTP tools.
fn classify_http(name: &str) -> Category {
    match name {
        "http.fetch" | "http.request" | "http.post" | "http.get" => Category::HttpOutbound,
        "http.serve" | "http.listen" => Category::HttpInbound,
        _ => Category::HttpOutbound, // conservative default
    }
}

/// Sub-classify LLM tools.
fn classify_llm(name: &str) -> Category {
    match name {
        "llm.input" | "llm.prompt" => Category::LlmInput,
        "llm.output" | "llm.response" => Category::LlmOutput,
        _ => Category::LlmInput, // conservative default
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Defense tier mapping ───────────────────────────────────────

    #[test]
    fn rules_tier_categories() {
        let rules_cats = [
            Category::Shell,
            Category::FilesystemRead,
            Category::FilesystemWrite,
            Category::DatabaseQuery,
            Category::DatabaseMutate,
            Category::HttpOutbound,
            Category::CodeEval,
            Category::NetworkDns,
            Category::LlmInput,
            Category::LlmOutput,
        ];
        for cat in &rules_cats {
            assert_eq!(cat.defense_tier(), DefenseTier::Rules, "{:?} should be Rules", cat);
        }
    }

    #[test]
    fn policy_tier_categories() {
        let policy_cats = [
            Category::HttpInbound,
        ];
        for cat in &policy_cats {
            assert_eq!(cat.defense_tier(), DefenseTier::Policy, "{:?} should be Policy", cat);
        }
        // Unknown is Rules tier — unknown tools must always be scanned
        assert_eq!(Category::Unknown.defense_tier(), DefenseTier::Rules);
    }

    #[test]
    fn hybrid_tier_categories() {
        let hybrid_cats = [
            Category::AuthSecrets,
            Category::EmailMessaging,
            Category::GitVcs,
            Category::CloudInfra,
            Category::BrowserScraping,
            Category::AgentDelegation,
            Category::Payment,
        ];
        for cat in &hybrid_cats {
            assert_eq!(cat.defense_tier(), DefenseTier::Hybrid, "{:?} should be Hybrid", cat);
        }
    }

    // ── Category names ─────────────────────────────────────────────

    #[test]
    fn category_names_are_nonempty() {
        let all = [
            Category::Shell,
            Category::FilesystemRead,
            Category::FilesystemWrite,
            Category::DatabaseQuery,
            Category::DatabaseMutate,
            Category::HttpOutbound,
            Category::HttpInbound,
            Category::AuthSecrets,
            Category::EmailMessaging,
            Category::CodeEval,
            Category::NetworkDns,
            Category::CloudInfra,
            Category::GitVcs,
            Category::BrowserScraping,
            Category::AgentDelegation,
            Category::LlmInput,
            Category::LlmOutput,
            Category::Unknown,
        ];
        for cat in &all {
            assert!(!cat.name().is_empty(), "{:?} has empty name", cat);
        }
    }

    #[test]
    fn specific_category_names() {
        assert_eq!(Category::Shell.name(), "Shell / Process Execution");
        assert_eq!(Category::Unknown.name(), "Unknown");
        assert_eq!(Category::LlmInput.name(), "LLM Input");
        assert_eq!(Category::DatabaseMutate.name(), "Database Mutation");
    }

    // ── Shell classification ───────────────────────────────────────

    #[test]
    fn shell_tools() {
        assert_eq!(classify_tool("shell.exec").category, Category::Shell);
        assert_eq!(classify_tool("shell.run").category, Category::Shell);
        assert_eq!(classify_tool("process.spawn").category, Category::Shell);
        assert_eq!(classify_tool("process.kill").category, Category::Shell);
    }

    // ── Filesystem sub-categories ──────────────────────────────────

    #[test]
    fn filesystem_read_tools() {
        assert_eq!(classify_tool("filesystem.read").category, Category::FilesystemRead);
        assert_eq!(classify_tool("filesystem.list").category, Category::FilesystemRead);
    }

    #[test]
    fn filesystem_write_tools() {
        assert_eq!(classify_tool("filesystem.write").category, Category::FilesystemWrite);
        assert_eq!(classify_tool("filesystem.delete").category, Category::FilesystemWrite);
        assert_eq!(classify_tool("filesystem.create").category, Category::FilesystemWrite);
    }

    #[test]
    fn filesystem_unknown_defaults_to_read() {
        assert_eq!(classify_tool("filesystem.stat").category, Category::FilesystemRead);
        assert_eq!(classify_tool("filesystem.info").category, Category::FilesystemRead);
    }

    // ── Database sub-categories ────────────────────────────────────

    #[test]
    fn database_query_tools() {
        assert_eq!(classify_tool("database.query").category, Category::DatabaseQuery);
        assert_eq!(classify_tool("database.search").category, Category::DatabaseQuery);
        assert_eq!(classify_tool("database.select").category, Category::DatabaseQuery);
    }

    #[test]
    fn database_mutate_tools() {
        assert_eq!(classify_tool("database.mutate").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.execute").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.insert").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.update").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.delete").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.create").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.drop").category, Category::DatabaseMutate);
        assert_eq!(classify_tool("database.alter").category, Category::DatabaseMutate);
    }

    #[test]
    fn database_unknown_defaults_to_query() {
        assert_eq!(classify_tool("database.status").category, Category::DatabaseQuery);
        assert_eq!(classify_tool("database.ping").category, Category::DatabaseQuery);
    }

    // ── HTTP sub-categories ────────────────────────────────────────

    #[test]
    fn http_outbound_tools() {
        assert_eq!(classify_tool("http.fetch").category, Category::HttpOutbound);
        assert_eq!(classify_tool("http.request").category, Category::HttpOutbound);
        assert_eq!(classify_tool("http.post").category, Category::HttpOutbound);
        assert_eq!(classify_tool("http.get").category, Category::HttpOutbound);
    }

    #[test]
    fn http_inbound_tools() {
        assert_eq!(classify_tool("http.serve").category, Category::HttpInbound);
        assert_eq!(classify_tool("http.listen").category, Category::HttpInbound);
    }

    #[test]
    fn http_unknown_defaults_to_outbound() {
        assert_eq!(classify_tool("http.connect").category, Category::HttpOutbound);
        assert_eq!(classify_tool("http.websocket").category, Category::HttpOutbound);
    }

    // ── Auth / Secrets ─────────────────────────────────────────────

    #[test]
    fn auth_secrets_tools() {
        assert_eq!(classify_tool("auth.login").category, Category::AuthSecrets);
        assert_eq!(classify_tool("secret.read").category, Category::AuthSecrets);
        assert_eq!(classify_tool("credential.store").category, Category::AuthSecrets);
        assert_eq!(classify_tool("token.refresh").category, Category::AuthSecrets);
        assert_eq!(classify_tool("oauth.authorize").category, Category::AuthSecrets);
    }

    // ── Email / Messaging ──────────────────────────────────────────

    #[test]
    fn email_messaging_tools() {
        assert_eq!(classify_tool("email.send").category, Category::EmailMessaging);
        assert_eq!(classify_tool("slack.post").category, Category::EmailMessaging);
        assert_eq!(classify_tool("messaging.publish").category, Category::EmailMessaging);
        assert_eq!(classify_tool("sms.send").category, Category::EmailMessaging);
        assert_eq!(classify_tool("notification.push").category, Category::EmailMessaging);
    }

    // ── Code eval ──────────────────────────────────────────────────

    #[test]
    fn code_eval_tools() {
        assert_eq!(classify_tool("code.run").category, Category::CodeEval);
        assert_eq!(classify_tool("eval.python").category, Category::CodeEval);
        assert_eq!(classify_tool("python.exec").category, Category::CodeEval);
        assert_eq!(classify_tool("interpret.js").category, Category::CodeEval);
    }

    // ── Network / DNS ──────────────────────────────────────────────

    #[test]
    fn network_dns_tools() {
        assert_eq!(classify_tool("network.scan").category, Category::NetworkDns);
        assert_eq!(classify_tool("dns.resolve").category, Category::NetworkDns);
        assert_eq!(classify_tool("socket.connect").category, Category::NetworkDns);
        assert_eq!(classify_tool("connect.tcp").category, Category::NetworkDns);
    }

    // ── Cloud / Infra ──────────────────────────────────────────────

    #[test]
    fn cloud_infra_tools() {
        assert_eq!(classify_tool("cloud.provision").category, Category::CloudInfra);
        assert_eq!(classify_tool("infra.create").category, Category::CloudInfra);
        assert_eq!(classify_tool("deploy.service").category, Category::CloudInfra);
        assert_eq!(classify_tool("kubernetes.apply").category, Category::CloudInfra);
        assert_eq!(classify_tool("k8s.deploy").category, Category::CloudInfra);
    }

    // ── Git / VCS ──────────────────────────────────────────────────

    #[test]
    fn git_vcs_tools() {
        assert_eq!(classify_tool("git.push").category, Category::GitVcs);
        assert_eq!(classify_tool("git.commit").category, Category::GitVcs);
        assert_eq!(classify_tool("vcs.checkout").category, Category::GitVcs);
    }

    // ── Browser / Scraping ─────────────────────────────────────────

    #[test]
    fn browser_scraping_tools() {
        assert_eq!(classify_tool("browser.open").category, Category::BrowserScraping);
        assert_eq!(classify_tool("scrape.page").category, Category::BrowserScraping);
        assert_eq!(classify_tool("navigate.to").category, Category::BrowserScraping);
        assert_eq!(classify_tool("screenshot.take").category, Category::BrowserScraping);
    }

    // ── Agent delegation ───────────────────────────────────────────

    #[test]
    fn agent_delegation_tools() {
        assert_eq!(classify_tool("agent.call").category, Category::AgentDelegation);
        assert_eq!(classify_tool("delegate.task").category, Category::AgentDelegation);
        assert_eq!(classify_tool("handoff.to").category, Category::AgentDelegation);
        assert_eq!(classify_tool("spawn.child").category, Category::AgentDelegation);
        assert_eq!(classify_tool("a2a.invoke").category, Category::AgentDelegation);
    }

    // ── LLM sub-categories ─────────────────────────────────────────

    #[test]
    fn llm_input_tools() {
        assert_eq!(classify_tool("llm.input").category, Category::LlmInput);
        assert_eq!(classify_tool("llm.prompt").category, Category::LlmInput);
    }

    #[test]
    fn llm_output_tools() {
        assert_eq!(classify_tool("llm.output").category, Category::LlmOutput);
        assert_eq!(classify_tool("llm.response").category, Category::LlmOutput);
    }

    #[test]
    fn llm_unknown_defaults_to_input() {
        assert_eq!(classify_tool("llm.chat").category, Category::LlmInput);
        assert_eq!(classify_tool("llm.complete").category, Category::LlmInput);
    }

    // ── Unknown / fallback ─────────────────────────────────────────

    #[test]
    fn unknown_tools() {
        let tc = classify_tool("custom.tool");
        assert_eq!(tc.category, Category::Unknown);
        assert_eq!(tc.category.defense_tier(), DefenseTier::Rules); // Unknown tools must be scanned
    }

    #[test]
    fn completely_unknown_tool() {
        let tc = classify_tool("my_special_tool");
        assert_eq!(tc.category, Category::Unknown);
        assert_eq!(tc.canonical_name, "my_special_tool");
    }

    // ── Canonicalization integration ───────────────────────────────

    #[test]
    fn db_query_alias_classification() {
        // db.query → canonicalize → database.query → DatabaseQuery
        let tc = classify_tool("db.query");
        assert_eq!(tc.category, Category::DatabaseQuery);
        assert_eq!(tc.canonical_name, "database.query");
    }

    #[test]
    fn db_execute_alias_classification() {
        let tc = classify_tool("db.execute");
        assert_eq!(tc.category, Category::DatabaseMutate);
        assert_eq!(tc.canonical_name, "database.execute");
    }

    #[test]
    fn sql_query_alias_classification() {
        let tc = classify_tool("sql.query");
        assert_eq!(tc.category, Category::DatabaseQuery);
        assert_eq!(tc.canonical_name, "database.query");
    }

    #[test]
    fn file_read_alias_classification() {
        let tc = classify_tool("file.read");
        assert_eq!(tc.category, Category::FilesystemRead);
        assert_eq!(tc.canonical_name, "filesystem.read");
    }

    #[test]
    fn fs_write_alias_classification() {
        let tc = classify_tool("fs.write");
        assert_eq!(tc.category, Category::FilesystemWrite);
        assert_eq!(tc.canonical_name, "filesystem.write");
    }

    #[test]
    fn cmd_run_alias_classification() {
        let tc = classify_tool("cmd.run");
        assert_eq!(tc.category, Category::Shell);
        assert_eq!(tc.canonical_name, "shell.run");
    }

    #[test]
    fn net_request_alias_classification() {
        let tc = classify_tool("net.request");
        assert_eq!(tc.category, Category::HttpOutbound);
        assert_eq!(tc.canonical_name, "http.request");
    }

    #[test]
    fn read_file_full_alias_classification() {
        // read_file → canonicalize → filesystem.read → FilesystemRead
        let tc = classify_tool("read_file");
        assert_eq!(tc.category, Category::FilesystemRead);
        assert_eq!(tc.canonical_name, "filesystem.read");
    }

    #[test]
    fn write_file_full_alias_classification() {
        let tc = classify_tool("write_file");
        assert_eq!(tc.category, Category::FilesystemWrite);
        assert_eq!(tc.canonical_name, "filesystem.write");
    }

    #[test]
    fn run_command_full_alias_classification() {
        let tc = classify_tool("run_command");
        assert_eq!(tc.category, Category::Shell);
        assert_eq!(tc.canonical_name, "shell.exec");
    }

    #[test]
    fn email_send_full_alias_classification() {
        let tc = classify_tool("email_send");
        assert_eq!(tc.category, Category::EmailMessaging);
        assert_eq!(tc.canonical_name, "email.send");
    }

    // ── MCP prefix stripping ───────────────────────────────────────

    #[test]
    fn mcp_prefix_classification() {
        let tc = classify_tool("mcp.database.query");
        assert_eq!(tc.category, Category::DatabaseQuery);
        assert_eq!(tc.canonical_name, "database.query");
    }

    #[test]
    fn mcp_with_alias_classification() {
        let tc = classify_tool("mcp.db.query");
        assert_eq!(tc.category, Category::DatabaseQuery);
        assert_eq!(tc.canonical_name, "database.query");
    }

    #[test]
    fn mcp_shell_classification() {
        let tc = classify_tool("mcp.shell.exec");
        assert_eq!(tc.category, Category::Shell);
        assert_eq!(tc.canonical_name, "shell.exec");
    }

    // ── Canonical names pass through unchanged ─────────────────────

    #[test]
    fn canonical_names_classify_correctly() {
        assert_eq!(classify_tool("database.query").category, Category::DatabaseQuery);
        assert_eq!(classify_tool("filesystem.read").category, Category::FilesystemRead);
        assert_eq!(classify_tool("shell.exec").category, Category::Shell);
        assert_eq!(classify_tool("http.fetch").category, Category::HttpOutbound);
        assert_eq!(classify_tool("llm.input").category, Category::LlmInput);
    }

    // ── Defense tier end-to-end checks ─────────────────────────────

    #[test]
    fn shell_tool_needs_rules() {
        assert_eq!(classify_tool("cmd.run").category.defense_tier(), DefenseTier::Rules);
    }

    #[test]
    fn cloud_tool_needs_hybrid() {
        assert_eq!(classify_tool("cloud.provision").category.defense_tier(), DefenseTier::Hybrid);
    }

    #[test]
    fn auth_tool_needs_hybrid() {
        assert_eq!(classify_tool("auth.login").category.defense_tier(), DefenseTier::Hybrid);
    }

    #[test]
    fn unknown_tool_needs_policy() {
        assert_eq!(classify_tool("random.thing").category.defense_tier(), DefenseTier::Rules);
    }

    // ── Sub-category precision ─────────────────────────────────────

    #[test]
    fn database_subcategory_precision() {
        // query vs mutate must be distinguished
        assert_eq!(classify_tool("database.query").category, Category::DatabaseQuery);
        assert_eq!(classify_tool("database.execute").category, Category::DatabaseMutate);
        assert_ne!(
            classify_tool("database.query").category,
            classify_tool("database.execute").category,
        );
    }

    #[test]
    fn filesystem_subcategory_precision() {
        assert_eq!(classify_tool("filesystem.read").category, Category::FilesystemRead);
        assert_eq!(classify_tool("filesystem.write").category, Category::FilesystemWrite);
        assert_ne!(
            classify_tool("filesystem.read").category,
            classify_tool("filesystem.write").category,
        );
    }

    #[test]
    fn http_subcategory_precision() {
        assert_eq!(classify_tool("http.fetch").category, Category::HttpOutbound);
        assert_eq!(classify_tool("http.serve").category, Category::HttpInbound);
        assert_ne!(
            classify_tool("http.fetch").category,
            classify_tool("http.serve").category,
        );
    }

    #[test]
    fn llm_subcategory_precision() {
        assert_eq!(classify_tool("llm.input").category, Category::LlmInput);
        assert_eq!(classify_tool("llm.output").category, Category::LlmOutput);
        assert_ne!(
            classify_tool("llm.input").category,
            classify_tool("llm.output").category,
        );
    }

    // ── All prefix matches ─────────────────────────────────────────

    #[test]
    fn all_prefix_matches() {
        // Ensure every documented prefix maps to the expected category.
        let cases: Vec<(&str, Category)> = vec![
            ("shell.anything", Category::Shell),
            ("process.anything", Category::Shell),
            ("filesystem.read", Category::FilesystemRead),
            ("filesystem.write", Category::FilesystemWrite),
            ("database.query", Category::DatabaseQuery),
            ("database.mutate", Category::DatabaseMutate),
            ("http.fetch", Category::HttpOutbound),
            ("http.serve", Category::HttpInbound),
            ("auth.anything", Category::AuthSecrets),
            ("secret.anything", Category::AuthSecrets),
            ("credential.anything", Category::AuthSecrets),
            ("token.anything", Category::AuthSecrets),
            ("oauth.anything", Category::AuthSecrets),
            ("email.anything", Category::EmailMessaging),
            ("slack.anything", Category::EmailMessaging),
            ("messaging.anything", Category::EmailMessaging),
            ("sms.anything", Category::EmailMessaging),
            ("notification.anything", Category::EmailMessaging),
            ("code.anything", Category::CodeEval),
            ("eval.anything", Category::CodeEval),
            ("python.anything", Category::CodeEval),
            ("interpret.anything", Category::CodeEval),
            ("network.anything", Category::NetworkDns),
            ("dns.anything", Category::NetworkDns),
            ("socket.anything", Category::NetworkDns),
            ("connect.anything", Category::NetworkDns),
            ("cloud.anything", Category::CloudInfra),
            ("infra.anything", Category::CloudInfra),
            ("deploy.anything", Category::CloudInfra),
            ("kubernetes.anything", Category::CloudInfra),
            ("k8s.anything", Category::CloudInfra),
            ("git.anything", Category::GitVcs),
            ("vcs.anything", Category::GitVcs),
            ("browser.anything", Category::BrowserScraping),
            ("scrape.anything", Category::BrowserScraping),
            ("navigate.anything", Category::BrowserScraping),
            ("screenshot.anything", Category::BrowserScraping),
            ("agent.anything", Category::AgentDelegation),
            ("delegate.anything", Category::AgentDelegation),
            ("handoff.anything", Category::AgentDelegation),
            ("spawn.anything", Category::AgentDelegation),
            ("a2a.anything", Category::AgentDelegation),
            ("llm.input", Category::LlmInput),
            ("llm.output", Category::LlmOutput),
        ];

        for (tool, expected) in &cases {
            let tc = classify_tool(tool);
            assert_eq!(tc.category, *expected, "tool '{}' should be {:?}", tool, expected);
        }
    }
}
