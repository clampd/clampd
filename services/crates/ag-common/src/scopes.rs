//! Unified scope system for AgentGuard.
//!
//! A **scope** is the single global key used for:
//! - **Routing**: which defense tier handles a tool call (rules/policy/hybrid)
//! - **Rule matching**: rules are tagged with scope patterns (`db:*`)
//! - **Permissions**: agents are granted scopes (`db:query:read`)
//! - **Exemptions**: rule exemptions reference scope + rule_id
//! - **Thresholds**: per-scope block/flag thresholds
//!
//! Format: `category:subcategory:action`
//!
//! Examples:
//!   `db:query:read`          - SELECT queries
//!   `db:mutate:destructive`  - DROP TABLE, TRUNCATE
//!   `exec:shell:run`         - shell command execution
//!   `fs:file:read`           - reading files
//!   `net:http:outbound`      - outbound HTTP requests
//!   `llm:input:prompt`       - LLM prompt input
//!
//! Hierarchy matching:
//!   `db:*`           matches `db:query:read`, `db:mutate:destructive`, etc.
//!   `db:query:*`     matches `db:query:read`, `db:query:search`
//!   `*`              matches everything (superadmin)

use crate::categories::{Category, DefenseTier};
use crate::tool_names::canonicalize;

// ── Scope struct ─────────────────────────────────────────────────

/// A parsed scope with its three components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Scope {
    /// Top-level category: db, fs, exec, net, llm, auth, comms, cloud, scm, browser, agent
    pub category: String,
    /// Subcategory: query, mutate, file, shell, http, input, etc.
    pub subcategory: String,
    /// Action: read, write, delete, run, send, destructive, etc.
    pub action: String,
}

impl Scope {
    /// Parse a scope string like "db:query:read" into components.
    /// Returns None if the format is invalid.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return None;
        }
        if parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        Some(Scope {
            category: parts[0].to_string(),
            subcategory: parts[1].to_string(),
            action: parts[2].to_string(),
        })
    }

    /// Format as "category:subcategory:action".
    pub fn as_str(&self) -> String {
        format!("{}:{}:{}", self.category, self.subcategory, self.action)
    }

    /// Get the defense tier from the scope category prefix.
    pub fn defense_tier(&self) -> DefenseTier {
        defense_tier_for_category(&self.category)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.category, self.subcategory, self.action)
    }
}

// ── Scope pattern matching ───────────────────────────────────────

/// Check if a scope matches a pattern.
///
/// Patterns support `*` wildcard at any level:
///   `db:*`           matches any db scope
///   `db:query:*`     matches db:query:read, db:query:search
///   `db:query:read`  exact match only
///   `*`              matches everything
/// Check whether a granted scope pattern covers a requested scope.
///
/// Hierarchical matching:
/// - `db:*` covers `db:query:read` (wildcard at any level)
/// - `db:query:read:pii` covers `db:query:read` (4-level grant covers 3-level request)
/// - `db:query:read` does NOT cover `db:query:read:pii` (3-level doesn't grant 4-level)
/// - `*` covers everything
///
/// The rule: iterate over the *requested* scope parts. If all parts match the
/// corresponding pattern parts, the grant covers the request - even if the
/// pattern has additional qualifier levels beyond the request. A more specific
/// grant (db:query:read:pii) implies less specific access (db:query:read).
pub fn scope_matches(pattern: &str, scope: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pat_parts: Vec<&str> = pattern.split(':').collect();
    let scope_parts: Vec<&str> = scope.split(':').collect();

    // Iterate over requested scope parts (not pattern parts).
    // Every scope part must have a matching pattern part.
    for (i, scope_part) in scope_parts.iter().enumerate() {
        match pat_parts.get(i) {
            Some(&"*") => return true, // wildcard matches everything from here
            Some(pat) if *pat == *scope_part => {} // exact match, continue
            _ => return false, // mismatch or pattern shorter than scope
        }
    }

    // All scope parts matched. Pattern may be longer (more specific grant)
    // which is fine - a 4-level grant covers a 3-level request.
    true
}

// ── Tool name → Scope mapping ────────────────────────────────────

/// Map a raw tool name to its default scope.
///
/// The tool name is first canonicalized (e.g., `db.query` → `database.query`)
/// then mapped to the scope format.
///
/// The "default scope" is derived from the tool name alone, NOT from the payload.
/// Payload analysis (rules) may reveal a more specific scope at runtime
/// (e.g., `database.query` with `DROP TABLE` → `db:mutate:destructive`).
pub fn tool_to_scope(tool_name: &str) -> Scope {
    let canonical = canonicalize(tool_name);
    canonical_to_scope(&canonical)
}

/// Map a canonical tool name to a scope.
fn canonical_to_scope(name: &str) -> Scope {
    // Split on first dot: "database.query" → ("database", "query")
    let (prefix, action) = match name.find('.') {
        Some(pos) => (&name[..pos], &name[pos + 1..]),
        None => (name, "default"),
    };

    match prefix {
        "shell" | "process" => Scope {
            category: "exec".into(),
            subcategory: "shell".into(),
            action: map_exec_action(action),
        },
        "filesystem" => Scope {
            category: "fs".into(),
            subcategory: "file".into(),
            action: map_fs_action(action),
        },
        "database" => Scope {
            category: "db".into(),
            subcategory: map_db_subcategory(action),
            action: map_db_action(action),
        },
        "http" => Scope {
            category: "net".into(),
            subcategory: "http".into(),
            action: map_http_action(action),
        },
        "auth" | "secret" | "credential" | "token" | "oauth" => Scope {
            category: "auth".into(),
            subcategory: map_auth_subcategory(prefix),
            action: map_auth_action(action),
        },
        "email" | "slack" | "messaging" | "sms" | "notification" => Scope {
            category: "comms".into(),
            subcategory: prefix.into(),
            action: map_comms_action(action),
        },
        "code" | "eval" | "python" | "interpret" => Scope {
            category: "exec".into(),
            subcategory: "code".into(),
            action: "eval".into(),
        },
        "network" | "dns" | "socket" | "connect" => Scope {
            category: "net".into(),
            subcategory: map_net_subcategory(prefix),
            action: map_net_action(action),
        },
        "cloud" | "infra" | "deploy" | "kubernetes" | "k8s" => Scope {
            category: "cloud".into(),
            subcategory: map_cloud_subcategory(prefix, action),
            action: map_cloud_action(action),
        },
        "git" | "vcs" => Scope {
            category: "scm".into(),
            subcategory: "git".into(),
            action: map_scm_action(action),
        },
        "browser" | "scrape" | "navigate" | "screenshot" => Scope {
            category: "browser".into(),
            subcategory: "page".into(),
            action: "navigate".into(),
        },
        "agent" | "delegate" | "handoff" | "spawn" | "a2a" | "config" | "settings" => {
            // For the "agent" prefix, subcategory comes from the action (e.g., agent.delegate → agent:delegate:spawn).
            // For other prefixes (delegate, handoff, etc.), the prefix IS the subcategory.
            let subcategory = if prefix == "agent" {
                match action {
                    "delegate" | "handoff" => "delegate",
                    "spawn" | "create" => "spawn",
                    "config" | "settings" | "configure" => "config",
                    "a2a" | "discover" => "a2a",
                    _ => action,
                }
            } else {
                prefix
            };
            let mapped_action = match action {
                "delegate" | "handoff" => "spawn",
                _ => action,
            };
            Scope {
                category: "agent".into(),
                subcategory: subcategory.into(),
                action: mapped_action.into(),
            }
        }
        "llm" => Scope {
            category: "llm".into(),
            subcategory: map_llm_subcategory(action),
            action: map_llm_action(action),
        },
        "payment" | "billing" | "stripe" | "checkout" | "invoice" | "refund" => Scope {
            category: "payment".into(),
            subcategory: prefix.into(),
            action: action.into(),
        },
        "user" | "account" | "profile" => Scope {
            category: "agent".into(),
            subcategory: "user".into(),
            action: action.into(),
        },
        "webhook" | "callback" => Scope {
            category: "net".into(),
            subcategory: "webhook".into(),
            action: action.into(),
        },
        "function" | "invoke" | "lambda" => Scope {
            category: "exec".into(),
            subcategory: "function".into(),
            action: action.into(),
        },
        "api" | "rest" | "graphql" | "grpc" => Scope {
            category: "net".into(),
            subcategory: "http".into(),
            action: map_http_action(action),
        },
        _ => Scope {
            category: "unknown".into(),
            subcategory: prefix.into(),
            action: action.into(),
        },
    }
}

// ── Action mappers ───────────────────────────────────────────────

fn map_exec_action(action: &str) -> String {
    match action {
        "exec" | "run" | "spawn" | "start" => "run".into(),
        _ => action.into(),
    }
}

fn map_fs_action(action: &str) -> String {
    match action {
        "read" | "list" | "stat" | "exists" | "list_directory" => "read".into(),
        "write" | "create" | "append" | "mkdir" => "write".into(),
        "delete" | "remove" | "rm" | "rmdir" | "unlink" => "delete".into(),
        _ => "read".into(), // conservative default
    }
}

fn map_db_subcategory(action: &str) -> String {
    match action {
        "query" | "search" | "select" | "find" | "get" | "list" => "query".into(),
        "execute" | "insert" | "update" | "delete" | "upsert" | "merge" => "mutate".into(),
        "drop" | "truncate" | "alter" | "create_table" | "create" => "mutate".into(),
        "schema" | "describe" | "explain" | "tables" => "schema".into(),
        _ => "query".into(), // conservative default
    }
}

fn map_db_action(action: &str) -> String {
    match action {
        "query" | "search" | "select" | "find" | "get" | "list" => "read".into(),
        "insert" | "upsert" | "merge" => "write".into(),
        "update" => "write".into(),
        "delete" => "delete".into(),
        "execute" | "mutate" => "write".into(),
        "drop" | "truncate" | "alter" | "create_table" | "create" => "destructive".into(),
        "schema" | "describe" | "explain" | "tables" => "read".into(),
        _ => "read".into(),
    }
}

fn map_http_action(action: &str) -> String {
    match action {
        "fetch" | "get" | "request" | "post" | "put" | "patch" | "delete" => "outbound".into(),
        "serve" | "listen" | "accept" | "bind" => "inbound".into(),
        _ => "outbound".into(),
    }
}

fn map_auth_subcategory(prefix: &str) -> String {
    match prefix {
        "secret" => "secret".into(),
        "credential" => "credential".into(),
        "token" => "token".into(),
        "oauth" => "oauth".into(),
        _ => "secret".into(),
    }
}

fn map_auth_action(action: &str) -> String {
    match action {
        "read" | "get" | "fetch" | "list" => "read".into(),
        "write" | "set" | "store" | "create" | "rotate" => "write".into(),
        "delete" | "revoke" | "remove" => "delete".into(),
        "refresh" => "refresh".into(),
        _ => "read".into(),
    }
}

fn map_comms_action(action: &str) -> String {
    match action {
        "send" | "post" | "publish" | "notify" => "send".into(),
        "read" | "fetch" | "list" | "get" => "read".into(),
        _ => "send".into(),
    }
}

fn map_net_subcategory(prefix: &str) -> String {
    match prefix {
        "dns" => "dns".into(),
        "socket" | "connect" => "socket".into(),
        _ => "tcp".into(),
    }
}

fn map_net_action(action: &str) -> String {
    match action {
        "resolve" | "lookup" | "query" => "resolve".into(),
        "connect" | "open" | "bind" => "connect".into(),
        "scan" => "scan".into(),
        _ => "connect".into(),
    }
}

fn map_cloud_subcategory(_prefix: &str, action: &str) -> String {
    match action {
        "deploy" | "provision" | "scale" | "create_instance" => "infra".into(),
        "modify" | "create_role" | "attach_policy" | "iam" => "iam".into(),
        "upload" | "put" | "s3" | "blob" => "storage".into(),
        _ => "infra".into(),
    }
}

fn map_cloud_action(action: &str) -> String {
    match action {
        "deploy" | "provision" | "create_instance" | "create" | "launch" => "provision".into(),
        "scale" | "resize" | "update" => "modify".into(),
        "delete" | "terminate" | "destroy" => "delete".into(),
        "modify" | "create_role" | "attach_policy" => "modify".into(),
        "upload" | "put" => "write".into(),
        _ => "provision".into(),
    }
}

fn map_scm_action(action: &str) -> String {
    match action {
        "push" | "force_push" => "push".into(),
        "commit" | "add" | "stage" => "commit".into(),
        "pull" | "fetch" | "clone" | "checkout" => "read".into(),
        "merge" | "rebase" => "merge".into(),
        "branch" | "tag" => "branch".into(),
        "delete" | "delete_branch" => "delete".into(),
        _ => "read".into(),
    }
}

fn map_llm_subcategory(action: &str) -> String {
    match action {
        "input" | "prompt" | "system" | "inject" => "input".into(),
        "output" | "response" | "completion" => "output".into(),
        _ => "input".into(),
    }
}

fn map_llm_action(action: &str) -> String {
    match action {
        "input" | "prompt" | "system" | "inject" => "prompt".into(),
        "output" | "response" | "completion" => "response".into(),
        _ => "prompt".into(),
    }
}

// ── Defense tier lookup from scope category prefix ───────────────

/// Get the defense tier for a scope category prefix.
pub fn defense_tier_for_category(category: &str) -> DefenseTier {
    match category {
        // Rules - payload inspection required
        "db" | "exec" | "fs" | "net" | "llm" => DefenseTier::Rules,
        // Policy - scope enforcement only (no payload rules)
        "unknown" => DefenseTier::Policy,
        // Hybrid - payload inspection + scope enforcement
        "cloud" | "browser" | "agent" | "auth" | "comms" | "scm" | "payment" => DefenseTier::Hybrid,
        // Unknown → Policy (default-deny)
        _ => DefenseTier::Policy,
    }
}

/// Convert a Category enum to its scope category prefix.
pub fn category_to_scope_prefix(cat: Category) -> &'static str {
    match cat {
        Category::Shell | Category::CodeEval => "exec",
        Category::FilesystemRead | Category::FilesystemWrite => "fs",
        Category::DatabaseQuery | Category::DatabaseMutate => "db",
        Category::HttpOutbound | Category::HttpInbound => "net",
        Category::AuthSecrets => "auth",
        Category::EmailMessaging => "comms",
        Category::NetworkDns => "net",
        Category::CloudInfra => "cloud",
        Category::GitVcs => "scm",
        Category::BrowserScraping => "browser",
        Category::AgentDelegation => "agent",
        Category::LlmInput | Category::LlmOutput => "llm",
        Category::Payment => "payment",
        Category::Unknown => "unknown",
    }
}

// ── Permission → Scopes ─────────────────────────────────────────

/// Resolve a permission level to scope strings for a tool.
/// Mirrors dashboard/api/src/lib/permission-scopes.ts.
pub fn permission_to_scopes(tool_name: &str, permission: &str) -> Vec<String> {
    let canonical = crate::tool_names::canonicalize(tool_name);
    let category = canonical.split('.').next().unwrap_or(&canonical);

    if permission == "custom" {
        return vec![]; // caller must supply custom_scopes
    }

    match (category, permission) {
        ("database", "read_only") => vec!["db:query:read".into()],
        ("database", "read_write") => vec!["db:query:read".into(), "db:query:write".into()],
        ("database", "full") => vec!["db:*".into()],

        ("filesystem", "read_only") => vec!["fs:file:read".into()],
        ("filesystem", "read_write") => vec!["fs:file:read".into(), "fs:file:write".into()],
        ("filesystem", "full") => vec!["fs:*".into()],

        ("shell" | "process" | "docker", "full") => vec!["exec:shell:run".into()],
        ("shell" | "process" | "docker", _) => vec![], // shell: full or denied

        ("kubernetes", "read_only") => vec!["cloud:kubernetes:read".into()],
        ("kubernetes", "read_write") => vec!["cloud:kubernetes:read".into(), "cloud:kubernetes:write".into()],
        ("kubernetes", "full") => vec!["cloud:*".into()],

        ("http" | "network", "read_only") => vec!["net:http:outbound".into()],
        ("http" | "network", "read_write") => vec!["net:http:outbound".into(), "net:http:inbound".into()],
        ("http" | "network", "full") => vec!["net:*".into()],

        ("llm", "read_only") => vec!["llm:input:*".into()],
        ("llm", "read_write") => vec!["llm:input:*".into(), "llm:output:*".into()],
        ("llm", "full") => vec!["llm:*".into()],

        ("email", "read_only") => vec!["comms:email:read".into()],
        ("email", "read_write") => vec!["comms:email:read".into(), "comms:email:send".into()],
        ("email", "full") => vec!["comms:*".into()],

        ("secret" | "credential" | "auth", "read_only") => vec!["auth:secret:read".into()],
        ("secret" | "credential" | "auth", "read_write") => vec!["auth:secret:read".into(), "auth:secret:write".into()],
        ("secret" | "credential" | "auth", "full") => vec!["auth:*".into()],

        ("agent", _) => vec!["agent:delegate:spawn".into()],

        ("payment", "read_only") => vec!["payment:transaction:read".into()],
        ("payment", "read_write") => vec!["payment:transaction:read".into(), "payment:transaction:write".into()],
        ("payment", "full") => vec!["payment:*".into()],

        // Unknown category - derive from category name
        (cat, "full") => vec![format!("{cat}:*")],
        (cat, "read_write") => vec![format!("{cat}:*:read"), format!("{cat}:*:write")],
        (cat, _) => vec![format!("{cat}:*:read")],
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Scope parsing ─────────────────────────

    #[test]
    fn parse_valid_scope() {
        let s = Scope::parse("db:query:read").unwrap();
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "query");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn parse_invalid_scopes() {
        assert!(Scope::parse("db").is_none());
        assert!(Scope::parse("db:query").is_none());
        assert!(Scope::parse("").is_none());
        assert!(Scope::parse("db::read").is_none());
        assert!(Scope::parse("db:query:read:extra").is_none());
    }

    #[test]
    fn scope_display() {
        let s = Scope::parse("exec:shell:run").unwrap();
        assert_eq!(s.to_string(), "exec:shell:run");
        assert_eq!(s.as_str(), "exec:shell:run");
    }

    // ── Pattern matching ──────────────────────

    #[test]
    fn wildcard_star_matches_all() {
        assert!(scope_matches("*", "db:query:read"));
        assert!(scope_matches("*", "exec:shell:run"));
    }

    #[test]
    fn category_wildcard() {
        assert!(scope_matches("db:*", "db:query:read"));
        assert!(scope_matches("db:*", "db:mutate:destructive"));
        assert!(!scope_matches("db:*", "exec:shell:run"));
    }

    #[test]
    fn subcategory_wildcard() {
        assert!(scope_matches("db:query:*", "db:query:read"));
        assert!(scope_matches("db:query:*", "db:query:search"));
        assert!(!scope_matches("db:query:*", "db:mutate:write"));
    }

    #[test]
    fn exact_match() {
        assert!(scope_matches("db:query:read", "db:query:read"));
        assert!(!scope_matches("db:query:read", "db:query:write"));
        assert!(!scope_matches("db:query:read", "db:mutate:read"));
    }

    #[test]
    fn hierarchical_grant_covers_less_specific() {
        // 4-level grant covers 3-level request (more specific implies less specific)
        assert!(scope_matches("db:query:read:pii", "db:query:read"));
        assert!(scope_matches("exec:shell:run:readonly", "exec:shell:run"));
        assert!(scope_matches("net:http:outbound:internal", "net:http:outbound"));
        assert!(scope_matches("fs:file:read:sensitive", "fs:file:read"));

        // 3-level does NOT cover 4-level (less specific does NOT imply more specific)
        assert!(!scope_matches("db:query:read", "db:query:read:pii"));
        assert!(!scope_matches("exec:shell:run", "exec:shell:run:readonly"));

        // 2-level pattern still doesn't match 3-level scope (no wildcard)
        assert!(!scope_matches("db:query", "db:query:read"));
    }

    // ── Tool name → scope mapping ─────────────

    #[test]
    fn database_query_scope() {
        let s = tool_to_scope("database.query");
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "query");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn database_drop_scope() {
        let s = tool_to_scope("database.drop");
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "mutate");
        assert_eq!(s.action, "destructive");
    }

    #[test]
    fn database_insert_scope() {
        let s = tool_to_scope("database.insert");
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "mutate");
        assert_eq!(s.action, "write");
    }

    #[test]
    fn database_execute_scope() {
        let s = tool_to_scope("database.execute");
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "mutate");
        assert_eq!(s.action, "write");
    }

    #[test]
    fn shell_exec_scope() {
        let s = tool_to_scope("shell.exec");
        assert_eq!(s.category, "exec");
        assert_eq!(s.subcategory, "shell");
        assert_eq!(s.action, "run");
    }

    #[test]
    fn filesystem_read_scope() {
        let s = tool_to_scope("filesystem.read");
        assert_eq!(s.category, "fs");
        assert_eq!(s.subcategory, "file");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn filesystem_write_scope() {
        let s = tool_to_scope("filesystem.write");
        assert_eq!(s.category, "fs");
        assert_eq!(s.subcategory, "file");
        assert_eq!(s.action, "write");
    }

    #[test]
    fn filesystem_delete_scope() {
        let s = tool_to_scope("filesystem.delete");
        assert_eq!(s.category, "fs");
        assert_eq!(s.subcategory, "file");
        assert_eq!(s.action, "delete");
    }

    #[test]
    fn http_fetch_scope() {
        let s = tool_to_scope("http.fetch");
        assert_eq!(s.category, "net");
        assert_eq!(s.subcategory, "http");
        assert_eq!(s.action, "outbound");
    }

    #[test]
    fn http_serve_scope() {
        let s = tool_to_scope("http.serve");
        assert_eq!(s.category, "net");
        assert_eq!(s.subcategory, "http");
        assert_eq!(s.action, "inbound");
    }

    #[test]
    fn llm_input_scope() {
        let s = tool_to_scope("llm.input");
        assert_eq!(s.category, "llm");
        assert_eq!(s.subcategory, "input");
        assert_eq!(s.action, "prompt");
    }

    #[test]
    fn llm_output_scope() {
        let s = tool_to_scope("llm.output");
        assert_eq!(s.category, "llm");
        assert_eq!(s.subcategory, "output");
        assert_eq!(s.action, "response");
    }

    #[test]
    fn email_send_scope() {
        let s = tool_to_scope("email.send");
        assert_eq!(s.category, "comms");
        assert_eq!(s.subcategory, "email");
        assert_eq!(s.action, "send");
    }

    #[test]
    fn git_push_scope() {
        let s = tool_to_scope("git.push");
        assert_eq!(s.category, "scm");
        assert_eq!(s.subcategory, "git");
        assert_eq!(s.action, "push");
    }

    #[test]
    fn git_commit_scope() {
        let s = tool_to_scope("git.commit");
        assert_eq!(s.category, "scm");
        assert_eq!(s.subcategory, "git");
        assert_eq!(s.action, "commit");
    }

    #[test]
    fn cloud_deploy_scope() {
        let s = tool_to_scope("cloud.deploy");
        assert_eq!(s.category, "cloud");
        assert_eq!(s.subcategory, "infra");
        assert_eq!(s.action, "provision");
    }

    #[test]
    fn agent_delegate_scope() {
        let s = tool_to_scope("agent.delegate");
        assert_eq!(s.category, "agent");
        assert_eq!(s.subcategory, "delegate");
        assert_eq!(s.action, "spawn");
    }

    #[test]
    fn browser_navigate_scope() {
        let s = tool_to_scope("browser.navigate");
        assert_eq!(s.category, "browser");
        assert_eq!(s.subcategory, "page");
        assert_eq!(s.action, "navigate");
    }

    #[test]
    fn auth_secret_read_scope() {
        let s = tool_to_scope("secret.get");
        assert_eq!(s.category, "auth");
        assert_eq!(s.subcategory, "secret");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn code_eval_scope() {
        let s = tool_to_scope("eval.python");
        assert_eq!(s.category, "exec");
        assert_eq!(s.subcategory, "code");
        assert_eq!(s.action, "eval");
    }

    #[test]
    fn dns_resolve_scope() {
        let s = tool_to_scope("dns.resolve");
        assert_eq!(s.category, "net");
        assert_eq!(s.subcategory, "dns");
        assert_eq!(s.action, "resolve");
    }

    #[test]
    fn payment_tool_scope() {
        let s = tool_to_scope("payment.transfer");
        assert_eq!(s.category, "payment");
        assert_eq!(s.subcategory, "payment");
        assert_eq!(s.action, "transfer");
    }

    // ── Alias canonicalization → scope ────────

    #[test]
    fn db_query_alias_maps_to_scope() {
        let s = tool_to_scope("db.query");
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "query");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn cmd_run_alias_maps_to_scope() {
        let s = tool_to_scope("cmd.run");
        assert_eq!(s.category, "exec");
        assert_eq!(s.subcategory, "shell");
        assert_eq!(s.action, "run");
    }

    #[test]
    fn file_read_alias_maps_to_scope() {
        let s = tool_to_scope("file.read");
        assert_eq!(s.category, "fs");
        assert_eq!(s.subcategory, "file");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn read_file_fullname_alias() {
        let s = tool_to_scope("read_file");
        assert_eq!(s.category, "fs");
        assert_eq!(s.subcategory, "file");
        assert_eq!(s.action, "read");
    }

    #[test]
    fn run_command_fullname_alias() {
        let s = tool_to_scope("run_command");
        assert_eq!(s.category, "exec");
        assert_eq!(s.subcategory, "shell");
        assert_eq!(s.action, "run");
    }

    #[test]
    fn mcp_prefix_stripped() {
        let s = tool_to_scope("mcp.db.query");
        assert_eq!(s.category, "db");
        assert_eq!(s.subcategory, "query");
        assert_eq!(s.action, "read");
    }

    // ── Defense tier from scope ───────────────

    #[test]
    fn scope_defense_tiers() {
        assert_eq!(tool_to_scope("database.query").defense_tier(), DefenseTier::Rules);
        assert_eq!(tool_to_scope("shell.exec").defense_tier(), DefenseTier::Rules);
        assert_eq!(tool_to_scope("filesystem.read").defense_tier(), DefenseTier::Rules);
        assert_eq!(tool_to_scope("http.fetch").defense_tier(), DefenseTier::Rules);
        assert_eq!(tool_to_scope("llm.input").defense_tier(), DefenseTier::Rules);

        assert_eq!(tool_to_scope("cloud.deploy").defense_tier(), DefenseTier::Hybrid);
        assert_eq!(tool_to_scope("browser.navigate").defense_tier(), DefenseTier::Hybrid);
        assert_eq!(tool_to_scope("agent.delegate").defense_tier(), DefenseTier::Hybrid);
        assert_eq!(tool_to_scope("payment.transfer").defense_tier(), DefenseTier::Hybrid);

        assert_eq!(tool_to_scope("auth.read").defense_tier(), DefenseTier::Hybrid);
        assert_eq!(tool_to_scope("email.send").defense_tier(), DefenseTier::Hybrid);
        assert_eq!(tool_to_scope("git.push").defense_tier(), DefenseTier::Hybrid);
    }

    // ── Scope pattern matching with tool names ─

    #[test]
    fn rule_scope_pattern_matches_tool() {
        let scope = tool_to_scope("database.query").as_str();
        assert!(scope_matches("db:*", &scope));
        assert!(scope_matches("db:query:*", &scope));
        assert!(scope_matches("db:query:read", &scope));
        assert!(!scope_matches("exec:*", &scope));
    }

    #[test]
    fn shell_rule_matches_all_exec() {
        let s1 = tool_to_scope("shell.exec").as_str();
        let s2 = tool_to_scope("eval.python").as_str();
        assert!(scope_matches("exec:*", &s1));
        assert!(scope_matches("exec:*", &s2));
    }

    // ── Category ↔ scope prefix ──────────────

    #[test]
    fn category_to_prefix_roundtrip() {
        assert_eq!(category_to_scope_prefix(Category::Shell), "exec");
        assert_eq!(category_to_scope_prefix(Category::DatabaseQuery), "db");
        assert_eq!(category_to_scope_prefix(Category::FilesystemRead), "fs");
        assert_eq!(category_to_scope_prefix(Category::HttpOutbound), "net");
        assert_eq!(category_to_scope_prefix(Category::LlmInput), "llm");
        assert_eq!(category_to_scope_prefix(Category::EmailMessaging), "comms");
        assert_eq!(category_to_scope_prefix(Category::GitVcs), "scm");
        assert_eq!(category_to_scope_prefix(Category::CloudInfra), "cloud");
    }

    // ── permission_to_scopes ─────────────────────

    #[test]
    fn permission_database_read_only() {
        assert_eq!(permission_to_scopes("database.query", "read_only"), vec!["db:query:read"]);
    }

    #[test]
    fn permission_database_read_write() {
        assert_eq!(
            permission_to_scopes("database.query", "read_write"),
            vec!["db:query:read", "db:query:write"]
        );
    }

    #[test]
    fn permission_database_full() {
        assert_eq!(permission_to_scopes("database.query", "full"), vec!["db:*"]);
    }

    #[test]
    fn permission_shell_read_only_denied() {
        assert!(permission_to_scopes("shell.exec", "read_only").is_empty());
    }

    #[test]
    fn permission_shell_full() {
        assert_eq!(permission_to_scopes("shell.exec", "full"), vec!["exec:shell:run"]);
    }

    #[test]
    fn permission_filesystem_read_write() {
        assert_eq!(
            permission_to_scopes("filesystem.read", "read_write"),
            vec!["fs:file:read", "fs:file:write"]
        );
    }

    #[test]
    fn permission_http_read_only() {
        assert_eq!(permission_to_scopes("http.fetch", "read_only"), vec!["net:http:outbound"]);
    }

    #[test]
    fn permission_llm_read_write() {
        assert_eq!(
            permission_to_scopes("llm.prompt", "read_write"),
            vec!["llm:input:*", "llm:output:*"]
        );
    }

    #[test]
    fn permission_email_read_only() {
        assert_eq!(permission_to_scopes("email.send", "read_only"), vec!["comms:email:read"]);
    }

    #[test]
    fn permission_secret_full() {
        assert_eq!(permission_to_scopes("secret.read", "full"), vec!["auth:*"]);
    }

    #[test]
    fn permission_custom_returns_empty() {
        assert!(permission_to_scopes("database.query", "custom").is_empty());
    }

    #[test]
    fn permission_unknown_category_derives() {
        assert_eq!(permission_to_scopes("magic.wand", "read_only"), vec!["magic:*:read"]);
        assert_eq!(permission_to_scopes("magic.wand", "full"), vec!["magic:*"]);
    }

    #[test]
    fn permission_underscore_tool_names() {
        // Underscore names get canonicalized to dot names first
        assert_eq!(permission_to_scopes("database_query", "read_only"), vec!["db:query:read"]);
        assert_eq!(permission_to_scopes("shell_exec", "full"), vec!["exec:shell:run"]);
        assert_eq!(permission_to_scopes("http_fetch", "read_only"), vec!["net:http:outbound"]);
    }
}
