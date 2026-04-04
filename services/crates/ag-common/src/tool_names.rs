//! Tool name canonicalization.
//!
//! Normalizes short/alternate tool names to canonical forms used in rules.
//! Called at the gateway so ALL downstream services see consistent names.
//!
//! Examples:
//!   "db.query"      → "database.query"
//!   "file.read"     → "filesystem.read"
//!   "cmd.run"       → "shell.run"
//!   "mcp.db.query"  → "database.query"
//!   "read_file"     → "filesystem.read"

/// Prefix aliases: short prefix → canonical prefix.
const PREFIX_ALIASES: &[(&str, &str)] = &[
    ("db.", "database."),
    ("sql.", "database."),
    ("file.", "filesystem."),
    ("fs.", "filesystem."),
    ("cmd.", "shell."),
    ("net.", "http."),
    ("fetch.", "http."),
];

/// Full name aliases: exact match → canonical name.
const FULL_ALIASES: &[(&str, &str)] = &[
    ("run_command", "shell.exec"),
    ("run_cmd", "shell.exec"),
    ("execute_command", "shell.exec"),
    ("exec_command", "shell.exec"),
    ("execute_code", "shell.exec"),
    ("read_file", "filesystem.read"),
    ("write_file", "filesystem.write"),
    ("process_data", "function.invoke"),
    // Underscore variants (Claude.ai MCP connectors disallow dots in tool names)
    ("database_query", "database.query"),
    ("database_schema", "database.schema"),
    ("database_mutate", "database.mutate"),
    ("shell_exec", "shell.exec"),
    ("process_list", "process.list"),
    ("docker_exec", "docker.exec"),
    ("kubernetes_apply", "kubernetes.apply"),
    ("filesystem_read", "filesystem.read"),
    ("filesystem_write", "filesystem.write"),
    ("filesystem_list", "filesystem.list"),
    ("http_fetch", "http.fetch"),
    ("network_scan", "network.scan"),
    ("email_send", "email.send"),
    ("email_search", "email.search"),
    ("llm_prompt", "llm.prompt"),
    ("llm_embed", "llm.embed"),
    ("secret_read", "secret.read"),
    ("credential_rotate", "credential.rotate"),
];

/// Canonicalize a tool name to the form expected by detection rules.
///
/// 1. Strip `mcp.` prefix (MCP server tools)
/// 2. Check full name aliases (e.g., `read_file` → `filesystem.read`)
/// 3. Check prefix aliases (e.g., `db.` → `database.`)
/// 4. Return as-is if no alias matches
pub fn canonicalize(tool: &str) -> String {
    // Strip MCP prefix
    let stripped = tool.strip_prefix("mcp.").unwrap_or(tool);

    // Check full name aliases
    for (alias, canonical) in FULL_ALIASES {
        if stripped == *alias {
            return canonical.to_string();
        }
    }

    // Check prefix aliases
    for (short, canonical) in PREFIX_ALIASES {
        if stripped.starts_with(short) {
            return format!("{}{}", canonical, &stripped[short.len()..]);
        }
    }

    // Return stripped version (MCP prefix removed) or original
    if stripped.len() < tool.len() {
        stripped.to_string()
    } else {
        tool.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_to_database() {
        assert_eq!(canonicalize("db.query"), "database.query");
        assert_eq!(canonicalize("db.execute"), "database.execute");
    }

    #[test]
    fn sql_to_database() {
        assert_eq!(canonicalize("sql.query"), "database.query");
    }

    #[test]
    fn file_to_filesystem() {
        assert_eq!(canonicalize("file.read"), "filesystem.read");
        assert_eq!(canonicalize("fs.write"), "filesystem.write");
    }

    #[test]
    fn cmd_to_shell() {
        assert_eq!(canonicalize("cmd.run"), "shell.run");
    }

    #[test]
    fn net_to_http() {
        assert_eq!(canonicalize("net.request"), "http.request");
        assert_eq!(canonicalize("fetch.url"), "http.url");
    }

    #[test]
    fn full_name_aliases() {
        assert_eq!(canonicalize("read_file"), "filesystem.read");
        assert_eq!(canonicalize("write_file"), "filesystem.write");
        assert_eq!(canonicalize("run_command"), "shell.exec");
        assert_eq!(canonicalize("execute_code"), "shell.exec");
    }

    #[test]
    fn mcp_prefix_stripped() {
        assert_eq!(canonicalize("mcp.database.query"), "database.query");
        assert_eq!(canonicalize("mcp.db.query"), "database.query");
        assert_eq!(canonicalize("mcp.shell.exec"), "shell.exec");
    }

    #[test]
    fn canonical_names_unchanged() {
        assert_eq!(canonicalize("database.query"), "database.query");
        assert_eq!(canonicalize("filesystem.read"), "filesystem.read");
        assert_eq!(canonicalize("shell.exec"), "shell.exec");
        assert_eq!(canonicalize("http.fetch"), "http.fetch");
        assert_eq!(canonicalize("llm.input"), "llm.input");
        assert_eq!(canonicalize("function.invoke"), "function.invoke");
    }

    #[test]
    fn underscore_to_dot_aliases() {
        assert_eq!(canonicalize("database_query"), "database.query");
        assert_eq!(canonicalize("database_schema"), "database.schema");
        assert_eq!(canonicalize("database_mutate"), "database.mutate");
        assert_eq!(canonicalize("shell_exec"), "shell.exec");
        assert_eq!(canonicalize("filesystem_read"), "filesystem.read");
        assert_eq!(canonicalize("filesystem_write"), "filesystem.write");
        assert_eq!(canonicalize("http_fetch"), "http.fetch");
        assert_eq!(canonicalize("network_scan"), "network.scan");
        assert_eq!(canonicalize("llm_prompt"), "llm.prompt");
        assert_eq!(canonicalize("secret_read"), "secret.read");
        assert_eq!(canonicalize("credential_rotate"), "credential.rotate");
    }

    #[test]
    fn unknown_names_unchanged() {
        assert_eq!(canonicalize("custom.tool"), "custom.tool");
        assert_eq!(canonicalize("my_special_tool"), "my_special_tool");
    }
}
