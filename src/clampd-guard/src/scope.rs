/// Maps Claude Code tool names to Clampd scope strings.
///
/// Scopes follow `category:subcategory:action` and are matched
/// against Cedar policies and detection rules on the gateway.

pub fn map_tool_to_scope(tool_name: &str) -> &'static str {
    match tool_name {
        "Bash" => "exec:shell:run",
        "Write" => "fs:write:file",
        "Edit" => "fs:write:file",
        "Read" => "fs:read:file",
        "Glob" => "fs:read:search",
        "Grep" => "fs:read:search",
        "NotebookEdit" => "exec:eval:notebook",
        "WebFetch" => "net:http:outbound",
        "WebSearch" => "net:http:outbound",
        "Agent" => "agent:subagent:spawn",
        "TodoRead" => "fs:read:file",
        "TodoWrite" => "fs:write:file",
        _ if tool_name.starts_with("mcp__github__") => "scm:git:api",
        _ if tool_name.starts_with("mcp__slack__") => "comms:slack:send",
        _ if tool_name.starts_with("mcp__") => "agent:mcp:tool",
        _ => "unknown",
    }
}

pub fn is_low_risk(tool_name: &str) -> bool {
    matches!(tool_name, "Read" | "Glob" | "Grep" | "TodoRead")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_tools() {
        assert_eq!(map_tool_to_scope("Bash"), "exec:shell:run");
        assert_eq!(map_tool_to_scope("Write"), "fs:write:file");
        assert_eq!(map_tool_to_scope("Edit"), "fs:write:file");
        assert_eq!(map_tool_to_scope("Read"), "fs:read:file");
        assert_eq!(map_tool_to_scope("Glob"), "fs:read:search");
        assert_eq!(map_tool_to_scope("Grep"), "fs:read:search");
        assert_eq!(map_tool_to_scope("NotebookEdit"), "exec:eval:notebook");
        assert_eq!(map_tool_to_scope("WebFetch"), "net:http:outbound");
        assert_eq!(map_tool_to_scope("WebSearch"), "net:http:outbound");
        assert_eq!(map_tool_to_scope("Agent"), "agent:subagent:spawn");
    }

    #[test]
    fn mcp_tools() {
        assert_eq!(map_tool_to_scope("mcp__github__create_pr"), "scm:git:api");
        assert_eq!(map_tool_to_scope("mcp__slack__send_message"), "comms:slack:send");
        assert_eq!(map_tool_to_scope("mcp__jira__create_issue"), "agent:mcp:tool");
    }

    #[test]
    fn unknown_tool() {
        assert_eq!(map_tool_to_scope("SomeFutureTool"), "unknown");
    }

    #[test]
    fn low_risk() {
        assert!(is_low_risk("Read"));
        assert!(is_low_risk("Glob"));
        assert!(is_low_risk("Grep"));
        assert!(!is_low_risk("Bash"));
        assert!(!is_low_risk("Write"));
        assert!(!is_low_risk("mcp__github__push"));
    }
}
