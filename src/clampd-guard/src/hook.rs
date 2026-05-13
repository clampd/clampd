/// Install/uninstall clampd-guard hooks in Claude Code and Cursor settings.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Supported hook targets.
pub enum Target {
    ClaudeCode,
    Cursor,
}

impl Target {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "claude-code" | "claude" | "cc" => Ok(Self::ClaudeCode),
            "cursor" => Ok(Self::Cursor),
            _ => anyhow::bail!("Unknown target '{}'. Supported: claude-code, cursor", s),
        }
    }

    fn settings_path(&self) -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        match self {
            Self::ClaudeCode => home.join(".claude").join("settings.json"),
            Self::Cursor => home.join(".cursor").join("hooks.json"),
        }
    }

    fn settings_dir(&self) -> PathBuf {
        self.settings_path().parent().unwrap().to_path_buf()
    }

    fn name(&self) -> &str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
        }
    }
}

/// The binary name. OS resolves from PATH at runtime.
fn guard_binary() -> &'static str {
    "clampd-guard"
}

/// Install PreToolUse + PostToolUse hooks into target's settings.
pub fn install(target: &Target) -> Result<()> {
    let settings_path = target.settings_path();
    let settings_dir = target.settings_dir();

    if !settings_dir.exists() {
        std::fs::create_dir_all(&settings_dir)
            .with_context(|| format!("Failed to create {}", settings_dir.display()))?;
    }

    // Read existing settings or start fresh
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let command = guard_binary();

    // Install PreToolUse
    install_hook_entry(hooks, "PreToolUse", command)?;

    // Install PostToolUse
    install_hook_entry(hooks, "PostToolUse", command)?;

    let content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, format!("{}\n", content))
        .with_context(|| format!("Failed to write {}", settings_path.display()))?;

    eprintln!("[clampd] Hooks installed in {} ({})", target.name(), settings_path.display());
    Ok(())
}

/// Add a hook entry for a specific event type, removing any existing clampd-guard entry first.
fn install_hook_entry(
    hooks: &mut serde_json::Value,
    event: &str,
    command: &str,
) -> Result<()> {
    let entries = hooks
        .as_object_mut()
        .unwrap()
        .entry(event)
        .or_insert_with(|| serde_json::json!([]));

    let arr = entries.as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not an array in settings", event))?;

    // Remove existing clampd-guard entries
    arr.retain(|entry| {
        let hooks_arr = entry.get("hooks").and_then(|h| h.as_array());
        if let Some(hooks) = hooks_arr {
            !hooks.iter().any(|h| {
                h.get("command").and_then(|c| c.as_str()) == Some(command)
            })
        } else {
            true
        }
    });

    // Add our entry
    arr.push(serde_json::json!({
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": command,
        }]
    }));

    Ok(())
}

/// Remove clampd-guard hooks from target's settings.
pub fn uninstall(target: &Target) -> Result<()> {
    let settings_path = target.settings_path();
    if !settings_path.exists() {
        eprintln!("[clampd] No settings file found at {}", settings_path.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    let command = guard_binary();

    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        for event in ["PreToolUse", "PostToolUse"] {
            if let Some(entries) = hooks.get_mut(event).and_then(|e| e.as_array_mut()) {
                entries.retain(|entry| {
                    let hooks_arr = entry.get("hooks").and_then(|h| h.as_array());
                    if let Some(hook_list) = hooks_arr {
                        !hook_list.iter().any(|h| {
                            h.get("command").and_then(|c| c.as_str()) == Some(command)
                        })
                    } else {
                        true
                    }
                });
                if entries.is_empty() {
                    hooks.remove(event);
                }
            }
        }
        if hooks.is_empty() {
            settings.as_object_mut().unwrap().remove("hooks");
        }
    }

    let content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, format!("{}\n", content))?;

    eprintln!("[clampd] Hooks removed from {} ({})", target.name(), settings_path.display());
    Ok(())
}
