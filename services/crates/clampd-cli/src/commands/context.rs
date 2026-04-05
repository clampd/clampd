use anyhow::Result;
use crate::config::{CliConfig, ClampdContext};
use crate::output::OutputFormat;

/// List all contexts, highlighting the active one.
pub async fn list(cfg: &CliConfig, fmt: OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Json => {
            let out = serde_json::json!({
                "current_context": cfg.current_context,
                "contexts": cfg.contexts,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        _ => {
            println!("{:<4} {:<15} {:<40} {:<30} {:<20}",
                "", "NAME", "DASHBOARD", "GATEWAY", "ORG_ID");
            for ctx in &cfg.contexts {
                let marker = if ctx.name == cfg.current_context { " *" } else { "  " };
                let org_display = if ctx.org_id.is_empty() {
                    "(not set)".to_string()
                } else if ctx.org_id.len() > 18 {
                    format!("{}...", &ctx.org_id[..15])
                } else {
                    ctx.org_id.clone()
                };
                println!("{:<4} {:<15} {:<40} {:<30} {:<20}",
                    marker, ctx.name, ctx.dashboard_url, ctx.gateway_url, org_display);
            }
        }
    }
    Ok(())
}

/// Show the currently active context.
pub async fn current(cfg: &CliConfig) -> Result<()> {
    println!("{}", cfg.current_context);
    Ok(())
}

/// Switch the active context.
pub async fn use_ctx(name: &str) -> Result<()> {
    let mut cfg = CliConfig::load()?.with_env_overrides();
    cfg.use_context(name)?;
    let path = cfg.save()?;
    println!("Switched to context '{name}'.");
    println!("Config saved to {}", path.display());
    Ok(())
}

/// Add a new context.
pub async fn add(
    name: &str,
    endpoint: &str,
    gateway_url: Option<&str>,
    org_id: Option<&str>,
    api_token: Option<&str>,
) -> Result<()> {
    let mut cfg = CliConfig::load()?.with_env_overrides();
    let ctx = ClampdContext {
        name: name.to_string(),
        dashboard_url: endpoint.to_string(),
        gateway_url: gateway_url.unwrap_or("http://127.0.0.1:8080").to_string(),
        org_id: org_id.unwrap_or("").to_string(),
        api_token: api_token.unwrap_or("").to_string(),
        license_token: String::new(),
    };
    cfg.add_context(ctx)?;
    let path = cfg.save()?;
    println!("Context '{name}' added.");
    println!("Config saved to {}", path.display());
    println!("Use `clampd context use {name}` to switch to it.");
    Ok(())
}

/// Remove a context.
pub async fn remove(name: &str) -> Result<()> {
    let mut cfg = CliConfig::load()?.with_env_overrides();
    cfg.remove_context(name)?;
    let path = cfg.save()?;
    println!("Context '{name}' removed.");
    println!("Config saved to {}", path.display());
    Ok(())
}

/// Set a field on a context.
pub async fn set(name: &str, field: &str, value: &str) -> Result<()> {
    let mut cfg = CliConfig::load()?.with_env_overrides();
    cfg.set_context_field(name, field, value)?;
    let path = cfg.save()?;
    println!("Context '{name}': {field} = {value}");
    println!("Config saved to {}", path.display());
    Ok(())
}
