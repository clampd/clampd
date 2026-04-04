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
            println!("{:<4} {:<15} {:<40} {:<20} {:<8}",
                "", "NAME", "ENDPOINT", "ORG_ID", "TRANSPORT");
            for ctx in &cfg.contexts {
                let marker = if ctx.name == cfg.current_context { " *" } else { "  " };
                let org_display = if ctx.org_id.is_empty() {
                    "(not set)".to_string()
                } else if ctx.org_id.len() > 18 {
                    format!("{}...", &ctx.org_id[..15])
                } else {
                    ctx.org_id.clone()
                };
                println!("{:<4} {:<15} {:<40} {:<20} {:<8}",
                    marker, ctx.name, ctx.endpoint, org_display, ctx.transport);
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
    org_id: Option<&str>,
    api_token: Option<&str>,
    transport: &str,
) -> Result<()> {
    let mut cfg = CliConfig::load()?.with_env_overrides();
    let ctx = ClampdContext {
        name: name.to_string(),
        endpoint: endpoint.to_string(),
        org_id: org_id.unwrap_or("").to_string(),
        api_token: api_token.unwrap_or("").to_string(),
        transport: transport.to_string(),
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
