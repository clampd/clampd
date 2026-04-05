use anyhow::Result;
use crate::config::CliConfig;
use crate::state::AppState;

pub async fn init() -> Result<()> {
    let path = CliConfig::write_default()?;
    println!("Config written to {}", path.display());
    println!();
    println!("Default context 'local' created.");
    println!("Add more contexts with: clampd context add <name> --endpoint <url>");
    Ok(())
}

pub async fn show(state: &AppState) -> Result<()> {
    let toml_str = toml::to_string_pretty(&state.config)?;
    println!("{toml_str}");

    // Show active context summary
    if let Some(ctx) = state.config.active_context() {
        println!("# Active context: {}", ctx.name);
        println!("#   dashboard:   {}", ctx.dashboard_url);
        println!("#   gateway_url: {}", ctx.gateway_url);
        println!("#   org_id:      {}", if ctx.org_id.is_empty() { "(not set)" } else { &ctx.org_id });
    }
    Ok(())
}
