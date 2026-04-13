//! clampd-guard — runtime security guard for AI coding tools.
//!
//! Single binary that serves as:
//!   - PreToolUse hook (blocks dangerous tool calls before execution)
//!   - PostToolUse hook (inspects tool output for PII/secrets)
//!   - Hook installer for Claude Code and Cursor
//!
//! Hook mode (no subcommand): reads CLAUDE_TOOL_NAME/CLAUDE_TOOL_INPUT env vars.
//! Management mode: subcommands for setup, hook install/uninstall.

mod auth;
mod config;
mod guard;
mod hook;
mod scope;
mod sync;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "clampd-guard",
    version,
    about = "Runtime security guard for AI coding tools (Claude Code, Cursor)",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install guard config and hooks in one step
    Setup {
        /// Clampd gateway URL
        #[arg(long, short)]
        url: String,
        /// API key
        #[arg(long, short)]
        key: String,
        /// Agent UUID
        #[arg(long, short)]
        agent: String,
        /// Agent signing secret
        #[arg(long, short)]
        secret: String,
        /// Target IDE: claude-code (default) or cursor
        #[arg(long, default_value = "claude-code")]
        target: String,
    },
    /// Install/uninstall hooks in IDE settings
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Sync available tools to the gateway for dashboard discovery
    Sync {
        /// Target: claude-code (default), cursor, or all
        #[arg(long, default_value = "all")]
        target: String,
    },
}

#[derive(Subcommand)]
enum HookAction {
    /// Install PreToolUse + PostToolUse hooks
    Install {
        /// Target: claude-code (default) or cursor
        #[arg(long, default_value = "claude-code")]
        target: String,
    },
    /// Remove hooks
    Uninstall {
        /// Target: claude-code (default) or cursor
        #[arg(long, default_value = "claude-code")]
        target: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        // No subcommand → hook mode (called by Claude Code / Cursor)
        None => {
            guard::run().await;
        }

        Some(Commands::Setup { url, key, agent, secret, target }) => {
            // 1. Validate gateway
            eprint!("[clampd] Validating gateway at {}... ", url);
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();

            let base = url.trim_end_matches('/');
            let health_ok = client.get(format!("{}/health", base)).send().await;
            match health_ok {
                Ok(r) if r.status().is_success() => eprintln!("OK"),
                _ => {
                    match client.get(format!("{}/.well-known/jwks.json", base)).send().await {
                        Ok(r) if r.status().is_success() => eprintln!("OK (via JWKS)"),
                        _ => {
                            eprintln!("FAILED");
                            eprintln!("[clampd] Cannot reach gateway at {}", url);
                            std::process::exit(1);
                        }
                    }
                }
            }

            // 2. Save config
            let cfg = config::GuardConfig {
                gateway_url: url.clone(),
                api_key: key,
                agent_id: agent,
                secret,
                skip_low_risk: false,
                fail_open: true,
                timeout_ms: 2000,
            };
            match cfg.save() {
                Ok(path) => eprintln!("[clampd] Config saved to {}", path.display()),
                Err(e) => {
                    eprintln!("[clampd] Failed to save config: {:#}", e);
                    std::process::exit(1);
                }
            }

            // 3. Install hooks
            let t = hook::Target::from_str(&target).unwrap_or_else(|e| {
                eprintln!("[clampd] {}", e);
                std::process::exit(1);
            });
            if let Err(e) = hook::install(&t) {
                eprintln!("[clampd] Failed to install hooks: {:#}", e);
                std::process::exit(1);
            }

            eprintln!();
            eprintln!("  Guard active. Every tool call is now verified before execution.");
            eprintln!("  243 detection rules | Cedar policies | Real-time enforcement");
            eprintln!();
        }

        Some(Commands::Sync { target }) => {
            sync::run(&target).await;
        }

        Some(Commands::Hook { action }) => {
            let result = match action {
                HookAction::Install { target } => {
                    let t = hook::Target::from_str(&target).unwrap_or_else(|e| {
                        eprintln!("[clampd] {}", e);
                        std::process::exit(1);
                    });
                    hook::install(&t)
                }
                HookAction::Uninstall { target } => {
                    let t = hook::Target::from_str(&target).unwrap_or_else(|e| {
                        eprintln!("[clampd] {}", e);
                        std::process::exit(1);
                    });
                    hook::uninstall(&t)
                }
            };
            if let Err(e) = result {
                eprintln!("[clampd] Error: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
