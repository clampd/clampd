//! clampd-cli - command-line interface for Clampd.
//!
//! Architecture boundaries:
//! - Connects to Dashboard API via HTTP for ALL management operations
//! - Connects to ag-gateway via HTTP for proxy/demo operations
//! - NEVER connects directly to internal services (ag-intent, ag-policy, etc.)
//! - NEVER connects directly to infrastructure (Postgres, Redis, NATS)

mod commands;
mod config;
#[allow(dead_code)]
mod db; // Legacy direct-DB queries; kept for local-only mode fallback
mod http_client;
mod license_gate;
mod output;
mod state;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use config::CliConfig;
use output::OutputFormat;
use state::AppState;

#[derive(Parser)]
#[command(name = "clampd", version, about = "Clampd - Non-Human Identity Governor CLI")]
struct Cli {
    /// Output format: table, json, plain
    #[arg(long, short = 'o', global = true, default_value = "table")]
    format: String,

    /// Organization ID (or set CLAMPD_ORG_ID)
    #[arg(long, global = true, env = "CLAMPD_ORG_ID")]
    org_id: Option<Uuid>,

    /// Dashboard API URL (or set CLAMPD_DASHBOARD_URL)
    #[arg(long, global = true, env = "CLAMPD_DASHBOARD_URL")]
    dashboard_url: Option<String>,

    /// API token for dashboard auth (or set CLAMPD_API_TOKEN)
    #[arg(long, global = true, env = "CLAMPD_API_TOKEN")]
    api_token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Cluster health and lifecycle
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Agent management
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Emergency kill switch
    Kill {
        #[command(subcommand)]
        action: KillAction,
    },
    /// License management
    License {
        #[command(subcommand)]
        action: LicenseAction,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Context management (like kubectl context)
    Context {
        #[command(subcommand)]
        action: ContextAction,
    },
    /// Policy and rule management
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Keyword dictionary management
    Keyword {
        #[command(subcommand)]
        action: KeywordAction,
    },
    /// Organization management
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Token operations
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
    /// Audit log queries
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Risk score management
    Risk {
        #[command(subcommand)]
        action: RiskAction,
    },
    /// Webhook management
    Webhook {
        #[command(subcommand)]
        action: WebhookAction,
    },
    /// API key management
    Apikey {
        #[command(subcommand)]
        action: ApikeyAction,
    },
    /// Live TUI dashboard
    #[cfg(feature = "tui")]
    Watch {
        /// Watch a specific agent
        #[arg(long)]
        agent: Option<Uuid>,
    },
    /// Demo mode with pre-scripted scenarios
    #[cfg(feature = "tui")]
    Demo {
        /// Scenario name
        #[arg(long, default_value = "basic")]
        scenario: String,
    },
    /// Compliance checks
    Compliance {
        #[command(subcommand)]
        action: ComplianceAction,
    },
    /// Red team test suite: run attack vectors against the gateway
    Test {
        /// Gateway URL (or set CLAMPD_GATEWAY_URL)
        #[arg(long, env = "CLAMPD_GATEWAY_URL")]
        gateway: Option<String>,
        /// Attack categories to run (comma-separated: sqli,ssrf,rce,traversal,prompt,exfil,evasion,safe)
        #[arg(long)]
        attacks: Option<String>,
        /// Output format: table or json
        #[arg(long, default_value = "table")]
        test_format: String,
        /// Show matched rules and risk scores for each vector
        #[arg(long)]
        verbose: bool,
        /// Continuously re-run tests on a loop
        #[arg(long)]
        watch: bool,
        /// Interval between watch runs (e.g. "30s", "5m", "1h"). Default: 5m
        #[arg(long, default_value = "5m")]
        interval: String,
        /// Exit with code 1 if any test fails (for CI pipelines)
        #[arg(long)]
        exit_on_fail: bool,
    },
    /// Activate a license (provisions org from clampd.dev license JWT)
    Activate {
        /// License JWT token from clampd.dev
        #[arg(long, env = "CLAMPD_LICENSE_TOKEN")]
        license: String,
    },
}

// ── Cluster ──────────────────────────────────────────────

#[derive(Subcommand)]
enum ClusterAction {
    /// Show health of all services
    Status,
    /// Start all services (docker compose up)
    Up {
        /// Run in detached mode
        #[arg(short, long)]
        detach: bool,
    },
    /// Stop all services (docker compose down)
    Down,
}

// ── Agent ────────────────────────────────────────────────

#[derive(Subcommand)]
enum AgentAction {
    /// List agents in organization
    List,
    /// Get agent details
    Get {
        /// Agent ID
        id: Uuid,
    },
    /// Register a new agent
    Register {
        /// Agent name
        #[arg(long)]
        name: String,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Declared purpose
        #[arg(long)]
        purpose: Option<String>,
        /// Framework (e.g. langchain, autogen)
        #[arg(long)]
        framework: Option<String>,
    },
    /// Update an agent
    Update {
        /// Agent ID
        id: Uuid,
        /// Agent name
        #[arg(long)]
        name: String,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Framework
        #[arg(long)]
        framework: Option<String>,
    },
    /// Delete an agent
    Delete {
        /// Agent ID
        id: Uuid,
    },
    /// Suspend an agent
    Suspend {
        /// Agent ID
        id: Uuid,
    },
    /// Resume a suspended agent
    Resume {
        /// Agent ID
        id: Uuid,
    },
    /// View agent boundaries
    Boundaries {
        /// Agent ID
        id: Uuid,
    },
    /// Manage agent scopes (list, set, add, remove)
    Scopes {
        /// Agent ID
        id: Uuid,
        /// Set scopes (comma-separated, replaces all existing)
        #[arg(long)]
        set: Option<String>,
        /// Add a single scope
        #[arg(long)]
        add: Option<String>,
        /// Remove a single scope
        #[arg(long)]
        remove: Option<String>,
    },
    /// Show the delegation graph
    Graph {
        /// Filter to a specific agent
        #[arg(long)]
        agent: Option<Uuid>,
    },
    /// Link two agents (declare a delegation relationship)
    Link {
        /// Parent (caller) agent ID
        parent: Uuid,
        /// Child (callee) agent ID
        child: Uuid,
        /// Allowed tools (comma-separated, empty = all)
        #[arg(long)]
        tools: Option<String>,
        /// Max delegation depth
        #[arg(long, default_value = "5")]
        max_depth: u32,
    },
    /// Unlink two agents (block a delegation relationship)
    Unlink {
        /// Parent agent ID
        parent: Uuid,
        /// Child agent ID
        child: Uuid,
    },
    /// Approve an observed delegation relationship
    Approve {
        /// Parent agent ID
        parent: Uuid,
        /// Child agent ID
        child: Uuid,
    },
    /// Lock the delegation graph (enable enforcement mode)
    LockGraph,
    /// Unlock the delegation graph (disable enforcement, return to learning)
    UnlockGraph,
}

// ── Kill ─────────────────────────────────────────────────

#[derive(Subcommand)]
enum KillAction {
    /// Kill a specific agent
    Agent {
        /// Agent ID
        id: Uuid,
        /// Reason for kill
        #[arg(long)]
        reason: Option<String>,
    },
    /// Kill all agents in the organization
    All {
        /// Reason for kill-all
        #[arg(long)]
        reason: Option<String>,
    },
    /// List active kill switches
    List,
    /// Get kill status for an agent
    Status {
        /// Agent ID
        id: Uuid,
    },
}

// ── License ──────────────────────────────────────────────

#[derive(Subcommand)]
enum LicenseAction {
    /// Show current license status
    Status,
    /// List all licenses
    List,
}

// ── Config ───────────────────────────────────────────────

#[derive(Subcommand)]
enum ConfigAction {
    /// Create default config file
    Init,
    /// Show current configuration
    Show,
}

// ── Context ─────────────────────────────────────────────

#[derive(Subcommand)]
enum ContextAction {
    /// List all contexts
    List,
    /// Show the currently active context name
    Current,
    /// Switch the active context
    Use {
        /// Context name to switch to
        name: String,
    },
    /// Add a new context
    Add {
        /// Context name (e.g. "prod", "staging")
        name: String,
        /// Endpoint URL (Dashboard API or ag-control)
        #[arg(long)]
        endpoint: String,
        /// Organization ID for this context
        #[arg(long = "set-org-id")]
        ctx_org_id: Option<String>,
        /// API token for authentication
        #[arg(long = "set-api-token")]
        ctx_api_token: Option<String>,
        /// Transport: http or grpc
        #[arg(long, default_value = "http")]
        transport: String,
    },
    /// Remove a context
    Remove {
        /// Context name to remove
        name: String,
    },
    /// Set a field on a context
    Set {
        /// Context name
        name: String,
        /// Field to set: endpoint, org_id, api_token, transport, license_token
        #[arg(long)]
        field: String,
        /// Value to set
        #[arg(long)]
        value: String,
    },
}

// ── Keyword ─────────────────────────────────────────────

#[derive(Subcommand)]
enum KeywordAction {
    /// List custom keywords
    List,
    /// Add a keyword to the dictionary
    Add {
        /// Keyword string
        #[arg(long)]
        keyword: String,
        /// Category: prompt_injection, goal_hijack, security_disable, data_exfil,
        /// pii_field, dangerous_op, infra_target, exfil_destination, compliance
        #[arg(long)]
        category: String,
        /// Risk weight 0.0-1.0
        #[arg(long, default_value = "0.5")]
        weight: f64,
        /// Language code (e.g. en, zh, ar)
        #[arg(long, default_value = "en")]
        lang: String,
    },
    /// Remove a keyword
    Remove {
        /// Keyword ID
        id: Uuid,
    },
    /// Import keywords from CSV file (keyword,category,weight,lang)
    ImportCsv {
        /// Path to CSV file
        #[arg(long)]
        file: String,
    },
    /// Import a RulePack JSON file (rules + keywords)
    ImportPack {
        /// Path to RulePack JSON file
        #[arg(long)]
        file: String,
    },
}

// ── Policy ───────────────────────────────────────────────

#[derive(Subcommand)]
enum PolicyAction {
    /// List policies
    List,
    /// Create a new policy
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: Option<String>,
        /// Policy mode: dsl or rego
        #[arg(long, default_value = "dsl")]
        mode: String,
        /// Policy source code
        #[arg(long)]
        source: String,
    },
    /// Delete a policy
    Delete {
        /// Policy ID
        id: Uuid,
    },
    /// List rules for the organization
    Rules,
    /// Import rules from external format
    Import {
        /// Import format: invariant, opa, yaml
        #[arg(long)]
        from: String,
        /// Path to file
        #[arg(long)]
        file: String,
    },
}

// ── Org ──────────────────────────────────────────────────

#[derive(Subcommand)]
enum OrgAction {
    /// List organizations
    List,
    /// Create an organization
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        slug: String,
        #[arg(long)]
        billing_email: String,
    },
    /// Update an organization
    Update {
        id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        billing_email: String,
    },
    /// Delete an organization
    Delete { id: Uuid },
    /// List organization members
    Members,
}

// ── Token ────────────────────────────────────────────────

#[derive(Subcommand)]
enum TokenAction {
    /// Exchange credentials for a token
    Exchange {
        /// Agent ID
        agent_id: Uuid,
        /// Requested scopes (comma-separated)
        #[arg(long)]
        scopes: Option<String>,
    },
    /// Introspect a token
    Introspect {
        /// Token string
        token: String,
    },
    /// Revoke all tokens for an agent
    Revoke {
        /// Agent ID
        agent_id: Uuid,
    },
}

// ── Audit ────────────────────────────────────────────────

#[derive(Subcommand)]
enum AuditAction {
    /// List audit events
    List {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<Uuid>,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Max results
        #[arg(long, default_value = "50")]
        limit: u32,
    },
    /// Export audit logs
    Export {
        /// Export format: csv or json
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
        /// Max results
        #[arg(long, default_value = "1000")]
        limit: u32,
    },
}

// ── Risk ─────────────────────────────────────────────────

#[derive(Subcommand)]
enum RiskAction {
    /// Show current risk scores
    Scores,
    /// Show risk history for an agent
    History {
        /// Agent ID
        agent_id: Uuid,
    },
}

// ── Webhook ──────────────────────────────────────────────

#[derive(Subcommand)]
enum WebhookAction {
    /// List webhooks
    List,
    /// Create a webhook
    Create {
        #[arg(long)]
        url: String,
        /// Event types (comma-separated)
        #[arg(long)]
        events: String,
    },
    /// Delete a webhook
    Delete { id: Uuid },
}

// ── API Key ──────────────────────────────────────────────

#[derive(Subcommand)]
enum ApikeyAction {
    /// List API keys
    List,
    /// Create an API key
    Create {
        #[arg(long)]
        name: Option<String>,
    },
    /// Revoke an API key
    Revoke { id: Uuid },
}

// ── Compliance ───────────────────────────────────────────

#[derive(Subcommand)]
enum ComplianceAction {
    /// Run compliance checks interactively
    Run {
        /// Framework: soc2, hipaa, iso27001, gdpr
        #[arg(long)]
        framework: String,
    },
    /// Export compliance report to file
    Report {
        /// Framework: soc2, hipaa, iso27001, gdpr, all
        #[arg(long, default_value = "all")]
        framework: String,
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
}

// ── Org auto-detect ──────────────────────────────────────

/// Decode a JWT payload without verifying signature (for claim extraction).
/// Full verification happens server-side; this just reads the claims.
fn decode_license_claims(token: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    // Try URL_SAFE_NO_PAD first, then standard
    let payload = engine.decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(parts[1]))
        .ok()?;
    serde_json::from_slice(&payload).ok()
}

/// Resolve org_id with priority:
/// 1. Explicit --org-id flag
/// 2. License token (extract org_id from JWT claims)
/// 3. Config file org_id
/// 4. Fail with a helpful message (no auto-detect from DB - we use HTTP now)
async fn resolve_org_id(cli: &Cli, state: &AppState) -> Result<Uuid> {
    // 1. Explicit CLI flag
    if let Some(id) = cli.org_id {
        return Ok(id);
    }

    // 2. License token → extract org_id
    let lt = state.config.license_token();
    let license_token = if !lt.is_empty() {
        Some(lt.to_string())
    } else {
        None
    };

    if let Some(ref token) = license_token {
        if let Some(claims) = decode_license_claims(token) {
            if let Some(org_id_str) = claims.get("org_id").or(claims.get("sub")).and_then(|v| v.as_str()) {
                if let Ok(org_id) = org_id_str.parse::<Uuid>() {
                    return Ok(org_id);
                }
            }
        }
    }

    // 3. Config file org_id (from active context)
    let cfg_org = state.config.org_id();
    if let Ok(id) = cfg_org.parse::<Uuid>() {
        if !id.is_nil() {
            return Ok(id);
        }
    }

    // 4. No org_id available
    eprintln!("No organization ID configured.");
    eprintln!("Set one via:");
    eprintln!("  --org-id <UUID>");
    eprintln!("  CLAMPD_ORG_ID=<UUID>");
    eprintln!("  clampd activate --license <TOKEN>");
    Ok(Uuid::nil())
}

// ── Main ─────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let mut cfg = CliConfig::load()?.with_env_overrides();

    // Apply CLI flag overrides (highest priority) on active context
    if let Some(ref url) = cli.dashboard_url {
        if let Some(ctx) = cfg.active_context_mut() {
            ctx.endpoint = url.clone();
        }
    }
    if let Some(ref token) = cli.api_token {
        if let Some(ctx) = cfg.active_context_mut() {
            ctx.api_token = token.clone();
        }
    }

    let state = AppState::new(cfg);
    let fmt = OutputFormat::from_str_loose(&cli.format);

    // ── License verification ──
    // Commands that can run without a license (help, version handled by clap,
    // plus config/context/activate for initial setup).
    let mut needs_license = !matches!(
        cli.command,
        Commands::Config { .. } | Commands::Context { .. } | Commands::Activate { .. } | Commands::Test { .. }
    );
    #[cfg(feature = "tui")]
    if matches!(cli.command, Commands::Demo { .. }) {
        needs_license = false;
    }

    let license_guard = match license_gate::load_guard(&state.config) {
        Ok(guard) => {
            tracing::debug!(plan = %guard.plan, org = %guard.org_id, "License loaded");
            Some(guard)
        }
        Err(e) => {
            if needs_license {
                eprintln!("============================================================");
                eprintln!("LICENSE ERROR: {e}");
                eprintln!("This command requires a valid Clampd license.");
                eprintln!("Set CLAMPD_LICENSE_KEY or run: clampd activate --license <TOKEN>");
                eprintln!("Get a design-partner license: https://clampd.dev | Sales: sales@clampd.dev");
                eprintln!("============================================================");
                std::process::exit(1);
            }
            None
        }
    };

    let org_id = resolve_org_id(&cli, &state).await?;

    match cli.command {
        // ── Cluster ──
        Commands::Cluster { action } => match action {
            ClusterAction::Status => commands::cluster::status(&state).await?,
            ClusterAction::Up { detach } => commands::cluster::up(&state, detach).await?,
            ClusterAction::Down => commands::cluster::down(&state).await?,
        },

        // ── Agent ──
        Commands::Agent { action } => match action {
            AgentAction::List => commands::agent::list(&state, org_id, fmt).await?,
            AgentAction::Get { id } => commands::agent::get(&state, id, fmt).await?,
            AgentAction::Register {
                name,
                description,
                purpose,
                framework,
            } => {
                // Check agent limit before registering
                if let Some(ref guard) = license_guard {
                    let client = state.api_client();
                    let path = format!("/v1/orgs/{}/agents", org_id);
                    let agents_list: Vec<serde_json::Value> = client.get(&path).await.unwrap_or_default();
                    if let Err(e) = guard.check_agent_limit(agents_list.len() as u32) {
                        eprintln!("\n\u{2718} {e}");
                        eprintln!("  Current plan: {}", guard.plan);
                        eprintln!("  Upgrade: https://clampd.dev/#early-access\n");
                        anyhow::bail!("{e}");
                    }
                }
                commands::agent::register(
                    &state,
                    org_id,
                    &name,
                    description.as_deref(),
                    purpose.as_deref(),
                    framework.as_deref(),
                )
                .await?
            }
            AgentAction::Update {
                id,
                name,
                description,
                framework,
            } => {
                commands::agent::update(
                    &state,
                    id,
                    &name,
                    description.as_deref(),
                    framework.as_deref(),
                )
                .await?
            }
            AgentAction::Delete { id } => commands::agent::delete(&state, id).await?,
            AgentAction::Suspend { id } => commands::agent::suspend(&state, id).await?,
            AgentAction::Resume { id } => commands::agent::resume(&state, id).await?,
            AgentAction::Boundaries { id } => {
                commands::agent::boundaries(&state, id, fmt).await?
            }
            AgentAction::Scopes { id, set, add, remove } => {
                // Scope management requires SCOPE_PERMISSIONS feature
                if set.is_some() || add.is_some() || remove.is_some() {
                    license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::SCOPE_PERMISSIONS)?;
                }
                commands::agent::scopes(
                    &state,
                    id,
                    set.as_deref(),
                    add.as_deref(),
                    remove.as_deref(),
                )
                .await?
            }
            AgentAction::Graph { agent } => {
                commands::agent::delegation_graph(&state, org_id, agent, fmt).await?
            }
            AgentAction::Link { parent, child, tools, max_depth } => {
                license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::A2A_DELEGATION)?;
                commands::agent::delegation_link(&state, org_id, parent, child, tools.as_deref(), max_depth).await?
            }
            AgentAction::Unlink { parent, child } => {
                license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::A2A_DELEGATION)?;
                commands::agent::delegation_unlink(&state, org_id, parent, child).await?
            }
            AgentAction::Approve { parent, child } => {
                license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::A2A_DELEGATION)?;
                commands::agent::delegation_approve(&state, org_id, parent, child).await?
            }
            AgentAction::LockGraph => {
                license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::A2A_DELEGATION)?;
                commands::agent::delegation_lock_graph(&state, org_id).await?
            }
            AgentAction::UnlockGraph => {
                license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::A2A_DELEGATION)?;
                commands::agent::delegation_unlock_graph(&state, org_id).await?
            }
        },

        // ── Kill ──
        Commands::Kill { action } => match action {
            KillAction::Agent { id, reason } => {
                commands::kill::kill_agent(&state, id, reason.as_deref()).await?
            }
            KillAction::All { reason } => {
                commands::kill::kill_all(&state, org_id, reason.as_deref()).await?
            }
            KillAction::List => commands::kill::list(&state, org_id).await?,
            KillAction::Status { id } => commands::kill::status(&state, id).await?,
        },

        // ── License ──
        Commands::License { action } => match action {
            LicenseAction::Status => commands::license::status(&state, org_id, fmt).await?,
            LicenseAction::List => commands::license::list(&state, org_id, fmt).await?,
        },

        // ── Config ──
        Commands::Config { action } => match action {
            ConfigAction::Init => commands::config_cmd::init().await?,
            ConfigAction::Show => commands::config_cmd::show(&state).await?,
        },

        // ── Context ──
        Commands::Context { action } => match action {
            ContextAction::List => commands::context::list(&state.config, fmt).await?,
            ContextAction::Current => commands::context::current(&state.config).await?,
            ContextAction::Use { name } => commands::context::use_ctx(&name).await?,
            ContextAction::Add { name, endpoint, ctx_org_id, ctx_api_token, transport } => {
                commands::context::add(&name, &endpoint, ctx_org_id.as_deref(), ctx_api_token.as_deref(), &transport).await?
            }
            ContextAction::Remove { name } => commands::context::remove(&name).await?,
            ContextAction::Set { name, field, value } => {
                commands::context::set(&name, &field, &value).await?
            }
        },

        // ── Policy ──
        Commands::Policy { action } => match action {
            PolicyAction::List => commands::policy::list(&state, org_id, fmt).await?,
            PolicyAction::Create {
                name,
                description,
                mode,
                source,
            } => {
                commands::policy::create(
                    &state,
                    org_id,
                    &name,
                    description.as_deref(),
                    &mode,
                    &source,
                )
                .await?
            }
            PolicyAction::Delete { id } => commands::policy::delete(&state, id).await?,
            PolicyAction::Rules => commands::policy::rules(&state, org_id, fmt).await?,
            PolicyAction::Import { from, file } => {
                commands::policy::import_rules(&state, org_id, &from, &file).await?
            }
        },

        // ── Keyword ──
        Commands::Keyword { action } => match action {
            KeywordAction::List => commands::keyword::list(&state, org_id, fmt).await?,
            KeywordAction::Add {
                keyword,
                category,
                weight,
                lang,
            } => {
                commands::keyword::add(&state, org_id, &keyword, &category, weight, &lang).await?
            }
            KeywordAction::Remove { id } => {
                commands::keyword::remove(&state, org_id, id).await?
            }
            KeywordAction::ImportCsv { file } => {
                commands::keyword::import_csv(&state, org_id, &file).await?
            }
            KeywordAction::ImportPack { file } => {
                commands::keyword::import_rulepack(&state, org_id, &file).await?
            }
        },

        // ── Org ──
        Commands::Org { action } => match action {
            OrgAction::List => commands::org::list(&state, fmt).await?,
            OrgAction::Create {
                name,
                slug,
                billing_email,
            } => commands::org::create(&state, &name, &slug, &billing_email).await?,
            OrgAction::Update {
                id,
                name,
                billing_email,
            } => commands::org::update(&state, id, &name, &billing_email).await?,
            OrgAction::Delete { id } => commands::org::delete(&state, id).await?,
            OrgAction::Members => {
                license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::RBAC)?;
                commands::org::members(&state, org_id, fmt).await?
            }
        },

        // ── Token ──
        Commands::Token { action } => match action {
            TokenAction::Exchange { agent_id, scopes } => {
                commands::token::exchange(&state, agent_id, scopes.as_deref()).await?
            }
            TokenAction::Introspect { token } => {
                commands::token::introspect(&state, &token).await?
            }
            TokenAction::Revoke { agent_id } => {
                commands::token::revoke(&state, agent_id).await?
            }
        },

        // ── Audit ──
        Commands::Audit { action } => match action {
            AuditAction::List {
                agent,
                action,
                limit,
            } => {
                commands::audit::list(&state, agent, action.as_deref(), limit, fmt).await?
            }
            AuditAction::Export {
                format,
                output,
                limit,
            } => {
                commands::audit::export(&state, &format, output.as_deref(), limit).await?
            }
        },

        // ── Risk ──
        Commands::Risk { action } => match action {
            RiskAction::Scores => commands::risk::scores(&state).await?,
            RiskAction::History { agent_id } => {
                commands::risk::history(&state, agent_id).await?
            }
        },

        // ── Webhook (enterprise: WEBHOOKS) ──
        Commands::Webhook { action } => {
            license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::WEBHOOKS)?;
            match action {
                WebhookAction::List => commands::webhook::list(&state, org_id, fmt).await?,
                WebhookAction::Create { url, events } => {
                    commands::webhook::create(&state, org_id, &url, &events).await?
                }
                WebhookAction::Delete { id } => commands::webhook::delete(&state, id).await?,
            }
        },

        // ── API Key ──
        Commands::Apikey { action } => match action {
            ApikeyAction::List => commands::apikey::list(&state, org_id, fmt).await?,
            ApikeyAction::Create { name } => {
                commands::apikey::create(&state, org_id, name.as_deref()).await?
            }
            ApikeyAction::Revoke { id } => commands::apikey::revoke(&state, id).await?,
        },

        // ── Watch (TUI) ──
        #[cfg(feature = "tui")]
        Commands::Watch { agent } => {
            let plan_line = license_guard.as_ref().map(|g| license_gate::plan_info_line(g));
            // license_guard is always Some for operational commands (Watch requires license)
            commands::watch::run(&state, agent, plan_line.as_deref()).await?
        },

        // ── Demo (TUI) ──
        #[cfg(feature = "tui")]
        Commands::Demo { scenario } => commands::demo::run(&state, &scenario).await?,

        // ── Compliance (enterprise: COMPLIANCE_EXPORT) ──
        Commands::Compliance { action } => {
            license_gate::require_feature(license_guard.as_ref().unwrap(), ag_license::FeatureFlags::COMPLIANCE_EXPORT)?;
            match action {
                ComplianceAction::Run { framework } => {
                    commands::compliance::run(&state, &framework).await?
                }
                ComplianceAction::Report { framework, output } => {
                    commands::compliance::report(&state, &framework, output.as_deref()).await?
                }
            }
        },

        // ── Test (Red Team) ──
        Commands::Test {
            gateway,
            attacks,
            test_format,
            verbose,
            watch,
            interval,
            exit_on_fail,
        } => {
            let gw_url = gateway
                .unwrap_or_else(|| state.config.services.gateway_url.clone());
            let categories: Vec<String> = attacks
                .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            if watch {
                let dur = commands::test_suite::parse_duration(&interval)?;
                loop {
                    let has_failures = commands::test_suite::run_test_suite(
                        &state,
                        &gw_url,
                        &categories,
                        &test_format,
                        verbose,
                    )
                    .await?;
                    if exit_on_fail && has_failures {
                        std::process::exit(1);
                    }
                    eprintln!("  Next run in {}. Press Ctrl+C to stop.", interval);
                    tokio::time::sleep(dur).await;
                }
            } else {
                let has_failures = commands::test_suite::run_test_suite(
                    &state,
                    &gw_url,
                    &categories,
                    &test_format,
                    verbose,
                )
                .await?;
                if exit_on_fail && has_failures {
                    std::process::exit(1);
                }
            }
        }

        // ── Activate ──
        Commands::Activate { license } => {
            let claims = decode_license_claims(&license)
                .ok_or_else(|| anyhow::anyhow!("Invalid license token - could not decode JWT"))?;

            let org_id_str = claims.get("org_id")
                .or(claims.get("sub"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("License missing org_id claim"))?;
            let org_id: Uuid = org_id_str.parse()
                .map_err(|_| anyhow::anyhow!("Invalid org_id in license: {org_id_str}"))?;
            let tier = claims.get("tier").and_then(|v| v.as_str()).unwrap_or("design_partner");
            let limits = claims.get("limits");
            let max_agents = limits.and_then(|l| l.get("max_agents")).and_then(|v| v.as_i64()).unwrap_or(5) as i32;
            let max_api_keys = limits.and_then(|l| l.get("max_api_keys")).and_then(|v| v.as_i64()).unwrap_or(1) as i32;
            let max_rpm = limits.and_then(|l| l.get("max_requests_per_month")).and_then(|v| v.as_i64()).unwrap_or(100_000);
            let features: Vec<String> = claims.get("features")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let grace_hours = claims.get("grace_period_hours").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

            println!("License decoded:");
            println!("  Org:      {org_id}");
            println!("  Tier:     {tier}");
            println!("  Agents:   {max_agents}");
            println!("  API Keys: {max_api_keys}");
            println!("  Requests: {max_rpm}/month");
            println!("  Features: {}", if features.is_empty() { "community".to_string() } else { features.join(", ") });
            println!("  Grace:    {grace_hours}h");

            // Save to active context in config file
            let mut cfg = CliConfig::load().unwrap_or_default();
            if let Some(ctx) = cfg.active_context_mut() {
                ctx.license_token = license;
                ctx.org_id = org_id.to_string();
            }
            let config_path = cfg.save()?;

            println!("\nActivated! Config saved to {}", config_path.display());
            println!("Context '{}': org set to {org_id}.", cfg.current_context);
        },
    }

    Ok(())
}
