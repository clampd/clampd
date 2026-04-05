use anyhow::{Context, Result};
use std::sync::OnceLock;

use ag_proto::agentguard::control::control_service_client::ControlServiceClient;
use ag_proto::agentguard::risk::risk_service_client::RiskServiceClient;
use tonic::transport::Channel;

use crate::config::CliConfig;
use crate::http_client::ApiClient;

/// Application state with lazy-initialized connections.
/// Only connects to services the current command actually needs.
///
/// The primary path uses the Dashboard API via `api_client()`,
/// connecting to the active context's endpoint.
/// Direct gRPC connections are kept for risk analytics
/// and as fallback for local development.
pub struct AppState {
    pub config: CliConfig,
    api: OnceLock<ApiClient>,
    clickhouse: OnceLock<clickhouse::Client>,
}

impl AppState {
    pub fn new(config: CliConfig) -> Self {
        Self {
            config,
            api: OnceLock::new(),
            clickhouse: OnceLock::new(),
        }
    }

    /// Get the HTTP API client for communicating with the control plane.
    /// Uses the active context's endpoint and credentials.
    pub fn api_client(&self) -> &ApiClient {
        self.api.get_or_init(|| {
            let endpoint = self.config.dashboard_url();
            let org_id = self.config.org_id();
            let mut client = ApiClient::new(endpoint, org_id);
            let token = self.config.api_token();
            if !token.is_empty() {
                client = client.with_token(token);
            }
            client
        })
    }

    /// Set the org_id on the API client after initialization (e.g. after
    /// resolve_org_id determines the correct org).
    /// Note: OnceLock prevents mutation after init; commands pass org_id
    /// directly in path construction instead.
    pub fn set_api_org_id(&self, _org_id: &str) {
        // No-op - commands use org_id from resolve_org_id() when building paths.
    }

    // ── Direct service connections (analytics, fallback) ─────

    pub async fn clickhouse(&self) -> Result<&clickhouse::Client> {
        if let Some(client) = self.clickhouse.get() {
            return Ok(client);
        }
        let client = clickhouse::Client::default()
            .with_url(&self.config.services.clickhouse_url);
        Ok(self.clickhouse.get_or_init(|| client))
    }

    pub async fn risk_client(&self) -> Result<RiskServiceClient<Channel>> {
        let channel = Channel::from_shared(self.config.services.risk_url.clone())
            .context("Invalid risk service URL")?
            .connect()
            .await
            .context("Failed to connect to risk service")?;
        Ok(RiskServiceClient::new(channel))
    }

    pub async fn control_client(&self) -> Result<ControlServiceClient<Channel>> {
        let channel = Channel::from_shared(self.config.services.control_url.clone())
            .context("Invalid control service URL")?
            .connect()
            .await
            .context("Failed to connect to control service")?;
        Ok(ControlServiceClient::new(channel))
    }
}
