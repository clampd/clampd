use std::sync::OnceLock;

use crate::config::CliConfig;
use crate::http_client::ApiClient;

/// Application state with lazy-initialized connections.
/// The primary path uses the Dashboard API via `api_client()`,
/// connecting to the active context's endpoint.
pub struct AppState {
    pub config: CliConfig,
    api: OnceLock<ApiClient>,
}

impl AppState {
    pub fn new(config: CliConfig) -> Self {
        Self {
            config,
            api: OnceLock::new(),
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
}
