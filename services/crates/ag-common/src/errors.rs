use thiserror::Error;

/// All errors in ag-common are typed — no anyhow in public API.
#[derive(Debug, Error)]
pub enum AgError {
    #[error("JWT validation failed: {0}")]
    JwtValidation(String),

    #[error("License error: {0}")]
    License(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Agent denied: {0}")]
    AgentDenied(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[cfg(feature = "db")]
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[cfg(feature = "http-client")]
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Normalization error: {0}")]
    Normalization(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Service unavailable: {0}")]
    Unavailable(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AgError {
    /// Map to a gRPC status code.
    pub fn to_tonic_status(&self) -> tonic::Status {
        match self {
            AgError::JwtValidation(msg) => tonic::Status::unauthenticated(msg),
            AgError::AgentNotFound(msg) => tonic::Status::not_found(msg),
            AgError::InvalidStateTransition { .. } => {
                tonic::Status::failed_precondition(self.to_string())
            }
            AgError::AgentDenied(msg) => tonic::Status::permission_denied(msg),
            AgError::PolicyDenied(msg) => tonic::Status::permission_denied(msg),
            AgError::RateLimited(msg) => tonic::Status::resource_exhausted(msg),
            AgError::Unavailable(msg) => tonic::Status::unavailable(msg),
            _ => tonic::Status::internal(self.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── to_tonic_status code mapping ──

    #[test]
    fn test_jwt_validation_maps_to_unauthenticated() {
        let err = AgError::JwtValidation("bad token".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(status.message(), "bad token");
    }

    #[test]
    fn test_agent_not_found_maps_to_not_found() {
        let err = AgError::AgentNotFound("agent-42".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(status.message(), "agent-42");
    }

    #[test]
    fn test_invalid_state_transition_maps_to_failed_precondition() {
        let err = AgError::InvalidStateTransition {
            from: "active".to_string(),
            to: "active".to_string(),
        };
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains("active"));
    }

    #[test]
    fn test_agent_denied_maps_to_permission_denied() {
        let err = AgError::AgentDenied("kill switch active".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(status.message(), "kill switch active");
    }

    #[test]
    fn test_policy_denied_maps_to_permission_denied() {
        let err = AgError::PolicyDenied("scope mismatch".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(status.message(), "scope mismatch");
    }

    #[test]
    fn test_rate_limited_maps_to_resource_exhausted() {
        let err = AgError::RateLimited("60/min exceeded".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
        assert_eq!(status.message(), "60/min exceeded");
    }

    #[test]
    fn test_unavailable_maps_to_unavailable() {
        let err = AgError::Unavailable("registry down".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "registry down");
    }

    #[test]
    fn test_session_error_maps_to_internal() {
        let err = AgError::Session("redis connection lost".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    #[test]
    fn test_normalization_error_maps_to_internal() {
        let err = AgError::Normalization("decode failure".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    #[test]
    fn test_config_error_maps_to_internal() {
        let err = AgError::Config("missing env var".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    #[test]
    fn test_internal_error_maps_to_internal() {
        let err = AgError::Internal("unexpected".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    #[test]
    fn test_license_error_maps_to_internal() {
        let err = AgError::License("expired".to_string());
        let status = err.to_tonic_status();
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    // ── Display formatting ──

    #[test]
    fn test_display_jwt_validation() {
        let err = AgError::JwtValidation("expired".to_string());
        assert_eq!(format!("{}", err), "JWT validation failed: expired");
    }

    #[test]
    fn test_display_agent_not_found() {
        let err = AgError::AgentNotFound("agent-xyz".to_string());
        assert_eq!(format!("{}", err), "Agent not found: agent-xyz");
    }

    #[test]
    fn test_display_invalid_state_transition() {
        let err = AgError::InvalidStateTransition {
            from: "killed".to_string(),
            to: "active".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "Invalid state transition: killed -> active"
        );
    }

    #[test]
    fn test_display_agent_denied() {
        let err = AgError::AgentDenied("reason".to_string());
        assert_eq!(format!("{}", err), "Agent denied: reason");
    }

    #[test]
    fn test_display_policy_denied() {
        let err = AgError::PolicyDenied("no scope".to_string());
        assert_eq!(format!("{}", err), "Policy denied: no scope");
    }

    #[test]
    fn test_display_rate_limited() {
        let err = AgError::RateLimited("too many requests".to_string());
        assert_eq!(format!("{}", err), "Rate limited: too many requests");
    }

    #[test]
    fn test_display_session() {
        let err = AgError::Session("timeout".to_string());
        assert_eq!(format!("{}", err), "Session error: timeout");
    }

    #[test]
    fn test_display_normalization() {
        let err = AgError::Normalization("bad input".to_string());
        assert_eq!(format!("{}", err), "Normalization error: bad input");
    }

    #[test]
    fn test_display_config() {
        let err = AgError::Config("missing key".to_string());
        assert_eq!(format!("{}", err), "Configuration error: missing key");
    }

    #[test]
    fn test_display_unavailable() {
        let err = AgError::Unavailable("service down".to_string());
        assert_eq!(format!("{}", err), "Service unavailable: service down");
    }

    #[test]
    fn test_display_internal() {
        let err = AgError::Internal("panic".to_string());
        assert_eq!(format!("{}", err), "Internal error: panic");
    }

    #[test]
    fn test_display_license() {
        let err = AgError::License("invalid key".to_string());
        assert_eq!(format!("{}", err), "License error: invalid key");
    }

    // ── From impls ──

    #[test]
    fn test_from_serde_json_error() {
        let bad_json = "not json at all {{{";
        let serde_err = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let ag_err: AgError = serde_err.into();
        match ag_err {
            AgError::Serialization(_) => {} // expected
            other => panic!("Expected Serialization, got {:?}", other),
        }
    }
}
