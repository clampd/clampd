//! Tonic interceptors for service-to-service HMAC authentication.
//!
//! Uses HMAC-SHA256 with a shared secret (`AG_INTERNAL_SECRET` env var)
//! to authenticate internal gRPC calls between AgentGuard services.
//!
//! - **Client side**: `ClientAuthInterceptor` adds `x-ag-internal-hmac` and
//!   `x-ag-internal-timestamp` metadata to every outgoing request.
//! - **Server side**: `server_auth_interceptor` validates the HMAC on incoming
//!   requests, rejecting unauthenticated calls with `Status::unauthenticated`.
//!
//! When `AG_INTERNAL_SECRET` is not set, both sides pass through without
//! authentication (backward compat for dev/test), logging a warning on
//! first use.

use std::sync::OnceLock;
use tonic::{service::Interceptor, Request, Status};
use tracing::{error, warn};

use crate::auth::{generate_internal_hmac, verify_internal_hmac};

/// Cached shared secret - read once from env on first use.
fn shared_secret() -> &'static Option<String> {
    static SECRET: OnceLock<Option<String>> = OnceLock::new();
    SECRET.get_or_init(|| {
        let val = std::env::var("AG_INTERNAL_SECRET").ok().filter(|s| !s.is_empty());
        match &val {
            None => {
                error!("AG_INTERNAL_SECRET is not set - internal gRPC auth DISABLED. \
                       Set it in production: openssl rand -hex 64");
            }
            Some(s) if s.len() < 32 => {
                warn!("AG_INTERNAL_SECRET is shorter than 32 chars - weak internal auth");
            }
            _ => {}
        }
        val
    })
}

// ── Client-side interceptor ──────────────────────────────────────────────

/// A clonable interceptor that signs outgoing gRPC requests with HMAC.
#[derive(Clone, Debug)]
pub struct ClientAuthInterceptor;

impl Interceptor for ClientAuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if let Some(secret) = shared_secret() {
            let (timestamp, hmac) = generate_internal_hmac(secret);
            req.metadata_mut().insert(
                "x-ag-internal-hmac",
                hmac.parse().map_err(|_| Status::internal("invalid hmac header value"))?,
            );
            req.metadata_mut().insert(
                "x-ag-internal-timestamp",
                timestamp.parse().map_err(|_| Status::internal("invalid timestamp header value"))?,
            );
        }
        Ok(req)
    }
}

// ── Server-side interceptor ──────────────────────────────────────────────

/// Maximum allowed clock skew between services (seconds).
/// Requests with timestamps older than this are rejected to prevent replay attacks.
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300; // 5 minutes

/// Server-side interceptor function for validating incoming gRPC requests.
///
/// Use with `tonic::service::interceptor(server_auth_interceptor)` or
/// `InterceptedService::new(svc, server_auth_interceptor)`.
pub fn server_auth_interceptor(req: Request<()>) -> Result<Request<()>, Status> {
    let secret = match shared_secret() {
        Some(s) => s,
        None => {
            // In production (license key present), internal auth is mandatory.
            if std::env::var("CLAMPD_LICENSE_KEY").is_ok() {
                return Err(Status::unauthenticated(
                    "AG_INTERNAL_SECRET is required in production",
                ));
            }
            // In dev (no license), allow unauthenticated for local testing.
            return Ok(req);
        }
    };

    let hmac_val = req
        .metadata()
        .get("x-ag-internal-hmac")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("missing x-ag-internal-hmac header"))?;

    let timestamp = req
        .metadata()
        .get("x-ag-internal-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Status::unauthenticated("missing x-ag-internal-timestamp header"))?;

    // Check timestamp freshness to prevent replay attacks.
    if let Ok(ts) = timestamp.parse::<i64>() {
        let now = chrono::Utc::now().timestamp();
        let skew = (now - ts).abs();
        if skew > MAX_TIMESTAMP_SKEW_SECS {
            return Err(Status::unauthenticated("request timestamp too old or too far in the future"));
        }
    } else {
        return Err(Status::unauthenticated("invalid timestamp format"));
    }

    if !verify_internal_hmac(timestamp, hmac_val, secret) {
        return Err(Status::unauthenticated("invalid internal HMAC"));
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_server_roundtrip() {
        // Set the env var for this test
        std::env::set_var("AG_INTERNAL_SECRET", "test-roundtrip-secret-42");

        // Force re-init by using the functions directly instead of cached OnceLock
        let secret = "test-roundtrip-secret-42";
        let (timestamp, hmac) = generate_internal_hmac(secret);

        // Simulate server validation
        assert!(verify_internal_hmac(&timestamp, &hmac, secret));
    }

    #[test]
    fn test_server_rejects_bad_hmac() {
        let secret = "test-reject-secret";
        let (timestamp, _) = generate_internal_hmac(secret);

        assert!(!verify_internal_hmac(&timestamp, "bad-hmac-value", secret));
    }

    #[test]
    fn test_server_rejects_wrong_secret() {
        let (timestamp, hmac) = generate_internal_hmac("secret-a");
        assert!(!verify_internal_hmac(&timestamp, &hmac, "secret-b"));
    }
}
