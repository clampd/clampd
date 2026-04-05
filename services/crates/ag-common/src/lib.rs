pub mod auth;
pub mod categories;
pub mod scopes;
pub mod tool_names;
pub mod config;
pub mod degradation;
pub mod errors;
pub mod interceptor;
pub mod models;
pub mod tls;

#[cfg(feature = "license")]
pub mod license;

/// Hardware fingerprint for license binding (sha2 + stdlib only).
pub mod fingerprint;

/// License guard - every service validates CLAMPD_LICENSE_KEY on startup.
/// Uses only sha2 + stdlib. No jsonwebtoken/reqwest needed.
pub mod license_guard;

#[cfg(feature = "normalizer")]
pub mod normalizer;

#[cfg(feature = "session")]
pub mod session;

#[cfg(feature = "telemetry")]
pub mod telemetry;
