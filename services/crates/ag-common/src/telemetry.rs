//! Unified telemetry initialization for all Clampd services.
//!
//! Provides a single `init_telemetry(service_name)` function that sets up:
//! - tracing-subscriber with JSON format and env filter
//! - Service name propagation
//! - W3C Trace Context propagation helpers for gRPC metadata
//!
//! All services call this once in main() instead of duplicating
//! tracing-subscriber setup.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the telemetry stack for a service.
///
/// Sets up:
/// 1. tracing-subscriber with JSON format (for structured logging)
/// 2. Environment-based log level filter (RUST_LOG env var)
/// 3. Service name in log output
///
/// Call this once at the start of main() before any other initialization.
///
/// # Example
/// ```ignore
/// ag_common::telemetry::init_telemetry("ag-gateway");
/// ```
pub fn init_telemetry(service_name: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_current_span(true)
        .flatten_event(true)
        .init();

    tracing::info!(service = service_name, "Telemetry initialized");
}

/// W3C Trace Context header name.
pub const TRACEPARENT_HEADER: &str = "traceparent";

/// Generate a new trace ID (128-bit hex string).
pub fn new_trace_id() -> String {
    let id = uuid::Uuid::new_v4();
    id.as_simple().to_string()
}

/// Extract trace_id from a W3C traceparent header value.
///
/// Format: `{version}-{trace_id}-{parent_id}-{trace_flags}`
/// Example: `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`
pub fn extract_trace_id(traceparent: &str) -> Option<String> {
    let parts: Vec<&str> = traceparent.split('-').collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Build a W3C traceparent header value from a trace ID.
///
/// Uses version 00, generates a random parent_id, trace_flags=01 (sampled).
pub fn build_traceparent(trace_id: &str) -> String {
    let parent_id = &uuid::Uuid::new_v4().as_simple().to_string()[..16];
    format!("00-{}-{}-01", trace_id, parent_id)
}

/// Extract trace_id from gRPC metadata (tonic::Request).
///
/// Checks for the W3C `traceparent` metadata key.
/// Falls back to generating a new trace ID if not present.
pub fn trace_id_from_grpc_metadata(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get(TRACEPARENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|tp| extract_trace_id(tp))
        .unwrap_or_else(new_trace_id)
}

/// Inject trace_id into gRPC metadata for outbound calls.
pub fn inject_trace_id(metadata: &mut tonic::metadata::MetadataMap, trace_id: &str) {
    let traceparent = build_traceparent(trace_id);
    if let Ok(value) = traceparent.parse() {
        metadata.insert(TRACEPARENT_HEADER, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_trace_id() {
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let trace_id = extract_trace_id(traceparent);
        assert_eq!(
            trace_id,
            Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
        );
    }

    #[test]
    fn test_extract_trace_id_invalid() {
        assert_eq!(extract_trace_id("invalid"), None);
    }

    #[test]
    fn test_new_trace_id_format() {
        let trace_id = new_trace_id();
        assert_eq!(trace_id.len(), 32); // 128-bit hex = 32 chars
    }

    #[test]
    fn test_build_traceparent_format() {
        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let traceparent = build_traceparent(trace_id);
        assert!(traceparent.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(traceparent.ends_with("-01"));
        // Total: "00-" + 32 + "-" + 16 + "-01"
        let parts: Vec<&str> = traceparent.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1], trace_id);
        assert_eq!(parts[3], "01");
    }

    #[test]
    fn test_roundtrip_trace_id() {
        let original = new_trace_id();
        let traceparent = build_traceparent(&original);
        let extracted = extract_trace_id(&traceparent).unwrap();
        assert_eq!(original, extracted);
    }
}
