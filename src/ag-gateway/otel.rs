//! OpenTelemetry distributed tracing setup for ag-gateway.
//!
//! Configures an OTLP exporter (gRPC/tonic) that sends spans to a collector
//! such as Jaeger.  The endpoint is read from `OTEL_EXPORTER_OTLP_ENDPOINT`
//! (default: `http://localhost:4317`).
//!
//! Usage:
//! ```ignore
//! let _provider = otel::init_tracer("ag-gateway")?;
//! // ... run server ...
//! otel::shutdown_tracer();
//! ```

use anyhow::Result;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    resource::Resource,
    trace::{self as sdktrace, TracerProvider},
};
use std::sync::OnceLock;
use tracing::info;

/// Global handle so we can flush/shutdown on exit.
static PROVIDER: OnceLock<TracerProvider> = OnceLock::new();

/// Default OTLP gRPC endpoint used when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset.
const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4317";

/// Read the OTLP endpoint from the environment.
pub fn otlp_endpoint() -> String {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_else(|_| DEFAULT_OTLP_ENDPOINT.to_string())
}

/// Initialise the OpenTelemetry tracer pipeline and install a
/// `tracing-opentelemetry` layer into the global subscriber.
///
/// Returns `Ok(())` on success.  The [`TracerProvider`] is stored in a
/// module-level [`OnceLock`] so that [`shutdown_tracer`] can flush it later.
pub fn init_tracer(service_name: &str) -> Result<()> {
    let endpoint = otlp_endpoint();

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(&endpoint);

    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
    ]);

    let trace_config = sdktrace::Config::default().with_resource(resource);

    let provider = TracerProvider::builder()
        .with_batch_exporter(
            exporter.build_span_exporter()?,
            opentelemetry_sdk::runtime::Tokio,
        )
        .with_config(trace_config)
        .build();

    // Register as the global tracer provider.
    let tracer = provider.tracer(service_name.to_string());

    // Store the provider so we can shut it down later.
    let _ = PROVIDER.set(provider);

    // Build a tracing-opentelemetry layer and attach it as a global subscriber
    // alongside the existing fmt layer.
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_target(true);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    info!(
        otel.endpoint = %endpoint,
        service.name = service_name,
        "OpenTelemetry tracer initialized"
    );

    Ok(())
}

/// Gracefully shut down the tracer provider, flushing any pending spans.
///
/// Safe to call even if [`init_tracer`] was never called (no-op in that case).
pub fn shutdown_tracer() {
    if let Some(provider) = PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            tracing::warn!(error = %e, "OpenTelemetry tracer shutdown returned an error");
        } else {
            info!("OpenTelemetry tracer shut down cleanly");
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: create manual tracing spans with standard attributes.
// These are used by proxy/scan handlers to instrument key operations.
// ---------------------------------------------------------------------------

/// Create a `tracing::Span` for a proxy request.
pub fn proxy_request_span(tool_name: &str, agent_id: &str) -> tracing::Span {
    tracing::info_span!(
        "proxy_request",
        otel.kind = "server",
        tool_name = %tool_name,
        agent_id = %agent_id,
        risk_score = tracing::field::Empty,
    )
}

/// Create a `tracing::Span` for the classify_intent gRPC call.
pub fn classify_intent_span(tool_name: &str, agent_id: &str) -> tracing::Span {
    tracing::info_span!(
        "classify_intent",
        otel.kind = "client",
        rpc.system = "grpc",
        rpc.service = "IntentService",
        rpc.method = "ClassifyIntent",
        tool_name = %tool_name,
        agent_id = %agent_id,
    )
}

/// Create a `tracing::Span` for the evaluate_policy gRPC call.
pub fn evaluate_policy_span(tool_name: &str, agent_id: &str) -> tracing::Span {
    tracing::info_span!(
        "evaluate_policy",
        otel.kind = "client",
        rpc.system = "grpc",
        rpc.service = "PolicyService",
        rpc.method = "Evaluate",
        tool_name = %tool_name,
        agent_id = %agent_id,
    )
}

/// Create a `tracing::Span` for a Redis lookup.
pub fn redis_lookup_span(operation: &str) -> tracing::Span {
    tracing::info_span!(
        "redis_lookup",
        otel.kind = "client",
        db.system = "redis",
        db.operation = %operation,
    )
}

/// Create a `tracing::Span` for scan-input.
pub fn scan_input_span(agent_id: &str) -> tracing::Span {
    tracing::info_span!(
        "scan_input",
        otel.kind = "server",
        agent_id = %agent_id,
    )
}

/// Create a `tracing::Span` for scan-output.
pub fn scan_output_span(agent_id: &str) -> tracing::Span {
    tracing::info_span!(
        "scan_output",
        otel.kind = "server",
        agent_id = %agent_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otlp_endpoint_default() {
        // Clear the env var to test default behavior.
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        assert_eq!(otlp_endpoint(), DEFAULT_OTLP_ENDPOINT);
    }

    #[test]
    fn test_otlp_endpoint_from_env() {
        let custom = "http://collector.example.com:4317";
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", custom);
        assert_eq!(otlp_endpoint(), custom);
        // Clean up to avoid affecting other tests.
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_shutdown_tracer_no_panic_without_init() {
        // Calling shutdown before init should be a no-op, not a panic.
        shutdown_tracer();
    }

    #[test]
    fn test_proxy_request_span_fields() {
        let span = proxy_request_span("db.query", "agent-123");
        // Just verify the span was created without panic.
        let _guard = span.enter();
    }

    #[test]
    fn test_classify_intent_span_fields() {
        let span = classify_intent_span("fs.read", "agent-456");
        let _guard = span.enter();
    }

    #[test]
    fn test_evaluate_policy_span_fields() {
        let span = evaluate_policy_span("net.send", "agent-789");
        let _guard = span.enter();
    }

    #[test]
    fn test_redis_lookup_span_fields() {
        let span = redis_lookup_span("GET");
        let _guard = span.enter();
    }

    #[test]
    fn test_scan_input_span_fields() {
        let span = scan_input_span("agent-scan");
        let _guard = span.enter();
    }

    #[test]
    fn test_scan_output_span_fields() {
        let span = scan_output_span("agent-scan");
        let _guard = span.enter();
    }
}
