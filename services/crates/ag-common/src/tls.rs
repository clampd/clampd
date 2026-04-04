//! Optional TLS configuration for gRPC servers and clients.
//!
//! Set these env vars to enable TLS:
//! - `AG_GRPC_TLS_CERT`: Path to PEM certificate file (server)
//! - `AG_GRPC_TLS_KEY`: Path to PEM private key file (server)
//! - `AG_GRPC_TLS_CA`: Path to CA certificate for client verification (client)

use std::fs;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
use tracing::info;

/// Build server TLS config from env vars. Returns `None` if not configured.
pub fn server_tls_config() -> Option<ServerTlsConfig> {
    let cert_path = std::env::var("AG_GRPC_TLS_CERT").ok()?;
    let key_path = std::env::var("AG_GRPC_TLS_KEY").ok()?;

    let cert = fs::read_to_string(&cert_path)
        .unwrap_or_else(|e| panic!("Failed to read TLS cert {}: {}", cert_path, e));
    let key = fs::read_to_string(&key_path)
        .unwrap_or_else(|e| panic!("Failed to read TLS key {}: {}", key_path, e));

    let identity = Identity::from_pem(cert, key);
    let mut tls = ServerTlsConfig::new().identity(identity);

    // Optional: mutual TLS (client certificate verification)
    if let Ok(ca_path) = std::env::var("AG_GRPC_TLS_CA") {
        let ca = fs::read_to_string(&ca_path)
            .unwrap_or_else(|e| panic!("Failed to read CA cert {}: {}", ca_path, e));
        tls = tls.client_ca_root(Certificate::from_pem(ca));
        info!("gRPC server TLS enabled with mTLS (client cert required)");
    } else {
        info!("gRPC server TLS enabled (no client cert required)");
    }

    Some(tls)
}

/// Build client TLS config from env vars. Returns `None` if not configured.
pub fn client_tls_config() -> Option<ClientTlsConfig> {
    let ca_path = std::env::var("AG_GRPC_TLS_CA").ok()?;

    let ca = fs::read_to_string(&ca_path)
        .unwrap_or_else(|e| panic!("Failed to read CA cert {}: {}", ca_path, e));

    let mut tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));

    // Optional: client identity for mTLS
    if let Ok(cert_path) = std::env::var("AG_GRPC_TLS_CERT") {
        if let Ok(key_path) = std::env::var("AG_GRPC_TLS_KEY") {
            let cert = fs::read_to_string(&cert_path)
                .unwrap_or_else(|e| panic!("Failed to read TLS cert {}: {}", cert_path, e));
            let key = fs::read_to_string(&key_path)
                .unwrap_or_else(|e| panic!("Failed to read TLS key {}: {}", key_path, e));
            tls = tls.identity(Identity::from_pem(cert, key));
            info!("gRPC client TLS enabled with mTLS (client cert provided)");
        }
    } else {
        info!("gRPC client TLS enabled (server cert verification only)");
    }

    Some(tls)
}
