//! Shadow event publishing - shared between proxy.rs and scan.rs.
//!
//! Publishes ShadowEvent payloads to NATS for ag-shadow and ag-risk consumption.
//! Falls back to WAL (write-ahead log) when NATS is unavailable.
//!
//! Callers construct a `ShadowEvent` using struct update syntax:
//! ```ignore
//! ShadowEvent { field: val, ..ShadowEvent::default() }
//! ```

use crate::AppState;

/// Publish a shadow event to NATS (fire-and-forget), with WAL fallback.
///
/// Callers construct `ShadowEvent` directly using struct update syntax
/// against `ShadowEvent::default()` - no intermediate param structs needed.
pub async fn publish_event(state: &AppState, event: &ag_common::models::ShadowEvent) {
    publish_to_nats(state, event).await;
}

/// Internal: serialize and publish a ShadowEvent to NATS with WAL fallback.
async fn publish_to_nats(state: &AppState, event: &ag_common::models::ShadowEvent) {
    match serde_json::to_vec(event) {
        Ok(payload) => {
            let nats_payload: bytes::Bytes = payload.clone().into();
            if let Err(e) = state
                .nats
                .publish("agentguard.events", nats_payload)
                .await
            {
                tracing::warn!("Failed to publish shadow event to NATS: {} - writing to WAL", e);
                if let Some(ref wal) = state.wal {
                    let wal_result = wal.append(&payload).await;
                    if wal_result != crate::wal_file::WalAppendResult::Ok {
                        tracing::error!("WAL write also failed: {:?} - shadow event lost", wal_result);
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to serialize shadow event: {}", e);
        }
    }
}
