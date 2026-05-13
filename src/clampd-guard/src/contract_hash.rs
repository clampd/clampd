//! Re-export of the canonical contract-hash implementation.
//!
//! The implementation moved to `ag_common::contract_hash` so the gateway's
//! `/v1/register` handler can reuse the byte-identical hashing logic
//! without taking a dependency on this CLI crate. Existing callers that
//! `use clampd_guard::contract_hash::contract_hash` continue to work via
//! this re-export.

pub use ag_common::contract_hash::contract_hash;
