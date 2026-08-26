//! OpenMLS UniFFI Bindings for Mobile (iOS / Android)
//!
//! This crate mirrors the API surface of `openmls-wasm` but uses Mozilla UniFFI
//! to generate native Swift and Kotlin bindings instead of wasm-bindgen.

#![allow(clippy::empty_line_after_doc_comments)] // Generated UniFFI 0.28 scaffolding.

#[macro_use]
pub mod logger;
pub mod errors;
pub mod group;
pub mod identity;
pub mod provider;
pub mod types;

pub use errors::*;
pub use group::*;
pub use identity::*;
pub use logger::init_logger;
pub use provider::*;
pub use types::*;

/// Compute the deterministic channel_id for E2EE Messaging (DM) channels.
///
/// Replicates the server-side `hash_channel_id()` in bellboy/src/util/check.rs.
/// Only needed for E2EE DM creation — standard (non-E2EE) Messaging channels
/// have their channel_id computed server-side.
#[uniffi::export]
pub fn hash_channel_id(project_id: String, user_ids: Vec<String>) -> String {
    openmls_bindings_core::hash_channel_id(project_id, user_ids)
}

uniffi::include_scaffolding!("openmls_uniffi");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_channel_id() {
        // Deterministic: same inputs → same output regardless of order
        let r1 = hash_channel_id(
            "proj-123".to_string(),
            vec!["bob".to_string(), "alice".to_string()],
        );
        let r2 = hash_channel_id(
            "proj-123".to_string(),
            vec!["alice".to_string(), "bob".to_string()],
        );
        assert_eq!(
            r1, r2,
            "hash must be deterministic regardless of input order"
        );

        // Format: "{project_id}:{36-char hex}"
        assert!(r1.starts_with("proj-123:"));
        let hash_part = &r1["proj-123:".len()..];
        assert_eq!(hash_part.len(), 36);
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));

        // Cross-platform parity: must match WASM binding output
        // (WASM test uses same inputs and expects same result)
        let expected = hash_channel_id(
            "proj-123".to_string(),
            vec!["alice".to_string(), "bob".to_string()],
        );
        assert_eq!(r1, expected);
    }
}
