//! OpenMLS WASM Bindings
//!
//! Production-ready WebAssembly bindings for OpenMLS, designed for integration
//! with the Ermis chat system.
//!
//! ## Quick Start
//!
//! ```javascript
//! import init, { Provider, Identity, Group } from 'openmls-wasm';
//!
//! await init();
//! const provider = new Provider();
//!
//! // Create identity
//! const identity = new Identity(provider, "user_abc123");
//!
//! // Create E2EE channel
//! const group = Group.create_with_cid(provider, identity, "team:channel_xyz");
//!
//! // Send encrypted message
//! const ciphertext = group.create_message(provider, identity, plaintext);
//! ```
//!
//! ## Module Organization
//!
//! - `identity`: User identity and key package management
//! - `group`: MLS group operations (create, join, proposals, commits, messaging)
//! - `errors`: Error types for WASM binding
//! - `types`: Shared types (RatchetTree, etc.)

pub mod errors;
pub mod group;
pub mod identity;
pub mod types;
mod utils;

// Re-exports for convenience
pub use errors::*;
pub use group::*;
pub use identity::*;
pub use types::*;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// The ciphersuite used for all operations. Fixed to reduce binary size.
pub(crate) static CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Crypto provider for MLS operations
#[wasm_bindgen]
#[derive(Default)]
pub struct Provider(pub(crate) OpenMlsRustCrypto);

impl AsRef<OpenMlsRustCrypto> for Provider {
    fn as_ref(&self) -> &OpenMlsRustCrypto {
        &self.0
    }
}

impl AsMut<OpenMlsRustCrypto> for Provider {
    fn as_mut(&mut self) -> &mut OpenMlsRustCrypto {
        &mut self.0
    }
}

#[wasm_bindgen]
impl Provider {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Initialize the WASM module
///
/// Call this once at startup to set up panic hooks for better error messages.
#[wasm_bindgen]
pub fn init() {
    utils::set_panic_hook();
}

/// Test function to verify the module is working
#[wasm_bindgen]
pub fn greet() {
    alert("Hello from OpenMLS WASM!");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        v.as_string().unwrap_or_else(|| "Unknown error".to_string())
    }

    fn create_group_alice_and_bob() -> (Provider, Identity, Group, Provider, Identity, Group) {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice")
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::new(&bob_provider, "bob")
            .map_err(js_error_to_string)
            .unwrap();

        let mut chess_club_alice =
            Group::create_with_cid(&alice_provider, &alice, "team:chess_club")
                .map_err(js_error_to_string)
                .unwrap();

        let bob_key_pkg = bob.key_package(&bob_provider);

        let add_result = chess_club_alice
            .add_members(&alice_provider, &alice, vec![bob_key_pkg])
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&mut alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();
        let welcome = add_result.welcome().expect("Should have welcome");

        let chess_club_bob = Group::join_with_welcome(&bob_provider, &welcome, Some(ratchet_tree))
            .map_err(js_error_to_string)
            .unwrap();

        (
            alice_provider,
            alice,
            chess_club_alice,
            bob_provider,
            bob,
            chess_club_bob,
        )
    }

    #[test]
    fn test_cid_roundtrip() {
        let provider = Provider::new();
        let alice = Identity::new(&provider, "alice").unwrap();
        let cid = "team:my_channel_123";
        let group = Group::create_with_cid(&provider, &alice, cid).unwrap();

        assert_eq!(group.cid().unwrap(), cid);
    }

    #[test]
    fn test_group_creation_and_join() {
        let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
            create_group_alice_and_bob();

        // Both should have same key
        let bob_key = chess_club_bob
            .export_key(&bob_provider, "test_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let alice_key = chess_club_alice
            .export_key(&alice_provider, "test_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_key, alice_key);
    }

    #[test]
    fn test_encrypted_messaging() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let plaintext = b"Hello, Bob!";
        let ciphertext = chess_club_alice
            .create_message(&alice_provider, &alice, plaintext)
            .map_err(js_error_to_string)
            .unwrap();

        let processed = chess_club_bob
            .process_message(&mut bob_provider, &ciphertext)
            .map_err(js_error_to_string)
            .unwrap();

        assert!(processed.is_application_message());
        assert_eq!(processed.content().unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_proposal_commit_separation() {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();
        let charlie_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice").unwrap();
        let bob = Identity::new(&bob_provider, "bob").unwrap();
        let charlie = Identity::new(&charlie_provider, "charlie").unwrap();

        let mut group = Group::create_with_cid(&alice_provider, &alice, "team:test").unwrap();

        // Propose add both bob and charlie
        let bob_kp = bob.key_package(&bob_provider);
        let charlie_kp = charlie.key_package(&charlie_provider);

        let _prop1 = group
            .propose_add_member(&alice_provider, &alice, &bob_kp)
            .unwrap();
        let _prop2 = group
            .propose_add_member(&alice_provider, &alice, &charlie_kp)
            .unwrap();

        assert_eq!(group.pending_proposals_count(), 2);

        // Single commit for both
        let commit_bundle = group
            .commit_pending_proposals(&alice_provider, &alice)
            .unwrap();
        assert!(commit_bundle.has_welcome());

        group.merge_pending_commit(&mut alice_provider).unwrap();

        // Verify both are members
        let members = group.members();
        assert_eq!(members.len(), 3); // alice, bob, charlie
    }

    #[test]
    fn test_member_info() {
        let (_, _, chess_club_alice, _, _, _) = create_group_alice_and_bob();

        let members = chess_club_alice.members();
        assert_eq!(members.len(), 2);

        // Check we can find alice
        let alice_member = chess_club_alice.member_by_user_id("alice");
        assert!(alice_member.is_some());
        assert_eq!(alice_member.unwrap().user_id(), "alice");

        // Check we can find bob
        let bob_member = chess_club_alice.member_by_user_id("bob");
        assert!(bob_member.is_some());
        assert_eq!(bob_member.unwrap().user_id(), "bob");
    }

    #[test]
    fn test_identity_serialization() {
        let provider = Provider::new();
        let alice = Identity::new(&provider, "alice_user_123").unwrap();

        let bytes = alice.to_bytes().unwrap();
        let restored = Identity::from_bytes(&provider, &bytes).unwrap();

        assert_eq!(restored.user_id(), "alice_user_123");
    }
}
