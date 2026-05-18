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
use openmls_traits::OpenMlsProvider;
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

    /// Serialize the key store to bytes for persistence (e.g. IndexedDB)
    ///
    /// Returns the serialized key store as a byte array.
    /// Use `Provider.from_bytes()` to restore.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        let mut buf = Vec::new();
        self.0
            .storage()
            .serialize(&mut buf)
            .map_err(|e| JsError::new(&format!("Failed to serialize Provider: {}", e)))?;
        Ok(buf)
    }

    /// Restore a Provider from previously serialized bytes
    ///
    /// The crypto provider (RNG) is always fresh; only the key store
    /// (private keys, group state, etc.) is restored from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Provider, JsError> {
        let storage =
            openmls_rust_crypto::MemoryStorage::deserialize(&mut std::io::Cursor::new(bytes))
                .map_err(|e| JsError::new(&format!("Failed to deserialize Provider: {}", e)))?;

        Ok(Provider(OpenMlsRustCrypto::new_with_storage(storage)))
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

/// Compute the deterministic channel_id for E2EE Messaging (DM) channels.
///
/// Replicates the server-side `hash_channel_id()` in bellboy/src/util/check.rs.
/// Only needed for E2EE DM creation — standard (non-E2EE) Messaging channels
/// have their channel_id computed server-side.
///
/// Algorithm:
/// 1. Sort user_ids alphabetically
/// 2. Concatenate (no separator)
/// 3. SHA-256 → hex string
/// 4. Truncate to 36 chars
/// 5. Return "{project_id}:{hash36}"
///
/// # Example
/// ```javascript
/// const channelId = hash_channel_id("proj-uuid", ["alice", "bob"]);
/// const cid = `messaging:${channelId}`;
/// const group = Group.create_with_cid(provider, identity, cid);
/// ```
#[wasm_bindgen]
pub fn hash_channel_id(project_id: &str, user_ids: Vec<String>) -> String {
    use sha2::{Digest, Sha256};

    let mut sorted_ids = user_ids;
    sorted_ids.sort();
    let concatenated = sorted_ids.join("");

    let mut hasher = Sha256::new();
    hasher.update(concatenated.as_bytes());
    let hash_hex = hex::encode(hasher.finalize());

    format!("{}:{}", project_id, &hash_hex[..36])
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

    fn create_group_alice_bob_dave() -> (Provider, Identity, Group, Provider, Group) {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();
        let dave_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice").unwrap();
        let bob = Identity::new(&bob_provider, "bob").unwrap();
        let dave = Identity::new(&dave_provider, "dave").unwrap();

        let mut alice_group =
            Group::create_with_cid(&alice_provider, &alice, "team:wrapper_test").unwrap();

        let add_result = alice_group
            .add_members(
                &alice_provider,
                &alice,
                vec![
                    bob.key_package(&bob_provider),
                    dave.key_package(&dave_provider),
                ],
            )
            .unwrap();
        alice_group
            .merge_pending_commit(&mut alice_provider)
            .unwrap();

        let ratchet_tree = alice_group.export_ratchet_tree();
        let welcome = add_result.welcome().expect("Should have welcome");
        let dave_group =
            Group::join_with_welcome(&dave_provider, &welcome, Some(ratchet_tree)).unwrap();

        (
            alice_provider,
            alice,
            alice_group,
            dave_provider,
            dave_group,
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
    fn test_commit_group_changes_processes_without_standalone_proposals() {
        let mut alice_provider = Provider::new();
        let bob_provider = Provider::new();
        let mut dave_provider = Provider::new();
        let charlie_provider = Provider::new();

        let alice = Identity::new(&alice_provider, "alice").unwrap();
        let bob = Identity::new(&bob_provider, "bob").unwrap();
        let dave = Identity::new(&dave_provider, "dave").unwrap();
        let charlie = Identity::new(&charlie_provider, "charlie").unwrap();

        let mut alice_group =
            Group::create_with_cid(&alice_provider, &alice, "team:composite").unwrap();

        let initial_add = alice_group
            .add_members(
                &alice_provider,
                &alice,
                vec![
                    bob.key_package(&bob_provider),
                    dave.key_package(&dave_provider),
                ],
            )
            .unwrap();
        alice_group
            .merge_pending_commit(&mut alice_provider)
            .unwrap();

        let ratchet_tree = alice_group.export_ratchet_tree();
        let welcome = initial_add
            .welcome()
            .expect("initial add should have welcome");
        let mut dave_group =
            Group::join_with_welcome(&dave_provider, &welcome, Some(ratchet_tree)).unwrap();

        let epoch_before = alice_group.epoch();
        let composite = alice_group
            .commit_group_changes(
                &alice_provider,
                &alice,
                vec!["bob".to_string()],
                vec![charlie.key_package(&charlie_provider)],
                false,
            )
            .unwrap();
        assert!(composite.has_welcome());

        // Dave never receives standalone remove/add proposals. Processing only the commit proves
        // the composite commit carries the requested proposals by value.
        dave_group
            .process_message(&mut dave_provider, &composite.commit())
            .map_err(js_error_to_string)
            .unwrap();

        alice_group
            .merge_pending_commit(&mut alice_provider)
            .unwrap();
        assert_eq!(alice_group.epoch(), epoch_before + 1);
        assert!(alice_group.member_by_user_id("bob").is_none());
        assert!(alice_group.member_by_user_id("charlie").is_some());
        assert!(dave_group.member_by_user_id("bob").is_none());
        assert!(dave_group.member_by_user_id("charlie").is_some());
    }

    #[test]
    fn test_commit_member_add_with_removals_wrapper() {
        let (mut alice_provider, alice, mut alice_group, mut dave_provider, mut dave_group) =
            create_group_alice_bob_dave();
        let charlie_provider = Provider::new();
        let charlie = Identity::new(&charlie_provider, "charlie").unwrap();

        let epoch_before = alice_group.epoch();
        let composite = alice_group
            .commit_member_add_with_removals(
                &alice_provider,
                &alice,
                vec!["bob".to_string()],
                vec![charlie.key_package(&charlie_provider)],
            )
            .unwrap();

        assert!(composite.has_welcome());
        dave_group
            .process_message(&mut dave_provider, &composite.commit())
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .merge_pending_commit(&mut alice_provider)
            .unwrap();

        assert_eq!(alice_group.epoch(), epoch_before + 1);
        assert!(alice_group.member_by_user_id("bob").is_none());
        assert!(alice_group.member_by_user_id("charlie").is_some());
        assert!(dave_group.member_by_user_id("bob").is_none());
        assert!(dave_group.member_by_user_id("charlie").is_some());
    }

    #[test]
    fn test_commit_self_update_with_removals_wrapper() {
        let (mut alice_provider, alice, mut alice_group, mut dave_provider, mut dave_group) =
            create_group_alice_bob_dave();

        let epoch_before = alice_group.epoch();
        let composite = alice_group
            .commit_self_update_with_removals(&alice_provider, &alice, vec!["bob".to_string()])
            .unwrap();

        assert!(!composite.has_welcome());
        dave_group
            .process_message(&mut dave_provider, &composite.commit())
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .merge_pending_commit(&mut alice_provider)
            .unwrap();

        assert_eq!(alice_group.epoch(), epoch_before + 1);
        assert!(alice_group.member_by_user_id("bob").is_none());
        assert!(dave_group.member_by_user_id("bob").is_none());
    }

    #[test]
    fn test_commit_member_removals_wrapper() {
        let (mut alice_provider, alice, mut alice_group, mut dave_provider, mut dave_group) =
            create_group_alice_bob_dave();

        let epoch_before = alice_group.epoch();
        let composite = alice_group
            .commit_member_removals(&alice_provider, &alice, vec!["bob".to_string()])
            .unwrap();

        assert!(!composite.has_welcome());
        dave_group
            .process_message(&mut dave_provider, &composite.commit())
            .map_err(js_error_to_string)
            .unwrap();
        alice_group
            .merge_pending_commit(&mut alice_provider)
            .unwrap();

        assert_eq!(alice_group.epoch(), epoch_before + 1);
        assert!(alice_group.member_by_user_id("bob").is_none());
        assert!(dave_group.member_by_user_id("bob").is_none());
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

    #[test]
    fn test_provider_serialization_roundtrip() {
        // Create a provider and generate some state (identity + key package)
        let provider = Provider::new();
        let alice = Identity::new(&provider, "alice").unwrap();
        let _kp = alice.key_package(&provider);

        // Serialize and restore
        let bytes = provider.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        let restored = Provider::from_bytes(&bytes).unwrap();

        // The restored provider should still have Alice's signature key pair
        // which means we can create new key packages with it
        let alice_restored = Identity::from_bytes(&restored, &alice.to_bytes().unwrap()).unwrap();
        assert_eq!(alice_restored.user_id(), "alice");

        // Generate a new key package from restored provider — would panic
        // if the signature key pair wasn't restored
        let _kp2 = alice_restored.key_package(&restored);
    }

    #[test]
    fn test_hash_channel_id() {
        // Deterministic: order of user_ids must not affect result
        let id1 = hash_channel_id("proj-123", vec!["alice".into(), "bob".into()]);
        let id2 = hash_channel_id("proj-123", vec!["bob".into(), "alice".into()]);
        assert_eq!(id1, id2, "Order should not matter — sort is deterministic");

        // Format: "{project_id}:{36 hex chars}"
        let parts: Vec<&str> = id1.splitn(2, ':').collect();
        assert_eq!(parts[0], "proj-123");
        assert_eq!(parts[1].len(), 36);

        // Different members → different hash
        let id3 = hash_channel_id("proj-123", vec!["alice".into(), "charlie".into()]);
        assert_ne!(id1, id3);

        // Different project → different hash
        let id4 = hash_channel_id("proj-456", vec!["alice".into(), "bob".into()]);
        assert_ne!(id1, id4);
    }
}
