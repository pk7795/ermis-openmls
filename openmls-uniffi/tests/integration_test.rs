//! Integration tests for openmls-uniffi
//!
//! These tests verify the full API surface works correctly
//! and mirrors the openmls-wasm test suite.

use std::sync::Arc;

use openmls_uniffi::*;

type AliceBobGroup = (
    Arc<Provider>,
    Arc<Identity>,
    Arc<Group>,
    Arc<Provider>,
    Arc<Identity>,
    Arc<Group>,
);

type AliceBobDaveGroup = (
    Arc<Provider>,
    Arc<Identity>,
    Arc<Group>,
    Arc<Provider>,
    Arc<Group>,
);

// ============================================================================
// Helpers
// ============================================================================

fn create_provider() -> Arc<Provider> {
    Arc::new(Provider::new())
}

fn create_identity(provider: Arc<Provider>, name: &str) -> Arc<Identity> {
    Arc::new(Identity::new(provider, name.to_string()).fixture_value())
}

fn create_group_alice_and_bob() -> AliceBobGroup {
    let alice_provider = create_provider();
    let bob_provider = create_provider();

    let alice = create_identity(alice_provider.clone(), "alice");
    let bob = create_identity(bob_provider.clone(), "bob");

    let chess_club_alice = Arc::new(
        Group::create_with_cid(
            alice_provider.clone(),
            alice.clone(),
            "team:chess_club".into(),
        )
        .fixture_value(),
    );

    let bob_key_pkg = bob.key_package(bob_provider.clone()).fixture_value();

    let add_result = chess_club_alice
        .add_members(alice_provider.clone(), alice.clone(), vec![bob_key_pkg])
        .fixture_value();

    chess_club_alice
        .merge_pending_commit(alice_provider.clone())
        .fixture_value();

    let ratchet_tree = chess_club_alice.export_ratchet_tree();
    let welcome = add_result.welcome.fixture_value();

    let chess_club_bob = Arc::new(
        Group::join_with_welcome(bob_provider.clone(), welcome, Some(ratchet_tree)).fixture_value(),
    );

    (
        alice_provider,
        alice,
        chess_club_alice,
        bob_provider,
        bob,
        chess_club_bob,
    )
}

fn create_group_alice_bob_dave() -> AliceBobDaveGroup {
    let alice_provider = create_provider();
    let bob_provider = create_provider();
    let dave_provider = create_provider();

    let alice = create_identity(alice_provider.clone(), "alice");
    let bob = create_identity(bob_provider.clone(), "bob");
    let dave = create_identity(dave_provider.clone(), "dave");

    let alice_group = Arc::new(
        Group::create_with_cid(
            alice_provider.clone(),
            alice.clone(),
            "team:wrapper_test".into(),
        )
        .fixture_value(),
    );

    let add_result = alice_group
        .add_members(
            alice_provider.clone(),
            alice.clone(),
            vec![
                bob.key_package(bob_provider).fixture_value(),
                dave.key_package(dave_provider.clone()).fixture_value(),
            ],
        )
        .fixture_value();

    alice_group
        .merge_pending_commit(alice_provider.clone())
        .fixture_value();

    let ratchet_tree = alice_group.export_ratchet_tree();
    let welcome = add_result.welcome.fixture_value();
    let dave_group = Arc::new(
        Group::join_with_welcome(dave_provider.clone(), welcome, Some(ratchet_tree))
            .fixture_value(),
    );

    (
        alice_provider,
        alice,
        alice_group,
        dave_provider,
        dave_group,
    )
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_provider_creation() {
    let provider = create_provider();
    // Provider should be usable
    let _identity = Identity::new(provider, "test_user".to_string()).fixture_value();
}

#[test]
fn test_identity_creation() {
    let provider = create_provider();
    let identity = create_identity(provider, "alice_user_123");
    assert_eq!(identity.user_id(), "alice_user_123");
}

#[test]
fn test_identity_serialization() {
    let provider = create_provider();
    let alice = create_identity(provider.clone(), "alice_user_123");

    let bytes = alice.to_bytes().fixture_value();
    let restored = Identity::from_bytes(provider, bytes).fixture_value();

    assert_eq!(restored.user_id(), "alice_user_123");
}

#[test]
fn test_key_package_serialization() {
    let provider = create_provider();
    let alice = create_identity(provider.clone(), "alice");
    let kp = alice.key_package(provider).fixture_value();

    let bytes = kp.to_bytes().fixture_value();
    assert!(!bytes.is_empty());

    let restored = KeyPackage::from_bytes(bytes).fixture_value();
    assert!(!restored.to_bytes().fixture_value().is_empty());
}

#[test]
fn test_cid_roundtrip() {
    let provider = create_provider();
    let alice = create_identity(provider.clone(), "alice");
    let cid = "team:my_channel_123";

    let group = Group::create_with_cid(provider, alice, cid.to_string()).fixture_value();
    assert_eq!(group.cid().fixture_value(), cid);
}

#[test]
fn test_group_creation_and_join() {
    let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    // Both should have the same exported key
    let bob_key = chess_club_bob
        .export_key(bob_provider, "test_key".into(), vec![0x30], 32)
        .fixture_value();
    let alice_key = chess_club_alice
        .export_key(alice_provider, "test_key".into(), vec![0x30], 32)
        .fixture_value();

    assert_eq!(bob_key, alice_key);
}

#[test]
fn test_welcome_for_different_provider_returns_typed_no_matching_key_package() {
    let alice_provider = create_provider();
    let bob_provider = create_provider();
    let unrelated_provider = create_provider();
    let alice = create_identity(alice_provider.clone(), "alice");
    let bob = create_identity(bob_provider.clone(), "bob");
    let alice_group = Group::create_with_cid(
        alice_provider.clone(),
        alice.clone(),
        "team:typed_welcome_error".into(),
    )
    .fixture_value();
    let add_result = alice_group
        .add_members(
            alice_provider.clone(),
            alice,
            vec![bob.key_package(bob_provider).fixture_value()],
        )
        .fixture_value();
    alice_group
        .merge_pending_commit(alice_provider)
        .fixture_value();

    let result = Group::join_with_welcome(
        unrelated_provider,
        add_result.welcome.fixture_value(),
        Some(alice_group.export_ratchet_tree()),
    );

    assert!(matches!(result, Err(MlsError::NoMatchingKeyPackage)));
}

#[test]
fn test_encrypted_messaging() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    let plaintext = b"Hello, Bob!";
    let ciphertext = chess_club_alice
        .create_message(alice_provider, alice, plaintext.to_vec())
        .fixture_value();

    let processed = chess_club_bob
        .process_message(bob_provider, ciphertext)
        .fixture_value();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(processed.content.fixture_value(), plaintext.to_vec());
}

#[test]
fn test_v2_epoch_archive_decrypts_and_rejects_untrusted_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let (alice_provider, alice, alice_group, bob_provider, _, bob_group) =
        create_group_alice_and_bob();
    let exported = bob_group.archive_epoch_v2()?;
    let ciphertext = alice_group.create_message(
        alice_provider,
        alice,
        b"archived generation payload".to_vec(),
    )?;

    let recovered = decrypt_epoch_archive_v2(
        bob_provider.clone(),
        exported.archive_bytes.clone(),
        exported.snapshot_bytes.clone(),
        ciphertext.clone(),
        false,
        0,
    )?;
    assert_eq!(recovered.content, b"archived generation payload");
    assert!(!recovered.own_message);

    let mut untrusted_snapshot = exported.snapshot_bytes;
    if let Some(first) = untrusted_snapshot.first_mut() {
        *first ^= 1;
    }
    let rejected = decrypt_epoch_archive_v2(
        bob_provider,
        exported.archive_bytes,
        untrusted_snapshot,
        ciphertext,
        false,
        0,
    );
    assert!(matches!(rejected, Err(MlsError::InvalidMessage)));
    Ok(())
}

#[test]
fn test_encrypted_messaging_with_aad() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    let plaintext = b"Hello with AAD!";
    let aad = b"{\"sender\":\"alice\",\"channel\":\"chess_club\"}";

    let ciphertext = chess_club_alice
        .create_message_with_aad(alice_provider, alice, plaintext.to_vec(), aad.to_vec())
        .fixture_value();

    let processed = chess_club_bob
        .process_message(bob_provider, ciphertext)
        .fixture_value();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(processed.content.fixture_value(), plaintext.to_vec());
    assert_eq!(processed.aad, aad.to_vec());
}

#[test]
fn test_proposal_commit_separation() {
    let alice_provider = create_provider();
    let bob_provider = create_provider();
    let charlie_provider = create_provider();

    let alice = create_identity(alice_provider.clone(), "alice");
    let bob = create_identity(bob_provider.clone(), "bob");
    let charlie = create_identity(charlie_provider.clone(), "charlie");

    let group = Arc::new(
        Group::create_with_cid(alice_provider.clone(), alice.clone(), "team:test".into())
            .fixture_value(),
    );

    let bob_kp = bob.key_package(bob_provider).fixture_value();
    let charlie_kp = charlie.key_package(charlie_provider).fixture_value();

    let _prop1 = group
        .propose_add_member(alice_provider.clone(), alice.clone(), bob_kp)
        .fixture_value();
    let _prop2 = group
        .propose_add_member(alice_provider.clone(), alice.clone(), charlie_kp)
        .fixture_value();

    assert_eq!(group.pending_proposals_count(), 2);

    let commit_bundle = group
        .commit_pending_proposals(alice_provider.clone(), alice)
        .fixture_value();
    assert!(commit_bundle.welcome.is_some());

    group.merge_pending_commit(alice_provider).fixture_value();

    let members = group.members();
    assert_eq!(members.len(), 3); // alice, bob, charlie
}

#[test]
fn test_commit_group_changes_processes_without_standalone_proposals() {
    let (alice_provider, alice, alice_group, dave_provider, dave_group) =
        create_group_alice_bob_dave();
    let charlie_provider = create_provider();
    let charlie = create_identity(charlie_provider.clone(), "charlie");

    let epoch_before = alice_group.epoch();
    let composite = alice_group
        .commit_group_changes(
            alice_provider.clone(),
            alice.clone(),
            vec!["bob".to_string()],
            vec![charlie.key_package(charlie_provider).fixture_value()],
            false,
        )
        .fixture_value();
    assert!(composite.welcome.is_some());

    dave_group
        .process_message(dave_provider.clone(), composite.commit)
        .fixture_value();
    alice_group
        .merge_pending_commit(alice_provider)
        .fixture_value();

    assert_eq!(alice_group.epoch(), epoch_before + 1);
    assert!(alice_group.member_by_user_id("bob".into()).is_none());
    assert!(alice_group.member_by_user_id("charlie".into()).is_some());
    assert!(dave_group.member_by_user_id("bob".into()).is_none());
    assert!(dave_group.member_by_user_id("charlie".into()).is_some());
}

#[test]
fn test_commit_member_add_with_removals_wrapper() {
    let (alice_provider, alice, alice_group, dave_provider, dave_group) =
        create_group_alice_bob_dave();
    let charlie_provider = create_provider();
    let charlie = create_identity(charlie_provider.clone(), "charlie");

    let epoch_before = alice_group.epoch();
    let composite = alice_group
        .commit_member_add_with_removals(
            alice_provider.clone(),
            alice.clone(),
            vec!["bob".to_string()],
            vec![charlie.key_package(charlie_provider).fixture_value()],
        )
        .fixture_value();
    assert!(composite.welcome.is_some());

    dave_group
        .process_message(dave_provider.clone(), composite.commit)
        .fixture_value();
    alice_group
        .merge_pending_commit(alice_provider)
        .fixture_value();

    assert_eq!(alice_group.epoch(), epoch_before + 1);
    assert!(alice_group.member_by_user_id("bob".into()).is_none());
    assert!(alice_group.member_by_user_id("charlie".into()).is_some());
    assert!(dave_group.member_by_user_id("bob".into()).is_none());
    assert!(dave_group.member_by_user_id("charlie".into()).is_some());
}

#[test]
fn test_commit_self_update_with_removals_wrapper() {
    let (alice_provider, alice, alice_group, dave_provider, dave_group) =
        create_group_alice_bob_dave();

    let epoch_before = alice_group.epoch();
    let composite = alice_group
        .commit_self_update_with_removals(
            alice_provider.clone(),
            alice.clone(),
            vec!["bob".to_string()],
        )
        .fixture_value();
    assert!(composite.welcome.is_none());

    dave_group
        .process_message(dave_provider.clone(), composite.commit)
        .fixture_value();
    alice_group
        .merge_pending_commit(alice_provider)
        .fixture_value();

    assert_eq!(alice_group.epoch(), epoch_before + 1);
    assert!(alice_group.member_by_user_id("bob".into()).is_none());
    assert!(dave_group.member_by_user_id("bob".into()).is_none());
}

#[test]
fn test_commit_member_removals_wrapper() {
    let (alice_provider, alice, alice_group, dave_provider, dave_group) =
        create_group_alice_bob_dave();

    let epoch_before = alice_group.epoch();
    let composite = alice_group
        .commit_member_removals(
            alice_provider.clone(),
            alice.clone(),
            vec!["bob".to_string()],
        )
        .fixture_value();
    assert!(composite.welcome.is_none());

    dave_group
        .process_message(dave_provider.clone(), composite.commit)
        .fixture_value();
    alice_group
        .merge_pending_commit(alice_provider)
        .fixture_value();

    assert_eq!(alice_group.epoch(), epoch_before + 1);
    assert!(alice_group.member_by_user_id("bob".into()).is_none());
    assert!(dave_group.member_by_user_id("bob".into()).is_none());
}

#[test]
fn test_member_info() {
    let (_, _, chess_club_alice, _, _, _) = create_group_alice_and_bob();

    let members = chess_club_alice.members();
    assert_eq!(members.len(), 2);

    let alice_member = chess_club_alice.member_by_user_id("alice".into());
    assert!(alice_member.is_some());
    assert_eq!(alice_member.fixture_value().user_id, "alice");

    let bob_member = chess_club_alice.member_by_user_id("bob".into());
    assert!(bob_member.is_some());
    assert_eq!(bob_member.fixture_value().user_id, "bob");
}

#[test]
fn test_group_state() {
    let (_, _, chess_club_alice, _, _, _) = create_group_alice_and_bob();

    assert!(chess_club_alice.is_operational());
    assert!(!chess_club_alice.has_pending_commit());
    assert_eq!(chess_club_alice.own_leaf_index(), 0);
    assert!(chess_club_alice.epoch() > 0);
}

#[test]
fn test_ratchet_tree_serialization() {
    let (_, _, chess_club_alice, _, _, _) = create_group_alice_and_bob();

    let tree = chess_club_alice.export_ratchet_tree();
    let bytes = tree.to_bytes();
    assert!(!bytes.is_empty());

    let restored = RatchetTree::from_bytes(bytes).fixture_value();
    assert!(!restored.to_bytes().is_empty());
}

#[test]
fn test_self_update() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    let epoch_before = chess_club_alice.epoch();

    let commit = chess_club_alice
        .self_update(alice_provider.clone(), alice)
        .fixture_value();

    chess_club_alice
        .merge_pending_commit(alice_provider)
        .fixture_value();

    // Process the commit on bob's side
    chess_club_bob
        .process_message(bob_provider, commit.commit)
        .fixture_value();

    assert!(chess_club_alice.epoch() > epoch_before);
}

#[test]
fn test_remove_member() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    // Alice removes Bob
    let bob_index = chess_club_alice
        .member_by_user_id("bob".into())
        .fixture_value()
        .index;

    let commit = chess_club_alice
        .remove_members(alice_provider.clone(), alice, vec![bob_index])
        .fixture_value();

    chess_club_alice
        .merge_pending_commit(alice_provider)
        .fixture_value();

    // Process removal on Bob's side
    chess_club_bob
        .process_message(bob_provider, commit.commit)
        .fixture_value();

    // Alice's group should only have 1 member now
    assert_eq!(chess_club_alice.members().len(), 1);
}

// ============================================================================
// Persistent Storage Tests
// ============================================================================

#[test]
fn test_persistent_provider_creation() {
    let dir = std::env::temp_dir().join("openmls_test_persistent.db");
    let db_path = dir.to_str().fixture_value().to_string();

    // Clean up from previous runs
    let _ = std::fs::remove_file(&db_path);

    let provider = Arc::new(Provider::new_with_path(db_path.clone()).fixture_value());
    let identity = Arc::new(Identity::new(provider.clone(), "alice".to_string()).fixture_value());
    assert_eq!(identity.user_id(), "alice");

    // Should be able to create a group
    let group =
        Group::create_with_cid(provider.clone(), identity.clone(), "test:persistent".into())
            .fixture_value();
    assert_eq!(group.cid().fixture_value(), "test:persistent");

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_persistent_provider_full_flow() {
    let dir = std::env::temp_dir().join("openmls_test_full_flow.db");
    let db_path = dir.to_str().fixture_value().to_string();

    // Clean up from previous runs
    let _ = std::fs::remove_file(&db_path);

    // Create two persistent providers (simulating two different users on the same device)
    let alice_provider = Arc::new(Provider::new_with_path(db_path.clone()).fixture_value());
    let bob_provider = Arc::new(Provider::new());

    let alice =
        Arc::new(Identity::new(alice_provider.clone(), "alice".to_string()).fixture_value());
    let bob = Arc::new(Identity::new(bob_provider.clone(), "bob".to_string()).fixture_value());

    // Create group and add bob
    let group = Arc::new(
        Group::create_with_cid(
            alice_provider.clone(),
            alice.clone(),
            "team:persistent".into(),
        )
        .fixture_value(),
    );

    let bob_kp = bob.key_package(bob_provider.clone()).fixture_value();
    let add_result = group
        .add_members(alice_provider.clone(), alice.clone(), vec![bob_kp])
        .fixture_value();
    group
        .merge_pending_commit(alice_provider.clone())
        .fixture_value();

    let welcome = add_result.welcome.fixture_value();
    let ratchet_tree = group.export_ratchet_tree();

    let bob_group = Arc::new(
        Group::join_with_welcome(bob_provider.clone(), welcome, Some(ratchet_tree)).fixture_value(),
    );

    // Messaging should work
    let plaintext = b"Hello from persistent storage!";
    let ciphertext = group
        .create_message(alice_provider.clone(), alice, plaintext.to_vec())
        .fixture_value();

    let processed = bob_group
        .process_message(bob_provider, ciphertext)
        .fixture_value();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(processed.content.fixture_value(), plaintext.to_vec());

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_load_group_from_storage() {
    let dir = std::env::temp_dir().join("openmls_test_load_group.db");
    let db_path = dir.to_str().fixture_value().to_string();
    let _ = std::fs::remove_file(&db_path);

    let cid = "test:load_group";

    // Phase 1: Create group with persistent provider
    let provider = Arc::new(Provider::new_with_path(db_path.clone()).fixture_value());
    let alice = Arc::new(Identity::new(provider.clone(), "alice".to_string()).fixture_value());

    let group = Group::create_with_cid(provider.clone(), alice.clone(), cid.into()).fixture_value();
    assert_eq!(group.cid().fixture_value(), cid);
    assert_eq!(group.epoch(), 0);

    // Verify stored_group_ids returns the CID
    let ids = provider.stored_group_ids().fixture_value();
    assert!(
        ids.contains(&cid.to_string()),
        "Expected CID in stored groups: {:?}",
        ids
    );

    // Phase 2: Load the group from storage (simulate app restart with same DB)
    let loaded = Group::load_from_storage(provider.clone(), cid.into()).fixture_value();
    assert_eq!(loaded.cid().fixture_value(), cid);
    assert_eq!(loaded.epoch(), 0);
    assert_eq!(loaded.members().len(), 1);

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_group_management() {
    let dir = std::env::temp_dir().join("openmls_test_group_mgmt.db");
    let db_path = dir.to_str().fixture_value().to_string();
    let _ = std::fs::remove_file(&db_path);

    let provider = Arc::new(Provider::new_with_path(db_path.clone()).fixture_value());
    let alice = Arc::new(Identity::new(provider.clone(), "alice".to_string()).fixture_value());

    // Initially no groups
    assert_eq!(provider.group_count().fixture_value(), 0);
    assert!(provider.stored_group_ids().fixture_value().is_empty());

    // Create 2 groups
    let _g1 =
        Group::create_with_cid(provider.clone(), alice.clone(), "ch:one".into()).fixture_value();
    let _g2 =
        Group::create_with_cid(provider.clone(), alice.clone(), "ch:two".into()).fixture_value();

    assert_eq!(provider.group_count().fixture_value(), 2);
    let ids = provider.stored_group_ids().fixture_value();
    assert!(ids.contains(&"ch:one".to_string()));
    assert!(ids.contains(&"ch:two".to_string()));

    // Delete one group
    provider.delete_group("ch:one".into()).fixture_value();
    assert_eq!(provider.group_count().fixture_value(), 1);
    let ids = provider.stored_group_ids().fixture_value();
    assert!(!ids.contains(&"ch:one".to_string()));
    assert!(ids.contains(&"ch:two".to_string()));

    // Delete all
    provider.delete_all_groups().fixture_value();
    assert_eq!(provider.group_count().fixture_value(), 0);

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_identity_persistence() {
    let dir = std::env::temp_dir().join("openmls_test_identity_persist.db");
    let db_path = dir.to_str().fixture_value().to_string();
    let _ = std::fs::remove_file(&db_path);

    let provider = Arc::new(Provider::new_with_path(db_path.clone()).fixture_value());

    // Initially no identity
    assert!(provider.load_identity().fixture_value().is_none());

    // Create identity and store it
    let alice = Arc::new(Identity::new(provider.clone(), "alice".to_string()).fixture_value());
    let identity_bytes = alice.to_bytes().fixture_value();
    provider
        .store_identity("alice".to_string(), identity_bytes.clone())
        .fixture_value();

    // Load identity back
    let loaded = provider.load_identity().fixture_value();
    assert!(loaded.is_some());
    let loaded_bytes = loaded.fixture_value();
    assert_eq!(loaded_bytes, identity_bytes);

    // Restore identity from loaded bytes
    let restored = Identity::from_bytes(provider.clone(), loaded_bytes).fixture_value();
    assert_eq!(restored.user_id(), "alice");

    // Delete identity
    provider.delete_identity().fixture_value();
    assert!(provider.load_identity().fixture_value().is_none());

    let _ = std::fs::remove_file(&db_path);
}

// These pre-existing fixtures fail loudly on any unexpected error; no panic
// convenience methods, and no private payloads in fixture error messages.
trait FixtureValue {
    type Value;
    fn fixture_value(self) -> Self::Value;
}
impl<T, E> FixtureValue for Result<T, E> {
    type Value = T;
    fn fixture_value(self) -> T {
        match self {
            Ok(value) => value,
            Err(_) => panic!("invalid UniFFI integration fixture"),
        }
    }
}
impl<T> FixtureValue for Option<T> {
    type Value = T;
    fn fixture_value(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("missing UniFFI integration fixture value"),
        }
    }
}
