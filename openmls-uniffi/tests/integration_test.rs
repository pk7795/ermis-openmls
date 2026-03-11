//! Integration tests for openmls-uniffi
//!
//! These tests verify the full API surface works correctly
//! and mirrors the openmls-wasm test suite.

use std::sync::Arc;

use openmls_uniffi::*;

// ============================================================================
// Helpers
// ============================================================================

fn create_provider() -> Arc<Provider> {
    Arc::new(Provider::new())
}

fn create_identity(provider: Arc<Provider>, name: &str) -> Arc<Identity> {
    Arc::new(Identity::new(provider, name.to_string()).unwrap())
}

fn create_group_alice_and_bob() -> (
    Arc<Provider>,
    Arc<Identity>,
    Arc<Group>,
    Arc<Provider>,
    Arc<Identity>,
    Arc<Group>,
) {
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
        .unwrap(),
    );

    let bob_key_pkg = bob.key_package(bob_provider.clone());

    let add_result = chess_club_alice
        .add_members(alice_provider.clone(), alice.clone(), vec![bob_key_pkg])
        .unwrap();

    chess_club_alice
        .merge_pending_commit(alice_provider.clone())
        .unwrap();

    let ratchet_tree = chess_club_alice.export_ratchet_tree();
    let welcome = add_result.welcome.expect("Should have welcome");

    let chess_club_bob = Arc::new(
        Group::join_with_welcome(bob_provider.clone(), welcome, Some(ratchet_tree)).unwrap(),
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

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_provider_creation() {
    let provider = create_provider();
    // Provider should be usable
    let _identity = Identity::new(provider, "test_user".to_string()).unwrap();
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

    let bytes = alice.to_bytes().unwrap();
    let restored = Identity::from_bytes(provider, bytes).unwrap();

    assert_eq!(restored.user_id(), "alice_user_123");
}

#[test]
fn test_key_package_serialization() {
    let provider = create_provider();
    let alice = create_identity(provider.clone(), "alice");
    let kp = alice.key_package(provider);

    let bytes = kp.to_bytes();
    assert!(!bytes.is_empty());

    let restored = KeyPackage::from_bytes(bytes).unwrap();
    assert!(!restored.to_bytes().is_empty());
}

#[test]
fn test_cid_roundtrip() {
    let provider = create_provider();
    let alice = create_identity(provider.clone(), "alice");
    let cid = "team:my_channel_123";

    let group = Group::create_with_cid(provider, alice, cid.to_string()).unwrap();
    assert_eq!(group.cid().unwrap(), cid);
}

#[test]
fn test_group_creation_and_join() {
    let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    // Both should have the same exported key
    let bob_key = chess_club_bob
        .export_key(bob_provider, "test_key".into(), vec![0x30], 32)
        .unwrap();
    let alice_key = chess_club_alice
        .export_key(alice_provider, "test_key".into(), vec![0x30], 32)
        .unwrap();

    assert_eq!(bob_key, alice_key);
}

#[test]
fn test_encrypted_messaging() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    let plaintext = b"Hello, Bob!";
    let ciphertext = chess_club_alice
        .create_message(alice_provider, alice, plaintext.to_vec())
        .unwrap();

    let processed = chess_club_bob
        .process_message(bob_provider, ciphertext)
        .unwrap();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(processed.content.unwrap(), plaintext.to_vec());
}

#[test]
fn test_encrypted_messaging_with_aad() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    let plaintext = b"Hello with AAD!";
    let aad = b"{\"sender\":\"alice\",\"channel\":\"chess_club\"}";

    let ciphertext = chess_club_alice
        .create_message_with_aad(alice_provider, alice, plaintext.to_vec(), aad.to_vec())
        .unwrap();

    let processed = chess_club_bob
        .process_message(bob_provider, ciphertext)
        .unwrap();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(processed.content.unwrap(), plaintext.to_vec());
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
        Group::create_with_cid(alice_provider.clone(), alice.clone(), "team:test".into()).unwrap(),
    );

    let bob_kp = bob.key_package(bob_provider);
    let charlie_kp = charlie.key_package(charlie_provider);

    let _prop1 = group
        .propose_add_member(alice_provider.clone(), alice.clone(), bob_kp)
        .unwrap();
    let _prop2 = group
        .propose_add_member(alice_provider.clone(), alice.clone(), charlie_kp)
        .unwrap();

    assert_eq!(group.pending_proposals_count(), 2);

    let commit_bundle = group
        .commit_pending_proposals(alice_provider.clone(), alice)
        .unwrap();
    assert!(commit_bundle.welcome.is_some());

    group.merge_pending_commit(alice_provider).unwrap();

    let members = group.members();
    assert_eq!(members.len(), 3); // alice, bob, charlie
}

#[test]
fn test_member_info() {
    let (_, _, chess_club_alice, _, _, _) = create_group_alice_and_bob();

    let members = chess_club_alice.members();
    assert_eq!(members.len(), 2);

    let alice_member = chess_club_alice.member_by_user_id("alice".into());
    assert!(alice_member.is_some());
    assert_eq!(alice_member.unwrap().user_id, "alice");

    let bob_member = chess_club_alice.member_by_user_id("bob".into());
    assert!(bob_member.is_some());
    assert_eq!(bob_member.unwrap().user_id, "bob");
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

    let restored = RatchetTree::from_bytes(bytes).unwrap();
    assert!(!restored.to_bytes().is_empty());
}

#[test]
fn test_self_update() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    let epoch_before = chess_club_alice.epoch();

    let commit = chess_club_alice
        .self_update(alice_provider.clone(), alice)
        .unwrap();

    chess_club_alice
        .merge_pending_commit(alice_provider)
        .unwrap();

    // Process the commit on bob's side
    chess_club_bob
        .process_message(bob_provider, commit.commit)
        .unwrap();

    assert!(chess_club_alice.epoch() > epoch_before);
}

#[test]
fn test_remove_member() {
    let (alice_provider, alice, chess_club_alice, bob_provider, _, chess_club_bob) =
        create_group_alice_and_bob();

    // Alice removes Bob
    let bob_index = chess_club_alice
        .member_by_user_id("bob".into())
        .unwrap()
        .index;

    let commit = chess_club_alice
        .remove_members(alice_provider.clone(), alice, vec![bob_index])
        .unwrap();

    chess_club_alice
        .merge_pending_commit(alice_provider)
        .unwrap();

    // Process removal on Bob's side
    chess_club_bob
        .process_message(bob_provider, commit.commit)
        .unwrap();

    // Alice's group should only have 1 member now
    assert_eq!(chess_club_alice.members().len(), 1);
}

// ============================================================================
// Persistent Storage Tests
// ============================================================================

#[test]
fn test_persistent_provider_creation() {
    let dir = std::env::temp_dir().join("openmls_test_persistent.db");
    let db_path = dir.to_str().unwrap().to_string();

    // Clean up from previous runs
    let _ = std::fs::remove_file(&db_path);

    let provider = Arc::new(Provider::new_with_path(db_path.clone()).unwrap());
    let identity = Arc::new(Identity::new(provider.clone(), "alice".to_string()).unwrap());
    assert_eq!(identity.user_id(), "alice");

    // Should be able to create a group
    let group =
        Group::create_with_cid(provider.clone(), identity.clone(), "test:persistent".into())
            .unwrap();
    assert_eq!(group.cid().unwrap(), "test:persistent");

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_persistent_provider_full_flow() {
    let dir = std::env::temp_dir().join("openmls_test_full_flow.db");
    let db_path = dir.to_str().unwrap().to_string();

    // Clean up from previous runs
    let _ = std::fs::remove_file(&db_path);

    // Create two persistent providers (simulating two different users on the same device)
    let alice_provider = Arc::new(Provider::new_with_path(db_path.clone()).unwrap());
    let bob_provider = Arc::new(Provider::new());

    let alice = Arc::new(Identity::new(alice_provider.clone(), "alice".to_string()).unwrap());
    let bob = Arc::new(Identity::new(bob_provider.clone(), "bob".to_string()).unwrap());

    // Create group and add bob
    let group = Arc::new(
        Group::create_with_cid(
            alice_provider.clone(),
            alice.clone(),
            "team:persistent".into(),
        )
        .unwrap(),
    );

    let bob_kp = bob.key_package(bob_provider.clone());
    let add_result = group
        .add_members(alice_provider.clone(), alice.clone(), vec![bob_kp])
        .unwrap();
    group.merge_pending_commit(alice_provider.clone()).unwrap();

    let welcome = add_result.welcome.expect("Should have welcome");
    let ratchet_tree = group.export_ratchet_tree();

    let bob_group = Arc::new(
        Group::join_with_welcome(bob_provider.clone(), welcome, Some(ratchet_tree)).unwrap(),
    );

    // Messaging should work
    let plaintext = b"Hello from persistent storage!";
    let ciphertext = group
        .create_message(alice_provider.clone(), alice, plaintext.to_vec())
        .unwrap();

    let processed = bob_group.process_message(bob_provider, ciphertext).unwrap();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(processed.content.unwrap(), plaintext.to_vec());

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_load_group_from_storage() {
    let dir = std::env::temp_dir().join("openmls_test_load_group.db");
    let db_path = dir.to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&db_path);

    let cid = "test:load_group";

    // Phase 1: Create group with persistent provider
    let provider = Arc::new(Provider::new_with_path(db_path.clone()).unwrap());
    let alice = Arc::new(Identity::new(provider.clone(), "alice".to_string()).unwrap());

    let group = Group::create_with_cid(provider.clone(), alice.clone(), cid.into()).unwrap();
    assert_eq!(group.cid().unwrap(), cid);
    assert_eq!(group.epoch(), 0);

    // Verify stored_group_ids returns the CID
    let ids = provider.stored_group_ids().unwrap();
    assert!(
        ids.contains(&cid.to_string()),
        "Expected CID in stored groups: {:?}",
        ids
    );

    // Phase 2: Load the group from storage (simulate app restart with same DB)
    let loaded = Group::load_from_storage(provider.clone(), cid.into()).unwrap();
    assert_eq!(loaded.cid().unwrap(), cid);
    assert_eq!(loaded.epoch(), 0);
    assert_eq!(loaded.members().len(), 1);

    // Clean up
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_group_management() {
    let dir = std::env::temp_dir().join("openmls_test_group_mgmt.db");
    let db_path = dir.to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&db_path);

    let provider = Arc::new(Provider::new_with_path(db_path.clone()).unwrap());
    let alice = Arc::new(Identity::new(provider.clone(), "alice".to_string()).unwrap());

    // Initially no groups
    assert_eq!(provider.group_count().unwrap(), 0);
    assert!(provider.stored_group_ids().unwrap().is_empty());

    // Create 2 groups
    let _g1 = Group::create_with_cid(provider.clone(), alice.clone(), "ch:one".into()).unwrap();
    let _g2 = Group::create_with_cid(provider.clone(), alice.clone(), "ch:two".into()).unwrap();

    assert_eq!(provider.group_count().unwrap(), 2);
    let ids = provider.stored_group_ids().unwrap();
    assert!(ids.contains(&"ch:one".to_string()));
    assert!(ids.contains(&"ch:two".to_string()));

    // Delete one group
    provider.delete_group("ch:one".into()).unwrap();
    assert_eq!(provider.group_count().unwrap(), 1);
    let ids = provider.stored_group_ids().unwrap();
    assert!(!ids.contains(&"ch:one".to_string()));
    assert!(ids.contains(&"ch:two".to_string()));

    // Delete all
    provider.delete_all_groups().unwrap();
    assert_eq!(provider.group_count().unwrap(), 0);

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_identity_persistence() {
    let dir = std::env::temp_dir().join("openmls_test_identity_persist.db");
    let db_path = dir.to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&db_path);

    let provider = Arc::new(Provider::new_with_path(db_path.clone()).unwrap());

    // Initially no identity
    assert!(provider.load_identity().unwrap().is_none());

    // Create identity and store it
    let alice = Arc::new(Identity::new(provider.clone(), "alice".to_string()).unwrap());
    let identity_bytes = alice.to_bytes().unwrap();
    provider
        .store_identity("alice".to_string(), identity_bytes.clone())
        .unwrap();

    // Load identity back
    let loaded = provider.load_identity().unwrap();
    assert!(loaded.is_some());
    let loaded_bytes = loaded.unwrap();
    assert_eq!(loaded_bytes, identity_bytes);

    // Restore identity from loaded bytes
    let restored = Identity::from_bytes(provider.clone(), loaded_bytes).unwrap();
    assert_eq!(restored.user_id(), "alice");

    // Delete identity
    provider.delete_identity().unwrap();
    assert!(provider.load_identity().unwrap().is_none());

    let _ = std::fs::remove_file(&db_path);
}
