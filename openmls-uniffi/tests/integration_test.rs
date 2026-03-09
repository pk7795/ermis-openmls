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
