use openmls_flutter::api::{
    group::Group,
    identity::{hash_channel_id, validate_key_package_bytes, Identity},
    provider::Provider,
    types::MessageType,
};

fn create_group_pair(cid: &str) -> (Provider, Identity, Group, Provider, Group) {
    let alice_provider = Provider::new();
    let bob_provider = Provider::new();
    let alice = Identity::new(&alice_provider, "alice".to_string()).unwrap();
    let bob = Identity::new(&bob_provider, "bob".to_string()).unwrap();
    let alice_group = Group::create_with_cid(&alice_provider, &alice, cid.to_string()).unwrap();

    let bob_key_package = bob.key_package(&bob_provider);
    let add_result = alice_group
        .add_members(&alice_provider, &alice, vec![bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let bob_group = Group::join_with_welcome(
        &bob_provider,
        add_result
            .welcome
            .expect("add member must return a Welcome"),
        Some(alice_group.export_ratchet_tree()),
    )
    .unwrap();

    (alice_provider, alice, alice_group, bob_provider, bob_group)
}

#[test]
fn in_memory_provider_supports_identity_and_group_crud() {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "alice".to_string()).unwrap();
    let identity_bytes = identity.to_bytes().unwrap();

    provider
        .store_identity("alice".to_string(), identity_bytes.clone())
        .unwrap();
    assert_eq!(provider.load_identity().unwrap(), Some(identity_bytes));

    let cid = "team:flutter-storage";
    Group::create_with_cid(&provider, &identity, cid.to_string()).unwrap();
    assert_eq!(provider.group_count().unwrap(), 1);
    assert_eq!(provider.stored_group_ids().unwrap(), vec![cid.to_string()]);

    provider.delete_group(cid.to_string()).unwrap();
    assert_eq!(provider.group_count().unwrap(), 0);
    assert!(Group::load_from_storage(&provider, cid.to_string()).is_err());

    provider.delete_identity().unwrap();
    assert_eq!(provider.load_identity().unwrap(), None);
}

#[test]
fn in_memory_providers_are_isolated() {
    let first = Provider::new();
    let second = Provider::new();
    let identity = Identity::new(&first, "alice".to_string()).unwrap();

    Group::create_with_cid(&first, &identity, "team:first".to_string()).unwrap();

    assert_eq!(first.group_count().unwrap(), 1);
    assert_eq!(second.group_count().unwrap(), 0);
}

#[test]
fn group_message_round_trip_matches_the_native_api() {
    let (alice_provider, alice, alice_group, bob_provider, bob_group) =
        create_group_pair("team:flutter-message");

    let ciphertext = alice_group
        .create_message(&alice_provider, &alice, b"hello flutter".to_vec())
        .unwrap();
    let processed = bob_group
        .process_message(&bob_provider, ciphertext)
        .unwrap();

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(
        processed.content.as_deref(),
        Some(b"hello flutter".as_slice())
    );
}

#[test]
fn key_package_validation_and_channel_hash_are_deterministic() {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "alice".to_string()).unwrap();
    let key_package_bytes = identity.key_package(&provider).to_bytes();

    assert!(validate_key_package_bytes(key_package_bytes));
    assert_eq!(
        hash_channel_id(
            "project".to_string(),
            vec!["bob".to_string(), "alice".to_string()],
        ),
        hash_channel_id(
            "project".to_string(),
            vec!["alice".to_string(), "bob".to_string()],
        )
    );
}
