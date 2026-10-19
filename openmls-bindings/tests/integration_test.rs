use openmls_bindings_core::{
    hash_channel_id, validate_key_package_bytes, Group, Identity, MessageType, Provider,
};

fn create_group_pair(
    cid: &str,
) -> Result<(Provider, Identity, Group, Provider, Group), Box<dyn std::error::Error>> {
    let alice_provider = Provider::new();
    let bob_provider = Provider::new();
    let alice = Identity::new(&alice_provider, "alice".to_string())?;
    let bob = Identity::new(&bob_provider, "bob".to_string())?;
    let alice_group = Group::create_with_cid(&alice_provider, &alice, cid.to_string())?;

    let bob_key_package = bob.key_package(&bob_provider)?;
    let add_result = alice_group.add_members(&alice_provider, &alice, vec![bob_key_package])?;
    alice_group.merge_pending_commit(&alice_provider)?;

    let bob_group = Group::join_with_welcome(
        &bob_provider,
        add_result
            .welcome
            .ok_or("add member must return a Welcome")?,
        Some(alice_group.export_ratchet_tree()),
    )?;

    Ok((alice_provider, alice, alice_group, bob_provider, bob_group))
}

#[test]
fn in_memory_provider_supports_identity_and_group_crud() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "alice".to_string())?;
    let identity_bytes = identity.to_bytes()?;

    provider.store_identity("alice".to_string(), identity_bytes.clone())?;
    assert_eq!(provider.load_identity()?, Some(identity_bytes));

    let cid = "team:core-storage";
    Group::create_with_cid(&provider, &identity, cid.to_string())?;
    assert_eq!(provider.group_count()?, 1);
    assert_eq!(provider.stored_group_ids()?, vec![cid.to_string()]);

    provider.delete_group(cid.to_string())?;
    assert_eq!(provider.group_count()?, 0);
    assert!(Group::load_from_storage(&provider, cid.to_string()).is_err());

    provider.delete_identity()?;
    assert_eq!(provider.load_identity()?, None);
    Ok(())
}

#[test]
fn in_memory_providers_are_isolated() -> Result<(), Box<dyn std::error::Error>> {
    let first = Provider::new();
    let second = Provider::new();
    let identity = Identity::new(&first, "alice".to_string())?;

    Group::create_with_cid(&first, &identity, "team:first".to_string())?;

    assert_eq!(first.group_count()?, 1);
    assert_eq!(second.group_count()?, 0);
    Ok(())
}

#[test]
fn group_message_round_trip_is_binding_neutral() -> Result<(), Box<dyn std::error::Error>> {
    let (alice_provider, alice, alice_group, bob_provider, bob_group) =
        create_group_pair("team:core-message")?;

    let ciphertext =
        alice_group.create_message(&alice_provider, &alice, b"hello bindings".to_vec())?;
    let processed = bob_group.process_message(&bob_provider, ciphertext)?;

    assert_eq!(processed.message_type, MessageType::ApplicationMessage);
    assert_eq!(
        processed.content.as_deref(),
        Some(b"hello bindings".as_slice())
    );
    Ok(())
}

#[test]
fn key_package_validation_and_channel_hash_are_deterministic(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "alice".to_string())?;
    let key_package_bytes = identity.key_package(&provider)?.to_bytes()?;

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
    Ok(())
}
