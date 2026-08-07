use std::{error::Error, io, sync::Arc};

use openmls_uniffi::{Group, Identity, MlsError, Provider};

type TestPair = (
    Arc<Provider>,
    Arc<Identity>,
    Arc<Group>,
    Arc<Provider>,
    Arc<Group>,
);

fn create_group_pair(cid: &str) -> Result<TestPair, Box<dyn Error>> {
    let alice_provider = Arc::new(Provider::new());
    let bob_provider = Arc::new(Provider::new());
    let alice = Arc::new(Identity::new(alice_provider.clone(), "alice".to_string())?);
    let bob = Arc::new(Identity::new(bob_provider.clone(), "bob".to_string())?);
    let alice_group = Arc::new(Group::create_with_cid(
        alice_provider.clone(),
        alice.clone(),
        cid.to_string(),
    )?);

    let add_result = alice_group.add_members(
        alice_provider.clone(),
        alice.clone(),
        vec![bob.key_package(bob_provider.clone())],
    )?;
    alice_group.merge_pending_commit(alice_provider.clone())?;

    let welcome = add_result
        .welcome
        .ok_or_else(|| io::Error::other("add member did not return a Welcome"))?;
    let bob_group = Arc::new(Group::join_with_welcome(
        bob_provider.clone(),
        welcome,
        Some(alice_group.export_ratchet_tree()),
    )?);

    Ok((alice_provider, alice, alice_group, bob_provider, bob_group))
}

#[test]
fn persisted_application_message_replay_is_distinct_from_invalid_message(
) -> Result<(), Box<dyn Error>> {
    let cid = "team:message-replay";
    let (alice_provider, alice, alice_group, bob_provider, bob_group) = create_group_pair(cid)?;
    let ciphertext =
        alice_group.create_message(alice_provider, alice, b"persist before cursor".to_vec())?;

    let processed = bob_group.process_message(bob_provider.clone(), ciphertext.clone())?;
    if processed.content.as_deref() != Some(b"persist before cursor".as_slice()) {
        return Err(io::Error::other("unexpected decrypted plaintext").into());
    }
    bob_group.save_state(bob_provider.clone())?;

    let reloaded = Group::load_from_storage(bob_provider.clone(), cid.to_string())?;
    let replay_error = match reloaded.process_message(bob_provider, ciphertext) {
        Ok(_) => return Err(io::Error::other("replayed ciphertext unexpectedly decrypted").into()),
        Err(error) => error,
    };

    assert!(matches!(replay_error, MlsError::MessageAlreadyConsumed));
    Ok(())
}

#[test]
fn deferred_application_message_can_be_reprocessed_until_group_state_is_saved(
) -> Result<(), Box<dyn Error>> {
    let cid = "team:deferred-message-replay";
    let (alice_provider, alice, alice_group, bob_provider, bob_group) = create_group_pair(cid)?;
    let ciphertext = alice_group.create_message(
        alice_provider,
        alice,
        b"plaintext-first transaction".to_vec(),
    )?;

    let processed = bob_group.process_message_deferred(bob_provider.clone(), ciphertext.clone())?;
    if processed.content.as_deref() != Some(b"plaintext-first transaction".as_slice()) {
        return Err(io::Error::other("unexpected deferred plaintext").into());
    }

    // Simulate a crash before the app database commit and explicit group save. Reloading from the
    // provider must retain the receiver key so the durable raw event can be processed again.
    let replay = Group::load_from_storage(bob_provider.clone(), cid.to_string())?;
    let replayed = replay.process_message_deferred(bob_provider.clone(), ciphertext.clone())?;
    if replayed.content.as_deref() != Some(b"plaintext-first transaction".as_slice()) {
        return Err(io::Error::other("deferred ciphertext did not replay").into());
    }

    replay.save_state(bob_provider.clone())?;
    let persisted = Group::load_from_storage(bob_provider.clone(), cid.to_string())?;
    let replay_error = match persisted.process_message(bob_provider, ciphertext) {
        Ok(_) => {
            return Err(io::Error::other("saved deferred ciphertext unexpectedly replayed").into())
        }
        Err(error) => error,
    };
    assert!(matches!(replay_error, MlsError::MessageAlreadyConsumed));
    Ok(())
}

#[test]
fn corrupted_application_message_remains_invalid() -> Result<(), Box<dyn Error>> {
    let (alice_provider, alice, alice_group, bob_provider, bob_group) =
        create_group_pair("team:corrupted-message")?;
    let mut ciphertext =
        alice_group.create_message(alice_provider, alice, b"authenticated".to_vec())?;
    let last = ciphertext
        .last_mut()
        .ok_or_else(|| io::Error::other("ciphertext was empty"))?;
    *last ^= 0x01;

    let process_error = match bob_group.process_message(bob_provider, ciphertext) {
        Ok(_) => {
            return Err(io::Error::other("corrupted ciphertext unexpectedly decrypted").into())
        }
        Err(error) => error,
    };

    assert!(matches!(process_error, MlsError::InvalidMessage));
    Ok(())
}
