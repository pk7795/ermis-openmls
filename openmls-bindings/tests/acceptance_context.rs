use openmls::framing::AcceptanceContext;
use openmls_bindings_core::{Group, Identity, MlsError, Provider};
use sha2::{Digest, Sha256};

#[test]
fn metadata_rejection_preserves_group_and_context_commit_survives_restart(
) -> Result<(), Box<dyn std::error::Error>> {
    verify_mode(false)?;
    verify_mode(true)
}

fn verify_mode(defer_secret_persistence: bool) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir
        .path()
        .join("context.sqlite")
        .to_string_lossy()
        .into_owned();
    let alice_provider = Provider::new();
    let bob_provider = Provider::new_with_path(path.clone())?;
    let alice = Identity::new(&alice_provider, "alice".into())?;
    let bob = Identity::new(&bob_provider, "bob".into())?;
    let alice_group = Group::create_with_cid(&alice_provider, &alice, "team:context".into())?;
    let add = alice_group.add_members(
        &alice_provider,
        &alice,
        vec![bob.key_package(&bob_provider)?],
    )?;
    alice_group.merge_pending_commit(&alice_provider)?;
    let bob_group = Group::join_with_welcome(
        &bob_provider,
        add.welcome.ok_or("missing Welcome")?,
        Some(alice_group.export_ratchet_tree()),
    )?;
    let update = alice_group.self_update(&alice_provider, &alice)?;
    alice_group.merge_pending_commit(&alice_provider)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let context = AcceptanceContext {
        version: 1,
        event_id: "event".into(),
        cid: "team:context".into(),
        group_generation: 0,
        epoch: 2,
        accepted_at: now,
        payload_sha256: hex::encode(Sha256::digest(&update.commit)),
        provenance: "bellboy_transition_v1".into(),
    };
    for field in 0..8 {
        let mut wrong = context.clone();
        match field {
            0 => wrong.event_id = "other".into(),
            1 => wrong.cid = "other".into(),
            2 => wrong.group_generation = 1,
            3 => wrong.epoch = 9,
            4 => wrong.payload_sha256 = "0".repeat(64),
            5 => wrong.provenance = "imported".into(),
            6 => wrong.accepted_at = now + 3600,
            _ => wrong.version = 2,
        }
        assert!(matches!(
            bob_group.process_message_with_context(
                &bob_provider,
                update.commit.clone(),
                serde_json::to_string(&wrong)?,
                "event".into(),
                "team:context".into(),
                0,
                2,
                true
            ),
            Err(MlsError::AcceptanceMetadataInvalid)
        ));
        assert_eq!(bob_group.epoch(), 1);
        assert_eq!(
            Group::load_from_storage(&bob_provider, "team:context".into())?.epoch(),
            1
        );
    }
    assert!(matches!(
        bob_group.process_message_with_context(
            &bob_provider,
            update.commit.clone(),
            "null".into(),
            "event".into(),
            "team:context".into(),
            0,
            2,
            false
        ),
        Err(MlsError::AcceptanceMetadataInvalid)
    ));
    let mut corrupt = update.commit.clone();
    let last = corrupt.last_mut().ok_or("missing commit bytes")?;
    *last ^= 1;
    let mut crypto_context = context.clone();
    crypto_context.payload_sha256 = hex::encode(Sha256::digest(&corrupt));
    assert!(bob_group
        .process_message_with_context(
            &bob_provider,
            corrupt,
            serde_json::to_string(&crypto_context)?,
            "event".into(),
            "team:context".into(),
            0,
            2,
            true
        )
        .is_err());
    assert_eq!(bob_group.epoch(), 1);
    bob_group.process_message_with_context(
        &bob_provider,
        update.commit,
        serde_json::to_string(&context)?,
        "event".into(),
        "team:context".into(),
        0,
        2,
        defer_secret_persistence,
    )?;
    assert_eq!(bob_group.epoch(), 2);
    let restarted = Provider::new_with_path(path)?;
    let restored = Group::load_from_storage(&restarted, "team:context".into())?;
    assert_eq!(restored.epoch(), 2);
    let application =
        alice_group.create_message(&alice_provider, &alice, b"application".to_vec())?;
    let mut application_context = context;
    application_context.payload_sha256 = hex::encode(Sha256::digest(&application));
    assert!(matches!(
        restored.process_message_with_context(
            &restarted,
            application.clone(),
            serde_json::to_string(&application_context)?,
            "event".into(),
            "team:context".into(),
            0,
            2,
            false
        ),
        Err(MlsError::InvalidMessage)
    ));
    assert_eq!(
        restored.process_message(&restarted, application)?.content,
        Some(b"application".to_vec())
    );
    Ok(())
}
