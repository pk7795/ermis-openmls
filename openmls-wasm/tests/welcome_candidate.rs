use openmls_wasm::{Group, Identity, MlsErrorCode, Provider, WelcomeCandidate};

#[test]
fn welcome_candidate_failure_save_readback_and_concurrent_mutation_preserve_active(
) -> Result<(), String> {
    let mut alice_provider = Provider::new();
    let mut bob_provider = Provider::new();
    let alice = Identity::new(&alice_provider, "alice").map_err(|_| "Alice setup failed")?;
    let bob = Identity::new(&bob_provider, "bob").map_err(|_| "Bob setup failed")?;
    let mut group = Group::create_with_cid(&alice_provider, &alice, "team:candidate-test")
        .map_err(|_| "Group setup failed")?;
    let key_package = bob
        .key_package(&bob_provider)
        .map_err(|_| "KP generation failed")?;
    let commit = group
        .add_members(&alice_provider, &alice, vec![key_package])
        .map_err(|_| "Add failed")?;
    group
        .merge_pending_commit(&mut alice_provider)
        .map_err(|_| "Commit merge failed")?;
    let welcome = commit.welcome().ok_or("Welcome missing")?;
    let before = bob_provider
        .to_bytes()
        .map_err(|_| "Active serialization failed")?;
    assert!(WelcomeCandidate::create(&bob_provider, b"bad welcome", None, false).is_err());
    assert_eq!(
        bob_provider
            .to_bytes()
            .map_err(|_| "Active serialization failed")?,
        before
    );
    let mut candidate = WelcomeCandidate::create(&bob_provider, &welcome, None, false)
        .map_err(|error| error.code_name())?;
    let private_candidate_bytes = candidate
        .provider_bytes()
        .map_err(|error| error.code_name())?;
    assert_eq!(
        bob_provider
            .to_bytes()
            .map_err(|_| "Active serialization failed")?,
        before,
        "no consume in active provider before persistence"
    );
    assert!(candidate
        .activate(&mut bob_provider, b"failed durable readback")
        .is_err());
    assert_eq!(
        bob_provider
            .to_bytes()
            .map_err(|_| "Active serialization failed")?,
        before
    );
    assert_eq!(
        candidate
            .provider_bytes()
            .map_err(|error| error.code_name())?,
        private_candidate_bytes
    );
    // An SDK race must fail closed rather than overwrite the newer package.
    let new_private_package = bob
        .key_package(&bob_provider)
        .map_err(|_| "KP generation failed")?;
    let new_reference = new_private_package
        .hash_ref(&bob_provider)
        .map_err(|_| "Reference failed")?;
    let intervening = bob_provider
        .to_bytes()
        .map_err(|_| "Active serialization failed")?;
    match candidate.activate(&mut bob_provider, &private_candidate_bytes) {
        Err(error) => assert_eq!(error.code(), MlsErrorCode::InvalidState),
        Ok(_) => return Err("candidate overwrote concurrent provider mutation".into()),
    }
    assert_eq!(
        bob_provider
            .to_bytes()
            .map_err(|_| "Active serialization failed")?,
        intervening
    );
    // Rebase an isolated candidate with the original base: the intervening
    // private KP survives while the joined candidate consumes its original KP.
    let rebased = bob_provider
        .rebase_candidate(&before, &private_candidate_bytes)
        .map_err(|error| error.code_name())?;
    assert!(bob
        .owns_key_package_ref(&rebased, new_reference)
        .map_err(|_| "Probe failed")?);
    let rebased_group =
        Group::load(&rebased, "team:candidate-test").map_err(|_| "Rebased group failed")?;
    assert_eq!(rebased_group.epoch(), group.epoch());
    assert_eq!(
        bob_provider
            .to_bytes()
            .map_err(|_| "Active serialization failed")?,
        intervening
    );
    drop(candidate);
    // Candidate discard/restart before Ready leaves original private KP usable.
    let mut retry = WelcomeCandidate::create(&bob_provider, &welcome, None, false)
        .map_err(|error| error.code_name())?;
    let readback = retry.provider_bytes().map_err(|error| error.code_name())?;
    let joined = retry
        .activate(&mut bob_provider, &readback)
        .map_err(|error| error.code_name())?;
    assert_eq!(joined.epoch(), group.epoch());
    assert!(retry.activate(&mut bob_provider, &readback).is_err());
    match WelcomeCandidate::create(&bob_provider, &welcome, None, false) {
        Err(error) => assert_eq!(error.code(), MlsErrorCode::NoMatchingKeyPackage),
        Ok(_) => return Err("Welcome consumed twice".into()),
    }
    Ok(())
}

#[test]
fn candidate_three_way_conflicts_and_malformed_snapshots_fail_without_active_changes(
) -> Result<(), String> {
    fn encode(rows: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut bytes = (rows.len() as u64).to_be_bytes().to_vec();
        for (key, value) in rows {
            bytes.extend((key.len() as u64).to_be_bytes());
            bytes.extend((value.len() as u64).to_be_bytes());
            bytes.extend(*key);
            bytes.extend(*value);
        }
        bytes
    }
    let base = encode(&[(b"a", b"old"), (b"removed", b"old")]);
    let candidate = encode(&[(b"a", b"new"), (b"new", b"added")]);
    let current = encode(&[
        (b"a", b"intervening"),
        (b"removed", b"old"),
        (b"unrelated", b"keep"),
    ]);
    let active = Provider::from_bytes(&current).map_err(|_| "Setup failed")?;
    let before = active.to_bytes().map_err(|_| "Snapshot failed")?;
    match active.rebase_candidate(&base, &candidate) {
        Err(error) => assert_eq!(error.code(), MlsErrorCode::InvalidState),
        Ok(_) => return Err("conflict accepted".into()),
    };
    let mut trailing = base.clone();
    trailing.push(1);
    let malformed = [
        vec![],
        vec![255; 8],
        trailing,
        encode(&[(b"duplicate", b"1"), (b"duplicate", b"2")]),
        encode(&[(b"", b"empty")]),
    ];
    for bytes in malformed {
        match active.rebase_candidate(&bytes, &candidate) {
            Err(error) => assert_eq!(error.code(), MlsErrorCode::StorageCorruption),
            Ok(_) => return Err("corrupt base accepted".into()),
        };
        match active.rebase_candidate(&base, &bytes) {
            Err(error) => assert_eq!(error.code(), MlsErrorCode::StorageCorruption),
            Ok(_) => return Err("corrupt candidate accepted".into()),
        };
        assert_eq!(active.to_bytes().map_err(|_| "Snapshot failed")?, before);
    }
    Ok(())
}
