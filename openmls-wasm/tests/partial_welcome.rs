use openmls_wasm::{Group, Identity, MlsErrorCode, Provider};

#[test]
fn malformed_welcome_does_not_authorize_external_join() -> Result<(), String> {
    let provider = Provider::new();
    let error = match Group::join_with_welcome_typed(&provider, &[0x01, 0x02], None) {
        Ok(_) => return Err("malformed Welcome unexpectedly joined".to_string()),
        Err(error) => error,
    };
    assert_eq!(error.code(), MlsErrorCode::DeserializationError);
    assert_ne!(error.code(), MlsErrorCode::NoMatchingKeyPackage);
    Ok(())
}

#[test]
fn welcome_for_another_provider_returns_typed_no_matching_key_package() -> Result<(), String> {
    let mut alice_provider = Provider::new();
    let bob_provider = Provider::new();
    let dave_provider = Provider::new();

    let alice = Identity::new(&alice_provider, "alice").map_err(|error| format!("{error:?}"))?;
    let bob = Identity::new(&bob_provider, "bob").map_err(|error| format!("{error:?}"))?;
    let mut alice_group =
        Group::create_with_cid(&alice_provider, &alice, "team:partial-welcome-typed-error")
            .map_err(|error| format!("{error:?}"))?;
    let add_result = alice_group
        .add_members(
            &alice_provider,
            &alice,
            vec![bob.key_package(&bob_provider)],
        )
        .map_err(|error| format!("{error:?}"))?;
    alice_group
        .merge_pending_commit(&mut alice_provider)
        .map_err(|error| format!("{error:?}"))?;
    let welcome = add_result
        .welcome()
        .ok_or_else(|| "Add commit did not produce Welcome".to_string())?;

    let error = match Group::join_with_welcome_typed(
        &dave_provider,
        &welcome,
        Some(alice_group.export_ratchet_tree()),
    ) {
        Ok(_) => return Err("unrelated provider unexpectedly joined Welcome".to_string()),
        Err(error) => error,
    };
    assert_eq!(error.code(), MlsErrorCode::NoMatchingKeyPackage);
    assert_eq!(error.code_name(), "NoMatchingKeyPackage");
    Ok(())
}
