//! Regression coverage for delayed delivery of Add commits.
//!
//! RFC 9420 permits a KeyPackage to expire between commit creation and receipt by
//! another group member. The receiving member must not become permanently stuck
//! on the old epoch solely because wall-clock time advanced while it was offline.

use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    prelude::*,
    test_utils::single_group_test_framework::{AddMemberConfig, CorePartyState, GroupState},
};

const COMMIT_ACCEPTED_AT: u64 = 1_000_000;
const KEY_PACKAGE_EXPIRES_AT: u64 = COMMIT_ACCEPTED_AT + 60;

#[test]
fn outgoing_add_still_rejects_an_expired_key_package() -> Result<(), String> {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_party = CorePartyState::<OpenMlsRustCrypto>::new("fresh-alice");
    let bob_party = CorePartyState::<OpenMlsRustCrypto>::new("expired-bob");
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_lifetime(Lifetime::init(
            COMMIT_ACCEPTED_AT - 60,
            KEY_PACKAGE_EXPIRES_AT,
        ))
        .build();
    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"fresh-key-package-validation"),
        alice_pre_group,
        create_config,
    )
    .map_err(|error| format!("failed to create fresh validation group: {error:?}"))?;
    let key_package = bob_pre_group.key_package_bundle.key_package().clone();

    let result = Lifetime::with_test_unix_time(KEY_PACKAGE_EXPIRES_AT + 1, || {
        let [alice] = group_state.members_mut(&["fresh-alice"]);
        alice.group.add_members(
            &alice.party.core_state.provider,
            &alice.party.signer,
            &[key_package],
        )
    });

    assert!(
        result.is_err(),
        "outgoing Add must keep strict current-time KeyPackage validation"
    );
    Ok(())
}

#[test]
fn delayed_add_commit_remains_processable_after_key_package_expiry() -> Result<(), String> {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice_party = CorePartyState::<OpenMlsRustCrypto>::new("alice");
    let bob_party = CorePartyState::<OpenMlsRustCrypto>::new("bob");
    let charlie_party = CorePartyState::<OpenMlsRustCrypto>::new("charlie");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party
        .pre_group_builder(ciphersuite)
        .with_lifetime(Lifetime::init(
            COMMIT_ACCEPTED_AT - 60,
            KEY_PACKAGE_EXPIRES_AT,
        ))
        .build();

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();
    let mut group_state = GroupState::new_from_party(
        GroupId::from_slice(b"delayed-key-package-lifetime"),
        alice_pre_group,
        create_config,
    )
    .map_err(|error| format!("failed to create Alice's group: {error:?}"))?;

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .map_err(|error| format!("failed to establish the Alice/Bob baseline group: {error:?}"))?;

    let commit = Lifetime::with_test_unix_time(COMMIT_ACCEPTED_AT, || {
        assert!(
            charlie_pre_group
                .key_package_bundle
                .key_package()
                .life_time()
                .is_valid(),
            "precondition: Charlie's KeyPackage must be valid when Bob creates the Add commit"
        );

        let charlie_key_package = charlie_pre_group.key_package_bundle.key_package().clone();
        let [bob] = group_state.members_mut(&["bob"]);
        let add_result = bob.group.add_members(
            &bob.party.core_state.provider,
            &bob.party.signer,
            &[charlie_key_package],
        );
        let (commit, _welcome, _group_info) =
            add_result.map_err(|error| format!("Bob failed to create Add(Charlie): {error:?}"))?;

        bob.group
            .merge_pending_commit(&bob.party.core_state.provider)
            .map_err(|error| format!("Bob failed to merge Add(Charlie): {error:?}"))?;
        Ok::<_, String>(commit)
    })?;

    Lifetime::with_test_unix_time(KEY_PACKAGE_EXPIRES_AT + 1, || {
        assert!(
            !charlie_pre_group
                .key_package_bundle
                .key_package()
                .life_time()
                .is_valid(),
            "precondition: Charlie's KeyPackage must be expired when Alice receives the commit"
        );

        let [alice] = group_state.members_mut(&["alice"]);
        let message_secrets_before_replay = alice.group.message_secrets_store().clone();
        let protocol_message = MlsMessageIn::from(commit.clone())
            .try_into_protocol_message()
            .map_err(|error| format!("failed to extract delayed commit: {error:?}"))?;

        let tampered_result = alice.group.process_message_at(
            &alice.party.core_state.provider,
            protocol_message,
            KEY_PACKAGE_EXPIRES_AT + 1,
        );
        assert!(
            matches!(
                tampered_result,
                Err(ProcessMessageError::ValidationError(
                    ValidationError::KeyPackageVerifyError(KeyPackageVerifyError::InvalidLifetime)
                ))
            ),
            "a server acceptance timestamp outside the signed lifetime must fail closed"
        );
        assert_ne!(
            alice.group.message_secrets_store(),
            &message_secrets_before_replay,
            "private-message decryption should exercise the in-memory receiver ratchet"
        );

        // Reload the last durable state to model a process restart after the
        // failed attempt. The same commit must remain processable when replayed
        // with its original trusted acceptance timestamp.
        let reloaded = MlsGroup::load(
            alice.party.core_state.provider.storage(),
            alice.group.group_id(),
        )
        .map_err(|error| format!("failed to reload Alice's durable group: {error:?}"))?
        .ok_or_else(|| "Alice's durable group disappeared during restart".to_owned())?;
        assert_eq!(
            reloaded.message_secrets_store(),
            &message_secrets_before_replay,
            "failed contextual validation must not persist receiver-ratchet advancement"
        );
        alice.group = reloaded;

        let protocol_message = MlsMessageIn::from(commit)
            .try_into_protocol_message()
            .map_err(|error| {
                format!("failed to extract delayed commit after restart: {error:?}")
            })?;
        let processed = alice
            .group
            .process_message_at(
                &alice.party.core_state.provider,
                protocol_message,
                COMMIT_ACCEPTED_AT,
            )
            .map_err(|error| {
                format!(
                    "offline replay with the durable acceptance timestamp must succeed: {error:?}"
                )
            })?;
        let message_secrets_after_success = alice.group.message_secrets_store().clone();
        assert_ne!(
            message_secrets_after_success, message_secrets_before_replay,
            "successful private historical processing must advance the receiver ratchet"
        );
        let reloaded_after_success = MlsGroup::load(
            alice.party.core_state.provider.storage(),
            alice.group.group_id(),
        )
        .map_err(|error| format!("failed to reload Alice after successful replay: {error:?}"))?
        .ok_or_else(|| "Alice's durable group disappeared after successful replay".to_owned())?;
        assert_eq!(
            reloaded_after_success.message_secrets_store(),
            &message_secrets_after_success,
            "successful contextual validation must persist receiver-ratchet advancement"
        );
        alice.group = reloaded_after_success;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                alice
                    .group
                    .merge_staged_commit(&alice.party.core_state.provider, *staged_commit)
                    .map_err(|error| format!("failed to merge delayed commit: {error:?}"))?;
            }
            other => return Err(format!("expected staged commit, got {other:?}")),
        }
        Ok::<_, String>(())
    })?;

    assert!(
        group_state.members_mut(&["alice"])[0].group.epoch()
            == group_state.members_mut(&["bob"])[0].group.epoch(),
        "offline replay must converge Alice and Bob on the same epoch"
    );
    Ok(())
}
