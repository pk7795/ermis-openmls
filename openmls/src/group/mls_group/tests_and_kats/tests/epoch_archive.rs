use openmls_basic_credential::SignatureKeyPair;
use tls_codec::Serialize as _;

use crate::{
    credentials::test_utils::new_credential,
    group::{mls_group::EpochArchiveError, ProcessMessageError, ValidationError},
    prelude::*,
    test_utils::OpenMlsRustCrypto,
};

fn setup_two_member_group(
    group_id: &[u8],
    mls_group_create_config: MlsGroupCreateConfig,
) -> (
    OpenMlsRustCrypto,
    OpenMlsRustCrypto,
    SignatureKeyPair,
    SignatureKeyPair,
    MlsGroup,
    MlsGroup,
) {
    let ciphersuite = mls_group_create_config.ciphersuite();
    let join_config = mls_group_create_config.join_config().clone();
    let group_id = GroupId::from_slice(group_id);

    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();

    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            &bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap()
        .key_package()
        .to_owned();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential,
    )
    .unwrap();

    let (_, welcome, _) = alice_group
        .add_members(&alice_provider, &alice_signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();
    let bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &join_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    (
        alice_provider,
        bob_provider,
        alice_signer,
        bob_signer,
        alice_group,
        bob_group,
    )
}

fn default_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .max_past_epochs(5)
        .build()
}

fn app_bytes(processed_message: ProcessedMessage) -> Vec<u8> {
    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            application_message.into_bytes()
        }
        other => panic!("expected application message, got {other:?}"),
    }
}

fn message_bytes(message: &MlsMessageOut) -> Vec<u8> {
    message.tls_serialize_detached().unwrap()
}

fn advance_epoch(
    alice_group: &mut MlsGroup,
    alice_provider: &OpenMlsRustCrypto,
    alice_signer: &SignatureKeyPair,
    bob_group: &mut MlsGroup,
    bob_provider: &OpenMlsRustCrypto,
) {
    let commit = alice_group
        .self_update(alice_provider, alice_signer, LeafNodeParameters::default())
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let processed_message = bob_group
        .process_message(
            bob_provider,
            MlsMessageIn::from(commit.into_commit())
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    else {
        panic!("expected staged commit");
    };
    bob_group
        .merge_staged_commit(bob_provider, *staged_commit)
        .unwrap();
}

#[test]
fn epoch_archive_basic_historical_decrypt() {
    let (alice_provider, bob_provider, alice_signer, _bob_signer, mut alice_group, mut bob_group) =
        setup_two_member_group(b"epoch archive basic", default_config());
    let bob_archive = bob_group.export_current_epoch_archive().unwrap();

    let plaintext = b"historical message";
    let queued_message = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .unwrap();
    let ciphertext_bytes = message_bytes(&queued_message);

    let processed_message = bob_group
        .process_message(
            &bob_provider,
            queued_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap();
    assert_eq!(app_bytes(processed_message), plaintext);

    drop(bob_group);
    let recovery_provider = OpenMlsRustCrypto::default();
    let recovered = decrypt_with_epoch_archive(
        recovery_provider.crypto(),
        &bob_archive,
        &ciphertext_bytes,
        RecoveryDecryptOptions::default(),
    )
    .unwrap();
    assert_eq!(recovered.content, plaintext);
    assert!(!recovered.own_message);
}

#[test]
fn epoch_archive_decrypts_own_sent_message() {
    let (alice_provider, _bob_provider, alice_signer, _bob_signer, mut alice_group, _bob_group) =
        setup_two_member_group(b"epoch archive own message", default_config());
    let alice_archive = alice_group.export_current_epoch_archive().unwrap();

    let plaintext = b"own historical message";
    let queued_message = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .unwrap();
    let ciphertext_bytes = message_bytes(&queued_message);

    let own_message_error = alice_group
        .process_message(
            &alice_provider,
            queued_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        own_message_error,
        ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)
    ));

    let recovered = decrypt_with_epoch_archive(
        alice_provider.crypto(),
        &alice_archive,
        &ciphertext_bytes,
        RecoveryDecryptOptions::default(),
    )
    .unwrap();
    assert_eq!(recovered.content, plaintext);
    assert!(recovered.own_message);
}

#[test]
fn epoch_archive_decrypts_past_epoch_beyond_openmls_window() {
    let (alice_provider, bob_provider, alice_signer, _bob_signer, mut alice_group, mut bob_group) =
        setup_two_member_group(b"epoch archive past window", default_config());
    let bob_archive = bob_group.export_current_epoch_archive().unwrap();

    let plaintext = b"epoch one message";
    let queued_message = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .unwrap();
    let ciphertext_bytes = message_bytes(&queued_message);

    for _ in 0..6 {
        advance_epoch(
            &mut alice_group,
            &alice_provider,
            &alice_signer,
            &mut bob_group,
            &bob_provider,
        );
    }
    assert_eq!(bob_group.epoch().as_u64(), 7);

    let normal_error = bob_group
        .process_message(
            &bob_provider,
            queued_message.clone().into_protocol_message().unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        normal_error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_))
    ));

    let recovered = decrypt_with_epoch_archive(
        bob_provider.crypto(),
        &bob_archive,
        &ciphertext_bytes,
        RecoveryDecryptOptions::default(),
    )
    .unwrap();
    assert_eq!(recovered.content, plaintext);
}

#[test]
fn epoch_archive_decrypts_multiple_messages_sorted_by_generation() {
    let (alice_provider, bob_provider, alice_signer, _bob_signer, mut alice_group, bob_group) =
        setup_two_member_group(b"epoch archive sorted batch", default_config());
    let bob_archive = bob_group.export_current_epoch_archive().unwrap();

    let mut archived_messages = Vec::new();
    for generation in 0..6 {
        let plaintext = format!("sorted message {generation}").into_bytes();
        let queued_message = alice_group
            .create_message(&alice_provider, &alice_signer, &plaintext)
            .unwrap();
        let ciphertext_bytes = message_bytes(&queued_message);
        let sender_data =
            peek_sender_data_from_archive(bob_provider.crypto(), &bob_archive, &ciphertext_bytes)
                .unwrap();
        assert_eq!(sender_data.generation, generation);
        archived_messages.push((sender_data.generation, plaintext, ciphertext_bytes));
    }

    archived_messages.reverse();
    archived_messages.sort_by_key(|(generation, _, _)| *generation);
    for (expected_generation, plaintext, ciphertext_bytes) in archived_messages {
        let recovered = decrypt_with_epoch_archive(
            bob_provider.crypto(),
            &bob_archive,
            &ciphertext_bytes,
            RecoveryDecryptOptions::default(),
        )
        .unwrap();
        assert_eq!(recovered.generation, expected_generation);
        assert_eq!(recovered.content, plaintext);
    }
}

#[test]
fn epoch_archive_decrypts_out_of_order_with_fresh_clone_per_message() {
    let (alice_provider, bob_provider, alice_signer, _bob_signer, mut alice_group, bob_group) =
        setup_two_member_group(b"epoch archive out of order", default_config());
    let bob_archive = bob_group.export_current_epoch_archive().unwrap();

    let mut archived_messages = Vec::new();
    for generation in 0..8 {
        let plaintext = format!("out of order message {generation}").into_bytes();
        let queued_message = alice_group
            .create_message(&alice_provider, &alice_signer, &plaintext)
            .unwrap();
        let ciphertext_bytes = message_bytes(&queued_message);
        let sender_data =
            peek_sender_data_from_archive(bob_provider.crypto(), &bob_archive, &ciphertext_bytes)
                .unwrap();
        assert_eq!(sender_data.generation, generation);
        archived_messages.push((plaintext, ciphertext_bytes));
    }

    archived_messages.reverse();
    for (plaintext, ciphertext_bytes) in archived_messages {
        let recovered = decrypt_with_epoch_archive(
            bob_provider.crypto(),
            &bob_archive,
            &ciphertext_bytes,
            RecoveryDecryptOptions::default(),
        )
        .unwrap();
        assert_eq!(recovered.content, plaintext);
    }
}

#[test]
fn epoch_archive_forward_distance_override() {
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .max_past_epochs(5)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(5, 3))
        .build();
    let (alice_provider, bob_provider, alice_signer, _bob_signer, mut alice_group, bob_group) =
        setup_two_member_group(b"epoch archive forward distance", config);
    let bob_archive = bob_group.export_current_epoch_archive().unwrap();

    let mut last_ciphertext = Vec::new();
    for generation in 0..5 {
        let queued_message = alice_group
            .create_message(
                &alice_provider,
                &alice_signer,
                format!("generation {generation}").as_bytes(),
            )
            .unwrap();
        last_ciphertext = message_bytes(&queued_message);
    }
    let sender_data =
        peek_sender_data_from_archive(bob_provider.crypto(), &bob_archive, &last_ciphertext)
            .unwrap();
    assert_eq!(sender_data.generation, 4);

    let default_error = decrypt_with_epoch_archive(
        bob_provider.crypto(),
        &bob_archive,
        &last_ciphertext,
        RecoveryDecryptOptions::default(),
    )
    .unwrap_err();
    assert!(matches!(default_error, EpochArchiveError::Decrypt(_)));

    let recovered = decrypt_with_epoch_archive(
        bob_provider.crypto(),
        &bob_archive,
        &last_ciphertext,
        RecoveryDecryptOptions {
            allow_own_messages: true,
            max_forward_distance: Some(10),
        },
    )
    .unwrap();
    assert_eq!(recovered.generation, 4);
}

#[test]
fn epoch_archive_recovery_does_not_mutate_live_group() {
    let (alice_provider, bob_provider, alice_signer, _bob_signer, mut alice_group, mut bob_group) =
        setup_two_member_group(b"epoch archive no live mutate", default_config());
    let bob_archive = bob_group.export_current_epoch_archive().unwrap();

    let first_plaintext = b"first live message";
    let first_message = alice_group
        .create_message(&alice_provider, &alice_signer, first_plaintext)
        .unwrap();
    let first_ciphertext = message_bytes(&first_message);

    let recovered = decrypt_with_epoch_archive(
        bob_provider.crypto(),
        &bob_archive,
        &first_ciphertext,
        RecoveryDecryptOptions::default(),
    )
    .unwrap();
    assert_eq!(recovered.content, first_plaintext);

    let processed_first = bob_group
        .process_message(
            &bob_provider,
            first_message.into_protocol_message().unwrap(),
        )
        .unwrap();
    assert_eq!(app_bytes(processed_first), first_plaintext);

    let second_plaintext = b"second live message";
    let second_message = alice_group
        .create_message(&alice_provider, &alice_signer, second_plaintext)
        .unwrap();
    let processed_second = bob_group
        .process_message(
            &bob_provider,
            second_message.into_protocol_message().unwrap(),
        )
        .unwrap();
    assert_eq!(app_bytes(processed_second), second_plaintext);
}
