use openmls_bindings_core::{Identity, Provider};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme, OpenMlsProvider};

#[test]
fn registration_signature_is_domain_bound_and_private_key_stays_local(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "owner".into())?;
    let project = "00000000-0000-0000-0000-000000000001";
    let signature =
        identity.device_registration_signature("device".into(), project.into(), 123456789)?;
    let public = identity.signature_public_key();
    assert_eq!(public.len(), 32);
    assert_eq!(signature.len(), 64);
    let crypto = OpenMlsRustCrypto::default();
    let payload = serde_json::to_vec(&(
        "ermis.mls-device-registration.v1",
        "owner",
        project,
        "device",
        3u16,
        123456789i64,
    ))?;
    assert!(crypto
        .crypto()
        .verify_signature(SignatureScheme::ED25519, &payload, &public, &signature)
        .is_ok());
    assert!(crypto
        .crypto()
        .verify_signature(
            SignatureScheme::ED25519,
            b"arbitrary application payload",
            &public,
            &signature
        )
        .is_err());
    assert!(identity
        .device_registration_signature("".into(), project.into(), 123456789)
        .is_err());
    assert!(identity
        .device_registration_signature("device".into(), project.into(), 0)
        .is_err());
    let bytes = identity.to_bytes()?;
    let restored = Identity::from_bytes(&provider, bytes)?;
    assert_eq!(restored.signature_public_key(), public);
    Ok(())
}

#[test]
fn lor_request_signature_uses_restored_identity_and_shared_codec()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::new();
    let identity = Identity::new(&provider, "owner".into())?;
    let saved = identity.to_bytes()?;
    let restored = Identity::from_bytes(&provider, saved.clone())?;
    let json = r#"{"version":1,"project_id":"00000000-0000-0000-0000-000000000001","device_id":"device","registration_id":"00000000-0000-0000-0000-000000000002","generation":0,"operation":3,"target":"/v1/e2ee/group_info/validation_ack","body_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_id":"00000000-0000-0000-0000-000000000003","issued_at":123456789}"#;
    let context = ermis_lor_request_proof::SigningContext::parse(json)?;
    let signature = restored.lor_request_signature(json.into())?;
    let crypto = OpenMlsRustCrypto::default();
    crypto.crypto().verify_signature(SignatureScheme::ED25519,
        &context.payload("owner",3)?, &restored.signature_public_key(), &signature)
        .map_err(|e| format!("request verify failed: {e:?}"))?;
    assert!(crypto.crypto().verify_signature(SignatureScheme::ED25519,
        &context.payload("another-user",3)?, &restored.signature_public_key(), &signature).is_err());
    assert!(crypto.crypto().verify_signature(SignatureScheme::ED25519,
        b"arbitrary application payload", &restored.signature_public_key(), &signature).is_err());
    assert_eq!(restored.to_bytes()?,saved);
    assert_eq!(restored.signature_public_key(),identity.signature_public_key());
    Ok(())
}

#[test]
fn lor_signing_rejects_unknown_context_before_signing()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::new();
    let identity = Identity::new(&provider,"owner".into())?;
    let before = identity.to_bytes()?;
    for invalid in ["{}".to_string(), "x".repeat(6145), r#"{"version":99}"#.to_string()] {
        assert!(identity.lor_request_signature(invalid).is_err());
    }
    assert_eq!(identity.to_bytes()?,before);
    Ok(())
}
