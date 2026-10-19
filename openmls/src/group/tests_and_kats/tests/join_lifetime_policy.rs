//! Join-tree availability must not relax fresh Add or cryptographic validation.
use crate::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

fn credential(
    name: &[u8],
) -> Result<(CredentialWithKey, SignatureKeyPair), Box<dyn std::error::Error>> {
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519)?;
    Ok((
        CredentialWithKey {
            credential: BasicCredential::new(name.to_vec()).into(),
            signature_key: signer.public().into(),
        },
        signer,
    ))
}

struct Fixture {
    alice_provider: OpenMlsRustCrypto,
    alice_signer: SignatureKeyPair,
    alice: MlsGroup,
    charlie_provider: OpenMlsRustCrypto,
    charlie_credential: CredentialWithKey,
    welcome: Welcome,
}

fn fixture(now: u64, bob_lifetime: Lifetime) -> Result<Fixture, Box<dyn std::error::Error>> {
    Lifetime::with_test_unix_time(now, || {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let charlie_provider = OpenMlsRustCrypto::default();
        let (alice_credential, alice_signer) = credential(b"alice")?;
        let (bob_credential, bob_signer) = credential(b"bob")?;
        let (charlie_credential, charlie_signer) = credential(b"charlie")?;
        let mut alice = MlsGroup::builder()
            .ciphersuite(ciphersuite)
            .with_group_id(GroupId::from_slice(b"join-lifetime-policy"))
            .use_ratchet_tree_extension(true)
            .build(&alice_provider, &alice_signer, alice_credential)?;
        let bob_kp = KeyPackage::builder()
            .key_package_lifetime(bob_lifetime)
            .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)?;
        alice.add_members(
            &alice_provider,
            &alice_signer,
            &[bob_kp.key_package().clone()],
        )?;
        alice.merge_pending_commit(&alice_provider)?;
        let charlie_kp = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(now - 60, now + 1000))
            .build(
                ciphersuite,
                &charlie_provider,
                &charlie_signer,
                charlie_credential.clone(),
            )?;
        let (_, welcome, _) = alice.add_members(
            &alice_provider,
            &alice_signer,
            &[charlie_kp.key_package().clone()],
        )?;
        alice.merge_pending_commit(&alice_provider)?;
        let welcome = match MlsMessageIn::from(welcome).extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err("wrong Welcome fixture".into()),
        };
        Ok(Fixture {
            alice_provider,
            alice_signer,
            alice,
            charlie_provider,
            charlie_credential,
            welcome,
        })
    })
}

fn now() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

#[test]
fn welcome_allows_expired_tree_leaves_but_legacy_verify_rejects(
) -> Result<(), Box<dyn std::error::Error>> {
    let _validation_guard = crate::skip_validation::checks::leaf_node_lifetime::handle();
    let start = now()?;
    let fixture = fixture(start, Lifetime::init(start - 60, start + 60))?;
    // Default Verify fails without using the same private bundle a second time.
    // Core consumes eagerly; the production native wrapper rolls this back.
    let before = fixture
        .charlie_provider
        .storage()
        .values
        .read()
        .map_err(|_| "storage poisoned")?
        .clone();
    Lifetime::with_test_unix_time(start + 60, || {
        assert!(StagedWelcome::build_from_welcome(
            &fixture.charlie_provider,
            &MlsGroupJoinConfig::default(),
            fixture.welcome.clone()
        )?
        .build()
        .is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    *fixture
        .charlie_provider
        .storage()
        .values
        .write()
        .map_err(|_| "storage poisoned")? = before;
    Lifetime::with_test_unix_time(start + 61, || {
        let staged = StagedWelcome::build_from_welcome(
            &fixture.charlie_provider,
            &MlsGroupJoinConfig::default(),
            fixture.welcome,
        )?
        .lifetime_policy(LeafNodeLifetimePolicy::AllowExpired)
        .build()?;
        let group = staged.into_group(&fixture.charlie_provider)?;
        assert_eq!(group.epoch(), fixture.alice.epoch());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn allow_expired_does_not_allow_not_before_boundary_or_future_leaf(
) -> Result<(), Box<dyn std::error::Error>> {
    let _validation_guard = crate::skip_validation::checks::leaf_node_lifetime::handle();
    let start = now()?;
    let fixture = fixture(start + 100, Lifetime::init(start + 99, start + 160))?;
    Lifetime::with_test_unix_time(start + 99, || {
        let result = StagedWelcome::build_from_welcome(
            &fixture.charlie_provider,
            &MlsGroupJoinConfig::default(),
            fixture.welcome,
        )?
        .lifetime_policy(LeafNodeLifetimePolicy::AllowExpired)
        .build();
        assert!(result.is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[test]
fn external_join_allows_expired_leaf_and_rejects_tampered_group_info(
) -> Result<(), Box<dyn std::error::Error>> {
    let _validation_guard = crate::skip_validation::checks::leaf_node_lifetime::handle();
    let start = now()?;
    let fixture = fixture(start, Lifetime::init(start - 60, start + 60))?;
    let group_info = fixture.alice.export_group_info(
        fixture.alice_provider.crypto(),
        &fixture.alice_signer,
        true,
    )?;
    let gi = group_info
        .clone()
        .into_verifiable_group_info()
        .ok_or("missing GI")?;
    Lifetime::with_test_unix_time(start + 61, || {
        assert!(MlsGroup::external_commit_builder()
            .build_group(
                &fixture.charlie_provider,
                gi.clone(),
                fixture.charlie_credential.clone()
            )
            .is_err());
        MlsGroup::external_commit_builder()
            .lifetime_policy(LeafNodeLifetimePolicy::AllowExpired)
            .build_group(
                &fixture.charlie_provider,
                gi,
                fixture.charlie_credential.clone(),
            )?;
        let mut corrupt = group_info.tls_serialize_detached()?;
        *corrupt.last_mut().ok_or("empty GI")? ^= 1;
        let bad = match MlsMessageIn::tls_deserialize_exact(&corrupt)?.extract() {
            MlsMessageBodyIn::GroupInfo(gi) => gi,
            _ => return Err("wrong GI fixture".into()),
        };
        assert!(MlsGroup::external_commit_builder()
            .lifetime_policy(LeafNodeLifetimePolicy::AllowExpired)
            .build_group(&fixture.charlie_provider, bad, fixture.charlie_credential)
            .is_err());
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}
