//! Recovery cryptography shared with the web. No MLS provider state is changed.
use crate::MlsError;
use openmls_recovery as core;
use openmls_rust_crypto::OpenMlsRustCrypto;

#[derive(Clone)]
pub struct RecoveryKeys {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub ciphersuite: u16,
}
#[derive(Clone)]
pub struct RecoveryVaultMetadata {
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub ciphersuite: u16,
}
#[derive(Clone)]
pub struct RecoveryArchiveBlob {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aead_aad: Vec<u8>,
    pub adk: Vec<u8>,
}
#[derive(Clone)]
pub struct RecoveryArchiveWrap {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphersuite: u16,
    pub hpke_info: Vec<u8>,
}
fn failure(_: core::RecoveryError) -> MlsError {
    MlsError::CryptoError
}
pub fn generate_recovery_keys() -> Result<RecoveryKeys, MlsError> {
    let k = core::generate_recovery_keypair(&OpenMlsRustCrypto::default()).map_err(failure)?;
    Ok(RecoveryKeys {
        private_key: k.private_key,
        public_key: k.public_key,
        key_id: k.key_id,
        ciphersuite: k.ciphersuite,
    })
}
pub fn create_recovery_vault(pin: String, keys: RecoveryKeys) -> Result<Vec<u8>, MlsError> {
    core::wrap_recovery_private_key(
        &OpenMlsRustCrypto::default(),
        &pin,
        &keys.private_key,
        &keys.public_key,
        &keys.key_id,
        keys.ciphersuite,
        600_000,
    )
    .and_then(|v| v.to_bytes())
    .map_err(failure)
}
pub fn recovery_vault_metadata(vault: Vec<u8>) -> Result<RecoveryVaultMetadata, MlsError> {
    let v = core::WrappedRecoveryKey::from_bytes(&vault).map_err(failure)?;
    Ok(RecoveryVaultMetadata {
        public_key: v.public_key,
        key_id: v.key_id,
        ciphersuite: v.ciphersuite,
    })
}
pub fn unlock_recovery_vault(pin: String, vault: Vec<u8>) -> Result<Vec<u8>, MlsError> {
    let v = core::WrappedRecoveryKey::from_bytes(&vault).map_err(failure)?;
    core::unwrap_recovery_private_key(&OpenMlsRustCrypto::default(), &pin, &v).map_err(failure)
}
pub fn seal_recovery_archive(
    archive: Vec<u8>,
    cid: String,
    group_generation: u64,
    epoch: u64,
    scope: String,
    blob_id: String,
    snapshot_hash: String,
) -> Result<RecoveryArchiveBlob, MlsError> {
    let aad = core::ArchiveBlobAad::for_generation(
        cid,
        group_generation,
        epoch,
        scope,
        blob_id,
        snapshot_hash,
    );
    let b = core::encrypt_archive_blob(&OpenMlsRustCrypto::default(), &archive, &aad)
        .map_err(failure)?;
    Ok(RecoveryArchiveBlob {
        ciphertext: b.ciphertext,
        nonce: b.nonce,
        aead_aad: b.aead_aad,
        adk: b.adk,
    })
}
pub fn wrap_recovery_archive_key(
    adk: Vec<u8>,
    public_key: Vec<u8>,
    cid: String,
    group_generation: u64,
    epoch: u64,
    scope: String,
    blob_id: String,
    snapshot_hash: String,
    key_id: String,
) -> Result<RecoveryArchiveWrap, MlsError> {
    let info = core::ArchiveKeyWrapInfo::for_generation(
        cid,
        group_generation,
        epoch,
        scope,
        blob_id,
        snapshot_hash,
        key_id,
    );
    let w = core::wrap_archive_data_key(&OpenMlsRustCrypto::default(), &adk, &public_key, &info)
        .map_err(failure)?;
    Ok(RecoveryArchiveWrap {
        kem_output: w.kem_output,
        ciphertext: w.ciphertext,
        ciphersuite: w.ciphersuite,
        hpke_info: w.hpke_info,
    })
}
pub fn open_recovery_archive(
    private_key: Vec<u8>,
    blob: RecoveryArchiveBlob,
    wrap: RecoveryArchiveWrap,
) -> Result<Vec<u8>, MlsError> {
    let aad: core::ArchiveBlobAad =
        serde_json::from_slice(&blob.aead_aad).map_err(|_| MlsError::CryptoError)?;
    let info: core::ArchiveKeyWrapInfo =
        serde_json::from_slice(&wrap.hpke_info).map_err(|_| MlsError::CryptoError)?;
    if aad.domain != "ermis-archive-blob-v1"
        || info.domain != "ermis-archive-adk-v1"
        || aad.cid != info.channel_id
        || aad.group_generation != info.group_generation
        || aad.epoch != info.epoch
        || aad.scope != info.scope
        || aad.blob_id != info.blob_id
        || aad.snapshot_hash != info.snapshot_hash
        || wrap.ciphersuite != 3
    {
        return Err(MlsError::CryptoError);
    }
    let w = core::HpkeWrappedArchiveDataKey {
        kem_output: wrap.kem_output,
        ciphertext: wrap.ciphertext,
        ciphersuite: wrap.ciphersuite,
        hpke_info: wrap.hpke_info,
    };
    let p = OpenMlsRustCrypto::default();
    let adk = core::unwrap_archive_data_key(&p, &private_key, &w).map_err(failure)?;
    core::decrypt_archive_blob(&p, &adk, &blob.ciphertext, &blob.nonce, &blob.aead_aad)
        .map_err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vault_and_archive_roundtrip_reject_wrong_pin_recipient_and_generation() {
        let keys = generate_recovery_keys().unwrap();
        let vault = create_recovery_vault("12345678".into(), keys.clone()).unwrap();
        assert_eq!(
            unlock_recovery_vault("12345678".into(), vault.clone()).unwrap(),
            keys.private_key
        );
        assert!(unlock_recovery_vault("87654321".into(), vault).is_err());
        for generation in [0, 3] {
            let blob = seal_recovery_archive(
                vec![42, 43],
                "messaging:test".into(),
                generation,
                7,
                "account_owned".into(),
                "blob".into(),
                "hash".into(),
            )
            .unwrap();
            let wrap = wrap_recovery_archive_key(
                blob.adk.clone(),
                keys.public_key.clone(),
                "messaging:test".into(),
                generation,
                7,
                "account_owned".into(),
                "blob".into(),
                "hash".into(),
                keys.key_id.clone(),
            )
            .unwrap();
            assert_eq!(
                open_recovery_archive(keys.private_key.clone(), blob.clone(), wrap.clone())
                    .unwrap(),
                vec![42, 43]
            );
            let wrong = generate_recovery_keys().unwrap();
            assert!(open_recovery_archive(wrong.private_key, blob.clone(), wrap.clone()).is_err());
            let mut mismatch = blob.clone();
            let mut aad: serde_json::Value = serde_json::from_slice(&mismatch.aead_aad).unwrap();
            aad["group_generation"] = serde_json::json!(generation + 1);
            mismatch.aead_aad = serde_json::to_vec(&aad).unwrap();
            assert!(
                open_recovery_archive(keys.private_key.clone(), mismatch, wrap.clone()).is_err()
            );
            let mut tampered = blob;
            tampered.ciphertext[0] ^= 1;
            assert!(open_recovery_archive(keys.private_key.clone(), tampered, wrap).is_err());
        }
    }
}
