use openmls_traits::{
    OpenMlsProvider,
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, HpkeCiphertext},
};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use crate::{CIPHERSUITE, Provider};

const MIN_PIN_DIGITS: usize = 8;
const MIN_PBKDF2_ITERATIONS: u32 = 600_000;
const ARCHIVE_BLOB_DOMAIN: &str = "ermis-archive-blob-v1";
const ARCHIVE_ADK_DOMAIN: &str = "ermis-archive-adk-v1";

#[wasm_bindgen]
pub struct RecoveryKeypair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    key_id: String,
    ciphersuite: u16,
}

#[wasm_bindgen]
impl RecoveryKeypair {
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct WrappedRecoveryKey {
    version: u16,
    kdf: String,
    iterations: u32,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_private_key: Vec<u8>,
    public_key: Vec<u8>,
    key_id: String,
    ciphersuite: u16,
}

#[wasm_bindgen]
impl WrappedRecoveryKey {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        serde_json::to_vec(self).map_err(|e| JsError::new(&format!("serialize vault: {e}")))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<WrappedRecoveryKey, JsError> {
        serde_json::from_slice(bytes).map_err(|e| JsError::new(&format!("deserialize vault: {e}")))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct ArchiveBlobAad {
    domain: String,
    cid: String,
    #[serde(default, skip_serializing_if = "is_zero_generation")]
    group_generation: u64,
    epoch: u64,
    scope: String,
    blob_id: String,
    snapshot_hash: String,
}

#[wasm_bindgen]
impl ArchiveBlobAad {
    #[wasm_bindgen(constructor)]
    pub fn new(
        cid: String,
        epoch: u64,
        scope: String,
        blob_id: String,
        snapshot_hash: String,
    ) -> Self {
        Self {
            domain: ARCHIVE_BLOB_DOMAIN.to_string(),
            cid,
            group_generation: 0,
            epoch,
            scope,
            blob_id,
            snapshot_hash,
        }
    }
    #[wasm_bindgen(js_name = forGeneration)]
    pub fn for_generation(
        cid: String,
        group_generation: u64,
        epoch: u64,
        scope: String,
        blob_id: String,
        snapshot_hash: String,
    ) -> Self {
        Self {
            domain: ARCHIVE_BLOB_DOMAIN.to_string(),
            cid,
            group_generation,
            epoch,
            scope,
            blob_id,
            snapshot_hash,
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        serde_json::to_vec(self).map_err(|e| JsError::new(&format!("serialize archive AAD: {e}")))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct ArchiveKeyWrapInfo {
    domain: String,
    channel_id: String,
    #[serde(default, skip_serializing_if = "is_zero_generation")]
    group_generation: u64,
    epoch: u64,
    scope: String,
    blob_id: String,
    snapshot_hash: String,
    recipient_key_id: String,
}

#[wasm_bindgen]
impl ArchiveKeyWrapInfo {
    #[wasm_bindgen(constructor)]
    pub fn new(
        channel_id: String,
        epoch: u64,
        scope: String,
        blob_id: String,
        snapshot_hash: String,
        recipient_key_id: String,
    ) -> Self {
        Self {
            domain: ARCHIVE_ADK_DOMAIN.to_string(),
            channel_id,
            group_generation: 0,
            epoch,
            scope,
            blob_id,
            snapshot_hash,
            recipient_key_id,
        }
    }
    #[wasm_bindgen(js_name = forGeneration)]
    pub fn for_generation(
        channel_id: String,
        group_generation: u64,
        epoch: u64,
        scope: String,
        blob_id: String,
        snapshot_hash: String,
        recipient_key_id: String,
    ) -> Self {
        Self {
            domain: ARCHIVE_ADK_DOMAIN.to_string(),
            channel_id,
            group_generation,
            epoch,
            scope,
            blob_id,
            snapshot_hash,
            recipient_key_id,
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        serde_json::to_vec(self).map_err(|e| JsError::new(&format!("serialize HPKE info: {e}")))
    }
}

fn is_zero_generation(value: &u64) -> bool {
    *value == 0
}

#[wasm_bindgen]
pub struct EncryptedArchiveBlob {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    aead_aad: Vec<u8>,
    adk: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedArchiveBlob {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn aead_aad(&self) -> Vec<u8> {
        self.aead_aad.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn adk(&self) -> Vec<u8> {
        self.adk.clone()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct HpkeWrappedArchiveDataKey {
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
    ciphersuite: u16,
    hpke_info: Vec<u8>,
}

#[wasm_bindgen]
impl HpkeWrappedArchiveDataKey {
    #[wasm_bindgen(getter)]
    pub fn kem_output(&self) -> Vec<u8> {
        self.kem_output.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
    #[wasm_bindgen(getter)]
    pub fn hpke_info(&self) -> Vec<u8> {
        self.hpke_info.clone()
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        serde_json::to_vec(self).map_err(|e| JsError::new(&format!("serialize HPKE wrap: {e}")))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<HpkeWrappedArchiveDataKey, JsError> {
        serde_json::from_slice(bytes)
            .map_err(|e| JsError::new(&format!("deserialize HPKE wrap: {e}")))
    }
}

#[wasm_bindgen]
pub fn generate_recovery_keypair(provider: &Provider) -> Result<RecoveryKeypair, JsError> {

let value = openmls_recovery::generate_recovery_keypair(&provider.0).map_err(core_error)?;
Ok(RecoveryKeypair { private_key: value.private_key, public_key: value.public_key, key_id: value.key_id, ciphersuite: value.ciphersuite })
}

#[wasm_bindgen]
pub fn wrap_recovery_private_key(
    provider: &Provider,
    pin: &str,
    private_key: &[u8],
    public_key: &[u8],
    key_id: &str,
    ciphersuite: u16,
    iterations: u32,
) -> Result<WrappedRecoveryKey, JsError> {

let value = openmls_recovery::wrap_recovery_private_key(&provider.0, pin, private_key, public_key, key_id, ciphersuite, iterations).map_err(core_error)?;
Ok(WrappedRecoveryKey { version: value.version, kdf: value.kdf, iterations: value.iterations, salt: value.salt, nonce: value.nonce, wrapped_private_key: value.wrapped_private_key, public_key: value.public_key, key_id: value.key_id, ciphersuite: value.ciphersuite })
}

#[wasm_bindgen]
pub fn unwrap_recovery_private_key(
    provider: &Provider,
    pin: &str,
    wrapped: &WrappedRecoveryKey,
) -> Result<Vec<u8>, JsError> {
let core_wrapped = openmls_recovery::WrappedRecoveryKey::from_bytes(&wrapped.to_bytes()?).map_err(core_error)?;
openmls_recovery::unwrap_recovery_private_key(&provider.0, pin, &core_wrapped).map_err(core_error)
}

#[wasm_bindgen]
pub fn encrypt_archive_blob(
    provider: &Provider,
    archive_bytes: &[u8],
    aad: &ArchiveBlobAad,
) -> Result<EncryptedArchiveBlob, JsError> {
let core_aad: openmls_recovery::ArchiveBlobAad = serde_json::from_slice(&aad.to_bytes()?).map_err(|_| JsError::new("Invalid archive AAD"))?;
let value = openmls_recovery::encrypt_archive_blob(&provider.0, archive_bytes, &core_aad).map_err(core_error)?;
Ok(EncryptedArchiveBlob { ciphertext: value.ciphertext, nonce: value.nonce, aead_aad: value.aead_aad, adk: value.adk })
}

#[wasm_bindgen]
pub fn decrypt_archive_blob(
    provider: &Provider,
    adk: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aead_aad: &[u8],
) -> Result<Vec<u8>, JsError> {

openmls_recovery::decrypt_archive_blob(&provider.0, adk, ciphertext, nonce, aead_aad).map_err(core_error)
}

#[wasm_bindgen]
pub fn wrap_archive_data_key(
    provider: &Provider,
    adk: &[u8],
    recipient_recovery_public_key: &[u8],
    info: &ArchiveKeyWrapInfo,
) -> Result<HpkeWrappedArchiveDataKey, JsError> {
let core_info: openmls_recovery::ArchiveKeyWrapInfo = serde_json::from_slice(&info.to_bytes()?).map_err(|_| JsError::new("Invalid archive HPKE info"))?;
let value = openmls_recovery::wrap_archive_data_key(&provider.0, adk, recipient_recovery_public_key, &core_info).map_err(core_error)?;
Ok(HpkeWrappedArchiveDataKey { kem_output: value.kem_output, ciphertext: value.ciphertext, ciphersuite: value.ciphersuite, hpke_info: value.hpke_info })
}

#[wasm_bindgen]
pub fn unwrap_archive_data_key(
    provider: &Provider,
    recovery_private_key: &[u8],
    wrapped: &HpkeWrappedArchiveDataKey,
) -> Result<Vec<u8>, JsError> {
let core_wrapped = openmls_recovery::HpkeWrappedArchiveDataKey::from_bytes(&wrapped.to_bytes()?).map_err(core_error)?;
openmls_recovery::unwrap_archive_data_key(&provider.0, recovery_private_key, &core_wrapped).map_err(core_error)
}

#[wasm_bindgen]
pub fn unwrap_archive_data_key_from_parts(
    provider: &Provider,
    recovery_private_key: &[u8],
    kem_output: &[u8],
    ciphertext: &[u8],
    hpke_info: &[u8],
) -> Result<Vec<u8>, JsError> {

openmls_recovery::unwrap_archive_data_key_from_parts(&provider.0, recovery_private_key, kem_output, ciphertext, hpke_info).map_err(core_error)
}

fn validate_pin(pin: &str) -> Result<(), JsError> {
    if pin.len() < MIN_PIN_DIGITS || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(JsError::new("PIN must be at least 8 digits"));
    }
    Ok(())
}

fn derive_pin_key(pin: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin.as_bytes(), salt, iterations, &mut key);
    key
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    #[test]
    fn generation_zero_archive_aad_keeps_legacy_bytes() {
        let aad = ArchiveBlobAad::new(
            "messaging:cid".to_owned(),
            7,
            "account_owned".to_owned(),
            "blob".to_owned(),
            "snapshot".to_owned(),
        );
        let bytes = serde_json::to_vec(&aad).unwrap_or_default();
        assert_eq!(
            bytes,
            br#"{"domain":"ermis-archive-blob-v1","cid":"messaging:cid","epoch":7,"scope":"account_owned","blob_id":"blob","snapshot_hash":"snapshot"}"#
        );
    }

    #[test]
    fn archive_domains_separate_same_epoch_across_generations() {
        let generation_one = ArchiveBlobAad::for_generation(
            "messaging:cid".to_owned(),
            1,
            7,
            "account_owned".to_owned(),
            "blob".to_owned(),
            "snapshot".to_owned(),
        );
        let generation_two = ArchiveBlobAad::for_generation(
            "messaging:cid".to_owned(),
            2,
            7,
            "account_owned".to_owned(),
            "blob".to_owned(),
            "snapshot".to_owned(),
        );
        assert_ne!(
            serde_json::to_vec(&generation_one).unwrap_or_default(),
            serde_json::to_vec(&generation_two).unwrap_or_default()
        );

        let wrap = ArchiveKeyWrapInfo::for_generation(
            "messaging:cid".to_owned(),
            2,
            7,
            "account_owned".to_owned(),
            "blob".to_owned(),
            "snapshot".to_owned(),
            "recovery-key".to_owned(),
        );
        let wrap_json = serde_json::to_value(&wrap).unwrap_or_default();
        assert_eq!(wrap_json["group_generation"], 2);
    }
}

fn core_error(error: openmls_recovery::RecoveryError) -> JsError { JsError::new(&error.to_string()) }
