use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::Ciphersuite;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, HpkeCiphertext},
    OpenMlsProvider,
};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RecoveryError(String);
impl RecoveryError {
    pub fn new(message: &str) -> Self {
        Self(message.to_owned())
    }
}
impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for RecoveryError {}
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

const MIN_PIN_DIGITS: usize = 8;
const MIN_PBKDF2_ITERATIONS: u32 = 600_000;
const ARCHIVE_BLOB_DOMAIN: &str = "ermis-archive-blob-v1";
const ARCHIVE_ADK_DOMAIN: &str = "ermis-archive-adk-v1";

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryKeypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub ciphersuite: u16,
}

impl RecoveryKeypair {
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedRecoveryKey {
    pub version: u16,
    pub kdf: String,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub ciphersuite: u16,
}

impl WrappedRecoveryKey {
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        serde_json::to_vec(self).map_err(|e| RecoveryError::new(&format!("serialize vault: {e}")))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<WrappedRecoveryKey, RecoveryError> {
        serde_json::from_slice(bytes)
            .map_err(|e| RecoveryError::new(&format!("deserialize vault: {e}")))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ArchiveBlobAad {
    pub domain: String,
    pub cid: String,
    #[serde(default, skip_serializing_if = "is_zero_generation")]
    pub group_generation: u64,
    pub epoch: u64,
    pub scope: String,
    pub blob_id: String,
    pub snapshot_hash: String,
}

impl ArchiveBlobAad {
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        serde_json::to_vec(self)
            .map_err(|e| RecoveryError::new(&format!("serialize archive AAD: {e}")))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ArchiveKeyWrapInfo {
    pub domain: String,
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "is_zero_generation")]
    pub group_generation: u64,
    pub epoch: u64,
    pub scope: String,
    pub blob_id: String,
    pub snapshot_hash: String,
    pub recipient_key_id: String,
}

impl ArchiveKeyWrapInfo {
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        serde_json::to_vec(self)
            .map_err(|e| RecoveryError::new(&format!("serialize HPKE info: {e}")))
    }
}

fn is_zero_generation(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedArchiveBlob {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aead_aad: Vec<u8>,
    pub adk: Vec<u8>,
}

impl EncryptedArchiveBlob {
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
    pub fn aead_aad(&self) -> Vec<u8> {
        self.aead_aad.clone()
    }
    pub fn adk(&self) -> Vec<u8> {
        self.adk.clone()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HpkeWrappedArchiveDataKey {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphersuite: u16,
    pub hpke_info: Vec<u8>,
}

impl HpkeWrappedArchiveDataKey {
    pub fn kem_output(&self) -> Vec<u8> {
        self.kem_output.clone()
    }
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
    pub fn ciphersuite(&self) -> u16 {
        self.ciphersuite
    }
    pub fn hpke_info(&self) -> Vec<u8> {
        self.hpke_info.clone()
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        serde_json::to_vec(self)
            .map_err(|e| RecoveryError::new(&format!("serialize HPKE wrap: {e}")))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<HpkeWrappedArchiveDataKey, RecoveryError> {
        serde_json::from_slice(bytes)
            .map_err(|e| RecoveryError::new(&format!("deserialize HPKE wrap: {e}")))
    }
}

pub fn generate_recovery_keypair(
    provider: &OpenMlsRustCrypto,
) -> Result<RecoveryKeypair, RecoveryError> {
    let ikm = provider
        .rand()
        .random_vec(32)
        .map_err(|e| RecoveryError::new(&format!("recovery keypair random: {e:?}")))?;
    let keypair = provider
        .crypto()
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), &ikm)
        .map_err(|e| RecoveryError::new(&format!("derive recovery keypair: {e:?}")))?;
    let public_key = keypair.public.to_vec();
    let key_id = hex::encode(&Sha256::digest(&public_key)[..16]);
    Ok(RecoveryKeypair {
        private_key: keypair.private.to_vec(),
        public_key,
        key_id,
        ciphersuite: CIPHERSUITE.into(),
    })
}

pub fn wrap_recovery_private_key(
    provider: &OpenMlsRustCrypto,
    pin: &str,
    private_key: &[u8],
    public_key: &[u8],
    key_id: &str,
    ciphersuite: u16,
    iterations: u32,
) -> Result<WrappedRecoveryKey, RecoveryError> {
    validate_pin(pin)?;
    if iterations < MIN_PBKDF2_ITERATIONS {
        return Err(RecoveryError::new("PBKDF2 iterations must be >= 600,000"));
    }
    let salt = provider
        .rand()
        .random_vec(16)
        .map_err(|e| RecoveryError::new(&format!("{e:?}")))?;
    let nonce = provider
        .rand()
        .random_vec(12)
        .map_err(|e| RecoveryError::new(&format!("{e:?}")))?;
    let key = derive_pin_key(pin, &salt, iterations);
    let wrapped_private_key = provider
        .crypto()
        .aead_encrypt(
            AeadType::Aes256Gcm,
            &key,
            private_key,
            &nonce,
            key_id.as_bytes(),
        )
        .map_err(|e| RecoveryError::new(&format!("wrap recovery key: {e:?}")))?;
    Ok(WrappedRecoveryKey {
        version: 1,
        kdf: "PBKDF2-SHA256".to_string(),
        iterations,
        salt,
        nonce,
        wrapped_private_key,
        public_key: public_key.to_vec(),
        key_id: key_id.to_string(),
        ciphersuite,
    })
}

pub fn unwrap_recovery_private_key(
    provider: &OpenMlsRustCrypto,
    pin: &str,
    wrapped: &WrappedRecoveryKey,
) -> Result<Vec<u8>, RecoveryError> {
    validate_pin(pin)?;
    if wrapped.version != 1
        || wrapped.kdf != "PBKDF2-SHA256"
        || wrapped.iterations < MIN_PBKDF2_ITERATIONS
        || wrapped.ciphersuite != u16::from(CIPHERSUITE)
        || wrapped.salt.len() != 16
        || wrapped.nonce.len() != 12
        || wrapped.public_key.len() != 32
        || wrapped.wrapped_private_key.len() != 48
        || wrapped.key_id != hex::encode(&Sha256::digest(&wrapped.public_key)[..16])
    {
        return Err(RecoveryError::new("Invalid recovery vault metadata"));
    }
    let key = derive_pin_key(pin, &wrapped.salt, wrapped.iterations);
    provider
        .crypto()
        .aead_decrypt(
            AeadType::Aes256Gcm,
            &key,
            &wrapped.wrapped_private_key,
            &wrapped.nonce,
            wrapped.key_id.as_bytes(),
        )
        .map_err(|e| RecoveryError::new(&format!("unwrap recovery key: {e:?}")))
}

pub fn encrypt_archive_blob(
    provider: &OpenMlsRustCrypto,
    archive_bytes: &[u8],
    aad: &ArchiveBlobAad,
) -> Result<EncryptedArchiveBlob, RecoveryError> {
    let adk = provider
        .rand()
        .random_vec(32)
        .map_err(|e| RecoveryError::new(&format!("{e:?}")))?;
    let nonce = provider
        .rand()
        .random_vec(12)
        .map_err(|e| RecoveryError::new(&format!("{e:?}")))?;
    let aead_aad = aad.to_bytes()?;
    let ciphertext = provider
        .crypto()
        .aead_encrypt(AeadType::Aes256Gcm, &adk, archive_bytes, &nonce, &aead_aad)
        .map_err(|e| RecoveryError::new(&format!("encrypt archive blob: {e:?}")))?;
    Ok(EncryptedArchiveBlob {
        ciphertext,
        nonce,
        aead_aad,
        adk,
    })
}

pub fn decrypt_archive_blob(
    provider: &OpenMlsRustCrypto,
    adk: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aead_aad: &[u8],
) -> Result<Vec<u8>, RecoveryError> {
    provider
        .crypto()
        .aead_decrypt(AeadType::Aes256Gcm, adk, ciphertext, nonce, aead_aad)
        .map_err(|e| RecoveryError::new(&format!("decrypt archive blob: {e:?}")))
}

pub fn wrap_archive_data_key(
    provider: &OpenMlsRustCrypto,
    adk: &[u8],
    recipient_recovery_public_key: &[u8],
    info: &ArchiveKeyWrapInfo,
) -> Result<HpkeWrappedArchiveDataKey, RecoveryError> {
    let hpke_info = info.to_bytes()?;
    let ct = provider
        .crypto()
        .hpke_seal(
            CIPHERSUITE.hpke_config(),
            recipient_recovery_public_key,
            &hpke_info,
            &[],
            adk,
        )
        .map_err(|e| RecoveryError::new(&format!("wrap ADK: {e:?}")))?;
    Ok(HpkeWrappedArchiveDataKey {
        kem_output: ct.kem_output.as_slice().to_vec(),
        ciphertext: ct.ciphertext.as_slice().to_vec(),
        ciphersuite: CIPHERSUITE.into(),
        hpke_info,
    })
}

pub fn unwrap_archive_data_key(
    provider: &OpenMlsRustCrypto,
    recovery_private_key: &[u8],
    wrapped: &HpkeWrappedArchiveDataKey,
) -> Result<Vec<u8>, RecoveryError> {
    let ct = HpkeCiphertext {
        kem_output: wrapped.kem_output.clone().into(),
        ciphertext: wrapped.ciphertext.clone().into(),
    };
    provider
        .crypto()
        .hpke_open(
            CIPHERSUITE.hpke_config(),
            &ct,
            recovery_private_key,
            &wrapped.hpke_info,
            &[],
        )
        .map_err(|e| RecoveryError::new(&format!("unwrap ADK: {e:?}")))
}

pub fn unwrap_archive_data_key_from_parts(
    provider: &OpenMlsRustCrypto,
    recovery_private_key: &[u8],
    kem_output: &[u8],
    ciphertext: &[u8],
    hpke_info: &[u8],
) -> Result<Vec<u8>, RecoveryError> {
    let wrapped = HpkeWrappedArchiveDataKey {
        kem_output: kem_output.to_vec(),
        ciphertext: ciphertext.to_vec(),
        ciphersuite: CIPHERSUITE.into(),
        hpke_info: hpke_info.to_vec(),
    };
    unwrap_archive_data_key(provider, recovery_private_key, &wrapped)
}

fn validate_pin(pin: &str) -> Result<(), RecoveryError> {
    if pin.len() < MIN_PIN_DIGITS || !pin.chars().all(|c| c.is_ascii_digit()) {
        return Err(RecoveryError::new("PIN must be at least 8 digits"));
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
