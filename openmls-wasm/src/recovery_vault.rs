use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{AeadType, HpkeCiphertext},
    OpenMlsProvider,
};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use crate::{Provider, CIPHERSUITE};

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
    epoch: u64,
    scope: String,
    blob_id: String,
    snapshot_hash: String,
}

#[wasm_bindgen]
impl ArchiveBlobAad {
    #[wasm_bindgen(constructor)]
    pub fn new(cid: String, epoch: u64, scope: String, blob_id: String, snapshot_hash: String) -> Self {
        Self {
            domain: ARCHIVE_BLOB_DOMAIN.to_string(),
            cid,
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
        serde_json::from_slice(bytes).map_err(|e| JsError::new(&format!("deserialize HPKE wrap: {e}")))
    }
}

#[wasm_bindgen]
pub fn generate_recovery_keypair(provider: &Provider) -> Result<RecoveryKeypair, JsError> {
    let ikm = provider
        .0
        .rand()
        .random_vec(32)
        .map_err(|e| JsError::new(&format!("recovery keypair random: {e:?}")))?;
    let keypair = provider
        .0
        .crypto()
        .derive_hpke_keypair(CIPHERSUITE.hpke_config(), &ikm)
        .map_err(|e| JsError::new(&format!("derive recovery keypair: {e:?}")))?;
    let public_key = keypair.public.to_vec();
    let key_id = hex::encode(&Sha256::digest(&public_key)[..16]);
    Ok(RecoveryKeypair {
        private_key: keypair.private.to_vec(),
        public_key,
        key_id,
        ciphersuite: CIPHERSUITE.into(),
    })
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
    validate_pin(pin)?;
    if iterations < MIN_PBKDF2_ITERATIONS {
        return Err(JsError::new("PBKDF2 iterations must be >= 600,000"));
    }
    let salt = provider.0.rand().random_vec(16).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let nonce = provider.0.rand().random_vec(12).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let key = derive_pin_key(pin, &salt, iterations);
    let wrapped_private_key = provider
        .0
        .crypto()
        .aead_encrypt(AeadType::Aes256Gcm, &key, private_key, &nonce, key_id.as_bytes())
        .map_err(|e| JsError::new(&format!("wrap recovery key: {e:?}")))?;
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

#[wasm_bindgen]
pub fn unwrap_recovery_private_key(
    provider: &Provider,
    pin: &str,
    wrapped: &WrappedRecoveryKey,
) -> Result<Vec<u8>, JsError> {
    validate_pin(pin)?;
    let key = derive_pin_key(pin, &wrapped.salt, wrapped.iterations);
    provider
        .0
        .crypto()
        .aead_decrypt(
            AeadType::Aes256Gcm,
            &key,
            &wrapped.wrapped_private_key,
            &wrapped.nonce,
            wrapped.key_id.as_bytes(),
        )
        .map_err(|e| JsError::new(&format!("unwrap recovery key: {e:?}")))
}

#[wasm_bindgen]
pub fn encrypt_archive_blob(
    provider: &Provider,
    archive_bytes: &[u8],
    aad: &ArchiveBlobAad,
) -> Result<EncryptedArchiveBlob, JsError> {
    let adk = provider.0.rand().random_vec(32).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let nonce = provider.0.rand().random_vec(12).map_err(|e| JsError::new(&format!("{e:?}")))?;
    let aead_aad = aad.to_bytes()?;
    let ciphertext = provider
        .0
        .crypto()
        .aead_encrypt(AeadType::Aes256Gcm, &adk, archive_bytes, &nonce, &aead_aad)
        .map_err(|e| JsError::new(&format!("encrypt archive blob: {e:?}")))?;
    Ok(EncryptedArchiveBlob {
        ciphertext,
        nonce,
        aead_aad,
        adk,
    })
}

#[wasm_bindgen]
pub fn decrypt_archive_blob(
    provider: &Provider,
    adk: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aead_aad: &[u8],
) -> Result<Vec<u8>, JsError> {
    provider
        .0
        .crypto()
        .aead_decrypt(AeadType::Aes256Gcm, adk, ciphertext, nonce, aead_aad)
        .map_err(|e| JsError::new(&format!("decrypt archive blob: {e:?}")))
}

#[wasm_bindgen]
pub fn wrap_archive_data_key(
    provider: &Provider,
    adk: &[u8],
    recipient_recovery_public_key: &[u8],
    info: &ArchiveKeyWrapInfo,
) -> Result<HpkeWrappedArchiveDataKey, JsError> {
    let hpke_info = info.to_bytes()?;
    let ct = provider
        .0
        .crypto()
        .hpke_seal(
            CIPHERSUITE.hpke_config(),
            recipient_recovery_public_key,
            &hpke_info,
            &[],
            adk,
        )
        .map_err(|e| JsError::new(&format!("wrap ADK: {e:?}")))?;
    Ok(HpkeWrappedArchiveDataKey {
        kem_output: ct.kem_output.as_slice().to_vec(),
        ciphertext: ct.ciphertext.as_slice().to_vec(),
        ciphersuite: CIPHERSUITE.into(),
        hpke_info,
    })
}

#[wasm_bindgen]
pub fn unwrap_archive_data_key(
    provider: &Provider,
    recovery_private_key: &[u8],
    wrapped: &HpkeWrappedArchiveDataKey,
) -> Result<Vec<u8>, JsError> {
    let ct = HpkeCiphertext {
        kem_output: wrapped.kem_output.clone().into(),
        ciphertext: wrapped.ciphertext.clone().into(),
    };
    provider
        .0
        .crypto()
        .hpke_open(
            CIPHERSUITE.hpke_config(),
            &ct,
            recovery_private_key,
            &wrapped.hpke_info,
            &[],
        )
        .map_err(|e| JsError::new(&format!("unwrap ADK: {e:?}")))
}

#[wasm_bindgen]
pub fn unwrap_archive_data_key_from_parts(
    provider: &Provider,
    recovery_private_key: &[u8],
    kem_output: &[u8],
    ciphertext: &[u8],
    hpke_info: &[u8],
) -> Result<Vec<u8>, JsError> {
    let wrapped = HpkeWrappedArchiveDataKey {
        kem_output: kem_output.to_vec(),
        ciphertext: ciphertext.to_vec(),
        ciphersuite: CIPHERSUITE.into(),
        hpke_info: hpke_info.to_vec(),
    };
    unwrap_archive_data_key(provider, recovery_private_key, &wrapped)
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
