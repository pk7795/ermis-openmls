//! Identity and KeyPackage management for OpenMLS WASM

use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{Provider, CIPHERSUITE};

/// Represents a user's MLS identity with credentials and signing keys
#[wasm_bindgen]
pub struct Identity {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) keypair: SignatureKeyPair,
    pub(crate) user_id: String,
}

#[wasm_bindgen]
impl Identity {
    /// Create a new identity for a user
    ///
    /// # Arguments
    /// * `provider` - The crypto provider
    /// * `user_id` - Unique identifier for the user (e.g., from Ermis user system)
    #[wasm_bindgen(constructor)]
    pub fn new(provider: &Provider, user_id: &str) -> Result<Identity, JsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity_bytes: Vec<u8> = user_id.bytes().collect();
        let credential = BasicCredential::new(identity_bytes);
        let keypair = SignatureKeyPair::new(signature_scheme)?;

        keypair.store(provider.0.storage())?;

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
            user_id: user_id.to_string(),
        })
    }

    /// Get the user_id from this identity
    #[wasm_bindgen(getter)]
    pub fn user_id(&self) -> String {
        self.user_id.clone()
    }

    /// Generate a single key package for this identity
    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &provider.0,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone(),
        )
    }

    /// Generate multiple key packages for multi-device support
    ///
    /// # Arguments
    /// * `provider` - The crypto provider
    /// * `count` - Number of key packages to generate
    pub fn key_packages(&self, provider: &Provider, count: u32) -> Vec<KeyPackage> {
        (0..count).map(|_| self.key_package(provider)).collect()
    }

    /// Serialize identity for storage
    /// Note: This only exports the keypair, credential will be reconstructed
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        // Serialize: user_id length (4 bytes) + user_id + keypair bytes
        let user_id_bytes = self.user_id.as_bytes();
        let keypair_bytes = self
            .keypair
            .tls_serialize_detached()
            .map_err(|e| JsError::new(&format!("Identity serialization error: {e}")))?;

        let mut result = Vec::new();
        result.extend_from_slice(&(user_id_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(user_id_bytes);
        result.extend_from_slice(&keypair_bytes);

        Ok(result)
    }

    /// Restore identity from bytes
    pub fn from_bytes(provider: &Provider, bytes: &[u8]) -> Result<Identity, JsError> {
        if bytes.len() < 4 {
            return Err(JsError::new("Identity bytes too short"));
        }

        let user_id_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + user_id_len {
            return Err(JsError::new("Identity bytes too short for user_id"));
        }

        let user_id = String::from_utf8(bytes[4..4 + user_id_len].to_vec())
            .map_err(|e| JsError::new(&format!("Invalid user_id encoding: {e}")))?;

        let mut keypair_slice = &bytes[4 + user_id_len..];
        let keypair = SignatureKeyPair::tls_deserialize(&mut keypair_slice)
            .map_err(|e| JsError::new(&format!("Keypair deserialization error: {e}")))?;

        keypair.store(provider.0.storage())?;

        let identity_bytes: Vec<u8> = user_id.bytes().collect();
        let credential = BasicCredential::new(identity_bytes);

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: keypair.public().into(),
        };

        Ok(Identity {
            credential_with_key,
            keypair,
            user_id,
        })
    }
}

/// A KeyPackage for joining groups
#[wasm_bindgen]
pub struct KeyPackage(pub(crate) OpenMlsKeyPackage);

#[wasm_bindgen]
impl KeyPackage {
    /// Serialize this KeyPackage to bytes
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    /// Deserialize a KeyPackage from bytes
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyPackage, JsError> {
        let mut s = bytes;
        let kp_in = openmls::key_packages::KeyPackageIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("KeyPackage deserialization error: {e}")))?;
        let kp = kp_in
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|e| JsError::new(&format!("KeyPackage validation error: {e}")))?;
        Ok(KeyPackage(kp))
    }

    /// Get the hash reference of this key package
    pub fn hash_ref(&self, provider: &Provider) -> Result<Vec<u8>, JsError> {
        let hash_ref = self
            .0
            .hash_ref(provider.0.crypto())
            .map_err(|e| JsError::new(&format!("KeyPackage hash_ref error: {e}")))?;
        Ok(hash_ref.as_slice().to_vec())
    }
}
