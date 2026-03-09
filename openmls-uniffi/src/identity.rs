//! Identity and KeyPackage management for UniFFI bindings

use std::sync::Arc;

use openmls::{
    credentials::{BasicCredential, CredentialWithKey},
    key_packages::KeyPackage as OpenMlsKeyPackage,
    prelude::SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

use crate::{errors::MlsError, provider::Provider};

/// The ciphersuite used for all operations
pub(crate) static CIPHERSUITE: openmls_traits::types::Ciphersuite =
    openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Represents a user's MLS identity with credentials and signing keys
pub struct Identity {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) keypair: SignatureKeyPair,
    pub(crate) user_id: String,
}

impl Identity {
    /// Create a new identity for a user
    pub fn new(provider: Arc<Provider>, user_id: String) -> Result<Self, MlsError> {
        let signature_scheme = SignatureScheme::ED25519;
        let identity_bytes: Vec<u8> = user_id.bytes().collect();
        let credential = BasicCredential::new(identity_bytes);
        let keypair = SignatureKeyPair::new(signature_scheme).map_err(|_| MlsError::CryptoError)?;

        let guard = provider.lock();
        keypair
            .store(guard.storage())
            .map_err(|_| MlsError::StorageError)?;

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

    /// Get the user_id from this identity
    pub fn user_id(&self) -> String {
        self.user_id.clone()
    }

    /// Generate a single key package for this identity
    pub fn key_package(&self, provider: Arc<Provider>) -> Arc<KeyPackage> {
        let guard = provider.lock();
        Arc::new(KeyPackage {
            inner: OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &*guard,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .clone(),
        })
    }

    /// Generate multiple key packages
    pub fn key_packages(&self, provider: Arc<Provider>, count: u32) -> Vec<Arc<KeyPackage>> {
        (0..count)
            .map(|_| self.key_package(provider.clone()))
            .collect()
    }

    /// Serialize identity for storage
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        let user_id_bytes = self.user_id.as_bytes();
        let keypair_bytes = self
            .keypair
            .tls_serialize_detached()
            .map_err(|_| MlsError::SerializationError)?;

        let mut result = Vec::new();
        result.extend_from_slice(&(user_id_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(user_id_bytes);
        result.extend_from_slice(&keypair_bytes);

        Ok(result)
    }

    /// Restore identity from bytes
    pub fn from_bytes(provider: Arc<Provider>, data: Vec<u8>) -> Result<Self, MlsError> {
        if data.len() < 4 {
            return Err(MlsError::DeserializationError);
        }

        let user_id_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + user_id_len {
            return Err(MlsError::DeserializationError);
        }

        let user_id = String::from_utf8(data[4..4 + user_id_len].to_vec())
            .map_err(|_| MlsError::DeserializationError)?;

        let mut keypair_slice = &data[4 + user_id_len..];
        let keypair = SignatureKeyPair::tls_deserialize(&mut keypair_slice)
            .map_err(|_| MlsError::DeserializationError)?;

        let guard = provider.lock();
        keypair
            .store(guard.storage())
            .map_err(|_| MlsError::StorageError)?;

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
pub struct KeyPackage {
    pub(crate) inner: OpenMlsKeyPackage,
}

impl KeyPackage {
    /// Serialize this KeyPackage to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.tls_serialize_detached().unwrap()
    }

    /// Deserialize a KeyPackage from bytes
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, MlsError> {
        let mut s = data.as_slice();
        let kp_in = openmls::key_packages::KeyPackageIn::tls_deserialize(&mut s)
            .map_err(|_| MlsError::DeserializationError)?;
        let kp = kp_in
            .validate(
                &openmls_rust_crypto::RustCrypto::default(),
                openmls::prelude::ProtocolVersion::Mls10,
            )
            .map_err(|_| MlsError::DeserializationError)?;
        Ok(KeyPackage { inner: kp })
    }

    /// Get the hash reference of this key package
    pub fn hash_ref(&self, provider: Arc<Provider>) -> Result<Vec<u8>, MlsError> {
        let guard = provider.lock();
        let hash_ref = self
            .inner
            .hash_ref(guard.crypto())
            .map_err(|_| MlsError::CryptoError)?;
        Ok(hash_ref.as_slice().to_vec())
    }
}
