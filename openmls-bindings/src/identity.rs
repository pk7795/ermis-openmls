//! Binding-neutral identity and KeyPackage management

use openmls_traits::storage::StorageProvider;

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
pub static CIPHERSUITE: openmls_traits::types::Ciphersuite =
    openmls_traits::types::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

// ============================================================================
// Identity
// ============================================================================

/// Represents a user's MLS identity with credentials and signing keys
pub struct Identity {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) keypair: SignatureKeyPair,
    pub(crate) user_id: String,
}

impl Identity {
    /// Create a new identity for a user
    pub fn new(provider: &Provider, user_id: String) -> crate::MlsResult<Self> {
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
    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
        let guard = provider.lock();
        KeyPackage {
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
        }
    }

    /// Generate multiple key packages
    pub fn key_packages(&self, provider: &Provider, count: u32) -> Vec<KeyPackage> {
        (0..count).map(|_| self.key_package(provider)).collect()
    }

    /// Serialize identity for storage
    pub fn to_bytes(&self) -> crate::MlsResult<Vec<u8>> {
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
    pub fn from_bytes(provider: &Provider, data: Vec<u8>) -> crate::MlsResult<Self> {
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
        // Delete any existing entry first — SqliteStorageProvider uses INSERT
        // (not INSERT OR REPLACE), so re-storing the same public key would
        // violate the UNIQUE constraint.
        let _ = guard
            .storage()
            .delete_signature_key_pair::<openmls_basic_credential::StorageId>(&keypair.id());
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

// ============================================================================
// KeyPackage
// ============================================================================

/// A KeyPackage for joining groups
pub struct KeyPackage {
    pub(crate) inner: OpenMlsKeyPackage,
}

impl Clone for KeyPackage {
    fn clone(&self) -> Self {
        KeyPackage {
            inner: self.inner.clone(),
        }
    }
}

impl KeyPackage {
    /// Serialize this KeyPackage to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.tls_serialize_detached().unwrap()
    }

    /// Deserialize a KeyPackage from bytes
    pub fn from_bytes(data: Vec<u8>) -> crate::MlsResult<Self> {
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
    pub fn hash_ref(&self, provider: &Provider) -> crate::MlsResult<Vec<u8>> {
        let guard = provider.lock();
        let hash_ref = self
            .inner
            .hash_ref(guard.crypto())
            .map_err(|_| MlsError::CryptoError)?;
        Ok(hash_ref.as_slice().to_vec())
    }
}

// ============================================================================
// Free functions
// ============================================================================

/// Validate raw key package bytes without constructing a KeyPackage object.
///
/// Performs full validation: TLS deserialization, signature verification,
/// protocol version check, lifetime check, init_key ≠ encryption_key.
///
/// Returns `true` if the KeyPackage is valid, `false` otherwise.
pub fn validate_key_package_bytes(data: Vec<u8>) -> bool {
    KeyPackage::from_bytes(data).is_ok()
}

/// Compute the deterministic channel_id for E2EE Messaging (DM) channels.
///
/// Replicates the server-side `hash_channel_id()` in bellboy/src/util/check.rs.
/// Only needed for E2EE DM creation — standard (non-E2EE) Messaging channels
/// have their channel_id computed server-side.
pub fn hash_channel_id(project_id: String, user_ids: Vec<String>) -> String {
    use sha2::{Digest, Sha256};

    let mut sorted_ids = user_ids;
    sorted_ids.sort();
    let concatenated = sorted_ids.join("");

    let mut hasher = Sha256::new();
    hasher.update(concatenated.as_bytes());
    let hash_hex = hex::encode(hasher.finalize());

    format!("{}:{}", project_id, &hash_hex[..36])
}
