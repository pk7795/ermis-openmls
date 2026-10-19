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

use crate::{MlsError, MlsErrorCode, Provider, CIPHERSUITE};

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

    /// Signs only a validated, domain-separated LOR control request.
    pub fn lor_request_signature(&self, context_json: String) -> Result<Vec<u8>, JsError> {
        use openmls_traits::signatures::Signer;
        let context = ermis_lor_request_proof::SigningContext::parse(&context_json)
            .map_err(|_| JsError::new("Invalid LOR request context"))?;
        let payload = context.payload(&self.user_id, CIPHERSUITE as u16)
            .map_err(|_| JsError::new("Invalid LOR request context"))?;
        self.keypair.sign(&payload).map_err(|_| JsError::new("LOR request proof failed"))
    }

    pub fn signature_public_key(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    pub fn device_registration_signature(
        &self,
        device_id: String,
        project_id: String,
        issued_at: i64,
    ) -> Result<Vec<u8>, JsError> {
        use openmls_traits::signatures::Signer;
        if device_id.is_empty()
            || device_id.len() > 256
            || device_id.chars().any(char::is_control)
            || issued_at <= 0
            || project_id.len() != 36
        {
            return Err(JsError::new("Invalid device registration context"));
        }
        let payload = serde_json::to_vec(&(
            "ermis.mls-device-registration.v1",
            &self.user_id,
            project_id,
            device_id,
            CIPHERSUITE as u16,
            issued_at,
        ))
        .map_err(|_| JsError::new("Invalid device registration context"))?;
        self.keypair
            .sign(&payload)
            .map_err(|_| JsError::new("Device registration proof failed"))
    }

    /// Read-only private-bundle ownership probe for selective pool reconciliation.
    pub fn owns_key_package_ref(
        &self,
        provider: &Provider,
        reference: Vec<u8>,
    ) -> Result<bool, JsError> {
        use openmls::prelude::{KeyPackageBundle, KeyPackageRef};
        use openmls_traits::storage::StorageProvider;
        if reference.len() != 32 {
            return Err(JsError::new("Invalid KeyPackage reference length"));
        }
        let encoded = tls_codec::VLBytes::new(reference)
            .tls_serialize_detached()
            .map_err(|_| JsError::new("Invalid KeyPackage reference"))?;
        let reference = KeyPackageRef::tls_deserialize_exact(&encoded)
            .map_err(|_| JsError::new("Invalid KeyPackage reference"))?;
        let bundle: Option<KeyPackageBundle> = provider
            .0
            .storage()
            .key_package(&reference)
            .map_err(|_| JsError::new("KeyPackage storage read failed"))?;
        let Some(bundle) = bundle else {
            return Ok(false);
        };
        // Verify the bundle reference before using its signing identity. A
        // corrupt/foreign row is uncertain and must never authorize retirement.
        let actual_reference = bundle
            .key_package()
            .hash_ref(provider.0.crypto())
            .map_err(|_| JsError::new("KeyPackage reference mismatch"))?;
        if actual_reference != reference {
            return Err(JsError::new("KeyPackage reference mismatch"));
        }
        Ok(bundle.key_package().leaf_node().signature_key().as_slice() == self.keypair.public())
    }

    /// Generate a single key package for this identity
    pub fn key_package(&self, provider: &Provider) -> Result<KeyPackage, JsError> {
        Ok(KeyPackage(
            OpenMlsKeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &provider.0,
                    &self.keypair,
                    self.credential_with_key.clone(),
                )
                .map_err(|_| JsError::new("KeyPackage generation failed"))?
                .key_package()
                .clone(),
        ))
    }

    /// Generate multiple key packages for multi-device support
    ///
    /// # Arguments
    /// * `provider` - The crypto provider
    /// * `count` - Number of key packages to generate
    pub fn key_packages(
        &self,
        provider: &Provider,
        count: u32,
    ) -> Result<Vec<KeyPackage>, JsError> {
        (0..count).map(|_| self.key_package(provider)).collect()
    }

    /// Typed fallible generation for durable SDK candidate operations.
    pub fn key_package_typed(&self, provider: &Provider) -> Result<KeyPackage, MlsError> {
        let bundle = OpenMlsKeyPackage::builder()
            .build(
                CIPHERSUITE,
                &provider.0,
                &self.keypair,
                self.credential_with_key.clone(),
            )
            .map_err(|error| {
                use openmls::prelude::KeyPackageNewError;
                let code = match error {
                    KeyPackageNewError::LifetimeCreation(
                        openmls::key_packages::LifetimeCreationError::InvalidClock,
                    ) => MlsErrorCode::InvalidClock,
                    KeyPackageNewError::LifetimeCreation(_) => MlsErrorCode::LifetimeRangeInvalid,
                    KeyPackageNewError::StorageError => MlsErrorCode::StorageError,
                    _ => MlsErrorCode::CryptoError,
                };
                MlsError::new(code, "KeyPackage generation unavailable")
            })?;
        Ok(KeyPackage(bundle.key_package().clone()))
    }

    /// The SDK bounds the batch and persists candidate/private keys before upload.
    pub fn key_packages_typed(
        &self,
        provider: &Provider,
        count: u32,
    ) -> Result<Vec<KeyPackage>, MlsError> {
        if count == 0 || count > 100 {
            return Err(MlsError::new(
                MlsErrorCode::InvalidMessage,
                "Invalid KeyPackage batch size",
            ));
        }
        (0..count)
            .map(|_| self.key_package_typed(provider))
            .collect()
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsError> {
        self.0
            .tls_serialize_detached()
            .map_err(|_| JsError::new("KeyPackage serialization failed"))
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

/// Validate raw key package bytes without constructing a KeyPackage object.
///
/// Performs full validation: TLS deserialization, signature verification,
/// protocol version check, lifetime check, init_key ≠ encryption_key.
///
/// # Arguments
/// * `bytes` - TLS-serialized KeyPackage bytes (from server API)
///
/// # Returns
/// `true` if the KeyPackage is valid, `false` otherwise.
///
/// # Example
/// ```javascript
/// const isValid = validate_key_package_bytes(kpBytes);
/// if (!isValid) console.warn("Invalid KeyPackage!");
/// ```
#[wasm_bindgen]
pub fn validate_key_package_bytes(bytes: &[u8]) -> bool {
    KeyPackage::from_bytes(bytes).is_ok()
}
