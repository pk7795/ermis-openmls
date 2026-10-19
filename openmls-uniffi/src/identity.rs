//! UniFFI adapters for identities and key packages.

use std::sync::Arc;

use crate::{errors::MlsError, provider::Provider};

pub struct Identity {
    inner: openmls_bindings_core::Identity,
}

impl Identity {
    pub fn new(provider: Arc<Provider>, user_id: String) -> Result<Self, MlsError> {
        Ok(Self {
            inner: openmls_bindings_core::Identity::new(provider.core(), user_id)
                .map_err(MlsError::from_core)?,
        })
    }

    pub fn user_id(&self) -> String {
        self.inner.user_id()
    }

    pub fn lor_request_signature(&self, context_json: String) -> Result<Vec<u8>, MlsError> {
        self.inner.lor_request_signature(context_json).map_err(MlsError::from_core)
    }

    pub fn signature_public_key(&self) -> Vec<u8> {
        self.inner.signature_public_key()
    }

    pub fn device_registration_signature(
        &self,
        device_id: String,
        project_id: String,
        issued_at: i64,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .device_registration_signature(device_id, project_id, issued_at)
            .map_err(MlsError::from_core)
    }

    pub fn owns_key_package_ref(
        &self,
        provider: Arc<Provider>,
        reference: Vec<u8>,
    ) -> Result<bool, MlsError> {
        self.inner
            .owns_key_package_ref(provider.core(), reference)
            .map_err(MlsError::from_core)
    }

    pub fn key_package(&self, provider: Arc<Provider>) -> Result<Arc<KeyPackage>, MlsError> {
        Ok(Arc::new(KeyPackage {
            inner: self
                .inner
                .key_package(provider.core())
                .map_err(MlsError::from_core)?,
        }))
    }

    pub fn key_packages(
        &self,
        provider: Arc<Provider>,
        count: u32,
    ) -> Result<Vec<Arc<KeyPackage>>, MlsError> {
        Ok(self
            .inner
            .key_packages(provider.core(), count)
            .map_err(MlsError::from_core)?
            .into_iter()
            .map(|inner| Arc::new(KeyPackage { inner }))
            .collect())
    }

    pub fn prepare_key_package_upload(
        &self, provider: Arc<Provider>, operation_id: String, scope: String,
        expected_provider_id: String, count: u32,
    ) -> Result<Vec<Vec<u8>>, MlsError> {
        self.inner.prepare_key_package_upload(provider.core(), operation_id, scope, expected_provider_id, count)
            .map_err(MlsError::from_core)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.inner.to_bytes().map_err(MlsError::from_core)
    }

    pub fn from_bytes(provider: Arc<Provider>, data: Vec<u8>) -> Result<Self, MlsError> {
        Ok(Self {
            inner: openmls_bindings_core::Identity::from_bytes(provider.core(), data)
                .map_err(MlsError::from_core)?,
        })
    }

    pub(crate) fn core(&self) -> &openmls_bindings_core::Identity {
        &self.inner
    }
}

pub struct KeyPackage {
    inner: openmls_bindings_core::KeyPackage,
}

impl KeyPackage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsError> {
        self.inner.to_bytes().map_err(MlsError::from_core)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, MlsError> {
        Ok(Self {
            inner: openmls_bindings_core::KeyPackage::from_bytes(data)
                .map_err(MlsError::from_core)?,
        })
    }

    pub fn hash_ref(&self, provider: Arc<Provider>) -> Result<Vec<u8>, MlsError> {
        self.inner
            .hash_ref(provider.core())
            .map_err(MlsError::from_core)
    }

    pub(crate) fn core(&self) -> &openmls_bindings_core::KeyPackage {
        &self.inner
    }

    pub(crate) fn clone_core(&self) -> openmls_bindings_core::KeyPackage {
        self.inner.clone()
    }
}

pub fn validate_key_package_bytes(data: Vec<u8>) -> bool {
    openmls_bindings_core::validate_key_package_bytes(data)
}
