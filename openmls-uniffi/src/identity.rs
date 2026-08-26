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

    pub fn key_package(&self, provider: Arc<Provider>) -> Arc<KeyPackage> {
        Arc::new(KeyPackage {
            inner: self.inner.key_package(provider.core()),
        })
    }

    pub fn key_packages(&self, provider: Arc<Provider>, count: u32) -> Vec<Arc<KeyPackage>> {
        self.inner
            .key_packages(provider.core(), count)
            .into_iter()
            .map(|inner| Arc::new(KeyPackage { inner }))
            .collect()
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
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
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
