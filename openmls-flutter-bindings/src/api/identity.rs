//! Flutter adapters for identities and key packages.

use flutter_rust_bridge::frb;

use super::provider::Provider;

#[frb(opaque)]
pub struct Identity {
    inner: openmls_bindings_core::Identity,
}

impl Identity {
    pub fn new(provider: &Provider, user_id: String) -> anyhow::Result<Self> {
        Ok(Self {
            inner: openmls_bindings_core::Identity::new(provider.core(), user_id)?,
        })
    }

    pub fn user_id(&self) -> String {
        self.inner.user_id()
    }

    pub fn key_package(&self, provider: &Provider) -> KeyPackage {
        KeyPackage {
            inner: self.inner.key_package(provider.core()),
        }
    }

    pub fn key_packages(&self, provider: &Provider, count: u32) -> Vec<KeyPackage> {
        self.inner
            .key_packages(provider.core(), count)
            .into_iter()
            .map(|inner| KeyPackage { inner })
            .collect()
    }

    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        super::dart_result(self.inner.to_bytes())
    }

    pub fn from_bytes(provider: &Provider, data: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            inner: openmls_bindings_core::Identity::from_bytes(provider.core(), data)?,
        })
    }

    pub(crate) fn core(&self) -> &openmls_bindings_core::Identity {
        &self.inner
    }
}

#[frb(opaque)]
pub struct KeyPackage {
    inner: openmls_bindings_core::KeyPackage,
}

impl Clone for KeyPackage {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl KeyPackage {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn from_bytes(data: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            inner: openmls_bindings_core::KeyPackage::from_bytes(data)?,
        })
    }

    pub fn hash_ref(&self, provider: &Provider) -> anyhow::Result<Vec<u8>> {
        super::dart_result(self.inner.hash_ref(provider.core()))
    }

    pub(crate) fn core(&self) -> &openmls_bindings_core::KeyPackage {
        &self.inner
    }

    pub(crate) fn into_core(self) -> openmls_bindings_core::KeyPackage {
        self.inner
    }
}

pub fn validate_key_package_bytes(data: Vec<u8>) -> bool {
    openmls_bindings_core::validate_key_package_bytes(data)
}

pub fn hash_channel_id(project_id: String, user_ids: Vec<String>) -> String {
    openmls_bindings_core::hash_channel_id(project_id, user_ids)
}
