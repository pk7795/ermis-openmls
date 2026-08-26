//! UniFFI adapter for the binding-neutral provider.

use crate::errors::MlsError;

pub struct Provider {
    inner: openmls_bindings_core::Provider,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            inner: openmls_bindings_core::Provider::new(),
        }
    }

    pub fn new_with_path(db_path: String) -> Result<Self, MlsError> {
        Ok(Self {
            inner: openmls_bindings_core::Provider::new_with_path(db_path)
                .map_err(MlsError::from_core)?,
        })
    }

    pub fn stored_group_ids(&self) -> Result<Vec<String>, MlsError> {
        self.inner.stored_group_ids().map_err(MlsError::from_core)
    }

    pub fn group_count(&self) -> Result<u32, MlsError> {
        self.inner.group_count().map_err(MlsError::from_core)
    }

    pub fn delete_group(&self, cid: String) -> Result<(), MlsError> {
        self.inner.delete_group(cid).map_err(MlsError::from_core)
    }

    pub fn delete_all_groups(&self) -> Result<(), MlsError> {
        self.inner.delete_all_groups().map_err(MlsError::from_core)
    }

    pub fn store_identity(&self, user_id: String, identity_bytes: Vec<u8>) -> Result<(), MlsError> {
        self.inner
            .store_identity(user_id, identity_bytes)
            .map_err(MlsError::from_core)
    }

    pub fn load_identity(&self) -> Result<Option<Vec<u8>>, MlsError> {
        self.inner.load_identity().map_err(MlsError::from_core)
    }

    pub fn delete_identity(&self) -> Result<(), MlsError> {
        self.inner.delete_identity().map_err(MlsError::from_core)
    }

    pub(crate) fn core(&self) -> &openmls_bindings_core::Provider {
        &self.inner
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
