//! Binding-neutral thread-safe provider handle.

use std::sync::Mutex;

use crate::{errors::MlsError, storage::PersistentCryptoProvider};

/// MLS crypto provider backed by SQLite.
pub struct Provider {
    inner: Option<Mutex<PersistentCryptoProvider>>,
}

impl Provider {
    fn storage_error(operation: &'static str) -> MlsError {
        mls_error!("[MLS] storage operation failed: {operation}");
        MlsError::StorageError
    }

    /// Create a new isolated in-memory provider.
    pub fn new() -> Self {
        Self {
            // Legacy infallible constructor keeps its ABI; failed initialization
            // produces an unavailable handle whose operations return StorageError.
            inner: PersistentCryptoProvider::new_in_memory()
                .ok()
                .map(Mutex::new),
        }
    }

    /// Create a persistent provider backed by a SQLite file at `db_path`.
    pub fn new_with_path(db_path: String) -> crate::MlsResult<Self> {
        let persistent = PersistentCryptoProvider::new_with_path(&db_path)
            .map_err(|_| Self::storage_error("provider_open"))?;
        Ok(Self {
            inner: Some(Mutex::new(persistent)),
        })
    }

    /// List all group IDs stored in the SQLite database.
    pub fn stored_group_ids(&self) -> crate::MlsResult<Vec<String>> {
        self.lock()?
            .stored_group_ids()
            .map_err(|_| Self::storage_error("stored_group_ids"))
    }

    /// Count groups stored in the SQLite database.
    pub fn group_count(&self) -> crate::MlsResult<u32> {
        self.lock()?
            .group_count()
            .map_err(|_| Self::storage_error("group_count"))
    }

    /// Atomically delete all persisted state scoped to one group.
    pub fn delete_group(&self, cid: String) -> crate::MlsResult<()> {
        self.lock()?
            .delete_group(&cid)
            .map_err(|_| Self::storage_error("delete_group"))
    }

    /// Atomically delete all persisted group state.
    pub fn delete_all_groups(&self) -> crate::MlsResult<()> {
        self.lock()?
            .delete_all_groups()
            .map_err(|_| Self::storage_error("delete_all_groups"))
    }

    /// Store serialized identity bytes, replacing the previous identity.
    pub fn store_identity(&self, user_id: String, identity_bytes: Vec<u8>) -> crate::MlsResult<()> {
        self.lock()?
            .store_identity(&user_id, &identity_bytes)
            .map_err(|_| Self::storage_error("store_identity"))
    }

    /// Load serialized identity bytes, if present.
    pub fn load_identity(&self) -> crate::MlsResult<Option<Vec<u8>>> {
        self.lock()?
            .load_identity()
            .map(|value| value.map(|(_, bytes)| bytes))
            .map_err(|_| Self::storage_error("load_identity"))
    }

    /// Delete the stored identity.
    pub fn delete_identity(&self) -> crate::MlsResult<()> {
        self.lock()?
            .delete_identity()
            .map_err(|_| Self::storage_error("delete_identity"))
    }

    #[cfg(test)]
    pub(crate) fn inner_for_poison_test(
        &self,
    ) -> crate::MlsResult<&Mutex<PersistentCryptoProvider>> {
        self.inner.as_ref().ok_or(MlsError::StorageError)
    }

    pub(crate) fn lock(
        &self,
    ) -> crate::MlsResult<std::sync::MutexGuard<'_, PersistentCryptoProvider>> {
        let mutex = self
            .inner
            .as_ref()
            .ok_or_else(|| Self::storage_error("provider_unavailable"))?;
        let guard = mutex
            .lock()
            .map_err(|_| Self::storage_error("provider_poisoned"))?;
        if !guard.is_available() {
            return Err(Self::storage_error("provider_unavailable"));
        }
        Ok(guard)
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
