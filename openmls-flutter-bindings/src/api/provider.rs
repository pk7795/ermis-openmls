//! Flutter adapter for the binding-neutral provider.

use flutter_rust_bridge::frb;

#[frb(opaque)]
pub struct Provider {
    inner: openmls_bindings_core::Provider,
}

#[allow(clippy::new_without_default)]
impl Provider {
    pub fn new() -> Self {
        Self {
            inner: openmls_bindings_core::Provider::new(),
        }
    }

    pub fn new_with_path(db_path: String) -> anyhow::Result<Self> {
        Ok(Self {
            inner: openmls_bindings_core::Provider::new_with_path(db_path)?,
        })
    }

    pub fn stored_group_ids(&self) -> anyhow::Result<Vec<String>> {
        super::dart_result(self.inner.stored_group_ids())
    }

    pub fn group_count(&self) -> anyhow::Result<u32> {
        super::dart_result(self.inner.group_count())
    }

    pub fn delete_group(&self, cid: String) -> anyhow::Result<()> {
        super::dart_result(self.inner.delete_group(cid))
    }

    pub fn delete_all_groups(&self) -> anyhow::Result<()> {
        super::dart_result(self.inner.delete_all_groups())
    }

    pub fn store_identity(&self, user_id: String, identity_bytes: Vec<u8>) -> anyhow::Result<()> {
        super::dart_result(self.inner.store_identity(user_id, identity_bytes))
    }

    pub fn load_identity(&self) -> anyhow::Result<Option<Vec<u8>>> {
        super::dart_result(self.inner.load_identity())
    }

    pub fn delete_identity(&self) -> anyhow::Result<()> {
        super::dart_result(self.inner.delete_identity())
    }

    pub(crate) fn core(&self) -> &openmls_bindings_core::Provider {
        &self.inner
    }
}
