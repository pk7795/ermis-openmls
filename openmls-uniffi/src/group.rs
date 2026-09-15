//! UniFFI adapter for binding-neutral MLS group operations.

use std::sync::Arc;

use crate::{
    errors::MlsError,
    identity::{Identity, KeyPackage},
    provider::Provider,
    types::{
        ArchivedMessage, CommitBundle, ExportedEpochArchiveV2, ExternalJoinResult, MemberInfo,
        ProcessedMessage, ProposalMessage, RatchetTree,
    },
};

pub struct Group {
    inner: openmls_bindings_core::Group,
}

impl Group {
    fn from_core(inner: openmls_bindings_core::Group) -> Self {
        Self { inner }
    }

    pub fn create_with_cid(
        provider: Arc<Provider>,
        founder: Arc<Identity>,
        cid: String,
    ) -> Result<Self, MlsError> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::create_with_cid(provider.core(), founder.core(), cid)
                .map_err(MlsError::from_core)?,
        ))
    }

    pub fn create_with_group_id(
        provider: Arc<Provider>,
        founder: Arc<Identity>,
        group_id: Vec<u8>,
    ) -> Result<Self, MlsError> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::create_with_group_id(
                provider.core(),
                founder.core(),
                group_id,
            )
            .map_err(MlsError::from_core)?,
        ))
    }

    pub fn load_from_storage(provider: Arc<Provider>, cid: String) -> Result<Self, MlsError> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::load_from_storage(provider.core(), cid)
                .map_err(MlsError::from_core)?,
        ))
    }

    pub fn load_from_storage_with_group_id(
        provider: Arc<Provider>,
        group_id: Vec<u8>,
    ) -> Result<Self, MlsError> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::load_from_storage_with_group_id(
                provider.core(),
                group_id,
            )
            .map_err(MlsError::from_core)?,
        ))
    }

    pub fn save_state(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        self.inner
            .save_state(provider.core())
            .map_err(MlsError::from_core)
    }

    pub fn delete_state(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        self.inner
            .delete_state(provider.core())
            .map_err(MlsError::from_core)
    }

    pub fn join_with_welcome(
        provider: Arc<Provider>,
        welcome: Vec<u8>,
        ratchet_tree: Option<Arc<RatchetTree>>,
    ) -> Result<Self, MlsError> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::join_with_welcome(
                provider.core(),
                welcome,
                ratchet_tree.map(|value| value.inner.clone()),
            )
            .map_err(MlsError::from_core)?,
        ))
    }

    pub fn cid(&self) -> Result<String, MlsError> {
        self.inner.cid().map_err(MlsError::from_core)
    }

    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id()
    }

    pub fn epoch(&self) -> u64 {
        self.inner.epoch()
    }

    pub fn members(&self) -> Vec<MemberInfo> {
        self.inner.members().into_iter().map(Into::into).collect()
    }

    pub fn member_by_user_id(&self, user_id: String) -> Option<MemberInfo> {
        self.inner.member_by_user_id(user_id).map(Into::into)
    }

    pub fn members_by_user_id(&self, user_id: String) -> Vec<MemberInfo> {
        self.inner
            .members_by_user_id(user_id)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub fn own_leaf_index(&self) -> u32 {
        self.inner.own_leaf_index()
    }

    pub fn is_operational(&self) -> bool {
        self.inner.is_operational()
    }

    pub fn has_pending_commit(&self) -> bool {
        self.inner.has_pending_commit()
    }

    pub fn export_ratchet_tree(&self) -> Arc<RatchetTree> {
        Arc::new(RatchetTree {
            inner: self.inner.export_ratchet_tree(),
        })
    }

    pub fn archive_epoch_v2(&self) -> Result<ExportedEpochArchiveV2, MlsError> {
        Ok(self
            .inner
            .archive_epoch_v2()
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn export_group_info(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        with_ratchet_tree: bool,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .export_group_info(provider.core(), sender.core(), with_ratchet_tree)
            .map_err(MlsError::from_core)
    }

    pub fn export_key(
        &self,
        provider: Arc<Provider>,
        label: String,
        context: Vec<u8>,
        key_length: u32,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .export_key(provider.core(), label, context, key_length)
            .map_err(MlsError::from_core)
    }

    pub fn create_message(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .create_message(provider.core(), sender.core(), plaintext)
            .map_err(MlsError::from_core)
    }

    pub fn set_aad(&self, aad: Vec<u8>) {
        self.inner.set_aad(aad);
    }

    pub fn create_message_with_aad(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .create_message_with_aad(provider.core(), sender.core(), plaintext, aad)
            .map_err(MlsError::from_core)
    }

    pub fn process_message(
        &self,
        provider: Arc<Provider>,
        msg: Vec<u8>,
    ) -> Result<ProcessedMessage, MlsError> {
        Ok(self
            .inner
            .process_message(provider.core(), msg)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn process_message_deferred(
        &self,
        provider: Arc<Provider>,
        msg: Vec<u8>,
    ) -> Result<ProcessedMessage, MlsError> {
        Ok(self
            .inner
            .process_message_deferred(provider.core(), msg)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn process_message_at(
        &self,
        provider: Arc<Provider>,
        msg: Vec<u8>,
        server_accepted_at_seconds: u64,
    ) -> Result<ProcessedMessage, MlsError> {
        Ok(self
            .inner
            .process_message_at(provider.core(), msg, server_accepted_at_seconds)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn process_message_raw(
        &self,
        provider: Arc<Provider>,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .process_message_raw(provider.core(), msg)
            .map_err(MlsError::from_core)
    }

    pub fn propose_add_member(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        new_member: Arc<KeyPackage>,
    ) -> Result<ProposalMessage, MlsError> {
        Ok(self
            .inner
            .propose_add_member(provider.core(), sender.core(), new_member.core())
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn propose_add_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        device_key_packages: Vec<Arc<KeyPackage>>,
    ) -> Result<Vec<ProposalMessage>, MlsError> {
        Ok(self
            .inner
            .propose_add_user(
                provider.core(),
                sender.core(),
                device_key_packages
                    .iter()
                    .map(|value| value.clone_core())
                    .collect(),
            )
            .map_err(MlsError::from_core)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn propose_remove_member(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        member_index: u32,
    ) -> Result<ProposalMessage, MlsError> {
        Ok(self
            .inner
            .propose_remove_member(provider.core(), sender.core(), member_index)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn propose_remove_member_by_user_id(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_id: String,
    ) -> Result<ProposalMessage, MlsError> {
        Ok(self
            .inner
            .propose_remove_member_by_user_id(provider.core(), sender.core(), user_id)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn propose_remove_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_id: String,
    ) -> Result<Vec<ProposalMessage>, MlsError> {
        Ok(self
            .inner
            .propose_remove_user(provider.core(), sender.core(), user_id)
            .map_err(MlsError::from_core)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn propose_self_update(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<ProposalMessage, MlsError> {
        Ok(self
            .inner
            .propose_self_update(provider.core(), sender.core())
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn leave_group(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<Vec<u8>, MlsError> {
        self.inner
            .leave_group(provider.core(), sender.core())
            .map_err(MlsError::from_core)
    }

    pub fn pending_proposals_count(&self) -> u64 {
        self.inner.pending_proposals_count()
    }

    pub fn clear_pending_proposals(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        self.inner
            .clear_pending_proposals(provider.core())
            .map_err(MlsError::from_core)
    }

    pub fn commit_pending_proposals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .commit_pending_proposals(provider.core(), sender.core())
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn merge_pending_commit(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        self.inner
            .merge_pending_commit(provider.core())
            .map_err(MlsError::from_core)
    }

    pub fn clear_pending_commit(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        self.inner
            .clear_pending_commit(provider.core())
            .map_err(MlsError::from_core)
    }

    pub fn add_members(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        new_members: Vec<Arc<KeyPackage>>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .add_members(
                provider.core(),
                sender.core(),
                new_members.iter().map(|value| value.clone_core()).collect(),
            )
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn add_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        device_key_packages: Vec<Arc<KeyPackage>>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .add_user(
                provider.core(),
                sender.core(),
                device_key_packages
                    .iter()
                    .map(|value| value.clone_core())
                    .collect(),
            )
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn remove_members(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        member_indices: Vec<u32>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .remove_members(provider.core(), sender.core(), member_indices)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn remove_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_id: String,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .remove_user(provider.core(), sender.core(), user_id)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn remove_users(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_ids: Vec<String>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .remove_users(provider.core(), sender.core(), user_ids)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn commit_group_changes(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
        add_members: Vec<Arc<KeyPackage>>,
        force_self_update: bool,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .commit_group_changes(
                provider.core(),
                sender.core(),
                remove_user_ids,
                add_members.iter().map(|value| value.clone_core()).collect(),
                force_self_update,
            )
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn commit_member_add_with_removals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
        add_members: Vec<Arc<KeyPackage>>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .commit_member_add_with_removals(
                provider.core(),
                sender.core(),
                remove_user_ids,
                add_members.iter().map(|value| value.clone_core()).collect(),
            )
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn commit_self_update_with_removals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .commit_self_update_with_removals(provider.core(), sender.core(), remove_user_ids)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn commit_member_removals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .commit_member_removals(provider.core(), sender.core(), remove_user_ids)
            .map_err(MlsError::from_core)?
            .into())
    }

    pub fn self_update(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<CommitBundle, MlsError> {
        Ok(self
            .inner
            .self_update(provider.core(), sender.core())
            .map_err(MlsError::from_core)?
            .into())
    }
}

pub fn join_external(
    provider: Arc<Provider>,
    identity: Arc<Identity>,
    group_info: Vec<u8>,
    ratchet_tree: Option<Arc<RatchetTree>>,
) -> Result<ExternalJoinResult, MlsError> {
    let result = openmls_bindings_core::join_external(
        provider.core(),
        identity.core(),
        group_info,
        ratchet_tree.map(|value| value.inner.clone()),
    )
    .map_err(MlsError::from_core)?;
    Ok(ExternalJoinResult {
        group: Arc::new(Group::from_core(result.group())),
        commit: result.commit_bytes(),
    })
}

pub fn decrypt_epoch_archive_v2(
    provider: Arc<Provider>,
    archive: Vec<u8>,
    snapshot: Vec<u8>,
    ciphertext: Vec<u8>,
    allow_own_messages: bool,
    max_forward_distance: u32,
) -> Result<ArchivedMessage, MlsError> {
    Ok(openmls_bindings_core::decrypt_epoch_archive_v2(
        provider.core(),
        archive,
        snapshot,
        ciphertext,
        allow_own_messages,
        max_forward_distance,
    )
    .map_err(MlsError::from_core)?
    .into())
}
