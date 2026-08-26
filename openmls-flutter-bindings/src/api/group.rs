//! Flutter adapter for binding-neutral MLS group operations.

use flutter_rust_bridge::frb;

use super::{
    identity::{Identity, KeyPackage},
    provider::Provider,
    types::{
        CommitBundle, ExternalJoinResult, MemberInfo, ProcessedMessage, ProposalMessage,
        RatchetTree,
    },
};

#[frb(opaque)]
pub struct Group {
    inner: openmls_bindings_core::Group,
}

impl Clone for Group {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Group {
    pub(crate) fn from_core(inner: openmls_bindings_core::Group) -> Self {
        Self { inner }
    }

    pub fn create_with_cid(
        provider: &Provider,
        founder: &Identity,
        cid: String,
    ) -> anyhow::Result<Self> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::create_with_cid(provider.core(), founder.core(), cid)?,
        ))
    }

    pub fn load_from_storage(provider: &Provider, cid: String) -> anyhow::Result<Self> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::load_from_storage(provider.core(), cid)?,
        ))
    }

    pub fn save_state(&self, provider: &Provider) -> anyhow::Result<()> {
        super::dart_result(self.inner.save_state(provider.core()))
    }

    pub fn delete_state(&self, provider: &Provider) -> anyhow::Result<()> {
        super::dart_result(self.inner.delete_state(provider.core()))
    }

    pub fn join_with_welcome(
        provider: &Provider,
        welcome: Vec<u8>,
        ratchet_tree: Option<RatchetTree>,
    ) -> anyhow::Result<Self> {
        Ok(Self::from_core(
            openmls_bindings_core::Group::join_with_welcome(
                provider.core(),
                welcome,
                ratchet_tree.map(|value| value.inner),
            )?,
        ))
    }

    pub fn cid(&self) -> anyhow::Result<String> {
        super::dart_result(self.inner.cid())
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

    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree {
            inner: self.inner.export_ratchet_tree(),
        }
    }

    pub fn export_group_info(
        &self,
        provider: &Provider,
        sender: &Identity,
        with_ratchet_tree: bool,
    ) -> anyhow::Result<Vec<u8>> {
        super::dart_result(self.inner.export_group_info(
            provider.core(),
            sender.core(),
            with_ratchet_tree,
        ))
    }

    pub fn export_key(
        &self,
        provider: &Provider,
        label: String,
        context: Vec<u8>,
        key_length: u32,
    ) -> anyhow::Result<Vec<u8>> {
        super::dart_result(
            self.inner
                .export_key(provider.core(), label, context, key_length),
        )
    }

    pub fn create_message(
        &self,
        provider: &Provider,
        sender: &Identity,
        plaintext: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        super::dart_result(
            self.inner
                .create_message(provider.core(), sender.core(), plaintext),
        )
    }

    pub fn set_aad(&self, aad: Vec<u8>) {
        self.inner.set_aad(aad);
    }

    pub fn create_message_with_aad(
        &self,
        provider: &Provider,
        sender: &Identity,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        super::dart_result(self.inner.create_message_with_aad(
            provider.core(),
            sender.core(),
            plaintext,
            aad,
        ))
    }

    pub fn process_message(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
    ) -> anyhow::Result<ProcessedMessage> {
        Ok(self.inner.process_message(provider.core(), msg)?.into())
    }

    pub fn process_message_deferred(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
    ) -> anyhow::Result<ProcessedMessage> {
        Ok(self
            .inner
            .process_message_deferred(provider.core(), msg)?
            .into())
    }

    pub fn process_message_raw(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
    ) -> anyhow::Result<Vec<u8>> {
        super::dart_result(self.inner.process_message_raw(provider.core(), msg))
    }

    pub fn propose_add_member(
        &self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> anyhow::Result<ProposalMessage> {
        Ok(self
            .inner
            .propose_add_member(provider.core(), sender.core(), new_member.core())?
            .into())
    }

    pub fn propose_add_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        device_key_packages: Vec<KeyPackage>,
    ) -> anyhow::Result<Vec<ProposalMessage>> {
        Ok(self
            .inner
            .propose_add_user(
                provider.core(),
                sender.core(),
                device_key_packages
                    .into_iter()
                    .map(KeyPackage::into_core)
                    .collect(),
            )?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn propose_remove_member(
        &self,
        provider: &Provider,
        sender: &Identity,
        member_index: u32,
    ) -> anyhow::Result<ProposalMessage> {
        Ok(self
            .inner
            .propose_remove_member(provider.core(), sender.core(), member_index)?
            .into())
    }

    pub fn propose_remove_member_by_user_id(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_id: String,
    ) -> anyhow::Result<ProposalMessage> {
        Ok(self
            .inner
            .propose_remove_member_by_user_id(provider.core(), sender.core(), user_id)?
            .into())
    }

    pub fn propose_remove_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_id: String,
    ) -> anyhow::Result<Vec<ProposalMessage>> {
        Ok(self
            .inner
            .propose_remove_user(provider.core(), sender.core(), user_id)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    pub fn propose_self_update(
        &self,
        provider: &Provider,
        sender: &Identity,
    ) -> anyhow::Result<ProposalMessage> {
        Ok(self
            .inner
            .propose_self_update(provider.core(), sender.core())?
            .into())
    }

    pub fn leave_group(&self, provider: &Provider, sender: &Identity) -> anyhow::Result<Vec<u8>> {
        super::dart_result(self.inner.leave_group(provider.core(), sender.core()))
    }

    pub fn pending_proposals_count(&self) -> u64 {
        self.inner.pending_proposals_count()
    }

    pub fn clear_pending_proposals(&self, provider: &Provider) -> anyhow::Result<()> {
        super::dart_result(self.inner.clear_pending_proposals(provider.core()))
    }

    pub fn commit_pending_proposals(
        &self,
        provider: &Provider,
        sender: &Identity,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .commit_pending_proposals(provider.core(), sender.core())?
            .into())
    }

    pub fn merge_pending_commit(&self, provider: &Provider) -> anyhow::Result<()> {
        super::dart_result(self.inner.merge_pending_commit(provider.core()))
    }

    pub fn clear_pending_commit(&self, provider: &Provider) -> anyhow::Result<()> {
        super::dart_result(self.inner.clear_pending_commit(provider.core()))
    }

    pub fn add_members(
        &self,
        provider: &Provider,
        sender: &Identity,
        new_members: Vec<KeyPackage>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .add_members(
                provider.core(),
                sender.core(),
                new_members.into_iter().map(KeyPackage::into_core).collect(),
            )?
            .into())
    }

    pub fn add_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        device_key_packages: Vec<KeyPackage>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .add_user(
                provider.core(),
                sender.core(),
                device_key_packages
                    .into_iter()
                    .map(KeyPackage::into_core)
                    .collect(),
            )?
            .into())
    }

    pub fn remove_members(
        &self,
        provider: &Provider,
        sender: &Identity,
        member_indices: Vec<u32>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .remove_members(provider.core(), sender.core(), member_indices)?
            .into())
    }

    pub fn remove_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_id: String,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .remove_user(provider.core(), sender.core(), user_id)?
            .into())
    }

    pub fn remove_users(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_ids: Vec<String>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .remove_users(provider.core(), sender.core(), user_ids)?
            .into())
    }

    pub fn commit_group_changes(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
        add_members: Vec<KeyPackage>,
        force_self_update: bool,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .commit_group_changes(
                provider.core(),
                sender.core(),
                remove_user_ids,
                add_members.into_iter().map(KeyPackage::into_core).collect(),
                force_self_update,
            )?
            .into())
    }

    pub fn commit_member_add_with_removals(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
        add_members: Vec<KeyPackage>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .commit_member_add_with_removals(
                provider.core(),
                sender.core(),
                remove_user_ids,
                add_members.into_iter().map(KeyPackage::into_core).collect(),
            )?
            .into())
    }

    pub fn commit_self_update_with_removals(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .commit_self_update_with_removals(provider.core(), sender.core(), remove_user_ids)?
            .into())
    }

    pub fn commit_member_removals(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .commit_member_removals(provider.core(), sender.core(), remove_user_ids)?
            .into())
    }

    pub fn self_update(
        &self,
        provider: &Provider,
        sender: &Identity,
    ) -> anyhow::Result<CommitBundle> {
        Ok(self
            .inner
            .self_update(provider.core(), sender.core())?
            .into())
    }
}

pub fn join_external(
    provider: &Provider,
    identity: &Identity,
    group_info: Vec<u8>,
    ratchet_tree: Option<RatchetTree>,
) -> anyhow::Result<ExternalJoinResult> {
    Ok(ExternalJoinResult {
        inner: openmls_bindings_core::join_external(
            provider.core(),
            identity.core(),
            group_info,
            ratchet_tree.map(|value| value.inner),
        )?,
    })
}
