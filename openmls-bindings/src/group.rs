//! Binding-neutral MLS group operations

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, MutexGuard},
};

use openmls::{
    credentials::BasicCredential,
    framing::{
        MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
        errors::{MessageDecryptionError, SecretTreeError},
    },
    group::{
        GroupId, MlsGroup, MlsGroupJoinConfig, RecoveryDecryptOptions, StagedWelcome, WelcomeError,
        decrypt_with_epoch_archive_v2,
    },
    prelude::{LeafNodeIndex, ProcessMessageError, SenderRatchetConfiguration, ValidationError},
};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

use crate::{
    errors::MlsError,
    identity::{CIPHERSUITE, Identity, KeyPackage},
    provider::Provider,
    types::*,
};

/// An MLS Group representing an encrypted channel.
///
/// Uses `Arc<Mutex<MlsGroup>>` so binding adapters can clone handles while all
/// clones continue to operate on the same MLS state.
pub struct Group {
    pub(crate) mls_group: Arc<Mutex<MlsGroup>>,
}

impl Clone for Group {
    fn clone(&self) -> Self {
        Group {
            mls_group: Arc::clone(&self.mls_group),
        }
    }
}

impl Group {
    fn lock_group(&self) -> MutexGuard<'_, MlsGroup> {
        self.mls_group.lock().unwrap_or_else(|poisoned| {
            mls_error!("[MLS] recovering a poisoned group mutex");
            poisoned.into_inner()
        })
    }

    // ========================================================================
    // Creation & Joining
    // ========================================================================

    /// Create a new group with a CID from Ermis
    pub fn create_with_cid(
        provider: &Provider,
        founder: &Identity,
        cid: String,
    ) -> crate::MlsResult<Self> {
        Self::create_with_group_id(provider, founder, cid.into_bytes())
    }

    /// Create a group with an explicit, server-authorized MLS GroupId.
    ///
    /// Generation-aware consumers persist the CID -> (generation, GroupId)
    /// mapping separately. The CID remains the application channel identity.
    pub fn create_with_group_id(
        provider: &Provider,
        founder: &Identity,
        group_id_bytes: Vec<u8>,
    ) -> crate::MlsResult<Self> {
        if group_id_bytes.is_empty() || group_id_bytes.len() > 255 {
            return Err(MlsError::InvalidGroupId);
        }
        let guard = provider.lock();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .use_ratchet_tree_extension(true)
            .max_past_epochs(5)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build(
                &*guard,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .map_err(|_| {
                mls_error!("[MLS] create_with_cid failed");
                MlsError::InternalError
            })?;

        Ok(Group {
            mls_group: Arc::new(Mutex::new(mls_group)),
        })
    }

    /// Load an existing group from persistent storage by its CID.
    pub fn load_from_storage(provider: &Provider, cid: String) -> crate::MlsResult<Self> {
        Self::load_from_storage_with_group_id(provider, cid.into_bytes())
    }

    /// Load persisted group state by its exact MLS GroupId bytes.
    pub fn load_from_storage_with_group_id(
        provider: &Provider,
        group_id_bytes: Vec<u8>,
    ) -> crate::MlsResult<Self> {
        if group_id_bytes.is_empty() || group_id_bytes.len() > 255 {
            return Err(MlsError::InvalidGroupId);
        }
        let group_id = GroupId::from_slice(&group_id_bytes);
        let guard = provider.lock();

        let mls_group = MlsGroup::load(guard.storage(), &group_id)
            .map_err(|_| MlsError::StorageError)?
            .ok_or(MlsError::GroupNotFound)?;

        Ok(Group {
            mls_group: Arc::new(Mutex::new(mls_group)),
        })
    }

    /// Persist the group's current state to the Provider's storage.
    ///
    /// MUST be called after processing application messages (decrypt) to save
    /// the updated ratchet/secret tree state.
    pub fn save_state(&self, provider: &Provider) -> crate::MlsResult<()> {
        let group = self.lock_group();
        let prov_guard = provider.lock();
        group
            .store(prov_guard.storage())
            .map_err(|_| MlsError::StorageError)?;
        Ok(())
    }

    /// Delete this group's persisted OpenMLS state from the Provider storage.
    pub fn delete_state(&self, provider: &Provider) -> crate::MlsResult<()> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();
        group.delete(prov_guard.storage()).map_err(|_| {
            mls_error!("[MLS] delete_state failed");
            MlsError::StorageError
        })?;
        Ok(())
    }

    /// Join a group using a Welcome message
    pub fn join_with_welcome(
        provider: &Provider,
        welcome: Vec<u8>,
        ratchet_tree: Option<RatchetTree>,
    ) -> crate::MlsResult<Self> {
        let mut welcome_slice = welcome.as_slice();
        let mls_welcome = match MlsMessageIn::tls_deserialize(&mut welcome_slice)
            .map_err(|_| MlsError::DeserializationError)?
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            _ => Err(MlsError::InvalidMessage),
        }?;

        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(5)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build();
        let ratchet_tree_in = ratchet_tree.map(|rt| rt.inner.clone());

        let guard = provider.lock();
        let mls_group =
            StagedWelcome::new_from_welcome(&*guard, &config, mls_welcome, ratchet_tree_in)
                .map_err(|error| {
                    mls_error!("[MLS] join_with_welcome: welcome validation failed");
                    match error {
                        WelcomeError::NoMatchingKeyPackage => MlsError::NoMatchingKeyPackage,
                        _ => MlsError::InternalError,
                    }
                })?
                .into_group(&*guard)
                .map_err(|_| {
                    mls_error!("[MLS] join_with_welcome: group creation failed");
                    MlsError::InternalError
                })?;

        Ok(Group {
            mls_group: Arc::new(Mutex::new(mls_group)),
        })
    }

    // ========================================================================
    // State
    // ========================================================================

    /// Get the CID (group_id as string)
    pub fn cid(&self) -> crate::MlsResult<String> {
        let group = self.lock_group();
        let group_id = group.group_id();
        String::from_utf8(group_id.as_slice().to_vec()).map_err(|_| MlsError::InvalidCid)
    }

    /// Get the raw group_id bytes
    pub fn group_id(&self) -> Vec<u8> {
        let group = self.lock_group();
        group.group_id().as_slice().to_vec()
    }

    /// Get current epoch number
    pub fn epoch(&self) -> u64 {
        let group = self.lock_group();
        group.epoch().as_u64()
    }

    /// Get all members in the group
    pub fn members(&self) -> Vec<MemberInfo> {
        let group = self.lock_group();
        group
            .members()
            .map(|m| {
                let user_id =
                    String::from_utf8_lossy(m.credential.serialized_content()).to_string();
                MemberInfo {
                    index: m.index.u32(),
                    user_id,
                    encryption_key: m.encryption_key,
                    signature_key: m.signature_key,
                }
            })
            .collect()
    }

    /// Get a member by user_id (returns first match)
    pub fn member_by_user_id(&self, user_id: String) -> Option<MemberInfo> {
        self.members().into_iter().find(|m| m.user_id == user_id)
    }

    /// Get ALL members (leaf nodes) for a given user_id
    pub fn members_by_user_id(&self, user_id: String) -> Vec<MemberInfo> {
        self.members()
            .into_iter()
            .filter(|m| m.user_id == user_id)
            .collect()
    }

    /// Get the local member's leaf index
    pub fn own_leaf_index(&self) -> u32 {
        let group = self.lock_group();
        group.own_leaf_index().u32()
    }

    /// Check if the group is in operational state
    pub fn is_operational(&self) -> bool {
        let group = self.lock_group();
        group.is_active()
    }

    /// Check if there's a pending commit
    pub fn has_pending_commit(&self) -> bool {
        let group = self.lock_group();
        group.pending_commit().is_some()
    }

    /// Export the ratchet tree
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        let group = self.lock_group();
        RatchetTree {
            inner: group.export_ratchet_tree().into(),
        }
    }

    /// Export private current-epoch secrets plus a canonical verification snapshot.
    pub fn archive_epoch_v2(&self) -> crate::MlsResult<ExportedEpochArchiveV2> {
        let exported = self
            .lock_group()
            .export_epoch_archive_v2()
            .map_err(|_| MlsError::InvalidState)?;
        Ok(ExportedEpochArchiveV2 {
            archive_bytes: exported.archive_bytes,
            snapshot_bytes: exported.snapshot_bytes,
            snapshot_hash: exported.snapshot_hash.to_vec(),
        })
    }

    /// Export group info for external commits
    pub fn export_group_info(
        &self,
        provider: &Provider,
        sender: &Identity,
        with_ratchet_tree: bool,
    ) -> crate::MlsResult<Vec<u8>> {
        let group = self.lock_group();
        let prov_guard = provider.lock();
        let group_info = group
            .export_group_info(prov_guard.crypto(), &sender.keypair, with_ratchet_tree)
            .map_err(|_| MlsError::InternalError)?;

        let mut bytes = vec![];
        group_info
            .tls_serialize(&mut bytes)
            .map_err(|_| MlsError::SerializationError)?;
        Ok(bytes)
    }

    /// Export a secret key derived from the group state
    pub fn export_key(
        &self,
        provider: &Provider,
        label: String,
        context: Vec<u8>,
        key_length: u32,
    ) -> crate::MlsResult<Vec<u8>> {
        let group = self.lock_group();
        let prov_guard = provider.lock();
        group
            .export_secret(prov_guard.crypto(), &label, &context, key_length as usize)
            .map_err(|_| MlsError::CryptoError)
    }

    // ========================================================================
    // Messaging
    // ========================================================================

    /// Create an encrypted message
    pub fn create_message(
        &self,
        provider: &Provider,
        sender: &Identity,
        plaintext: Vec<u8>,
    ) -> crate::MlsResult<Vec<u8>> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();
        let msg_out = group
            .create_message(&*prov_guard, &sender.keypair, &plaintext)
            .map_err(|_| MlsError::InternalError)?;
        let mut serialized = vec![];
        msg_out
            .tls_serialize(&mut serialized)
            .map_err(|_| MlsError::SerializationError)?;
        Ok(serialized)
    }

    /// Set Additional Authenticated Data (AAD) for the next outgoing message
    pub fn set_aad(&self, aad: Vec<u8>) {
        let mut group = self.lock_group();
        group.set_aad(aad);
    }

    /// Create an encrypted message with AAD in one call
    pub fn create_message_with_aad(
        &self,
        provider: &Provider,
        sender: &Identity,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> crate::MlsResult<Vec<u8>> {
        {
            let mut group = self.lock_group();
            group.set_aad(aad);
        }
        self.create_message(provider, sender, plaintext)
    }

    /// Process an incoming message (decrypt or handle proposal/commit)
    pub fn process_message(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
    ) -> crate::MlsResult<ProcessedMessage> {
        self.process_message_with_secret_persistence(provider, msg, true, None)
    }

    /// Process a durable protocol event using its trusted Delivery Service
    /// acceptance timestamp for KeyPackage lifetime validation.
    pub fn process_message_at(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
        server_accepted_at_seconds: u64,
    ) -> crate::MlsResult<ProcessedMessage> {
        self.process_message_with_secret_persistence(
            provider,
            msg,
            true,
            Some(server_accepted_at_seconds),
        )
    }

    /// Process an incoming application message while keeping the durable
    /// receiver ratchet at its previous state.
    pub fn process_message_deferred(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
    ) -> crate::MlsResult<ProcessedMessage> {
        self.process_message_with_secret_persistence(provider, msg, false, None)
    }

    fn process_message_with_secret_persistence(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
        persist_message_secrets: bool,
        server_accepted_at_seconds: Option<u64>,
    ) -> crate::MlsResult<ProcessedMessage> {
        mls_debug!(
            "[MLS] process_message: msg_len={}, group_epoch={}",
            msg.len(),
            self.epoch()
        );

        let mut msg_slice = msg.as_slice();
        let mls_msg = MlsMessageIn::tls_deserialize(&mut msg_slice).map_err(|_| {
            mls_error!("[MLS] process_message: deserialization failed");
            MlsError::DeserializationError
        })?;

        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let processed_msg = match mls_msg.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                mls_debug!("[MLS] process_message: msg_type=PublicMessage");
                let result = match server_accepted_at_seconds {
                    Some(accepted_at) => group.process_message_at(&*prov_guard, msg, accepted_at),
                    None if persist_message_secrets => group.process_message(&*prov_guard, msg),
                    None => group.process_message_deferred(&*prov_guard, msg),
                };
                if result.is_err() && server_accepted_at_seconds.is_some() {
                    let group_id = group.group_id().clone();
                    let durable_group = MlsGroup::load(prov_guard.storage(), &group_id)
                        .map_err(|_| MlsError::StorageError)?
                        .ok_or(MlsError::GroupNotFound)?;
                    *group = durable_group;
                }
                result.map_err(|error| {
                    mls_error!("[MLS] process_message: public message processing failed");
                    map_process_message_error(error)
                })?
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                mls_debug!("[MLS] process_message: msg_type=PrivateMessage");
                let result = match server_accepted_at_seconds {
                    Some(accepted_at) => group.process_message_at(&*prov_guard, msg, accepted_at),
                    None if persist_message_secrets => group.process_message(&*prov_guard, msg),
                    None => group.process_message_deferred(&*prov_guard, msg),
                };
                if result.is_err() && server_accepted_at_seconds.is_some() {
                    let group_id = group.group_id().clone();
                    let durable_group = MlsGroup::load(prov_guard.storage(), &group_id)
                        .map_err(|_| MlsError::StorageError)?
                        .ok_or(MlsError::GroupNotFound)?;
                    *group = durable_group;
                }
                result.map_err(|error| {
                    mls_error!("[MLS] process_message: private message processing failed");
                    map_process_message_error(error)
                })?
            }
            MlsMessageBodyIn::Welcome(_) => {
                return Err(MlsError::InvalidMessage);
            }
            MlsMessageBodyIn::GroupInfo(_) => {
                return Err(MlsError::InvalidMessage);
            }
            MlsMessageBodyIn::KeyPackage(_) => {
                return Err(MlsError::InvalidMessage);
            }
        };

        let epoch = processed_msg.epoch().as_u64();
        let sender_index = if let openmls::prelude::Sender::Member(idx) = processed_msg.sender() {
            idx.u32()
        } else {
            0
        };

        let aad = processed_msg.aad().to_vec();

        // Drop prov_guard before store/merge operations that also need the provider
        drop(prov_guard);

        match processed_msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                mls_debug!(
                    "[MLS] process_message: OK ApplicationMessage, epoch={}, deferred={}",
                    epoch,
                    !persist_message_secrets
                );
                Ok(ProcessedMessage {
                    message_type: MessageType::ApplicationMessage,
                    content: Some(app_msg.into_bytes()),
                    sender_index,
                    epoch,
                    aad,
                })
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let prov_guard = provider.lock();
                group
                    .store_pending_proposal(prov_guard.storage(), *proposal)
                    .map_err(|_| {
                        mls_error!("[MLS] process_message: proposal persistence failed");
                        MlsError::StorageError
                    })?;
                Ok(ProcessedMessage {
                    message_type: MessageType::Proposal,
                    content: None,
                    sender_index,
                    epoch,
                    aad,
                })
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let prov_guard = provider.lock();
                group
                    .merge_staged_commit(&*prov_guard, *staged_commit)
                    .map_err(|_| {
                        mls_error!("[MLS] process_message: staged commit merge failed");
                        MlsError::InternalError
                    })?;
                Ok(ProcessedMessage {
                    message_type: MessageType::Commit,
                    content: None,
                    sender_index,
                    epoch,
                    aad,
                })
            }
        }
    }

    /// Process message and return raw bytes (legacy API)
    pub fn process_message_raw(
        &self,
        provider: &Provider,
        msg: Vec<u8>,
    ) -> crate::MlsResult<Vec<u8>> {
        let processed = self.process_message(provider, msg)?;
        Ok(processed.content.unwrap_or_default())
    }

    // ========================================================================
    // Proposals
    // ========================================================================

    /// Propose adding a new member
    pub fn propose_add_member(
        &self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> crate::MlsResult<ProposalMessage> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let (proposal_msg, proposal_ref) = group
            .propose_add_member(&*prov_guard, &sender.keypair, &new_member.inner)
            .map_err(|_| MlsError::InternalError)?;

        let mut serialized = vec![];
        proposal_msg
            .tls_serialize(&mut serialized)
            .map_err(|_| MlsError::SerializationError)?;

        Ok(ProposalMessage {
            bytes: serialized,
            proposal_ref: proposal_ref.as_slice().to_vec(),
        })
    }

    /// Propose adding a user with multiple devices (does NOT commit immediately)
    pub fn propose_add_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        device_key_packages: Vec<KeyPackage>,
    ) -> crate::MlsResult<Vec<ProposalMessage>> {
        if device_key_packages.is_empty() {
            return Err(MlsError::InvalidState);
        }

        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let mut proposals = Vec::with_capacity(device_key_packages.len());
        for kp in &device_key_packages {
            let (proposal_msg, proposal_ref) = group
                .propose_add_member(&*prov_guard, &sender.keypair, &kp.inner)
                .map_err(|_| MlsError::InternalError)?;

            let mut serialized = vec![];
            proposal_msg
                .tls_serialize(&mut serialized)
                .map_err(|_| MlsError::SerializationError)?;

            proposals.push(ProposalMessage {
                bytes: serialized,
                proposal_ref: proposal_ref.as_slice().to_vec(),
            });
        }

        Ok(proposals)
    }

    /// Propose removing a member by leaf index
    pub fn propose_remove_member(
        &self,
        provider: &Provider,
        sender: &Identity,
        member_index: u32,
    ) -> crate::MlsResult<ProposalMessage> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();
        let leaf_index = LeafNodeIndex::new(member_index);

        let (proposal_msg, proposal_ref) = group
            .propose_remove_member(&*prov_guard, &sender.keypair, leaf_index)
            .map_err(|_| MlsError::InternalError)?;

        let mut serialized = vec![];
        proposal_msg
            .tls_serialize(&mut serialized)
            .map_err(|_| MlsError::SerializationError)?;

        Ok(ProposalMessage {
            bytes: serialized,
            proposal_ref: proposal_ref.as_slice().to_vec(),
        })
    }

    /// Propose removing a member by user_id (removes ONE leaf node)
    pub fn propose_remove_member_by_user_id(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_id: String,
    ) -> crate::MlsResult<ProposalMessage> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let user_id_bytes: Vec<u8> = user_id.bytes().collect();
        let credential = BasicCredential::new(user_id_bytes);

        let (proposal_msg, proposal_ref) = group
            .propose_remove_member_by_credential(&*prov_guard, &sender.keypair, &credential.into())
            .map_err(|_| MlsError::InternalError)?;

        let mut serialized = vec![];
        proposal_msg
            .tls_serialize(&mut serialized)
            .map_err(|_| MlsError::SerializationError)?;

        Ok(ProposalMessage {
            bytes: serialized,
            proposal_ref: proposal_ref.as_slice().to_vec(),
        })
    }

    /// Propose removing ALL devices of a user by user_id
    pub fn propose_remove_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_id: String,
    ) -> crate::MlsResult<Vec<ProposalMessage>> {
        let member_indices: Vec<u32> = self
            .members_by_user_id(user_id.clone())
            .iter()
            .map(|m| m.index)
            .collect();

        if member_indices.is_empty() {
            return Err(MlsError::MemberNotFound);
        }

        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let mut proposals = Vec::with_capacity(member_indices.len());
        for index in member_indices {
            let leaf_index = LeafNodeIndex::new(index);
            let (proposal_msg, proposal_ref) = group
                .propose_remove_member(&*prov_guard, &sender.keypair, leaf_index)
                .map_err(|_| MlsError::InternalError)?;

            let mut serialized = vec![];
            proposal_msg
                .tls_serialize(&mut serialized)
                .map_err(|_| MlsError::SerializationError)?;

            proposals.push(ProposalMessage {
                bytes: serialized,
                proposal_ref: proposal_ref.as_slice().to_vec(),
            });
        }

        Ok(proposals)
    }

    /// Propose a self-update (key rotation)
    pub fn propose_self_update(
        &self,
        provider: &Provider,
        sender: &Identity,
    ) -> crate::MlsResult<ProposalMessage> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let (proposal_msg, proposal_ref) = group
            .propose_self_update(
                &*prov_guard,
                &sender.keypair,
                openmls::prelude::LeafNodeParameters::default(),
            )
            .map_err(|_| MlsError::InternalError)?;

        let mut serialized = vec![];
        proposal_msg
            .tls_serialize(&mut serialized)
            .map_err(|_| MlsError::SerializationError)?;

        Ok(ProposalMessage {
            bytes: serialized,
            proposal_ref: proposal_ref.as_slice().to_vec(),
        })
    }

    /// Leave the group by creating a self-remove proposal
    pub fn leave_group(&self, provider: &Provider, sender: &Identity) -> crate::MlsResult<Vec<u8>> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let proposal_msg = group
            .leave_group(&*prov_guard, &sender.keypair)
            .map_err(|_| {
                mls_error!("[MLS] leave_group failed");
                MlsError::InternalError
            })?;

        let mut serialized = vec![];
        proposal_msg
            .tls_serialize(&mut serialized)
            .map_err(|_| MlsError::SerializationError)?;

        Ok(serialized)
    }

    /// Get the number of pending proposals
    pub fn pending_proposals_count(&self) -> u64 {
        let group = self.lock_group();
        group.pending_proposals().count() as u64
    }

    /// Clear all pending proposals
    pub fn clear_pending_proposals(&self, provider: &Provider) -> crate::MlsResult<()> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();
        group
            .clear_pending_proposals(prov_guard.storage())
            .map_err(|_| MlsError::InternalError)?;
        Ok(())
    }

    // ========================================================================
    // Commits
    // ========================================================================

    /// Commit all pending proposals
    pub fn commit_pending_proposals(
        &self,
        provider: &Provider,
        sender: &Identity,
    ) -> crate::MlsResult<CommitBundle> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        // Auto-clear stale pending commit from a previous failed operation
        if group.pending_commit().is_some() {
            mls_debug!("[MLS] commit_pending_proposals: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|_| {
                    mls_error!("[MLS] clear_pending_commit failed");
                    MlsError::InternalError
                })?;
        }

        let (commit_msg, welcome_msg, group_info) = group
            .commit_to_pending_proposals(&*prov_guard, &sender.keypair)
            .map_err(|_| {
                mls_error!("[MLS] commit_pending_proposals failed");
                MlsError::InternalError
            })?;

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info)
    }

    /// Merge the pending commit after DS confirmation
    pub fn merge_pending_commit(&self, provider: &Provider) -> crate::MlsResult<()> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();
        group.merge_pending_commit(&*prov_guard).map_err(|_| {
            mls_error!("[MLS] merge_pending_commit failed");
            MlsError::InternalError
        })?;
        Ok(())
    }

    /// Discard the pending commit (rollback)
    pub fn clear_pending_commit(&self, provider: &Provider) -> crate::MlsResult<()> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();
        group
            .clear_pending_commit(prov_guard.storage())
            .map_err(|_| MlsError::InternalError)?;
        Ok(())
    }

    /// Add members and commit immediately
    pub fn add_members(
        &self,
        provider: &Provider,
        sender: &Identity,
        new_members: Vec<KeyPackage>,
    ) -> crate::MlsResult<CommitBundle> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        // Auto-clear stale pending commit
        if group.pending_commit().is_some() {
            mls_debug!("[MLS] add_members: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|_| {
                    mls_error!("[MLS] clear_pending_commit failed");
                    MlsError::InternalError
                })?;
        }

        // Filter duplicates by signature key
        let existing_sig_keys: std::collections::HashSet<Vec<u8>> =
            group.members().map(|m| m.signature_key.clone()).collect();

        let key_packages: Vec<_> = new_members
            .iter()
            .filter(|kp| {
                let sig_key = kp.inner.leaf_node().signature_key().as_slice().to_vec();
                let is_dup = existing_sig_keys.contains(&sig_key);
                if is_dup {
                    mls_debug!("[MLS] add_members: skipping duplicate signature key");
                }
                !is_dup
            })
            .map(|kp| kp.inner.clone())
            .collect();

        if key_packages.is_empty() {
            mls_debug!("[MLS] add_members: all members already in group, nothing to add");
            return Err(MlsError::InvalidState);
        }

        mls_debug!(
            "[MLS] add_members: key_packages count={}, group epoch={}",
            key_packages.len(),
            group.epoch().as_u64()
        );
        let (commit_msg, welcome_msg, group_info) = group
            .add_members(&*prov_guard, &sender.keypair, &key_packages)
            .map_err(|_| {
                mls_error!("[MLS] add_members failed");
                MlsError::InternalError
            })?;

        let mut welcome_bytes = vec![];
        welcome_msg
            .tls_serialize(&mut welcome_bytes)
            .map_err(|_| MlsError::SerializationError)?;

        let commit_bundle =
            serialize_commit_bundle(&commit_msg, None::<&MlsMessageOut>, group_info)?;
        Ok(CommitBundle {
            commit: commit_bundle.commit,
            welcome: Some(welcome_bytes),
            group_info: commit_bundle.group_info,
        })
    }

    /// Add a user with multiple devices and commit immediately
    pub fn add_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        device_key_packages: Vec<KeyPackage>,
    ) -> crate::MlsResult<CommitBundle> {
        if device_key_packages.is_empty() {
            return Err(MlsError::InvalidState);
        }
        self.add_members(provider, sender, device_key_packages)
    }

    /// Remove members and commit immediately
    pub fn remove_members(
        &self,
        provider: &Provider,
        sender: &Identity,
        member_indices: Vec<u32>,
    ) -> crate::MlsResult<CommitBundle> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        if group.pending_commit().is_some() {
            mls_debug!("[MLS] remove_members: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|_| {
                    mls_error!("[MLS] remove_members: clear_pending_commit failed");
                    MlsError::InternalError
                })?;
        }

        let leaf_indices: Vec<_> = member_indices
            .iter()
            .map(|i| LeafNodeIndex::new(*i))
            .collect();

        let (commit_msg, welcome_msg, group_info) = group
            .remove_members(&*prov_guard, &sender.keypair, &leaf_indices)
            .map_err(|_| {
                mls_error!("[MLS] remove_members failed");
                MlsError::InternalError
            })?;

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info)
    }

    /// Remove ALL devices of a user by user_id and commit immediately
    pub fn remove_user(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_id: String,
    ) -> crate::MlsResult<CommitBundle> {
        let member_indices: Vec<u32> = self
            .members_by_user_id(user_id.clone())
            .iter()
            .map(|m| m.index)
            .collect();

        if member_indices.is_empty() {
            return Err(MlsError::MemberNotFound);
        }

        self.remove_members(provider, sender, member_indices)
    }

    /// Remove multiple users (all their devices) and commit immediately
    pub fn remove_users(
        &self,
        provider: &Provider,
        sender: &Identity,
        user_ids: Vec<String>,
    ) -> crate::MlsResult<CommitBundle> {
        let mut member_indices: Vec<u32> = Vec::new();

        for user_id in &user_ids {
            let indices: Vec<u32> = self
                .members_by_user_id(user_id.clone())
                .iter()
                .map(|m| m.index)
                .collect();
            member_indices.extend(indices);
        }

        member_indices.sort();
        member_indices.dedup();

        if member_indices.is_empty() {
            return Err(MlsError::MemberNotFound);
        }

        self.remove_members(provider, sender, member_indices)
    }

    /// Create one inline commit containing removals, adds, and/or a self-update.
    pub fn commit_group_changes(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
        add_members: Vec<KeyPackage>,
        force_self_update: bool,
    ) -> crate::MlsResult<CommitBundle> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        if group.pending_commit().is_some() {
            mls_debug!("[MLS] commit_group_changes: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|_| {
                    mls_error!("[MLS] commit_group_changes: clear_pending_commit failed");
                    MlsError::InternalError
                })?;
        }

        let own_leaf_index = group.own_leaf_index().u32();
        let mut remove_indices: Vec<u32> = Vec::new();

        for user_id in &remove_user_ids {
            for member in group.members() {
                let member_user_id =
                    String::from_utf8_lossy(member.credential.serialized_content()).to_string();
                if &member_user_id != user_id {
                    continue;
                }
                if member.index.u32() == own_leaf_index {
                    mls_error!("[MLS] commit_group_changes: attempted to remove own leaf");
                    return Err(MlsError::InvalidState);
                }
                remove_indices.push(member.index.u32());
            }
        }

        remove_indices.sort_unstable();
        remove_indices.dedup();

        let removed_index_set: HashSet<u32> = remove_indices.iter().copied().collect();
        let existing_sig_keys: HashSet<Vec<u8>> = group
            .members()
            .filter(|member| !removed_index_set.contains(&member.index.u32()))
            .map(|member| member.signature_key.clone())
            .collect();

        let key_packages: Vec<_> = add_members
            .iter()
            .filter(|kp| {
                let sig_key = kp.inner.leaf_node().signature_key().as_slice().to_vec();
                !existing_sig_keys.contains(&sig_key)
            })
            .map(|kp| kp.inner.clone())
            .collect();

        if remove_indices.is_empty() && key_packages.is_empty() && !force_self_update {
            mls_debug!("[MLS] commit_group_changes: no valid operation");
            return Err(MlsError::InvalidState);
        }

        let leaf_indices = remove_indices.into_iter().map(LeafNodeIndex::new);
        let commit_bundle = group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_removals(leaf_indices)
            .propose_adds(key_packages)
            .force_self_update(force_self_update)
            .load_psks(prov_guard.storage())
            .map_err(|_| {
                mls_error!("[MLS] commit_group_changes: PSK load failed");
                MlsError::InternalError
            })?
            .build(
                prov_guard.rand(),
                prov_guard.crypto(),
                &sender.keypair,
                |_| true,
            )
            .map_err(|_| {
                mls_error!("[MLS] commit_group_changes: commit build failed");
                MlsError::InternalError
            })?
            .stage_commit(&*prov_guard)
            .map_err(|_| {
                mls_error!("[MLS] commit_group_changes: commit staging failed");
                MlsError::InternalError
            })?;

        let (commit_msg, welcome, group_info) = commit_bundle.into_contents();
        let welcome_msg = welcome
            .map(|w| MlsMessageOut::from_welcome(w, openmls::prelude::ProtocolVersion::Mls10));

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info)
    }

    /// Create one inline commit that removes stale members and adds new members.
    pub fn commit_member_add_with_removals(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
        add_members: Vec<KeyPackage>,
    ) -> crate::MlsResult<CommitBundle> {
        self.commit_group_changes(provider, sender, remove_user_ids, add_members, false)
    }

    /// Create one inline commit that removes stale members and rotates the sender leaf.
    pub fn commit_self_update_with_removals(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
    ) -> crate::MlsResult<CommitBundle> {
        self.commit_group_changes(provider, sender, remove_user_ids, vec![], true)
    }

    /// Create one inline commit that removes one or more members.
    pub fn commit_member_removals(
        &self,
        provider: &Provider,
        sender: &Identity,
        remove_user_ids: Vec<String>,
    ) -> crate::MlsResult<CommitBundle> {
        self.commit_group_changes(provider, sender, remove_user_ids, vec![], false)
    }

    /// Key rotation with immediate commit
    pub fn self_update(
        &self,
        provider: &Provider,
        sender: &Identity,
    ) -> crate::MlsResult<CommitBundle> {
        let mut group = self.lock_group();
        let prov_guard = provider.lock();

        let bundle = group
            .self_update(
                &*prov_guard,
                &sender.keypair,
                openmls::prelude::LeafNodeParameters::default(),
            )
            .map_err(|_| MlsError::InternalError)?;

        let (commit_msg, welcome, group_info) = bundle.into_contents();
        let welcome_msg = welcome
            .map(|w| MlsMessageOut::from_welcome(w, openmls::prelude::ProtocolVersion::Mls10));

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info)
    }
}

/// Decrypt and verify one application ciphertext against explicit V2 archive material.
pub fn decrypt_epoch_archive_v2(
    provider: &Provider,
    archive: Vec<u8>,
    snapshot: Vec<u8>,
    ciphertext: Vec<u8>,
    allow_own_messages: bool,
    max_forward_distance: u32,
) -> crate::MlsResult<ArchivedMessage> {
    let provider = provider.lock();
    let plaintext = decrypt_with_epoch_archive_v2(
        provider.crypto(),
        &archive,
        &snapshot,
        &ciphertext,
        RecoveryDecryptOptions {
            allow_own_messages,
            max_forward_distance: (max_forward_distance != 0).then_some(max_forward_distance),
        },
    )
    .map_err(|_| MlsError::InvalidMessage)?;
    Ok(ArchivedMessage {
        content: plaintext.content,
        sender_index: plaintext.sender_index,
        generation: plaintext.generation,
        epoch: plaintext.epoch,
        aad: plaintext.aad,
        own_message: plaintext.own_message,
    })
}

// ============================================================================
// Error mapping
// ============================================================================

fn map_process_message_error<StorageError>(error: ProcessMessageError<StorageError>) -> MlsError {
    match error {
        ProcessMessageError::StorageError(_) => MlsError::StorageError,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
            MessageDecryptionError::SecretTreeError(SecretTreeError::SecretReuseError),
        )) => MlsError::MessageAlreadyConsumed,
        _ => MlsError::InvalidMessage,
    }
}

// ============================================================================
// Standalone binding-neutral operations
// ============================================================================

/// Join a group via External Commit
#[allow(deprecated)]
pub fn join_external(
    provider: &Provider,
    identity: &Identity,
    group_info: Vec<u8>,
    ratchet_tree: Option<RatchetTree>,
) -> crate::MlsResult<ExternalJoinResult> {
    let mut gi_slice = group_info.as_slice();
    let mls_message =
        MlsMessageIn::tls_deserialize(&mut gi_slice).map_err(|_| MlsError::DeserializationError)?;

    let verified_group_info = match mls_message.extract() {
        MlsMessageBodyIn::GroupInfo(gi) => Ok(gi),
        _ => Err(MlsError::InvalidMessage),
    }?;

    let ratchet_tree_in = ratchet_tree.map(|rt| rt.inner.clone());

    let guard = provider.lock();
    let (mls_group, commit_msg, _group_info) = MlsGroup::join_by_external_commit(
        &*guard,
        &identity.keypair,
        ratchet_tree_in,
        verified_group_info,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(5)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build(),
        None,
        None,
        &[],
        identity.credential_with_key.clone(),
    )
    .map_err(|_| MlsError::ExternalCommitError)?;

    let mut commit_bytes = vec![];
    commit_msg
        .tls_serialize(&mut commit_bytes)
        .map_err(|_| MlsError::SerializationError)?;

    Ok(ExternalJoinResult {
        group: Group {
            mls_group: Arc::new(Mutex::new(mls_group)),
        },
        commit: commit_bytes,
    })
}

// ============================================================================
// Helpers
// ============================================================================

/// Serialize a commit bundle into bytes.
fn serialize_commit_bundle(
    commit: &MlsMessageOut,
    welcome: Option<&MlsMessageOut>,
    group_info: Option<openmls::messages::group_info::GroupInfo>,
) -> crate::MlsResult<CommitBundle> {
    let mut commit_bytes = vec![];
    commit
        .tls_serialize(&mut commit_bytes)
        .map_err(|_| MlsError::SerializationError)?;

    let welcome_bytes = welcome
        .map(|w| {
            let mut bytes = vec![];
            w.tls_serialize(&mut bytes)
                .map_err(|_| MlsError::SerializationError)?;
            Ok::<_, MlsError>(bytes)
        })
        .transpose()?;

    let group_info_bytes = group_info
        .map(|gi| {
            let mls_msg: MlsMessageOut = gi.into();
            let mut bytes = vec![];
            mls_msg
                .tls_serialize(&mut bytes)
                .map_err(|_| MlsError::SerializationError)?;
            Ok::<_, MlsError>(bytes)
        })
        .transpose()?;

    Ok(CommitBundle {
        commit: commit_bytes,
        welcome: welcome_bytes,
        group_info: group_info_bytes,
    })
}
