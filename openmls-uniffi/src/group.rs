//! MLS Group operations for UniFFI bindings
//!
//! Ported from openmls-wasm/src/group/ — combines mod.rs, commit.rs, messaging.rs,
//! proposal.rs, and state.rs into a single file for the UniFFI crate.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use openmls::{
    credentials::BasicCredential,
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::{LeafNodeIndex, SenderRatchetConfiguration},
};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};

use crate::{
    errors::MlsError,
    identity::{Identity, KeyPackage, CIPHERSUITE},
    provider::Provider,
    types::*,
};

/// An MLS Group representing an encrypted channel.
/// Wraps MlsGroup in a Mutex for thread-safe UniFFI usage.
pub struct Group {
    pub(crate) mls_group: Mutex<MlsGroup>,
}

impl Group {
    // ========================================================================
    // Creation & Joining
    // ========================================================================

    /// Create a new group with a CID from Ermis
    pub fn create_with_cid(
        provider: Arc<Provider>,
        founder: Arc<Identity>,
        cid: String,
    ) -> Result<Self, MlsError> {
        let group_id_bytes = cid.bytes().collect::<Vec<_>>();
        let guard = provider.lock();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .use_ratchet_tree_extension(true)
            // Keep decryption keys for 5 past epochs, allowing late-arriving
            // messages sent before a key rotation to still be decrypted.
            .max_past_epochs(5)
            // out_of_order_tolerance=10: keep 10 past decryption keys within an epoch
            // maximum_forward_distance=2000: allow skipping up to 2000 dropped messages
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build(
                &*guard,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .map_err(|e| {
                mls_error!("[MLS] create_with_cid failed: {:?}", e);
                MlsError::InternalError
            })?;

        Ok(Group {
            mls_group: Mutex::new(mls_group),
        })
    }

    /// Load an existing group from persistent storage by its CID.
    ///
    /// Returns `None` (wrapped in `MlsError`) if the group is not found.
    /// Use `Provider.storedGroupIds()` to discover which groups are available.
    pub fn load_from_storage(provider: Arc<Provider>, cid: String) -> Result<Self, MlsError> {
        let group_id_bytes = cid.bytes().collect::<Vec<_>>();
        let group_id = GroupId::from_slice(&group_id_bytes);
        let guard = provider.lock();

        let mls_group = MlsGroup::load(guard.storage(), &group_id)
            .map_err(|_| MlsError::StorageError)?
            .ok_or(MlsError::GroupNotFound)?;

        Ok(Group {
            mls_group: Mutex::new(mls_group),
        })
    }

    /// Persist the group's current state to the Provider's storage.
    ///
    /// MUST be called after processing application messages (decrypt) to save
    /// the updated ratchet/secret tree state. Without this, a Provider restore
    /// would load stale ratchet state, causing SecretReuseError.
    pub fn save_state(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        let group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();
        group
            .store(prov_guard.storage())
            .map_err(|_| MlsError::StorageError)
    }

    /// Delete this group's persisted OpenMLS state from the Provider storage.
    ///
    /// Use when the local user leaves or is removed from a channel. This clears
    /// stale group state so a later re-add with the same CID can join from a
    /// fresh Welcome without colliding with old provider records.
    pub fn delete_state(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();
        group.delete(prov_guard.storage()).map_err(|e| {
            mls_error!("[MLS] delete_state FAILED: {:?}", e);
            MlsError::StorageError
        })
    }

    /// Join a group using a Welcome message
    pub fn join_with_welcome(
        provider: Arc<Provider>,
        welcome: Vec<u8>,
        ratchet_tree: Option<Arc<RatchetTree>>,
    ) -> Result<Self, MlsError> {
        let mut welcome_slice = welcome.as_slice();
        let mls_welcome = match MlsMessageIn::tls_deserialize(&mut welcome_slice)
            .map_err(|_| MlsError::DeserializationError)?
            .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            _ => Err(MlsError::InvalidMessage),
        }?;

        // Must match the config used in create_with_cid for consistency.
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(5)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build();
        let ratchet_tree_in = ratchet_tree.map(|rt| rt.inner.clone());

        let guard = provider.lock();
        let mls_group =
            StagedWelcome::new_from_welcome(&*guard, &config, mls_welcome, ratchet_tree_in)
                .map_err(|e| {
                    mls_error!("[MLS] join_with_welcome: new_from_welcome failed: {:?}", e);
                    MlsError::InternalError
                })?
                .into_group(&*guard)
                .map_err(|e| {
                    mls_error!("[MLS] join_with_welcome: into_group failed: {:?}", e);
                    MlsError::InternalError
                })?;

        Ok(Group {
            mls_group: Mutex::new(mls_group),
        })
    }

    // ========================================================================
    // State
    // ========================================================================

    /// Get the CID (group_id as string)
    pub fn cid(&self) -> Result<String, MlsError> {
        let group = self.mls_group.lock().unwrap();
        let group_id = group.group_id();
        String::from_utf8(group_id.as_slice().to_vec()).map_err(|_| MlsError::InvalidCid)
    }

    /// Get the raw group_id bytes
    pub fn group_id(&self) -> Vec<u8> {
        let group = self.mls_group.lock().unwrap();
        group.group_id().as_slice().to_vec()
    }

    /// Get current epoch number
    pub fn epoch(&self) -> u64 {
        let group = self.mls_group.lock().unwrap();
        group.epoch().as_u64()
    }

    /// Get all members in the group
    pub fn members(&self) -> Vec<MemberInfo> {
        let group = self.mls_group.lock().unwrap();
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
    ///
    /// A user with N devices will have N entries in the group.
    pub fn members_by_user_id(&self, user_id: String) -> Vec<MemberInfo> {
        self.members()
            .into_iter()
            .filter(|m| m.user_id == user_id)
            .collect()
    }

    /// Get the local member's leaf index
    pub fn own_leaf_index(&self) -> u32 {
        let group = self.mls_group.lock().unwrap();
        group.own_leaf_index().u32()
    }

    /// Check if the group is in operational state
    pub fn is_operational(&self) -> bool {
        let group = self.mls_group.lock().unwrap();
        group.is_active()
    }

    /// Check if there's a pending commit
    pub fn has_pending_commit(&self) -> bool {
        let group = self.mls_group.lock().unwrap();
        group.pending_commit().is_some()
    }

    /// Export the ratchet tree
    pub fn export_ratchet_tree(&self) -> Arc<RatchetTree> {
        let group = self.mls_group.lock().unwrap();
        Arc::new(RatchetTree {
            inner: group.export_ratchet_tree().into(),
        })
    }

    /// Export group info for external commits
    pub fn export_group_info(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        with_ratchet_tree: bool,
    ) -> Result<Vec<u8>, MlsError> {
        let group = self.mls_group.lock().unwrap();
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
        provider: Arc<Provider>,
        label: String,
        context: Vec<u8>,
        key_length: u32,
    ) -> Result<Vec<u8>, MlsError> {
        let group = self.mls_group.lock().unwrap();
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
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
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
        let mut group = self.mls_group.lock().unwrap();
        group.set_aad(aad);
    }

    /// Create an encrypted message with AAD in one call
    pub fn create_message_with_aad(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        {
            let mut group = self.mls_group.lock().unwrap();
            group.set_aad(aad);
        }
        self.create_message(provider, sender, plaintext)
    }

    /// Process an incoming message (decrypt or handle proposal/commit)
    pub fn process_message(
        &self,
        provider: Arc<Provider>,
        msg: Vec<u8>,
    ) -> Result<ProcessedMessage, MlsError> {
        mls_debug!(
            "[MLS] process_message: msg_len={}, group_epoch={}",
            msg.len(),
            self.epoch()
        );

        let mut msg_slice = msg.as_slice();
        let mls_msg = MlsMessageIn::tls_deserialize(&mut msg_slice).map_err(|e| {
            mls_error!("[MLS] process_message: TLS deserialize FAILED: {:?}", e);
            MlsError::DeserializationError
        })?;

        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        let processed_msg = match mls_msg.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                mls_debug!("[MLS] process_message: msg_type=PublicMessage");
                group.process_message(&*prov_guard, msg).map_err(|e| {
                    mls_error!(
                        "[MLS] process_message: PublicMessage processing FAILED: {:?}",
                        e
                    );
                    MlsError::InvalidMessage
                })?
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                mls_debug!("[MLS] process_message: msg_type=PrivateMessage");
                group.process_message(&*prov_guard, msg).map_err(|e| {
                    mls_error!(
                        "[MLS] process_message: PrivateMessage processing FAILED: {:?}",
                        e
                    );
                    MlsError::InvalidMessage
                })?
            }
            MlsMessageBodyIn::Welcome(_) => {
                mls_debug!("[MLS] process_message: received Welcome — wrong message type for process_message");
                return Err(MlsError::InvalidMessage);
            }
            MlsMessageBodyIn::GroupInfo(_) => {
                mls_debug!("[MLS] process_message: received GroupInfo — wrong message type for process_message");
                return Err(MlsError::InvalidMessage);
            }
            MlsMessageBodyIn::KeyPackage(_) => {
                mls_debug!("[MLS] process_message: received KeyPackage — wrong message type for process_message");
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
                // NOTE: Ratchet state is advanced in-memory but NOT persisted here.
                // The caller MUST call `save_state()` after storing the decrypted
                // plaintext in their app database. This ensures that if the app
                // crashes before saving plaintext, the message can be re-decrypted
                // on next launch (ratchet key still in DB).
                //
                // Correct flow:
                //   1. plaintext = process_message(ciphertext)
                //   2. app_db.save(plaintext)        ← persist plaintext first
                //   3. group.save_state(provider)    ← then advance ratchet in DB

                mls_debug!(
                    "[MLS] process_message: OK ApplicationMessage, epoch={}",
                    epoch
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
                    .map_err(|e| {
                        mls_error!(
                            "[MLS] process_message: store_pending_proposal FAILED: {:?}",
                            e
                        );
                        MlsError::StorageError
                    })?;
                mls_debug!("[MLS] process_message: OK Proposal, epoch={}", epoch);
                Ok(ProcessedMessage {
                    message_type: MessageType::Proposal,
                    content: None,
                    sender_index,
                    epoch,
                    aad,
                })
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let mut prov_guard = provider.lock();
                group
                    .merge_staged_commit(&mut *prov_guard, *staged_commit)
                    .map_err(|e| {
                        mls_error!("[MLS] process_message: merge_staged_commit FAILED: {:?}", e);
                        MlsError::InternalError
                    })?;
                mls_debug!(
                    "[MLS] process_message: OK Commit, new_epoch={}",
                    group.epoch().as_u64()
                );
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

    /// Process message and return raw bytes (legacy API, for backwards compatibility)
    ///
    /// Returns decrypted bytes for application messages, empty for proposals/commits.
    pub fn process_message_raw(
        &self,
        provider: Arc<Provider>,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, MlsError> {
        let processed = self.process_message(provider, msg)?;
        Ok(processed.content.unwrap_or_default())
    }

    // ========================================================================
    // Proposals
    // ========================================================================

    /// Propose adding a new member
    pub fn propose_add_member(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        new_member: Arc<KeyPackage>,
    ) -> Result<ProposalMessage, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
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
    ///
    /// Each KeyPackage represents one device. Creates one add proposal
    /// per device, all queued as pending proposals.
    /// Call `commit_pending_proposals` to batch them into a single commit.
    pub fn propose_add_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        device_key_packages: Vec<Arc<KeyPackage>>,
    ) -> Result<Vec<ProposalMessage>, MlsError> {
        if device_key_packages.is_empty() {
            return Err(MlsError::InvalidState);
        }

        let mut group = self.mls_group.lock().unwrap();
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
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        member_index: u32,
    ) -> Result<ProposalMessage, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
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

    /// Propose removing a member by user_id
    /// Note: This only removes ONE leaf node. For multi-device users,
    /// use `propose_remove_user` instead.
    pub fn propose_remove_member_by_user_id(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_id: String,
    ) -> Result<ProposalMessage, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
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
    ///
    /// A user with N devices will have N leaf nodes. This creates
    /// one remove proposal per device. Call `commit_pending_proposals`
    /// after this to finalize all removals in a single commit.
    pub fn propose_remove_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_id: String,
    ) -> Result<Vec<ProposalMessage>, MlsError> {
        let member_indices: Vec<u32> = self
            .members_by_user_id(user_id.clone())
            .iter()
            .map(|m| m.index)
            .collect();

        if member_indices.is_empty() {
            return Err(MlsError::MemberNotFound);
        }

        let mut group = self.mls_group.lock().unwrap();
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
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<ProposalMessage, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
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
    ///
    /// Creates a Remove Proposal for the caller's own leaf node.
    /// This proposal must be sent to the server and committed by another member.
    /// Returns the serialized proposal message bytes.
    pub fn leave_group(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<Vec<u8>, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        let proposal_msg = group
            .leave_group(&*prov_guard, &sender.keypair)
            .map_err(|e| {
                mls_error!("[MLS] leave_group FAILED: {:?}", e);
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
        let group = self.mls_group.lock().unwrap();
        group.pending_proposals().count() as u64
    }

    /// Clear all pending proposals
    pub fn clear_pending_proposals(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();
        group
            .clear_pending_proposals(prov_guard.storage())
            .map_err(|_| MlsError::InternalError)
    }

    // ========================================================================
    // Commits
    // ========================================================================

    /// Commit all pending proposals
    pub fn commit_pending_proposals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<CommitBundle, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        // Auto-clear stale pending commit from a previous failed operation
        if group.pending_commit().is_some() {
            mls_debug!("[MLS] commit_pending_proposals: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|e| {
                    mls_error!("[MLS] clear_pending_commit FAILED: {:?}", e);
                    MlsError::InternalError
                })?;
        }

        let (commit_msg, welcome_msg, group_info) = group
            .commit_to_pending_proposals(&*prov_guard, &sender.keypair)
            .map_err(|e| {
                mls_error!("[MLS] commit_pending_proposals FAILED: {:?}", e);
                MlsError::InternalError
            })?;

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info)
    }

    /// Merge the pending commit after DS confirmation
    pub fn merge_pending_commit(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let mut prov_guard = provider.lock();
        group.merge_pending_commit(&mut *prov_guard).map_err(|e| {
            mls_error!("[MLS] merge_pending_commit FAILED: {:?}", e);
            MlsError::InternalError
        })
    }

    /// Discard the pending commit (rollback)
    pub fn clear_pending_commit(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();
        group
            .clear_pending_commit(prov_guard.storage())
            .map_err(|_| MlsError::InternalError)
    }

    /// Add members and commit immediately
    pub fn add_members(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        new_members: Vec<Arc<KeyPackage>>,
    ) -> Result<CommitBundle, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        // Auto-clear stale pending commit from a previous failed operation
        if group.pending_commit().is_some() {
            mls_debug!("[MLS] add_members: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|e| {
                    mls_error!("[MLS] clear_pending_commit FAILED: {:?}", e);
                    MlsError::InternalError
                })?;
        }

        // Collect existing members' signature keys to filter duplicates
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
            .map_err(|e| {
                mls_error!("[MLS] add_members FAILED: {:?}", e);
                MlsError::InternalError
            })?;

        // Use the shared helper — which wraps GroupInfo as MlsMessageOut before serializing.
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
    ///
    /// Each KeyPackage represents one device of the same user.
    /// All devices are added in a single commit.
    pub fn add_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        device_key_packages: Vec<Arc<KeyPackage>>,
    ) -> Result<CommitBundle, MlsError> {
        if device_key_packages.is_empty() {
            return Err(MlsError::InvalidState);
        }
        self.add_members(provider, sender, device_key_packages)
    }

    /// Remove members and commit immediately
    pub fn remove_members(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        member_indices: Vec<u32>,
    ) -> Result<CommitBundle, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        // Auto-clear stale pending commit from a previous failed operation
        if group.pending_commit().is_some() {
            mls_debug!("[MLS] remove_members: clearing stale pending commit");
            group
                .clear_pending_commit(prov_guard.storage())
                .map_err(|e| {
                    mls_error!("[MLS] remove_members: clear_pending_commit FAILED: {:?}", e);
                    MlsError::InternalError
                })?;
        }

        let own_index = group.own_leaf_index().u32();
        let leaf_indices: Vec<_> = member_indices
            .iter()
            .map(|i| LeafNodeIndex::new(*i))
            .collect();
        mls_debug!(
            "[MLS] remove_members: removing {} leaf indices {:?} (own_index={}, epoch={})",
            leaf_indices.len(),
            member_indices,
            own_index,
            group.epoch().as_u64()
        );

        let (commit_msg, welcome_msg, group_info) = group
            .remove_members(&*prov_guard, &sender.keypair, &leaf_indices)
            .map_err(|e| {
                mls_error!("[MLS] remove_members FAILED: {:?}", e);
                MlsError::InternalError
            })?;

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info)
    }

    /// Remove ALL devices of a user by user_id and commit immediately
    ///
    /// A user with N devices will have N leaf nodes in the group.
    /// This method finds all of them and removes them in a single commit.
    pub fn remove_user(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_id: String,
    ) -> Result<CommitBundle, MlsError> {
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
    ///
    /// Each user_id may have multiple leaf nodes (devices).
    /// This method finds ALL leaf nodes for ALL specified users
    /// and removes them in a single commit.
    pub fn remove_users(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        user_ids: Vec<String>,
    ) -> Result<CommitBundle, MlsError> {
        // Diagnostic: dump all group members for debugging
        let all_members = self.members();
        let own_index = self.own_leaf_index();
        mls_debug!(
            "[MLS] remove_users: target_user_ids={:?}, own_leaf_index={}, sender_user_id={}",
            user_ids,
            own_index,
            sender.user_id()
        );
        for m in &all_members {
            mls_debug!(
                "[MLS]   member: index={}, user_id=\"{}\"{}",
                m.index,
                m.user_id,
                if m.index == own_index {
                    " ← SELF"
                } else {
                    ""
                }
            );
        }

        let mut member_indices: Vec<u32> = Vec::new();

        for user_id in &user_ids {
            let indices: Vec<u32> = self
                .members_by_user_id(user_id.clone())
                .iter()
                .map(|m| m.index)
                .collect();
            mls_debug!(
                "[MLS] remove_users: user_id=\"{}\" → matched leaf indices: {:?}",
                user_id,
                indices
            );
            member_indices.extend(indices);
        }

        // Deduplicate in case of overlapping queries
        member_indices.sort();
        member_indices.dedup();

        if member_indices.is_empty() {
            return Err(MlsError::MemberNotFound);
        }

        self.remove_members(provider, sender, member_indices)
    }

    /// Create one inline commit containing removals, adds, and/or a self-update.
    ///
    /// Uses commit_builder().consume_proposal_store(false) so remove/add
    /// proposals are encoded by value inside the commit. Receivers only need the
    /// commit message; no standalone proposal delivery is required.
    pub fn commit_group_changes(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
        add_members: Vec<Arc<KeyPackage>>,
        force_self_update: bool,
    ) -> Result<CommitBundle, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        if group.pending_commit().is_some() {
            mls_debug!("[MLS] commit_group_changes: clearing stale pending commit");
            group.clear_pending_commit(prov_guard.storage()).map_err(|e| {
                mls_error!("[MLS] commit_group_changes: clear_pending_commit FAILED: {:?}", e);
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
            .map_err(|e| {
                mls_error!("[MLS] commit_group_changes: load_psks FAILED: {:?}", e);
                MlsError::InternalError
            })?
            .build(prov_guard.rand(), prov_guard.crypto(), &sender.keypair, |_| true)
            .map_err(|e| {
                mls_error!("[MLS] commit_group_changes: build FAILED: {:?}", e);
                MlsError::InternalError
            })?
            .stage_commit(&*prov_guard)
            .map_err(|e| {
                mls_error!("[MLS] commit_group_changes: stage_commit FAILED: {:?}", e);
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
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
        add_members: Vec<Arc<KeyPackage>>,
    ) -> Result<CommitBundle, MlsError> {
        self.commit_group_changes(provider, sender, remove_user_ids, add_members, false)
    }

    /// Create one inline commit that removes stale members and rotates the sender leaf.
    pub fn commit_self_update_with_removals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
    ) -> Result<CommitBundle, MlsError> {
        self.commit_group_changes(provider, sender, remove_user_ids, vec![], true)
    }

    /// Create one inline commit that removes one or more members.
    pub fn commit_member_removals(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
        remove_user_ids: Vec<String>,
    ) -> Result<CommitBundle, MlsError> {
        self.commit_group_changes(provider, sender, remove_user_ids, vec![], false)
    }

    /// Key rotation with immediate commit
    pub fn self_update(
        &self,
        provider: Arc<Provider>,
        sender: Arc<Identity>,
    ) -> Result<CommitBundle, MlsError> {
        let mut group = self.mls_group.lock().unwrap();
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

// ============================================================================
// Standalone functions (exposed via UDL namespace)
// ============================================================================

/// Join a group via External Commit
#[allow(deprecated)]
pub fn join_external(
    provider: Arc<Provider>,
    identity: Arc<Identity>,
    group_info: Vec<u8>,
    ratchet_tree: Option<Arc<RatchetTree>>,
) -> Result<ExternalJoinResult, MlsError> {
    // group_info bytes are TLS-serialized MlsMessageOut (from export_group_info)
    // → deserialize as MlsMessageIn first, then extract the GroupInfo body
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
        // Must match the config used in create_with_cid for consistency.
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
        group: Arc::new(Group {
            mls_group: Mutex::new(mls_group),
        }),
        commit: commit_bytes,
    })
}

// ============================================================================
// Helpers
// ============================================================================

/// Serialize a commit bundle into bytes.
///
/// IMPORTANT: GroupInfo MUST be wrapped as MlsMessageOut before serialization.
/// `join_external()` (and `join_with_welcome()`) deserialize via
/// `MlsMessageIn::tls_deserialize()`, which expects the MlsMessageOut wire format.
/// Serializing a raw `GroupInfo` struct directly produces bytes with a different
/// TLS header → `UnknownValue` deserialization error on the client.
fn serialize_commit_bundle(
    commit: &MlsMessageOut,
    welcome: Option<&MlsMessageOut>,
    group_info: Option<openmls::messages::group_info::GroupInfo>,
) -> Result<CommitBundle, MlsError> {
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

    // Convert GroupInfo → MlsMessageOut via Into trait, then serialize.
    // This produces the correct wire format expected by MlsMessageIn::tls_deserialize()
    // in join_external() and the server-side GroupInfo parsing.
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
