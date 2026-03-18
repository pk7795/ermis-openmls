//! MLS Group operations for UniFFI bindings
//!
//! Ported from openmls-wasm/src/group/ — combines mod.rs, commit.rs, messaging.rs,
//! proposal.rs, and state.rs into a single file for the UniFFI crate.

use std::sync::{Arc, Mutex};

use openmls::{
    credentials::BasicCredential,
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::LeafNodeIndex,
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
            .build(
                &*guard,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .map_err(|_| MlsError::InternalError)?;

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

        let config = MlsGroupJoinConfig::builder().build();
        let ratchet_tree_in = ratchet_tree.map(|rt| rt.inner.clone());

        let guard = provider.lock();
        let mls_group =
            StagedWelcome::new_from_welcome(&*guard, &config, mls_welcome, ratchet_tree_in)
                .map_err(|_| MlsError::InternalError)?
                .into_group(&*guard)
                .map_err(|_| MlsError::InternalError)?;

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
        let mut msg_slice = msg.as_slice();
        let mls_msg = MlsMessageIn::tls_deserialize(&mut msg_slice)
            .map_err(|_| MlsError::DeserializationError)?;

        let mut group = self.mls_group.lock().unwrap();
        let prov_guard = provider.lock();

        let processed_msg = match mls_msg.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => group
                .process_message(&*prov_guard, msg)
                .map_err(|_| MlsError::InvalidMessage)?,
            MlsMessageBodyIn::PrivateMessage(msg) => group
                .process_message(&*prov_guard, msg)
                .map_err(|_| MlsError::InvalidMessage)?,
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
                    .map_err(|_| MlsError::StorageError)?;
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
                    .map_err(|_| MlsError::InternalError)?;
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

        let (commit_msg, welcome_msg, group_info) = group
            .commit_to_pending_proposals(&*prov_guard, &sender.keypair)
            .map_err(|_| MlsError::InternalError)?;

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info.as_ref())
    }

    /// Merge the pending commit after DS confirmation
    pub fn merge_pending_commit(&self, provider: Arc<Provider>) -> Result<(), MlsError> {
        let mut group = self.mls_group.lock().unwrap();
        let mut prov_guard = provider.lock();
        group
            .merge_pending_commit(&mut *prov_guard)
            .map_err(|_| MlsError::InternalError)
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

        let key_packages: Vec<_> = new_members.iter().map(|kp| kp.inner.clone()).collect();

        let (commit_msg, welcome_msg, group_info) = group
            .add_members(&*prov_guard, &sender.keypair, &key_packages)
            .map_err(|_| MlsError::InternalError)?;

        let mut commit_bytes = vec![];
        commit_msg
            .tls_serialize(&mut commit_bytes)
            .map_err(|_| MlsError::SerializationError)?;

        let mut welcome_bytes = vec![];
        welcome_msg
            .tls_serialize(&mut welcome_bytes)
            .map_err(|_| MlsError::SerializationError)?;

        let group_info_bytes = group_info
            .map(|gi| {
                let mut bytes = vec![];
                gi.tls_serialize(&mut bytes)
                    .map_err(|_| MlsError::SerializationError)?;
                Ok::<_, MlsError>(bytes)
            })
            .transpose()?;

        Ok(CommitBundle {
            commit: commit_bytes,
            welcome: Some(welcome_bytes),
            group_info: group_info_bytes,
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

        let leaf_indices: Vec<_> = member_indices
            .iter()
            .map(|i| LeafNodeIndex::new(*i))
            .collect();

        let (commit_msg, welcome_msg, group_info) = group
            .remove_members(&*prov_guard, &sender.keypair, &leaf_indices)
            .map_err(|_| MlsError::InternalError)?;

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info.as_ref())
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

        serialize_commit_bundle(&commit_msg, welcome_msg.as_ref(), group_info.as_ref())
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
    let mut gi_slice = group_info.as_slice();
    let verified_group_info =
        openmls::messages::group_info::VerifiableGroupInfo::tls_deserialize(&mut gi_slice)
            .map_err(|_| MlsError::DeserializationError)?;

    let ratchet_tree_in = ratchet_tree.map(|rt| rt.inner.clone());

    let guard = provider.lock();
    let (mls_group, commit_msg, _group_info) = MlsGroup::join_by_external_commit(
        &*guard,
        &identity.keypair,
        ratchet_tree_in,
        verified_group_info,
        &MlsGroupJoinConfig::builder().build(),
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

fn serialize_commit_bundle<W, G>(
    commit: &MlsMessageOut,
    welcome: Option<&W>,
    group_info: Option<&G>,
) -> Result<CommitBundle, MlsError>
where
    W: Serialize,
    G: Serialize,
{
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
            let mut bytes = vec![];
            gi.tls_serialize(&mut bytes)
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
