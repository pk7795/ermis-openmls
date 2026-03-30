//! Proposal message types and APIs

use js_sys::Uint8Array;
use openmls::framing::MlsMessageOut;
use openmls::prelude::LeafNodeIndex;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize;
use wasm_bindgen::prelude::*;

use crate::{identity::Identity, Group, Provider};

/// A proposal message that can be sent to other group members
#[wasm_bindgen]
pub struct ProposalMessage {
    bytes: Vec<u8>,
    proposal_ref: Vec<u8>,
}

#[wasm_bindgen]
impl ProposalMessage {
    /// Get the serialized proposal message bytes
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Get the proposal reference for tracking
    #[wasm_bindgen(getter)]
    pub fn proposal_ref(&self) -> Vec<u8> {
        self.proposal_ref.clone()
    }

    /// Get bytes as Uint8Array for JavaScript
    pub fn bytes_as_uint8array(&self) -> Uint8Array {
        unsafe { Uint8Array::new(&Uint8Array::view(&self.bytes)) }
    }
}

impl ProposalMessage {
    pub(crate) fn new(msg: &MlsMessageOut, proposal_ref: Vec<u8>) -> Self {
        let mut serialized = vec![];
        msg.tls_serialize(&mut serialized).unwrap();
        Self {
            bytes: serialized,
            proposal_ref,
        }
    }
}

// Proposal methods for Group
#[wasm_bindgen]
impl Group {
    /// Propose adding a new member (does NOT commit immediately)
    ///
    /// Use this when you want to batch multiple proposals before committing.
    /// Call `commit_pending_proposals` after queuing all proposals.
    pub fn propose_add_member(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &crate::identity::KeyPackage,
    ) -> Result<ProposalMessage, JsError> {
        let (proposal_msg, proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        Ok(ProposalMessage::new(
            &proposal_msg,
            proposal_ref.as_slice().to_vec(),
        ))
    }

    /// Propose adding a user with multiple devices (does NOT commit immediately)
    ///
    /// Each KeyPackage represents one device. Creates one add proposal
    /// per device, all queued as pending proposals.
    /// Call `commit_pending_proposals` to batch them into a single commit.
    pub fn propose_add_user(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        device_key_packages: Vec<crate::identity::KeyPackage>,
    ) -> Result<Vec<ProposalMessage>, JsError> {
        if device_key_packages.is_empty() {
            return Err(JsError::new("At least one KeyPackage is required"));
        }

        let mut proposals = Vec::with_capacity(device_key_packages.len());
        for kp in &device_key_packages {
            let proposal = self.propose_add_member(provider, sender, kp)?;
            proposals.push(proposal);
        }

        Ok(proposals)
    }

    /// Propose removing a member by leaf index
    ///
    /// Use `member_by_user_id` to get the leaf index from a user_id.
    pub fn propose_remove_member(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        member_index: u32,
    ) -> Result<ProposalMessage, JsError> {
        let leaf_index = LeafNodeIndex::new(member_index);
        let (proposal_msg, proposal_ref) =
            self.mls_group
                .propose_remove_member(provider.as_ref(), &sender.keypair, leaf_index)?;

        Ok(ProposalMessage::new(
            &proposal_msg,
            proposal_ref.as_slice().to_vec(),
        ))
    }

    /// Propose removing a member by user_id
    ///
    /// This is a convenience method that finds the member by credential
    /// and proposes their removal.
    /// Note: This only removes ONE leaf node. For multi-device users,
    /// use `propose_remove_user` instead.
    pub fn propose_remove_member_by_user_id(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        user_id: &str,
    ) -> Result<ProposalMessage, JsError> {
        let user_id_bytes: Vec<u8> = user_id.bytes().collect();
        let credential = openmls::credentials::BasicCredential::new(user_id_bytes);

        let (proposal_msg, proposal_ref) = self.mls_group.propose_remove_member_by_credential(
            provider.as_ref(),
            &sender.keypair,
            &credential.into(),
        )?;

        Ok(ProposalMessage::new(
            &proposal_msg,
            proposal_ref.as_slice().to_vec(),
        ))
    }

    /// Propose removing ALL devices of a user by user_id
    ///
    /// A user with N devices will have N leaf nodes. This creates
    /// one remove proposal per device. Call `commit_pending_proposals`
    /// after this to finalize all removals in a single commit.
    pub fn propose_remove_user(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        user_id: &str,
    ) -> Result<Vec<ProposalMessage>, JsError> {
        let member_indices: Vec<u32> = self
            .members_by_user_id(user_id)
            .iter()
            .map(|m| m.index())
            .collect();

        if member_indices.is_empty() {
            return Err(JsError::new(&format!(
                "No members found for user_id: {user_id}"
            )));
        }

        let mut proposals = Vec::with_capacity(member_indices.len());
        for index in member_indices {
            let proposal = self.propose_remove_member(provider, sender, index)?;
            proposals.push(proposal);
        }

        Ok(proposals)
    }

    /// Propose a self-update (key rotation for forward secrecy)
    pub fn propose_self_update(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<ProposalMessage, JsError> {
        let (proposal_msg, proposal_ref) = self.mls_group.propose_self_update(
            provider.as_ref(),
            &sender.keypair,
            openmls::prelude::LeafNodeParameters::default(),
        )?;

        Ok(ProposalMessage::new(
            &proposal_msg,
            proposal_ref.as_slice().to_vec(),
        ))
    }

    /// Leave the group by creating a self-remove proposal
    ///
    /// Creates a Remove Proposal for the caller's own leaf node.
    /// This proposal must be sent to the server and committed by another member.
    /// The caller should NOT commit this proposal themselves.
    ///
    /// Returns the serialized proposal message bytes.
    pub fn leave_group(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<Vec<u8>, JsError> {
        let proposal_msg = self
            .mls_group
            .leave_group(provider.as_ref(), &sender.keypair)?;

        let mut serialized = vec![];
        proposal_msg
            .tls_serialize(&mut serialized)
            .map_err(|e| JsError::new(&format!("Failed to serialize leave proposal: {e}")))?;

        Ok(serialized)
    }

    /// Get the number of pending proposals
    pub fn pending_proposals_count(&self) -> usize {
        self.mls_group.pending_proposals().count()
    }

    /// Clear all pending proposals without committing
    pub fn clear_pending_proposals(&mut self, provider: &Provider) -> Result<(), JsError> {
        self.mls_group
            .clear_pending_proposals(provider.0.storage())
            .map_err(|e| JsError::new(&format!("Failed to clear pending proposals: {e}")))
    }
}
