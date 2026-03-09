//! Commit APIs for finalizing proposals

use js_sys::Uint8Array;
use openmls::framing::MlsMessageOut;
use openmls::messages::group_info::GroupInfo;
use openmls::prelude::LeafNodeIndex;
use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize;
use wasm_bindgen::prelude::*;

use crate::{
    errors::MlsError,
    identity::{Identity, KeyPackage},
    Group, Provider,
};

/// Bundle containing commit message and optional welcome
#[wasm_bindgen]
pub struct CommitBundle {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    group_info: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl CommitBundle {
    /// Get the commit message bytes
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }

    /// Get the welcome message bytes (if any new members were added)
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Option<Vec<u8>> {
        self.welcome.clone()
    }

    /// Get the group info bytes
    #[wasm_bindgen(getter)]
    pub fn group_info(&self) -> Option<Vec<u8>> {
        self.group_info.clone()
    }

    /// Check if this commit includes a welcome (new members added)
    pub fn has_welcome(&self) -> bool {
        self.welcome.is_some()
    }

    /// Get commit as Uint8Array
    pub fn commit_as_uint8array(&self) -> Uint8Array {
        unsafe { Uint8Array::new(&Uint8Array::view(&self.commit)) }
    }

    /// Get welcome as Uint8Array (returns empty if no welcome)
    pub fn welcome_as_uint8array(&self) -> Uint8Array {
        match &self.welcome {
            Some(w) => unsafe { Uint8Array::new(&Uint8Array::view(w)) },
            None => Uint8Array::new_with_length(0),
        }
    }
}

impl CommitBundle {
    pub(crate) fn new(
        commit: &MlsMessageOut,
        welcome: Option<&MlsMessageOut>,
        group_info: Option<&GroupInfo>,
    ) -> Self {
        let mut commit_bytes = vec![];
        commit.tls_serialize(&mut commit_bytes).unwrap();

        let welcome_bytes = welcome.map(|w| {
            let mut bytes = vec![];
            w.tls_serialize(&mut bytes).unwrap();
            bytes
        });

        let group_info_bytes = group_info.map(|gi| {
            let mut bytes = vec![];
            gi.tls_serialize(&mut bytes).unwrap();
            bytes
        });

        Self {
            commit: commit_bytes,
            welcome: welcome_bytes,
            group_info: group_info_bytes,
        }
    }

    /// Create from tuple (commit, welcome, group_info)
    pub(crate) fn from_add_tuple(
        commit: MlsMessageOut,
        welcome: MlsMessageOut,
        group_info: Option<GroupInfo>,
    ) -> Self {
        Self::new(&commit, Some(&welcome), group_info.as_ref())
    }

    /// Create from tuple (commit, optional_welcome, group_info)
    pub(crate) fn from_remove_tuple(
        commit: MlsMessageOut,
        welcome: Option<MlsMessageOut>,
        group_info: Option<GroupInfo>,
    ) -> Self {
        Self::new(&commit, welcome.as_ref(), group_info.as_ref())
    }
}

// Commit methods for Group
#[wasm_bindgen]
impl Group {
    /// Commit all pending proposals
    ///
    /// This creates a commit message that includes all queued proposals.
    /// Use `merge_pending_commit` after the DS confirms the commit.
    pub fn commit_pending_proposals(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<CommitBundle, JsError> {
        let (commit_msg, welcome_msg, group_info) = self
            .mls_group
            .commit_to_pending_proposals(provider.as_ref(), &sender.keypair)?;

        Ok(CommitBundle::new(
            &commit_msg,
            welcome_msg.as_ref(),
            group_info.as_ref(),
        ))
    }

    /// Merge the pending commit after DS confirmation
    pub fn merge_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .merge_pending_commit(provider.as_mut())
            .map_err(|e| JsError::new(&format!("Failed to merge pending commit: {e}")))
    }

    /// Discard the pending commit (rollback)
    pub fn clear_pending_commit(&mut self, provider: &mut Provider) -> Result<(), JsError> {
        self.mls_group
            .clear_pending_commit(provider.0.storage())
            .map_err(|e| JsError::new(&format!("Failed to clear pending commit: {e}")))
    }

    /// Add members and commit immediately (convenience method)
    ///
    /// Use this when you want to add members without batching.
    /// For batch operations, use `propose_add_member` + `commit_pending_proposals`.
    pub fn add_members(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_members: Vec<KeyPackage>,
    ) -> Result<CommitBundle, JsError> {
        let key_packages: Vec<_> = new_members.iter().map(|kp| kp.0.clone()).collect();

        let (commit_msg, welcome_msg, group_info) =
            self.mls_group
                .add_members(provider.as_ref(), &sender.keypair, &key_packages)?;

        Ok(CommitBundle::from_add_tuple(
            commit_msg,
            welcome_msg,
            group_info,
        ))
    }

    /// Remove members and commit immediately (convenience method)
    pub fn remove_members(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        member_indices: &[u32],
    ) -> Result<CommitBundle, JsError> {
        let leaf_indices: Vec<_> = member_indices
            .iter()
            .map(|i| LeafNodeIndex::new(*i))
            .collect();

        let (commit_msg, welcome_msg, group_info) =
            self.mls_group
                .remove_members(provider.as_ref(), &sender.keypair, &leaf_indices)?;

        Ok(CommitBundle::from_remove_tuple(
            commit_msg,
            welcome_msg,
            group_info,
        ))
    }

    /// Key rotation with immediate commit (convenience method)
    pub fn self_update(
        &mut self,
        provider: &Provider,
        sender: &Identity,
    ) -> Result<CommitBundle, JsError> {
        let bundle = self.mls_group.self_update(
            provider.as_ref(),
            &sender.keypair,
            openmls::prelude::LeafNodeParameters::default(),
        )?;

        let (commit_msg, welcome, group_info) = bundle.into_contents();
        let welcome_msg = welcome
            .map(|w| MlsMessageOut::from_welcome(w, openmls::prelude::ProtocolVersion::Mls10));

        Ok(CommitBundle::from_remove_tuple(
            commit_msg,
            welcome_msg,
            group_info,
        ))
    }

    /// Combined propose and commit for adding a single member
    /// This is kept for backwards compatibility with demo code
    pub fn propose_and_commit_add(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        new_member: &KeyPackage,
    ) -> Result<AddMessages, JsError> {
        let (proposal_msg, _proposal_ref) =
            self.mls_group
                .propose_add_member(provider.as_ref(), &sender.keypair, &new_member.0)?;

        let (commit_msg, welcome_msg, _group_info) = self
            .mls_group
            .commit_to_pending_proposals(&provider.0, &sender.keypair)?;

        let welcome_msg = welcome_msg.ok_or_else(|| MlsError::no_welcome())?;

        let proposal = mls_message_to_uint8array(&proposal_msg);
        let commit = mls_message_to_uint8array(&commit_msg);
        let welcome = mls_message_to_uint8array(&welcome_msg);

        Ok(AddMessages {
            proposal,
            commit,
            welcome,
        })
    }
}

/// Messages generated when adding a member (legacy format)
#[wasm_bindgen]
pub struct AddMessages {
    proposal: Uint8Array,
    commit: Uint8Array,
    welcome: Uint8Array,
}

#[wasm_bindgen]
impl AddMessages {
    #[wasm_bindgen(getter)]
    pub fn proposal(&self) -> Uint8Array {
        self.proposal.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Uint8Array {
        self.commit.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn welcome(&self) -> Uint8Array {
        self.welcome.clone()
    }
}

fn mls_message_to_uint8array(msg: &MlsMessageOut) -> Uint8Array {
    let mut serialized = vec![];
    msg.tls_serialize(&mut serialized).unwrap();
    unsafe { Uint8Array::new(&Uint8Array::view(&serialized)) }
}
