//! MLS Group module
//!
//! This module provides the Group struct and all related operations:
//! - Creation and joining
//! - Proposals (add, remove, update)
//! - Commits
//! - Messaging (encrypt/decrypt)
//! - State management

mod commit;
mod messaging;
mod proposal;
mod state;

pub use commit::*;
pub use messaging::*;
pub use proposal::*;
pub use state::*;

use openmls::{
    framing::{MlsMessageBodyIn, MlsMessageIn},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::SenderRatchetConfiguration,
};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{identity::Identity, types::RatchetTree, Provider, CIPHERSUITE};

/// An MLS Group representing an encrypted channel
#[wasm_bindgen]
pub struct Group {
    pub(crate) mls_group: MlsGroup,
}

/// Result of an external join (self-join with GroupInfo)
#[wasm_bindgen]
pub struct ExternalJoinResult {
    group: Option<Group>,
    commit: Vec<u8>,
}

#[wasm_bindgen]
impl ExternalJoinResult {
    /// Get the joined group
    #[wasm_bindgen(getter)]
    pub fn group(&mut self) -> Option<Group> {
        self.group.take()
    }

    /// Get the commit message to broadcast
    #[wasm_bindgen(getter)]
    pub fn commit(&self) -> Vec<u8> {
        self.commit.clone()
    }
}

#[wasm_bindgen]
impl Group {
    /// Create a new group with a CID from Ermis
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `founder` - Identity of the group creator
    /// * `cid` - Channel ID from Ermis (e.g., "team:channel_abc123")
    ///
    /// # Example
    /// ```javascript
    /// const group = Group.create_with_cid(provider, identity, "team:my_channel");
    /// ```
    pub fn create_with_cid(
        provider: &Provider,
        founder: &Identity,
        cid: &str,
    ) -> Result<Group, JsError> {
        let group_id_bytes = cid.bytes().collect::<Vec<_>>();

        let mls_group = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            .with_group_id(GroupId::from_slice(&group_id_bytes))
            .use_ratchet_tree_extension(true)
            // .max_past_epochs(5)
            // .sender_ratchet_configuration(SenderRatchetConfiguration::new(5, 1000))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .map_err(|e| JsError::new(&format!("Failed to create group: {e}")))?;

        Ok(Group { mls_group })
    }

    /// Create a new group (legacy API, uses group_id string directly)
    pub fn create_new(provider: &Provider, founder: &Identity, group_id: &str) -> Group {
        Self::create_with_cid(provider, founder, group_id).unwrap()
    }

    /// Join a group using a Welcome message
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `welcome` - Serialized Welcome message bytes
    /// * `ratchet_tree` - Optional ratchet tree (if not embedded in welcome)
    pub fn join_with_welcome(
        provider: &Provider,
        welcome: &[u8],
        ratchet_tree: Option<RatchetTree>,
    ) -> Result<Group, JsError> {
        let mut welcome_slice = welcome;
        let mls_welcome = match MlsMessageIn::tls_deserialize(&mut welcome_slice)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
            other => Err(JsError::new(&format!(
                "Expected Welcome message, got {:?}",
                std::mem::discriminant(&other)
            ))),
        }?;

        let config = MlsGroupJoinConfig::builder().build();
        let ratchet_tree_in = ratchet_tree.map(|rt| rt.0);

        let mls_group =
            StagedWelcome::new_from_welcome(&provider.0, &config, mls_welcome, ratchet_tree_in)?
                .into_group(&provider.0)?;

        Ok(Group { mls_group })
    }

    /// Join a group using a Welcome (legacy API)
    pub fn join(
        provider: &Provider,
        welcome: &[u8],
        ratchet_tree: RatchetTree,
    ) -> Result<Group, JsError> {
        Self::join_with_welcome(provider, welcome, Some(ratchet_tree))
    }

    /// Join a group via External Commit
    ///
    /// This allows a user to join a group without needing a Welcome message,
    /// using only the GroupInfo.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `identity` - Identity of the joiner
    /// * `group_info` - Serialized GroupInfo bytes
    /// * `ratchet_tree` - Optional ratchet tree
    ///
    /// # Returns
    /// ExternalJoinResult containing the joined group and commit message to broadcast
    #[allow(deprecated)]
    pub fn join_external(
        provider: &Provider,
        identity: &Identity,
        group_info: &[u8],
        ratchet_tree: Option<RatchetTree>,
    ) -> Result<ExternalJoinResult, JsError> {
        let mut gi_slice = group_info;
        let verified_group_info =
            openmls::messages::group_info::VerifiableGroupInfo::tls_deserialize(&mut gi_slice)
                .map_err(|e| JsError::new(&format!("GroupInfo deserialization error: {e}")))?;

        let ratchet_tree_in = ratchet_tree.map(|rt| rt.0);

        let (mls_group, commit_msg, _group_info) = MlsGroup::join_by_external_commit(
            &provider.0,
            &identity.keypair,
            ratchet_tree_in,
            verified_group_info,
            &MlsGroupJoinConfig::builder().build(),
            None, // No capabilities
            None, // No extra extensions
            &[],  // Empty AAD
            identity.credential_with_key.clone(),
        )?;

        let mut commit_bytes = vec![];
        commit_msg.tls_serialize(&mut commit_bytes)?;

        Ok(ExternalJoinResult {
            group: Some(Group { mls_group }),
            commit: commit_bytes,
        })
    }
}
