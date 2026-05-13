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
use openmls_traits::OpenMlsProvider;

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
            // Keep decryption keys for 5 past epochs, allowing late-arriving
            // messages sent before a key rotation to still be decrypted.
            .max_past_epochs(5)
            // out_of_order_tolerance=10: keep 10 past decryption keys within an epoch
            //   (handles messages arriving out of order)
            // maximum_forward_distance=2000: allow skipping up to 2000 dropped messages
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build(
                &provider.0,
                &founder.keypair,
                founder.credential_with_key.clone(),
            )
            .map_err(|e| JsError::new(&format!("Failed to create group: {e}")))?;

        Ok(Group { mls_group })
    }

    /// Load a group from the Provider's storage by CID
    ///
    /// After restoring a Provider from bytes (IndexedDB), call this to reopen
    /// a group that was previously created or joined.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider (restored from bytes)
    /// * `cid` - Channel ID (e.g., "team:channel_abc123")
    pub fn load(provider: &Provider, cid: &str) -> Result<Group, JsError> {
        let group_id_bytes = cid.bytes().collect::<Vec<_>>();
        let group_id = GroupId::from_slice(&group_id_bytes);

        let mls_group = MlsGroup::load(provider.0.storage(), &group_id)
            .map_err(|e| JsError::new(&format!("Failed to load group: {e}")))?
            .ok_or_else(|| JsError::new(&format!("Group not found in storage: {cid}")))?;

        Ok(Group { mls_group })
    }

    /// Persist the group's current state to the Provider's storage.
    ///
    /// MUST be called after processing application messages (decrypt) to save
    /// the updated ratchet/secret tree state. Without this, a Provider restore
    /// (e.g., on page reload) will load stale ratchet state, causing
    /// SecretReuseError for messages that were already decrypted.
    pub fn save_state(&self, provider: &Provider) -> Result<(), JsError> {
        self.mls_group
            .store(provider.0.storage())
            .map_err(|e| JsError::new(&format!("Failed to save group state: {e}")))
    }

    /// Delete this group's persisted OpenMLS state from the Provider storage.
    ///
    /// Use when the local user leaves or is removed from a channel. This clears
    /// the old MLS group state so a later re-add with the same CID can join from
    /// a fresh Welcome without colliding with stale provider records.
    pub fn delete_state(&mut self, provider: &Provider) -> Result<(), JsError> {
        self.mls_group
            .delete(provider.0.storage())
            .map_err(|e| JsError::new(&format!("Failed to delete group state: {e}")))
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

        // Must match the config used in create_with_cid for consistency.
        // See create_with_cid for detailed explanation of these values.
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(5)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build();
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
        // group_info bytes are TLS-serialized MlsMessageOut (from export_group_info)
        // → deserialize as MlsMessageIn first, then extract the GroupInfo body
        let mut gi_slice = group_info;
        let mls_message = MlsMessageIn::tls_deserialize(&mut gi_slice).map_err(|e| {
            JsError::new(&format!("GroupInfo MlsMessage deserialization error: {e}"))
        })?;

        let verified_group_info = match mls_message.extract() {
            MlsMessageBodyIn::GroupInfo(gi) => Ok(gi),
            other => Err(JsError::new(&format!(
                "Expected GroupInfo message, got {:?}",
                std::mem::discriminant(&other)
            ))),
        }?;

        let ratchet_tree_in = ratchet_tree.map(|rt| rt.0);

        let (mls_group, commit_msg, _group_info) = MlsGroup::join_by_external_commit(
            &provider.0,
            &identity.keypair,
            ratchet_tree_in,
            verified_group_info,
            // Must match the config used in create_with_cid for consistency.
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .max_past_epochs(5)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
                .build(),
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
