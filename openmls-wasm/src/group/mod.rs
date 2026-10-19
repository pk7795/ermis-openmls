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
mod welcome_candidate;
mod group_info_validation;

pub use commit::*;
pub use messaging::*;
pub use proposal::*;
pub use state::*;
pub use welcome_candidate::*;
pub use group_info_validation::*;

use openmls::{
    framing::{MlsMessageBodyIn, MlsMessageIn},
    group::{GroupId, MlsGroup, MlsGroupJoinConfig, StagedWelcome},
    prelude::SenderRatchetConfiguration,
};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{
    errors::{MlsError, MlsErrorCode},
    identity::Identity,
    types::RatchetTree,
    Provider, CIPHERSUITE,
};
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
    fn join_with_welcome_typed_inner(
        provider: &Provider,
        welcome: &[u8],
        ratchet_tree: Option<RatchetTree>,
        allow_expired_tree_leaves: bool,
    ) -> Result<Group, MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|_| {
            MlsError::new(
                MlsErrorCode::DeserializationError,
                "Welcome deserialization failed",
            )
        })?;
        let mls_welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(MlsError::new(
                    MlsErrorCode::InvalidMessage,
                    "Expected a Welcome message",
                ));
            }
        };

        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(5)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
            .build();
        let ratchet_tree_in = ratchet_tree.map(|tree| tree.0);
        let policy = if allow_expired_tree_leaves {
            openmls::prelude::LeafNodeLifetimePolicy::AllowExpired
        } else {
            openmls::prelude::LeafNodeLifetimePolicy::Verify
        };
        let mut builder = StagedWelcome::build_from_welcome(&provider.0, &config, mls_welcome)
            .map_err(MlsError::from_welcome_error)?
            .lifetime_policy(policy);
        if let Some(tree) = ratchet_tree_in {
            builder = builder.with_ratchet_tree(tree);
        }
        let staged = builder.build().map_err(MlsError::from_welcome_error)?;
        let mls_group = staged
            .into_group(&provider.0)
            .map_err(MlsError::from_welcome_error)?;
        Ok(Group { mls_group })
    }

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
        Self::create_with_group_id(provider, founder, cid.as_bytes())
    }

    /// Create a generation-aware group using explicit MLS GroupId bytes.
    pub fn create_with_group_id(
        provider: &Provider,
        founder: &Identity,
        group_id_bytes: &[u8],
    ) -> Result<Group, JsError> {
        if group_id_bytes.is_empty() || group_id_bytes.len() > 255 {
            return Err(JsError::new("MLS GroupId length must be 1..255 bytes"));
        }

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
        Self::load_with_group_id(provider, cid.as_bytes())
    }

    /// Load a generation-aware group using exact MLS GroupId bytes.
    pub fn load_with_group_id(
        provider: &Provider,
        group_id_bytes: &[u8],
    ) -> Result<Group, JsError> {
        if group_id_bytes.is_empty() || group_id_bytes.len() > 255 {
            return Err(JsError::new("MLS GroupId length must be 1..255 bytes"));
        }
        let group_id = GroupId::from_slice(&group_id_bytes);

        let mls_group = MlsGroup::load(provider.0.storage(), &group_id)
            .map_err(|e| JsError::new(&format!("Failed to load group: {e}")))?
            .ok_or_else(|| JsError::new("Group not found in storage for the supplied GroupId"))?;

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
        match Self::create_with_cid(provider, founder, group_id) {
            Ok(group) => group,
            Err(_) => wasm_bindgen::throw_str("Legacy group creation failed"),
        }
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

    /// Join using a Welcome while preserving a stable typed error. Clients may
    /// automatically fall back to external join only for
    /// `MlsErrorCode::NoMatchingKeyPackage`; every other error must fail closed.
    pub fn join_with_welcome_typed(
        provider: &Provider,
        welcome: &[u8],
        ratchet_tree: Option<RatchetTree>,
    ) -> Result<Group, MlsError> {
        Self::join_with_welcome_typed_inner(provider, welcome, ratchet_tree, false)
    }

    /// Opt-in checked AllowExpired for a Welcome tree. The caller mutates a
    /// candidate provider and persists it before publishing the new group.
    pub fn join_with_welcome_with_policy(
        provider: &Provider,
        welcome: &[u8],
        ratchet_tree: Option<RatchetTree>,
        allow_expired_tree_leaves: bool,
    ) -> Result<Group, MlsError> {
        Self::join_with_welcome_typed_inner(
            provider,
            welcome,
            ratchet_tree,
            allow_expired_tree_leaves,
        )
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
    pub fn join_external(
        provider: &Provider,
        identity: &Identity,
        group_info: &[u8],
        ratchet_tree: Option<RatchetTree>,
    ) -> Result<ExternalJoinResult, JsError> {
        Self::join_external_with_policy(provider, identity, group_info, ratchet_tree, false)
            .map_err(|error| JsError::new(&error.code_name()))
    }

    /// Typed opt-in expiry policy; caller uses a pending isolated provider and
    /// waits for durable backend acceptance/checkpoints before publishing Ready.
    pub fn join_external_with_policy(
        provider: &Provider,
        identity: &Identity,
        group_info: &[u8],
        ratchet_tree: Option<RatchetTree>,
        allow_expired_tree_leaves: bool,
    ) -> Result<ExternalJoinResult, MlsError> {
        let message = MlsMessageIn::tls_deserialize_exact(group_info).map_err(|_| {
            MlsError::new(
                MlsErrorCode::DeserializationError,
                "GroupInfo deserialization failed",
            )
        })?;
        let gi = match message.extract() {
            MlsMessageBodyIn::GroupInfo(gi) => gi,
            _ => {
                return Err(MlsError::new(
                    MlsErrorCode::GroupInfoInvalid,
                    "GroupInfo message required",
                ))
            }
        };
        let policy = if allow_expired_tree_leaves {
            openmls::prelude::LeafNodeLifetimePolicy::AllowExpired
        } else {
            openmls::prelude::LeafNodeLifetimePolicy::Verify
        };
        let mut builder = MlsGroup::external_commit_builder()
            .lifetime_policy(policy)
            .with_config(
                MlsGroupJoinConfig::builder()
                    .use_ratchet_tree_extension(true)
                    .max_past_epochs(5)
                    .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
                    .build(),
            );
        if let Some(tree) = ratchet_tree {
            builder = builder.with_ratchet_tree(tree.0);
        }
        let (mls_group, bundle) = builder
            .build_group(&provider.0, gi, identity.credential_with_key.clone())
            .map_err(|error| {
                let code = match error {
                    openmls::prelude::ExternalCommitBuilderError::PublicGroupError(
                        openmls::prelude::CreationFromExternalError::LeafNodeValidation(error),
                    ) => MlsError::from_leaf_validation(error),
                    openmls::prelude::ExternalCommitBuilderError::StorageError(_) => {
                        MlsErrorCode::StorageError
                    }
                    _ => MlsErrorCode::GroupInfoInvalid,
                };
                MlsError::new(code, "External join validation failed")
            })?
            .load_psks(provider.0.storage())
            .map_err(|_| MlsError::new(MlsErrorCode::CryptoError, "External join PSK unavailable"))?
            .build(
                provider.0.rand(),
                provider.0.crypto(),
                &identity.keypair,
                |_| true,
            )
            .map_err(|_| {
                MlsError::new(MlsErrorCode::ExternalCommitError, "External commit failed")
            })?
            .finalize(&provider.0)
            .map_err(|_| {
                MlsError::new(MlsErrorCode::StorageError, "External join storage failed")
            })?;
        let (commit, _, _) = bundle.into_contents();
        let commit = commit.tls_serialize_detached().map_err(|_| {
            MlsError::new(
                MlsErrorCode::SerializationError,
                "External commit serialization failed",
            )
        })?;
        Ok(ExternalJoinResult {
            group: Some(Group { mls_group }),
            commit,
        })
    }
}
