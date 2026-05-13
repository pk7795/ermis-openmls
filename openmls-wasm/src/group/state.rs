//! Group state management and export/import

use openmls_traits::OpenMlsProvider;
use tls_codec::Serialize;
use wasm_bindgen::prelude::*;

use crate::{types::RatchetTree, Group, Provider};

/// Information about a group member
#[wasm_bindgen]
pub struct MemberInfo {
    index: u32,
    user_id: String,
    encryption_key: Vec<u8>,
    signature_key: Vec<u8>,
}

#[wasm_bindgen]
impl MemberInfo {
    /// Get the member's leaf index
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get the member's user_id
    #[wasm_bindgen(getter)]
    pub fn user_id(&self) -> String {
        self.user_id.clone()
    }

    /// Get the member's encryption key
    #[wasm_bindgen(getter)]
    pub fn encryption_key(&self) -> Vec<u8> {
        self.encryption_key.clone()
    }

    /// Get the member's signature key
    #[wasm_bindgen(getter)]
    pub fn signature_key(&self) -> Vec<u8> {
        self.signature_key.clone()
    }
}

// State methods for Group
#[wasm_bindgen]
impl Group {
    /// Get the CID (group_id as string)
    ///
    /// This returns the original cid string used to create the group,
    /// matching the Ermis channel cid format (e.g., "team:channel_abc123")
    pub fn cid(&self) -> Result<String, JsError> {
        let group_id = self.mls_group.group_id();
        String::from_utf8(group_id.as_slice().to_vec())
            .map_err(|e| JsError::new(&format!("Invalid cid encoding: {e}")))
    }

    /// Get the raw group_id bytes
    pub fn group_id(&self) -> Vec<u8> {
        self.mls_group.group_id().as_slice().to_vec()
    }

    /// Get current epoch number
    ///
    /// Epoch increases with each commit
    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    /// Get all members in the group
    pub fn members(&self) -> Vec<MemberInfo> {
        self.mls_group
            .members()
            .map(|m| {
                // Extract user_id from credential identity
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
    pub fn member_by_user_id(&self, user_id: &str) -> Option<MemberInfo> {
        self.members().into_iter().find(|m| m.user_id == user_id)
    }

    /// Get ALL members (leaf nodes) for a given user_id
    ///
    /// A user with N devices will have N entries in the group.
    /// Use this to find all leaf indices for a multi-device user.
    pub fn members_by_user_id(&self, user_id: &str) -> Vec<MemberInfo> {
        self.members()
            .into_iter()
            .filter(|m| m.user_id == user_id)
            .collect()
    }

    /// Get the local member's leaf index
    pub fn own_leaf_index(&self) -> u32 {
        self.mls_group.own_leaf_index().u32()
    }

    /// Check if the group is in operational state
    ///
    /// Returns false if there's a pending commit or the group is inactive
    pub fn is_operational(&self) -> bool {
        self.mls_group.is_active()
    }

    /// Check if there's a pending commit that hasn't been merged
    pub fn has_pending_commit(&self) -> bool {
        self.mls_group.pending_commit().is_some()
    }

    /// Export the ratchet tree for sharing with new members
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        RatchetTree(self.mls_group.export_ratchet_tree().into())
    }

    /// Export the current epoch archive for historical message recovery.
    ///
    /// The returned bytes contain MLS secret material. Applications must encrypt
    /// them with their PIN/vault key before uploading or persisting outside the
    /// local device.
    pub fn archive_current_epoch(&self) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_current_epoch_archive()
            .map_err(|e| JsError::new(&format!("Archive current epoch error: {e}")))
    }

    /// Export group info for external commits
    ///
    /// # Arguments
    /// * `with_ratchet_tree` - Whether to include the ratchet tree in the group info
    pub fn export_group_info(
        &self,
        provider: &Provider,
        sender: &crate::identity::Identity,
        with_ratchet_tree: bool,
    ) -> Result<Vec<u8>, JsError> {
        let group_info = self.mls_group.export_group_info(
            provider.0.crypto(),
            &sender.keypair,
            with_ratchet_tree,
        )?;

        let mut bytes = vec![];
        group_info.tls_serialize(&mut bytes)?;
        Ok(bytes)
    }

    /// Export a secret key derived from the group state
    ///
    /// Useful for deriving encryption keys for media streams, etc.
    pub fn export_key(
        &self,
        provider: &Provider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group
            .export_secret(provider.0.crypto(), label, context, key_length)
            .map_err(|e| JsError::new(&format!("Export key error: {e}")))
    }
}
