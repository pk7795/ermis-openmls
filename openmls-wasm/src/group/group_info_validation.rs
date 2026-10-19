//! Public GroupInfo validation without a pending commit or provider writes.
//! This establishes the public external-join validation boundary only; the SDK
//! must separately prove a durable usable local checkpoint before sending ACK.
use crate::{Group, Identity, MlsError, MlsErrorCode, Provider};
use openmls::prelude::{
    ExternalCommitBuilderError, LeafNodeLifetimePolicy, MlsGroup, MlsMessageBodyIn, MlsMessageIn,
};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GroupInfoValidation {
    epoch: u64,
    group_id: Vec<u8>,
    ratchet_tree_sha256: Vec<u8>,
}

#[wasm_bindgen]
impl GroupInfoValidation {
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    #[wasm_bindgen(getter)]
    pub fn group_id(&self) -> Vec<u8> {
        self.group_id.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ratchet_tree_sha256(&self) -> Vec<u8> {
        self.ratchet_tree_sha256.clone()
    }
}

#[wasm_bindgen]
impl Group {
    /// Same signature/tree/lifetime checks as production external join, with
    /// explicit policy and no commit build/finalize, storage writes or KP use.
    /// Embedded ratchet tree and external_pub are required by that boundary.
    pub fn validate_group_info_with_policy(
        provider: &Provider,
        identity: &Identity,
        group_info: &[u8],
        allow_expired_tree_leaves: bool,
    ) -> Result<GroupInfoValidation, MlsError> {
        if group_info.is_empty() || group_info.len() > 1_048_576 {
            return Err(MlsError::new(
                MlsErrorCode::DeserializationError,
                "GroupInfo size invalid",
            ));
        }
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
        // These fields are untrusted until build_group validates the exact GI.
        let epoch = gi.epoch().as_u64();
        let group_id = gi.group_id().as_slice().to_vec();
        let tree = gi.extensions().ratchet_tree().ok_or_else(|| {
            MlsError::new(MlsErrorCode::GroupInfoInvalid, "GroupInfo tree missing")
        })?;
        let tree_bytes = tree.ratchet_tree().tls_serialize_detached().map_err(|_| {
            MlsError::new(
                MlsErrorCode::SerializationError,
                "GroupInfo tree serialization failed",
            )
        })?;
        let ratchet_tree_sha256 = Sha256::digest(&tree_bytes).to_vec();
        let policy = if allow_expired_tree_leaves {
            LeafNodeLifetimePolicy::AllowExpired
        } else {
            LeafNodeLifetimePolicy::Verify
        };
        let validated = MlsGroup::external_commit_builder()
            .lifetime_policy(policy)
            .build_group(&provider.0, gi, identity.credential_with_key.clone())
            .map_err(|error| {
                let code = match error {
                    ExternalCommitBuilderError::PublicGroupError(
                        openmls::prelude::CreationFromExternalError::LeafNodeValidation(error),
                    ) => MlsError::from_leaf_validation(error),
                    ExternalCommitBuilderError::StorageError(_) => MlsErrorCode::StorageError,
                    _ => MlsErrorCode::GroupInfoInvalid,
                };
                MlsError::new(code, "GroupInfo validation failed")
            })?;
        drop(validated);
        Ok(GroupInfoValidation {
            epoch,
            group_id,
            ratchet_tree_sha256,
        })
    }
}
