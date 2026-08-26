//! Binding-neutral shared MLS types
use openmls::treesync::RatchetTreeIn;
use tls_codec::{Deserialize, Serialize};

use crate::errors::MlsError;
use crate::group::Group;

// ============================================================================
// Opaque wrapper types
// ============================================================================

/// Ratchet tree for group state synchronization
pub struct RatchetTree {
    pub(crate) inner: RatchetTreeIn,
}

impl Clone for RatchetTree {
    fn clone(&self) -> Self {
        RatchetTree {
            inner: self.inner.clone(),
        }
    }
}

impl RatchetTree {
    /// Serialize this ratchet tree to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.tls_serialize_detached().unwrap()
    }

    /// Deserialize a ratchet tree from bytes
    pub fn from_bytes(data: Vec<u8>) -> crate::MlsResult<RatchetTree> {
        let mut s = data.as_slice();
        let tree =
            RatchetTreeIn::tls_deserialize(&mut s).map_err(|_| MlsError::DeserializationError)?;
        Ok(RatchetTree { inner: tree })
    }
}

// ============================================================================
// Data transfer types (transparent — all fields pub)
// ============================================================================

/// Type of processed message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Application message (encrypted user content)
    ApplicationMessage,
    /// Proposal message (add/remove/update)
    Proposal,
    /// Commit message (finalizing proposals)
    Commit,
}

/// Information about a group member
pub struct MemberInfo {
    pub index: u32,
    pub user_id: String,
    pub encryption_key: Vec<u8>,
    pub signature_key: Vec<u8>,
}

/// Bundle containing commit message and optional welcome
pub struct CommitBundle {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
}

/// A proposal message that can be sent to other group members
pub struct ProposalMessage {
    pub bytes: Vec<u8>,
    pub proposal_ref: Vec<u8>,
}

/// Result of processing an incoming message
pub struct ProcessedMessage {
    pub message_type: MessageType,
    pub content: Option<Vec<u8>>,
    pub sender_index: u32,
    pub epoch: u64,
    pub aad: Vec<u8>,
}

/// Result of an external join (self-join with GroupInfo).
///
/// Opaque because it contains the opaque `Group` type.
/// Use `group()` and `commit_bytes()` accessors.
pub struct ExternalJoinResult {
    pub(crate) group: Group,
    pub(crate) commit: Vec<u8>,
}

impl ExternalJoinResult {
    /// Get the newly joined Group.
    ///
    /// Returns a handle that shares the same underlying MLS state
    /// (cheap Arc clone, not a deep copy).
    pub fn group(&self) -> Group {
        self.group.clone()
    }

    /// Get the commit bytes to send to the server.
    pub fn commit_bytes(&self) -> Vec<u8> {
        self.commit.clone()
    }
}
