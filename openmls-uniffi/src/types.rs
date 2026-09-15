//! UniFFI DTOs and opaque adapters.

use std::sync::Arc;

use crate::{errors::MlsError, group::Group};

pub struct RatchetTree {
    pub(crate) inner: openmls_bindings_core::RatchetTree,
}

impl RatchetTree {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, MlsError> {
        Ok(Self {
            inner: openmls_bindings_core::RatchetTree::from_bytes(data)
                .map_err(MlsError::from_core)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    ApplicationMessage,
    Proposal,
    Commit,
}

impl From<openmls_bindings_core::MessageType> for MessageType {
    fn from(value: openmls_bindings_core::MessageType) -> Self {
        match value {
            openmls_bindings_core::MessageType::ApplicationMessage => Self::ApplicationMessage,
            openmls_bindings_core::MessageType::Proposal => Self::Proposal,
            openmls_bindings_core::MessageType::Commit => Self::Commit,
        }
    }
}

pub struct MemberInfo {
    pub index: u32,
    pub user_id: String,
    pub encryption_key: Vec<u8>,
    pub signature_key: Vec<u8>,
}

impl From<openmls_bindings_core::MemberInfo> for MemberInfo {
    fn from(value: openmls_bindings_core::MemberInfo) -> Self {
        Self {
            index: value.index,
            user_id: value.user_id,
            encryption_key: value.encryption_key,
            signature_key: value.signature_key,
        }
    }
}

pub struct CommitBundle {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub group_info: Option<Vec<u8>>,
}

impl From<openmls_bindings_core::CommitBundle> for CommitBundle {
    fn from(value: openmls_bindings_core::CommitBundle) -> Self {
        Self {
            commit: value.commit,
            welcome: value.welcome,
            group_info: value.group_info,
        }
    }
}

pub struct ProposalMessage {
    pub bytes: Vec<u8>,
    pub proposal_ref: Vec<u8>,
}

impl From<openmls_bindings_core::ProposalMessage> for ProposalMessage {
    fn from(value: openmls_bindings_core::ProposalMessage) -> Self {
        Self {
            bytes: value.bytes,
            proposal_ref: value.proposal_ref,
        }
    }
}

pub struct ProcessedMessage {
    pub message_type: MessageType,
    pub content: Option<Vec<u8>>,
    pub sender_index: u32,
    pub epoch: u64,
    pub aad: Vec<u8>,
}

pub struct ExportedEpochArchiveV2 {
    pub archive_bytes: Vec<u8>,
    pub snapshot_bytes: Vec<u8>,
    pub snapshot_hash: Vec<u8>,
}

impl From<openmls_bindings_core::ExportedEpochArchiveV2> for ExportedEpochArchiveV2 {
    fn from(value: openmls_bindings_core::ExportedEpochArchiveV2) -> Self {
        Self {
            archive_bytes: value.archive_bytes,
            snapshot_bytes: value.snapshot_bytes,
            snapshot_hash: value.snapshot_hash,
        }
    }
}

pub struct ArchivedMessage {
    pub content: Vec<u8>,
    pub sender_index: u32,
    pub generation: u32,
    pub epoch: u64,
    pub aad: Vec<u8>,
    pub own_message: bool,
}

impl From<openmls_bindings_core::ArchivedMessage> for ArchivedMessage {
    fn from(value: openmls_bindings_core::ArchivedMessage) -> Self {
        Self {
            content: value.content,
            sender_index: value.sender_index,
            generation: value.generation,
            epoch: value.epoch,
            aad: value.aad,
            own_message: value.own_message,
        }
    }
}

impl From<openmls_bindings_core::ProcessedMessage> for ProcessedMessage {
    fn from(value: openmls_bindings_core::ProcessedMessage) -> Self {
        Self {
            message_type: value.message_type.into(),
            content: value.content,
            sender_index: value.sender_index,
            epoch: value.epoch,
            aad: value.aad,
        }
    }
}

pub struct ExternalJoinResult {
    pub group: Arc<Group>,
    pub commit: Vec<u8>,
}
