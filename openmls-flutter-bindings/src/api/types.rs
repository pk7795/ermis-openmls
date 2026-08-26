//! Flutter DTOs and opaque result adapters.

use flutter_rust_bridge::frb;

use super::group::Group;

#[frb(opaque)]
pub struct RatchetTree {
    pub(crate) inner: openmls_bindings_core::RatchetTree,
}

impl Clone for RatchetTree {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl RatchetTree {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    pub fn from_bytes(data: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            inner: openmls_bindings_core::RatchetTree::from_bytes(data)?,
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

#[frb(opaque)]
pub struct ExternalJoinResult {
    pub(crate) inner: openmls_bindings_core::ExternalJoinResult,
}

impl ExternalJoinResult {
    pub fn group(&self) -> Group {
        Group::from_core(self.inner.group())
    }

    pub fn commit_bytes(&self) -> Vec<u8> {
        self.inner.commit_bytes()
    }
}
