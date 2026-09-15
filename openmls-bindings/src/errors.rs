//! Binding-neutral error types for OpenMLS mobile adapters

use std::fmt;

/// Stable error categories mapped by each binding adapter.
#[derive(Debug, Clone)]
pub enum MlsError {
    SerializationError,
    DeserializationError,
    MemberNotFound,
    InvalidMessage,
    MessageAlreadyConsumed,
    InvalidCid,
    InvalidGroupId,
    StorageError,
    GroupNotFound,
    CryptoError,
    InvalidState,
    ExternalCommitError,
    InternalError,
    NoMatchingKeyPackage,
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlsError::SerializationError => {
                write!(f, "MLS_SERIALIZATION_ERROR: Serialization error")
            }
            MlsError::DeserializationError => {
                write!(f, "MLS_DESERIALIZATION_ERROR: Deserialization error")
            }
            MlsError::MemberNotFound => write!(f, "MLS_MEMBER_NOT_FOUND: Member not found"),
            MlsError::InvalidMessage => write!(f, "MLS_INVALID_MESSAGE: Invalid message"),
            MlsError::MessageAlreadyConsumed => {
                write!(
                    f,
                    "MLS_MESSAGE_ALREADY_CONSUMED: Message ratchet secret was already consumed"
                )
            }
            MlsError::InvalidCid => write!(f, "MLS_INVALID_CID: Invalid CID format"),
            MlsError::InvalidGroupId => {
                write!(f, "MLS_INVALID_GROUP_ID: Invalid MLS GroupId")
            }
            MlsError::StorageError => write!(f, "MLS_STORAGE_ERROR: Storage operation failed"),
            MlsError::GroupNotFound => {
                write!(f, "MLS_GROUP_NOT_FOUND: Group not found in storage")
            }
            MlsError::CryptoError => write!(f, "MLS_CRYPTO_ERROR: Crypto operation failed"),
            MlsError::InvalidState => write!(f, "MLS_INVALID_STATE: Invalid state"),
            MlsError::ExternalCommitError => {
                write!(f, "MLS_EXTERNAL_COMMIT_ERROR: External commit failed")
            }
            MlsError::InternalError => write!(f, "MLS_INTERNAL_ERROR: Internal error"),
            MlsError::NoMatchingKeyPackage => {
                write!(f, "MLS_NO_MATCHING_KEY_PACKAGE: No matching key package")
            }
        }
    }
}

impl std::error::Error for MlsError {}
