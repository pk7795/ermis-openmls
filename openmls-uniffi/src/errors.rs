//! Error types for OpenMLS UniFFI bindings

use std::fmt;

/// Error type for MLS operations, exposed to Swift/Kotlin via UniFFI
#[derive(Debug, Clone)]
pub enum MlsError {
    SerializationError,
    DeserializationError,
    GroupNotOperational,
    MemberNotFound,
    InvalidMessage,
    MessageAlreadyConsumed,
    NoWelcome,
    InvalidCid,
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
            MlsError::SerializationError => write!(f, "Serialization error"),
            MlsError::DeserializationError => write!(f, "Deserialization error"),
            MlsError::GroupNotOperational => write!(f, "Group is not in operational state"),
            MlsError::MemberNotFound => write!(f, "Member not found"),
            MlsError::InvalidMessage => write!(f, "Invalid message"),
            MlsError::MessageAlreadyConsumed => {
                write!(f, "Message ratchet secret was already consumed")
            }
            MlsError::NoWelcome => write!(f, "Expected welcome message but none was generated"),
            MlsError::InvalidCid => write!(f, "Invalid CID format"),
            MlsError::StorageError => write!(f, "Storage operation failed"),
            MlsError::GroupNotFound => write!(f, "Group not found in storage"),
            MlsError::CryptoError => write!(f, "Crypto operation failed"),
            MlsError::InvalidState => write!(f, "Invalid state"),
            MlsError::ExternalCommitError => write!(f, "External commit failed"),
            MlsError::InternalError => write!(f, "Internal error"),
            MlsError::NoMatchingKeyPackage => write!(f, "No matching key package"),
        }
    }
}

impl std::error::Error for MlsError {}

impl MlsError {
    pub fn serialization(_msg: &str) -> Self {
        MlsError::SerializationError
    }

    pub fn deserialization(_msg: &str) -> Self {
        MlsError::DeserializationError
    }

    pub fn invalid_message(_msg: &str) -> Self {
        MlsError::InvalidMessage
    }

    pub fn invalid_cid(_msg: &str) -> Self {
        MlsError::InvalidCid
    }

    pub fn storage(_msg: &str) -> Self {
        MlsError::StorageError
    }

    pub fn crypto(_msg: &str) -> Self {
        MlsError::CryptoError
    }

    pub fn invalid_state(_msg: &str) -> Self {
        MlsError::InvalidState
    }
}
