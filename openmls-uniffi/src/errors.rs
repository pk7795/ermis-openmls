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
    InvalidGroupId,
    StorageError,
    GroupNotFound,
    CryptoError,
    InvalidState,
    ExternalCommitError,
    InternalError,
    NoMatchingKeyPackage,
    // Append-only codes: preserve every existing variant ordinal.
    LifetimeRangeInvalid,
    LeafNotYetValid,
    KeyPackageExpired,
    InvalidClock,
    StorageCorruption,
    GroupInfoInvalid,
    EpochConflict,
    TransportUnknown,
    AcceptanceMetadataInvalid,
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
            MlsError::InvalidGroupId => write!(f, "Invalid MLS GroupId"),
            MlsError::StorageError => write!(f, "Storage operation failed"),
            MlsError::GroupNotFound => write!(f, "Group not found in storage"),
            MlsError::CryptoError => write!(f, "Crypto operation failed"),
            MlsError::InvalidState => write!(f, "Invalid state"),
            MlsError::ExternalCommitError => write!(f, "External commit failed"),
            MlsError::InternalError => write!(f, "Internal error"),
            MlsError::LifetimeRangeInvalid => {
                write!(f, "MLS_LIFETIMERANGEINVALID: LifetimeRangeInvalid")
            }
            MlsError::LeafNotYetValid => write!(f, "MLS_LEAFNOTYETVALID: LeafNotYetValid"),
            MlsError::KeyPackageExpired => write!(f, "MLS_KEYPACKAGEEXPIRED: KeyPackageExpired"),
            MlsError::InvalidClock => write!(f, "MLS_INVALIDCLOCK: InvalidClock"),
            MlsError::StorageCorruption => write!(f, "MLS_STORAGECORRUPTION: StorageCorruption"),
            MlsError::GroupInfoInvalid => write!(f, "MLS_GROUPINFOINVALID: GroupInfoInvalid"),
            MlsError::EpochConflict => write!(f, "MLS_EPOCHCONFLICT: EpochConflict"),
            MlsError::TransportUnknown => write!(f, "MLS_TRANSPORTUNKNOWN: TransportUnknown"),
            MlsError::AcceptanceMetadataInvalid => write!(
                f,
                "MLS_ACCEPTANCE_METADATA_INVALID: Acceptance metadata rejected"
            ),
            MlsError::NoMatchingKeyPackage => write!(f, "No matching key package"),
        }
    }
}

impl std::error::Error for MlsError {}

impl MlsError {
    pub(crate) fn from_core(error: openmls_bindings_core::MlsError) -> Self {
        match error {
            openmls_bindings_core::MlsError::SerializationError => Self::SerializationError,
            openmls_bindings_core::MlsError::DeserializationError => Self::DeserializationError,
            openmls_bindings_core::MlsError::MemberNotFound => Self::MemberNotFound,
            openmls_bindings_core::MlsError::InvalidMessage => Self::InvalidMessage,
            openmls_bindings_core::MlsError::MessageAlreadyConsumed => Self::MessageAlreadyConsumed,
            openmls_bindings_core::MlsError::InvalidCid => Self::InvalidCid,
            openmls_bindings_core::MlsError::InvalidGroupId => Self::InvalidGroupId,
            openmls_bindings_core::MlsError::StorageError => Self::StorageError,
            openmls_bindings_core::MlsError::GroupNotFound => Self::GroupNotFound,
            openmls_bindings_core::MlsError::CryptoError => Self::CryptoError,
            openmls_bindings_core::MlsError::InvalidState => Self::InvalidState,
            openmls_bindings_core::MlsError::ExternalCommitError => Self::ExternalCommitError,
            openmls_bindings_core::MlsError::InternalError => Self::InternalError,
            openmls_bindings_core::MlsError::LifetimeRangeInvalid => Self::LifetimeRangeInvalid,
            openmls_bindings_core::MlsError::LeafNotYetValid => Self::LeafNotYetValid,
            openmls_bindings_core::MlsError::KeyPackageExpired => Self::KeyPackageExpired,
            openmls_bindings_core::MlsError::InvalidClock => Self::InvalidClock,
            openmls_bindings_core::MlsError::StorageCorruption => Self::StorageCorruption,
            openmls_bindings_core::MlsError::GroupInfoInvalid => Self::GroupInfoInvalid,
            openmls_bindings_core::MlsError::EpochConflict => Self::EpochConflict,
            openmls_bindings_core::MlsError::TransportUnknown => Self::TransportUnknown,
            openmls_bindings_core::MlsError::AcceptanceMetadataInvalid => {
                Self::AcceptanceMetadataInvalid
            }
            openmls_bindings_core::MlsError::NoMatchingKeyPackage => Self::NoMatchingKeyPackage,
        }
    }

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
