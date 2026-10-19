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
            MlsError::NoMatchingKeyPackage => {
                write!(f, "MLS_NO_MATCHING_KEY_PACKAGE: No matching key package")
            }
        }
    }
}

impl std::error::Error for MlsError {}

impl MlsError {
    pub(crate) fn from_leaf_validation(
        error: openmls::treesync::errors::LeafNodeValidationError,
    ) -> Self {
        use openmls::treesync::errors::{LeafNodeValidationError, LifetimeError};
        match error {
            LeafNodeValidationError::Lifetime(
                LifetimeError::RangeTooBig | LifetimeError::InvalidRange,
            ) => Self::LifetimeRangeInvalid,
            LeafNodeValidationError::Lifetime(LifetimeError::NotYetValid) => Self::LeafNotYetValid,
            LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent) => Self::KeyPackageExpired,
            LeafNodeValidationError::Lifetime(LifetimeError::InvalidClock) => Self::InvalidClock,
            _ => Self::GroupInfoInvalid,
        }
    }

    pub(crate) fn from_creation<StorageError>(
        error: openmls::prelude::CreationFromExternalError<StorageError>,
    ) -> Self {
        use openmls::prelude::CreationFromExternalError;
        match error {
            CreationFromExternalError::LeafNodeValidation(error) => {
                Self::from_leaf_validation(error)
            }
            CreationFromExternalError::WriteToStorageError(_) => Self::StorageError,
            _ => Self::GroupInfoInvalid,
        }
    }

    pub(crate) fn from_welcome<StorageError>(
        error: openmls::group::WelcomeError<StorageError>,
    ) -> Self {
        use openmls::group::WelcomeError;
        match error {
            WelcomeError::NoMatchingKeyPackage => Self::NoMatchingKeyPackage,
            WelcomeError::StorageError(_) => Self::StorageError,
            WelcomeError::PublicGroupError(error) => Self::from_creation(error),
            WelcomeError::LeafNodeValidation(error) => Self::from_leaf_validation(error),
            _ => Self::GroupInfoInvalid,
        }
    }
}
