//! POC API for decrypting historical private messages from archived epoch keys.
//!
//! The archive bytes intentionally contain only epoch-local MLS state. They are
//! expected to be encrypted by an application-level vault before they leave a
//! device.

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tls_codec::Deserialize as _;

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::{
        signable::Verifiable,
        signature::{OpenMlsSignaturePublicKey, SignaturePublicKey},
    },
    credentials::{BasicCredential, Credential, CredentialWithKey},
    framing::{
        mls_content::FramedContentBody, private_message_in::PrivateMessageIn,
        validation::SenderContext, ContentType, MlsMessageBodyIn, MlsMessageIn, Sender,
    },
    group::{GroupEpoch, GroupId},
    schedule::message_secrets::MessageSecrets,
    tree::sender_ratchet::SenderRatchetConfiguration,
    versions::ProtocolVersion,
};

use super::{Member, MlsGroup};

const EPOCH_ARCHIVE_VERSION: u16 = 1;
const EPOCH_ARCHIVE_V2_VERSION: u16 = 2;
const RECOVERY_SNAPSHOT_VERSION: u16 = 2;

/// Errors returned by epoch archive export and recovery decryption.
#[derive(Debug, Error)]
pub enum EpochArchiveError {
    /// The archive could not be serialized.
    #[error("could not serialize epoch archive: {0}")]
    Serialize(serde_json::Error),
    /// The archive could not be deserialized.
    #[error("could not deserialize epoch archive: {0}")]
    Deserialize(serde_json::Error),
    /// The supplied MLS message bytes could not be parsed.
    #[error("could not parse MLS message: {0}")]
    Codec(tls_codec::Error),
    /// The supplied MLS message is not a private message.
    #[error("message is not an MLS private message")]
    NotPrivateMessage,
    /// The archive format version is not supported by this build.
    #[error("archive version {0} is not supported")]
    UnsupportedArchiveVersion(u16),
    /// The V2 snapshot hash does not match the archive binding.
    #[error("snapshot hash does not match archive")]
    SnapshotHashMismatch,
    /// The V2 archive or snapshot is malformed.
    #[error("invalid v2 archive snapshot: {0}")]
    Snapshot(String),
    /// The ciphertext group ID does not match the archive group ID.
    #[error("ciphertext belongs to a different group")]
    WrongGroup,
    /// The ciphertext epoch does not match the archive epoch.
    #[error("ciphertext epoch {ciphertext} does not match archive epoch {archive}")]
    WrongEpoch {
        /// The epoch encoded in the archive.
        archive: u64,
        /// The epoch encoded in the ciphertext.
        ciphertext: u64,
    },
    /// The ciphertext protocol version does not match the archive version.
    #[error("ciphertext protocol version does not match archive")]
    WrongProtocolVersion,
    /// Sender data could not be decrypted using the archived sender data secret.
    #[error("could not decrypt sender data: {0}")]
    SenderData(String),
    /// Recovery was asked to reject ciphertext sent by the archive owner.
    #[error("own messages are disabled for this recovery call")]
    OwnMessageNotAllowed,
    /// The archive member snapshot does not contain the sender leaf.
    #[error("archive does not contain a member for sender leaf {0}")]
    UnknownSender(u32),
    /// The ciphertext body could not be decrypted using the archived ratchet.
    #[error("could not decrypt archived ciphertext: {0}")]
    Decrypt(String),
    /// Signature or semantic validation failed after decryption.
    #[error("could not verify archived ciphertext: {0}")]
    Verify(String),
    /// The decrypted message was not application data.
    #[error("archived ciphertext is not an application message")]
    NotApplicationMessage,
}

/// Options controlling recovery decryption from an epoch archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryDecryptOptions {
    /// Whether messages sent by the same leaf that exported the archive are accepted.
    pub allow_own_messages: bool,
    /// Optional recovery-only override for the sender ratchet maximum forward distance.
    pub max_forward_distance: Option<u32>,
}

impl Default for RecoveryDecryptOptions {
    fn default() -> Self {
        Self {
            allow_own_messages: true,
            max_forward_distance: None,
        }
    }
}

/// Sender metadata decrypted from an archived epoch without decrypting the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedSenderData {
    /// Sender leaf index.
    pub sender_index: u32,
    /// Sender ratchet generation.
    pub generation: u32,
    /// MLS epoch.
    pub epoch: u64,
    /// Framed content type.
    pub content_type: ContentType,
    /// Whether the sender leaf is the same leaf that exported the archive.
    pub own_message: bool,
}

/// Application plaintext recovered from an archived epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedPlaintext {
    /// Decrypted application bytes.
    pub content: Vec<u8>,
    /// Additional authenticated data from the MLS private message.
    pub aad: Vec<u8>,
    /// Verified message sender.
    pub sender: Sender,
    /// Sender leaf index.
    pub sender_index: u32,
    /// Sender ratchet generation.
    pub generation: u32,
    /// MLS epoch.
    pub epoch: u64,
    /// Whether the sender leaf is the same leaf that exported the archive.
    pub own_message: bool,
}

/// V2 export separates private epoch secrets from public member verification material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedEpochArchiveV2 {
    /// JSON archive bytes containing epoch-local private MLS secrets.
    pub archive_bytes: Vec<u8>,
    /// Canonical JSON member snapshot bytes used for recovery verification.
    pub snapshot_bytes: Vec<u8>,
    /// SHA-256 digest of `snapshot_bytes`.
    pub snapshot_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct EpochArchive {
    archive_version: u16,
    group_id: GroupId,
    epoch: GroupEpoch,
    ciphersuite: Ciphersuite,
    protocol_version: ProtocolVersion,
    sender_ratchet_config: SenderRatchetConfiguration,
    message_secrets: MessageSecrets,
    leaves: Vec<Member>,
    own_leaf_index: LeafNodeIndex,
}

#[derive(Serialize)]
struct EpochArchiveRef<'a> {
    archive_version: u16,
    group_id: GroupId,
    epoch: GroupEpoch,
    ciphersuite: Ciphersuite,
    protocol_version: ProtocolVersion,
    sender_ratchet_config: SenderRatchetConfiguration,
    message_secrets: &'a MessageSecrets,
    leaves: Vec<Member>,
    own_leaf_index: LeafNodeIndex,
}

#[derive(Serialize, Deserialize)]
struct EpochArchiveV2 {
    archive_version: u16,
    group_id: GroupId,
    epoch: GroupEpoch,
    ciphersuite: Ciphersuite,
    protocol_version: ProtocolVersion,
    sender_ratchet_config: SenderRatchetConfiguration,
    message_secrets: MessageSecrets,
    own_leaf_index: LeafNodeIndex,
    member_snapshot_hash: [u8; 32],
}

#[derive(Serialize)]
struct EpochArchiveV2Ref<'a> {
    archive_version: u16,
    group_id: GroupId,
    epoch: GroupEpoch,
    ciphersuite: Ciphersuite,
    protocol_version: ProtocolVersion,
    sender_ratchet_config: SenderRatchetConfiguration,
    message_secrets: &'a MessageSecrets,
    own_leaf_index: LeafNodeIndex,
    member_snapshot_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct RecoveryMemberSnapshot {
    snapshot_version: u16,
    hash_mode: String,
    group_id: GroupId,
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    signature_scheme: String,
    members: Vec<RecoveryMember>,
}

#[derive(Serialize, Deserialize)]
struct RecoveryMember {
    leaf_index: u32,
    user_id: String,
    signature_key: Vec<u8>,
}

impl MlsGroup {
    /// Export an archive of the current fresh epoch.
    ///
    /// This should be called immediately after the epoch is created and before
    /// application messages from that epoch are sent or decrypted.
    pub fn export_current_epoch_archive(&self) -> Result<Vec<u8>, EpochArchiveError> {
        let archive = EpochArchiveRef {
            archive_version: EPOCH_ARCHIVE_VERSION,
            group_id: self.group_id().clone(),
            epoch: self.epoch(),
            ciphersuite: self.ciphersuite(),
            protocol_version: self.version(),
            sender_ratchet_config: *self.configuration().sender_ratchet_configuration(),
            message_secrets: self.message_secrets_store.message_secrets(),
            leaves: self.members().collect(),
            own_leaf_index: self.own_leaf_index(),
        };
        serde_json::to_vec(&archive).map_err(EpochArchiveError::Serialize)
    }

    /// Export V2 archive bytes plus a canonical member snapshot.
    pub fn export_epoch_archive_v2(&self) -> Result<ExportedEpochArchiveV2, EpochArchiveError> {
        let leaves: Vec<Member> = self.members().collect();
        let snapshot = build_member_snapshot(
            self.group_id().clone(),
            self.version(),
            self.ciphersuite(),
            &leaves,
        )?;
        let snapshot_bytes = serde_json::to_vec(&snapshot).map_err(EpochArchiveError::Serialize)?;
        let snapshot_hash = Sha256::digest(&snapshot_bytes).into();
        let archive = EpochArchiveV2Ref {
            archive_version: EPOCH_ARCHIVE_V2_VERSION,
            group_id: self.group_id().clone(),
            epoch: self.epoch(),
            ciphersuite: self.ciphersuite(),
            protocol_version: self.version(),
            sender_ratchet_config: *self.configuration().sender_ratchet_configuration(),
            message_secrets: self.message_secrets_store.message_secrets(),
            own_leaf_index: self.own_leaf_index(),
            member_snapshot_hash: snapshot_hash,
        };
        let archive_bytes = serde_json::to_vec(&archive).map_err(EpochArchiveError::Serialize)?;
        Ok(ExportedEpochArchiveV2 {
            archive_bytes,
            snapshot_bytes,
            snapshot_hash,
        })
    }
}

/// Decrypt sender data from an archived epoch without consuming the message ratchet.
pub fn peek_sender_data_from_archive(
    crypto: &impl OpenMlsCrypto,
    archive_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<ArchivedSenderData, EpochArchiveError> {
    let archive = parse_archive(archive_bytes)?;
    let (message_version, ciphertext) = parse_private_message(ciphertext_bytes)?;
    validate_ciphertext_scope(&archive, &ciphertext, Some(message_version))?;
    let sender_data = ciphertext
        .sender_data(&archive.message_secrets, crypto, archive.ciphersuite)
        .map_err(|error| EpochArchiveError::SenderData(error.to_string()))?;
    Ok(ArchivedSenderData {
        sender_index: sender_data.leaf_index.u32(),
        generation: sender_data.generation,
        epoch: ciphertext.epoch().as_u64(),
        content_type: ciphertext.content_type(),
        own_message: sender_data.leaf_index == archive.own_leaf_index,
    })
}

/// Decrypt and verify an application private message with archived epoch state.
pub fn decrypt_with_epoch_archive(
    crypto: &impl OpenMlsCrypto,
    archive_bytes: &[u8],
    ciphertext_bytes: &[u8],
    options: RecoveryDecryptOptions,
) -> Result<ArchivedPlaintext, EpochArchiveError> {
    let archive = parse_archive(archive_bytes)?;
    decrypt_with_archive(crypto, archive, ciphertext_bytes, options)
}

/// Decrypt and verify an application private message with V2 archive + snapshot.
pub fn decrypt_with_epoch_archive_v2(
    crypto: &impl OpenMlsCrypto,
    archive_bytes: &[u8],
    snapshot_bytes: &[u8],
    ciphertext_bytes: &[u8],
    options: RecoveryDecryptOptions,
) -> Result<ArchivedPlaintext, EpochArchiveError> {
    let archive_v2: EpochArchiveV2 =
        serde_json::from_slice(archive_bytes).map_err(EpochArchiveError::Deserialize)?;
    if archive_v2.archive_version != EPOCH_ARCHIVE_V2_VERSION {
        return Err(EpochArchiveError::UnsupportedArchiveVersion(
            archive_v2.archive_version,
        ));
    }
    let snapshot_hash: [u8; 32] = Sha256::digest(snapshot_bytes).into();
    if snapshot_hash != archive_v2.member_snapshot_hash {
        return Err(EpochArchiveError::SnapshotHashMismatch);
    }
    let snapshot: RecoveryMemberSnapshot =
        serde_json::from_slice(snapshot_bytes).map_err(EpochArchiveError::Deserialize)?;
    let leaves = snapshot_to_members(&snapshot, &archive_v2)?;
    let archive = EpochArchive {
        archive_version: EPOCH_ARCHIVE_VERSION,
        group_id: archive_v2.group_id,
        epoch: archive_v2.epoch,
        ciphersuite: archive_v2.ciphersuite,
        protocol_version: archive_v2.protocol_version,
        sender_ratchet_config: archive_v2.sender_ratchet_config,
        message_secrets: archive_v2.message_secrets,
        leaves,
        own_leaf_index: archive_v2.own_leaf_index,
    };
    decrypt_with_archive(crypto, archive, ciphertext_bytes, options)
}

fn decrypt_with_archive(
    crypto: &impl OpenMlsCrypto,
    mut archive: EpochArchive,
    ciphertext_bytes: &[u8],
    options: RecoveryDecryptOptions,
) -> Result<ArchivedPlaintext, EpochArchiveError> {
    let (message_version, ciphertext) = parse_private_message(ciphertext_bytes)?;
    validate_ciphertext_scope(&archive, &ciphertext, Some(message_version))?;

    let sender_data = ciphertext
        .sender_data(&archive.message_secrets, crypto, archive.ciphersuite)
        .map_err(|error| EpochArchiveError::SenderData(error.to_string()))?;
    let sender_index = sender_data.leaf_index;
    let sender_generation = sender_data.generation;
    let own_message = sender_index == archive.own_leaf_index;
    if own_message && !options.allow_own_messages {
        return Err(EpochArchiveError::OwnMessageNotAllowed);
    }

    let sender_member = archive
        .leaves
        .iter()
        .find(|member| member.index == sender_index)
        .ok_or_else(|| EpochArchiveError::UnknownSender(sender_index.u32()))?;
    let CredentialWithKey {
        credential: _,
        signature_key,
    } = CredentialWithKey::from(sender_member);
    let signature_public_key = OpenMlsSignaturePublicKey::from_signature_key(
        SignaturePublicKey::from(signature_key.as_slice()),
        archive.ciphersuite.signature_algorithm(),
    );
    let sender_context = Some(SenderContext::Member((
        archive.group_id.clone(),
        sender_index,
    )));
    let sender_ratchet_config = recovery_ratchet_config(&archive, options);

    let verifiable = ciphertext
        .to_verifiable_content_for_recovery(
            archive.ciphersuite,
            crypto,
            &mut archive.message_secrets,
            sender_index,
            &sender_ratchet_config,
            sender_data,
        )
        .map_err(|error| EpochArchiveError::Decrypt(error.to_string()))?;
    let content = verifiable
        .verify(crypto, &signature_public_key)
        .map_err(|error| EpochArchiveError::Verify(error.to_string()))?
        .validate(
            archive.ciphersuite,
            crypto,
            sender_context,
            archive.protocol_version,
        )
        .map_err(|error| EpochArchiveError::Verify(error.to_string()))?;

    let application_bytes = match content.content() {
        FramedContentBody::Application(bytes) => bytes.as_slice().to_vec(),
        _ => return Err(EpochArchiveError::NotApplicationMessage),
    };

    Ok(ArchivedPlaintext {
        content: application_bytes,
        aad: content.authenticated_data().to_vec(),
        sender: content.sender().clone(),
        sender_index: sender_index.u32(),
        generation: sender_generation,
        epoch: content.epoch().as_u64(),
        own_message,
    })
}

fn build_member_snapshot(
    group_id: GroupId,
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    leaves: &[Member],
) -> Result<RecoveryMemberSnapshot, EpochArchiveError> {
    let mut members = leaves
        .iter()
        .map(|member| {
            let basic = BasicCredential::try_from(member.credential.clone())
                .map_err(|error| EpochArchiveError::Snapshot(error.to_string()))?;
            let user_id = String::from_utf8(basic.identity().to_vec())
                .map_err(|error| EpochArchiveError::Snapshot(error.to_string()))?;
            Ok(RecoveryMember {
                leaf_index: member.index.u32(),
                user_id,
                signature_key: member.signature_key.clone(),
            })
        })
        .collect::<Result<Vec<_>, EpochArchiveError>>()?;
    members.sort_by_key(|member| member.leaf_index);
    Ok(RecoveryMemberSnapshot {
        snapshot_version: RECOVERY_SNAPSHOT_VERSION,
        hash_mode: "optimized-member-signatures".to_string(),
        group_id,
        protocol_version,
        ciphersuite,
        signature_scheme: format!("{:?}", ciphersuite.signature_algorithm()),
        members,
    })
}

fn snapshot_to_members(
    snapshot: &RecoveryMemberSnapshot,
    archive: &EpochArchiveV2,
) -> Result<Vec<Member>, EpochArchiveError> {
    if snapshot.snapshot_version != RECOVERY_SNAPSHOT_VERSION {
        return Err(EpochArchiveError::Snapshot(
            "unsupported snapshot version".to_string(),
        ));
    }
    if snapshot.group_id != archive.group_id
        || snapshot.protocol_version != archive.protocol_version
        || snapshot.ciphersuite != archive.ciphersuite
    {
        return Err(EpochArchiveError::Snapshot(
            "snapshot scope does not match archive".to_string(),
        ));
    }
    let mut members = snapshot
        .members
        .iter()
        .map(|member| {
            Ok(Member {
                index: LeafNodeIndex::new(member.leaf_index),
                credential: Credential::from(BasicCredential::new(
                    member.user_id.as_bytes().to_vec(),
                )),
                encryption_key: Vec::new(),
                signature_key: member.signature_key.clone(),
            })
        })
        .collect::<Result<Vec<_>, EpochArchiveError>>()?;
    members.sort_by_key(|member| member.index);
    Ok(members)
}

fn parse_archive(archive_bytes: &[u8]) -> Result<EpochArchive, EpochArchiveError> {
    let archive: EpochArchive =
        serde_json::from_slice(archive_bytes).map_err(EpochArchiveError::Deserialize)?;
    if archive.archive_version != EPOCH_ARCHIVE_VERSION {
        return Err(EpochArchiveError::UnsupportedArchiveVersion(
            archive.archive_version,
        ));
    }
    Ok(archive)
}

fn parse_private_message(
    ciphertext_bytes: &[u8],
) -> Result<(ProtocolVersion, PrivateMessageIn), EpochArchiveError> {
    let mut readable = ciphertext_bytes;
    let message = MlsMessageIn::tls_deserialize(&mut readable).map_err(EpochArchiveError::Codec)?;
    let version = message.version;
    match message.extract() {
        MlsMessageBodyIn::PrivateMessage(ciphertext) => Ok((version, ciphertext)),
        _ => Err(EpochArchiveError::NotPrivateMessage),
    }
}

fn validate_ciphertext_scope(
    archive: &EpochArchive,
    ciphertext: &PrivateMessageIn,
    message_version: Option<ProtocolVersion>,
) -> Result<(), EpochArchiveError> {
    if ciphertext.group_id() != &archive.group_id {
        return Err(EpochArchiveError::WrongGroup);
    }
    if ciphertext.epoch() != archive.epoch {
        return Err(EpochArchiveError::WrongEpoch {
            archive: archive.epoch.as_u64(),
            ciphertext: ciphertext.epoch().as_u64(),
        });
    }
    if message_version.is_some_and(|version| version != archive.protocol_version) {
        return Err(EpochArchiveError::WrongProtocolVersion);
    }
    Ok(())
}

fn recovery_ratchet_config(
    archive: &EpochArchive,
    options: RecoveryDecryptOptions,
) -> SenderRatchetConfiguration {
    options
        .max_forward_distance
        .map(|maximum_forward_distance| {
            SenderRatchetConfiguration::new(
                archive.sender_ratchet_config.out_of_order_tolerance(),
                maximum_forward_distance,
            )
        })
        .unwrap_or(archive.sender_ratchet_config)
}
