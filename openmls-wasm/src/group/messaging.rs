//! Message encryption and processing

use openmls::{
    framing::{MlsMessageBodyIn, MlsMessageIn},
    group::{
        decrypt_with_epoch_archive as openmls_decrypt_with_epoch_archive,
        decrypt_with_epoch_archive_v2 as openmls_decrypt_with_epoch_archive_v2,
        peek_sender_data_from_archive as openmls_peek_sender_data_from_archive,
        RecoveryDecryptOptions,
    },
};
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::{identity::Identity, Group, Provider};

/// Type of processed message
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Application message (encrypted user content)
    ApplicationMessage,
    /// Proposal message (add/remove/update)
    Proposal,
    /// Commit message (finalizing proposals)
    Commit,
}

/// Result of processing an incoming message
#[wasm_bindgen]
pub struct ProcessedMessage {
    message_type: MessageType,
    content: Option<Vec<u8>>,
    sender_index: u32,
    epoch: u64,
    aad: Vec<u8>,
}

/// Sender data decoded from an archived epoch.
#[wasm_bindgen]
pub struct ArchivedSenderData {
    sender_index: u32,
    generation: u32,
    epoch: u64,
    content_type: String,
    own_message: bool,
}

#[wasm_bindgen]
impl ArchivedSenderData {
    /// Get the sender's leaf index.
    #[wasm_bindgen(getter)]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// Get the sender ratchet generation.
    #[wasm_bindgen(getter)]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Get the MLS epoch.
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the MLS content type.
    #[wasm_bindgen(getter)]
    pub fn content_type(&self) -> String {
        self.content_type.clone()
    }

    /// Whether this message was sent by the archive owner's own leaf.
    #[wasm_bindgen(getter)]
    pub fn own_message(&self) -> bool {
        self.own_message
    }
}

/// Application plaintext recovered from an archived epoch.
#[wasm_bindgen]
pub struct ArchivedMessage {
    content: Vec<u8>,
    sender_index: u32,
    generation: u32,
    epoch: u64,
    aad: Vec<u8>,
    own_message: bool,
}

#[wasm_bindgen]
impl ArchivedMessage {
    /// Get the decrypted application content.
    #[wasm_bindgen(getter)]
    pub fn content(&self) -> Vec<u8> {
        self.content.clone()
    }

    /// Get the sender's leaf index.
    #[wasm_bindgen(getter)]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// Get the sender ratchet generation.
    #[wasm_bindgen(getter)]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Get the MLS epoch.
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the additional authenticated data.
    #[wasm_bindgen(getter)]
    pub fn aad(&self) -> Vec<u8> {
        self.aad.clone()
    }

    /// Whether this message was sent by the archive owner's own leaf.
    #[wasm_bindgen(getter)]
    pub fn own_message(&self) -> bool {
        self.own_message
    }
}

#[wasm_bindgen]
impl ProcessedMessage {
    /// Get the type of message
    #[wasm_bindgen(getter)]
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Get the decrypted content (only for ApplicationMessage)
    #[wasm_bindgen(getter)]
    pub fn content(&self) -> Option<Vec<u8>> {
        self.content.clone()
    }

    /// Get the sender's leaf index
    #[wasm_bindgen(getter)]
    pub fn sender_index(&self) -> u32 {
        self.sender_index
    }

    /// Get the epoch this message belongs to
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the Additional Authenticated Data (AAD) from the message
    /// This is the metadata that was bound to the ciphertext during encryption
    #[wasm_bindgen(getter)]
    pub fn aad(&self) -> Vec<u8> {
        self.aad.clone()
    }

    /// Check if this is an application message
    pub fn is_application_message(&self) -> bool {
        self.message_type == MessageType::ApplicationMessage
    }

    /// Check if this is a proposal
    pub fn is_proposal(&self) -> bool {
        self.message_type == MessageType::Proposal
    }

    /// Check if this is a commit
    pub fn is_commit(&self) -> bool {
        self.message_type == MessageType::Commit
    }
}

/// Decrypt sender data using an archived epoch without consuming the message ratchet.
#[wasm_bindgen]
pub fn peek_sender_data_from_archive(
    provider: &Provider,
    archive: &[u8],
    ciphertext: &[u8],
) -> Result<ArchivedSenderData, JsError> {
    let sender_data =
        openmls_peek_sender_data_from_archive(provider.0.crypto(), archive, ciphertext)
            .map_err(|e| JsError::new(&format!("Peek archived sender data error: {e}")))?;
    Ok(ArchivedSenderData {
        sender_index: sender_data.sender_index,
        generation: sender_data.generation,
        epoch: sender_data.epoch,
        content_type: format!("{:?}", sender_data.content_type),
        own_message: sender_data.own_message,
    })
}

/// Decrypt and verify an MLS private message using archived epoch state.
///
/// `max_forward_distance` uses `0` as "use archive default".
#[wasm_bindgen]
pub fn decrypt_with_epoch_archive(
    provider: &Provider,
    archive: &[u8],
    ciphertext: &[u8],
    allow_own_messages: bool,
    max_forward_distance: u32,
) -> Result<ArchivedMessage, JsError> {
    let max_forward_distance = (max_forward_distance != 0).then_some(max_forward_distance);
    let plaintext = openmls_decrypt_with_epoch_archive(
        provider.0.crypto(),
        archive,
        ciphertext,
        RecoveryDecryptOptions {
            allow_own_messages,
            max_forward_distance,
        },
    )
    .map_err(|e| JsError::new(&format!("Decrypt with epoch archive error: {e}")))?;
    Ok(ArchivedMessage {
        content: plaintext.content,
        sender_index: plaintext.sender_index,
        generation: plaintext.generation,
        epoch: plaintext.epoch,
        aad: plaintext.aad,
        own_message: plaintext.own_message,
    })
}

/// Decrypt and verify an MLS private message using a V2 archive + snapshot.
#[wasm_bindgen]
pub fn decrypt_with_epoch_archive_v2(
    provider: &Provider,
    archive: &[u8],
    snapshot: &[u8],
    ciphertext: &[u8],
    allow_own_messages: bool,
    max_forward_distance: u32,
) -> Result<ArchivedMessage, JsError> {
    let max_forward_distance = (max_forward_distance != 0).then_some(max_forward_distance);
    let plaintext = openmls_decrypt_with_epoch_archive_v2(
        provider.0.crypto(),
        archive,
        snapshot,
        ciphertext,
        RecoveryDecryptOptions {
            allow_own_messages,
            max_forward_distance,
        },
    )
    .map_err(|e| JsError::new(&format!("Decrypt with epoch archive v2 error: {e}")))?;
    Ok(ArchivedMessage {
        content: plaintext.content,
        sender_index: plaintext.sender_index,
        generation: plaintext.generation,
        epoch: plaintext.epoch,
        aad: plaintext.aad,
        own_message: plaintext.own_message,
    })
}

// Messaging methods for Group
#[wasm_bindgen]
impl Group {
    /// Create an encrypted message
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `sender` - Identity of the sender
    /// * `plaintext` - The message content to encrypt
    ///1
    /// # Returns
    /// Serialized encrypted MLS message
    pub fn create_message(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let msg_out =
            &self
                .mls_group
                .create_message(provider.as_ref(), &sender.keypair, plaintext)?;
        let mut serialized = vec![];
        msg_out.tls_serialize(&mut serialized)?;
        Ok(serialized)
    }

    /// Set Additional Authenticated Data (AAD) for the next outgoing message
    ///
    /// AAD is authenticated but NOT encrypted - use for metadata that needs
    /// to be bound cryptographically to the ciphertext (e.g., sender_id, channel_id).
    /// AAD is automatically reset after create_message() is called.
    ///
    /// # Arguments
    /// * `aad` - Bytes to use as AAD (typically JSON-serialized metadata)
    pub fn set_aad(&mut self, aad: &[u8]) {
        self.mls_group.set_aad(aad.to_vec());
    }

    /// Create an encrypted message with AAD in one call
    ///
    /// This is a convenience method that sets AAD and creates the message.
    ///
    /// # Arguments
    /// * `provider` - Crypto provider
    /// * `sender` - Identity of the sender
    /// * `plaintext` - The message content to encrypt
    /// * `aad` - Additional authenticated data (metadata to bind to ciphertext)
    pub fn create_message_with_aad(
        &mut self,
        provider: &Provider,
        sender: &Identity,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        self.mls_group.set_aad(aad.to_vec());
        self.create_message(provider, sender, plaintext)
    }

    /// Process an incoming message (decrypt or handle proposal/commit)
    ///
    /// This method handles all MLS message types:
    /// - ApplicationMessage: Returns decrypted content
    /// - Proposal: Stores as pending proposal, returns empty content
    /// - Commit: Merges the staged commit, returns empty content
    pub fn process_message(
        &mut self,
        provider: &mut Provider,
        msg: &[u8],
    ) -> Result<ProcessedMessage, JsError> {
        let mut msg_slice = msg;
        let mls_msg = MlsMessageIn::tls_deserialize(&mut msg_slice)
            .map_err(|e| JsError::new(&format!("Message deserialization error: {e}")))?;

        let processed_msg = match mls_msg.extract() {
            MlsMessageBodyIn::PublicMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            MlsMessageBodyIn::PrivateMessage(msg) => {
                self.mls_group.process_message(provider.as_ref(), msg)?
            }
            MlsMessageBodyIn::Welcome(_) => {
                return Err(JsError::new(
                    "Use Group::join_with_welcome for Welcome messages",
                ));
            }
            MlsMessageBodyIn::GroupInfo(_) => {
                return Err(JsError::new(
                    "Use Group::join_external for GroupInfo messages",
                ));
            }
            MlsMessageBodyIn::KeyPackage(_) => {
                return Err(JsError::new("KeyPackage should be processed separately"));
            }
        };

        // Get epoch info
        let epoch = processed_msg.epoch().as_u64();

        // Get sender index - use a default if sender is not a member (external sender)
        let sender_index = if let openmls::prelude::Sender::Member(idx) = processed_msg.sender() {
            idx.u32()
        } else {
            0 // Default for external senders
        };

        // Extract AAD before into_content() consumes the message
        let aad = processed_msg.aad().to_vec();

        match processed_msg.into_content() {
            openmls::framing::ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(ProcessedMessage {
                    message_type: MessageType::ApplicationMessage,
                    content: Some(app_msg.into_bytes()),
                    sender_index,
                    epoch,
                    aad,
                })
            }
            openmls::framing::ProcessedMessageContent::ProposalMessage(proposal)
            | openmls::framing::ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.mls_group
                    .store_pending_proposal(provider.0.storage(), *proposal)?;
                Ok(ProcessedMessage {
                    message_type: MessageType::Proposal,
                    content: None,
                    sender_index,
                    epoch,
                    aad,
                })
            }
            openmls::framing::ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(provider.as_mut(), *staged_commit)?;
                Ok(ProcessedMessage {
                    message_type: MessageType::Commit,
                    content: None,
                    sender_index,
                    epoch,
                    aad,
                })
            }
        }
    }

    /// Process message and return raw bytes (legacy API, for backwards compatibility)
    ///
    /// Returns decrypted bytes for application messages, empty for proposals/commits.
    pub fn process_message_raw(
        &mut self,
        provider: &mut Provider,
        msg: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let processed = self.process_message(provider, msg)?;
        Ok(processed.content.unwrap_or_default())
    }
}
