//! Message encryption and processing

use openmls::framing::{MlsMessageBodyIn, MlsMessageIn};
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
