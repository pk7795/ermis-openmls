//! Error types for OpenMLS WASM binding

use wasm_bindgen::prelude::*;

/// Error codes for MLS operations
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsErrorCode {
    /// Error during serialization
    SerializationError,
    /// Error during deserialization
    DeserializationError,
    /// Group is not in operational state
    GroupNotOperational,
    /// Member not found in group
    MemberNotFound,
    /// Invalid message format or content
    InvalidMessage,
    /// Welcome message was expected but not generated
    NoWelcome,
    /// Invalid CID format
    InvalidCid,
    /// Storage operation failed
    StorageError,
    /// Crypto operation failed
    CryptoError,
    /// Invalid state
    InvalidState,
    /// External commit failed
    ExternalCommitError,
}

/// Custom error type for MLS operations
#[wasm_bindgen]
#[derive(Debug)]
pub struct MlsError {
    code: MlsErrorCode,
    message: String,
}

#[wasm_bindgen]
impl MlsError {
    /// Create a new MlsError
    #[wasm_bindgen(constructor)]
    pub fn new(code: MlsErrorCode, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }

    /// Get error code
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> MlsErrorCode {
        self.code
    }

    /// Get error message
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

impl std::fmt::Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.message)
    }
}

// Helper to convert internal errors
impl MlsError {
    pub fn serialization(msg: &str) -> JsError {
        JsError::new(&format!("[SerializationError] {}", msg))
    }

    pub fn deserialization(msg: &str) -> JsError {
        JsError::new(&format!("[DeserializationError] {}", msg))
    }

    pub fn group_not_operational() -> JsError {
        JsError::new("[GroupNotOperational] Group is not in operational state")
    }

    pub fn member_not_found(user_id: &str) -> JsError {
        JsError::new(&format!("[MemberNotFound] Member not found: {}", user_id))
    }

    pub fn invalid_message(msg: &str) -> JsError {
        JsError::new(&format!("[InvalidMessage] {}", msg))
    }

    pub fn no_welcome() -> JsError {
        JsError::new("[NoWelcome] Expected welcome message but none was generated")
    }

    pub fn invalid_cid(msg: &str) -> JsError {
        JsError::new(&format!("[InvalidCid] {}", msg))
    }

    pub fn storage(msg: &str) -> JsError {
        JsError::new(&format!("[StorageError] {}", msg))
    }

    pub fn crypto(msg: &str) -> JsError {
        JsError::new(&format!("[CryptoError] {}", msg))
    }

    pub fn invalid_state(msg: &str) -> JsError {
        JsError::new(&format!("[InvalidState] {}", msg))
    }
}
