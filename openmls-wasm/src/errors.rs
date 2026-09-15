//! Error types for OpenMLS WASM binding

use wasm_bindgen::prelude::*;

use openmls::group::WelcomeError;

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
    /// A Welcome does not contain a KeyPackage owned by this provider
    NoMatchingKeyPackage,
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

    /// Stable string representation for clients that cannot safely depend on
    /// wasm-bindgen's numeric enum layout.
    #[wasm_bindgen(getter)]
    pub fn code_name(&self) -> String {
        match self.code {
            MlsErrorCode::SerializationError => "SerializationError",
            MlsErrorCode::DeserializationError => "DeserializationError",
            MlsErrorCode::GroupNotOperational => "GroupNotOperational",
            MlsErrorCode::MemberNotFound => "MemberNotFound",
            MlsErrorCode::InvalidMessage => "InvalidMessage",
            MlsErrorCode::NoWelcome => "NoWelcome",
            MlsErrorCode::InvalidCid => "InvalidCid",
            MlsErrorCode::StorageError => "StorageError",
            MlsErrorCode::CryptoError => "CryptoError",
            MlsErrorCode::InvalidState => "InvalidState",
            MlsErrorCode::ExternalCommitError => "ExternalCommitError",
            MlsErrorCode::NoMatchingKeyPackage => "NoMatchingKeyPackage",
        }
        .to_string()
    }
}

impl std::fmt::Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.message)
    }
}

// Helper to convert internal errors
impl MlsError {
    pub(crate) fn from_welcome_error<StorageError: std::fmt::Display>(
        error: WelcomeError<StorageError>,
    ) -> Self {
        let code = match &error {
            WelcomeError::NoMatchingKeyPackage => MlsErrorCode::NoMatchingKeyPackage,
            WelcomeError::StorageError(_) => MlsErrorCode::StorageError,
            _ => MlsErrorCode::InvalidMessage,
        };
        Self::new(code, &error.to_string())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_matching_key_package_has_stable_typed_code() {
        let error = MlsError::from_welcome_error(WelcomeError::<String>::NoMatchingKeyPackage);
        assert_eq!(error.code(), MlsErrorCode::NoMatchingKeyPackage);
        assert_eq!(error.code_name(), "NoMatchingKeyPackage");
    }
}
