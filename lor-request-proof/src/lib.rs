//! Versioned, domain-separated MLS control-request signing codec.
//! Contains no auth-session, JWT, provider mutation or network behavior.
use sha2::{Digest, Sha256};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

pub const MAX_CLOCK_SKEW_SECONDS: u64 = 120;
const DOMAIN: &[u8] = b"ermis.lor-request.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    OwnershipInventory = 1,
    OwnershipRetire = 2,
    ValidationAck = 3,
    ExternalJoin = 4,
    ExternalJoinReceipt = 5,
    KeyPackageUpload = 6,
    RegistrationStatus = 7,
    RecoveryContinue = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    Invalid,
    Expired,
    ScopeMismatch,
    SignerMismatch,
    SignatureInvalid,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProofError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestIntent {
    pub user_id: String,
    pub project_id: Uuid,
    pub device_id: String,
    pub registration_id: Uuid,
    pub generation: i64,
    pub ciphersuite: u16,
    pub operation: Operation,
    /// The exact percent-encoded request target, including any query string.
    pub target: String,
    /// SHA-256 of bytes actually submitted to the transport (empty for GET).
    pub body_sha256: [u8; 32],
}

impl RequestIntent {
    pub fn digest(&self) -> Result<[u8; 32], ProofError> {
        if self.user_id.is_empty() || self.user_id.len() > 1024
            || self.user_id.chars().any(char::is_control)
            || self.device_id.is_empty() || self.device_id.len() > 256
            || self.device_id.chars().any(char::is_control)
            || self.project_id.is_nil() || self.registration_id.is_nil()
            || self.generation < 0 || !matches!(self.ciphersuite, 1..=3)
            || self.target.len() > 4096 || !self.target.starts_with("/v1/e2ee/")
            || self.target.chars().any(|c| c.is_control() || c == '#')
        {
            return Err(ProofError::Invalid);
        }
        let mut bytes = Vec::with_capacity(128 + self.user_id.len() + self.device_id.len() + self.target.len());
        append_text(&mut bytes, &self.user_id)?;
        bytes.extend_from_slice(self.project_id.as_bytes());
        append_text(&mut bytes, &self.device_id)?;
        bytes.extend_from_slice(self.registration_id.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.ciphersuite.to_be_bytes());
        bytes.push(self.operation as u8);
        append_text(&mut bytes, &self.target)?;
        bytes.extend_from_slice(&self.body_sha256);
        Ok(Sha256::digest(bytes).into())
    }
}

fn append_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), ProofError> {
    let len = u32::try_from(value.len()).map_err(|_| ProofError::Invalid)?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

pub fn signing_payload(intent: &RequestIntent, request_id: Uuid, issued_at: i64) -> Result<Vec<u8>, ProofError> {
    if request_id.is_nil() || issued_at <= 0 {
        return Err(ProofError::Invalid);
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 56);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&intent.digest()?);
    bytes.extend_from_slice(request_id.as_bytes());
    bytes.extend_from_slice(&issued_at.to_be_bytes());
    Ok(bytes)
}


#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SigningContext {
    pub version: u16,
    pub project_id: Uuid,
    pub device_id: String,
    pub registration_id: Uuid,
    pub generation: i64,
    pub operation: u8,
    pub target: String,
    pub body_sha256: String,
    pub request_id: Uuid,
    pub issued_at: i64,
}

impl Operation {
    pub fn from_code(code: u8) -> Result<Self, ProofError> {
        match code {
            1 => Ok(Self::OwnershipInventory), 2 => Ok(Self::OwnershipRetire),
            3 => Ok(Self::ValidationAck), 4 => Ok(Self::ExternalJoin),
            5 => Ok(Self::ExternalJoinReceipt), 6 => Ok(Self::KeyPackageUpload),
            7 => Ok(Self::RegistrationStatus), 8 => Ok(Self::RecoveryContinue), _ => Err(ProofError::Invalid),
        }
    }
    pub fn method(self) -> &'static str {
        match self { Self::OwnershipInventory | Self::ExternalJoinReceipt => "GET", _ => "POST" }
    }
}

impl SigningContext {
    pub fn parse(json: &str) -> Result<Self, ProofError> {
        if json.len() > 6144 { return Err(ProofError::Invalid); }
        serde_json::from_str(json).map_err(|_| ProofError::Invalid)
    }
    pub fn intent(&self, user_id: &str, ciphersuite: u16) -> Result<RequestIntent, ProofError> {
        if self.version != 1 || self.body_sha256.len() != 64 || !self.body_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(ProofError::Invalid);
        }
        let mut body_sha256 = [0u8; 32];
        for (i, octet) in body_sha256.iter_mut().enumerate() {
            *octet = u8::from_str_radix(&self.body_sha256[i*2..i*2+2], 16).map_err(|_| ProofError::Invalid)?;
        }
        let intent = RequestIntent { user_id: user_id.into(), project_id: self.project_id,
            device_id: self.device_id.clone(), registration_id: self.registration_id,
            generation: self.generation, ciphersuite, operation: Operation::from_code(self.operation)?,
            target: self.target.clone(), body_sha256 };
        intent.digest()?;
        Ok(intent)
    }
    pub fn payload(&self, user_id: &str, ciphersuite: u16) -> Result<Vec<u8>, ProofError> {
        signing_payload(&self.intent(user_id, ciphersuite)?, self.request_id, self.issued_at)
    }
}
