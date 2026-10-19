//! Delivery-Service acceptance metadata. This is not authenticated MLS time.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Expected envelope identity supplied independently of the context being checked.
pub struct AcceptanceBinding<'a> {
    /// Stable backend event identifier.
    pub event_id: &'a str,
    /// Routing channel identifier.
    pub cid: &'a str,
    /// Generation asserted by the backend envelope.
    pub group_generation: u64,
    /// Event epoch, which may be the resulting commit epoch.
    pub epoch: u64,
}

/// Version-one backend metadata, shared by live and durable replay consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceContext {
    /// Context schema version, currently one.
    pub version: u16,
    /// Stable backend event identifier.
    pub event_id: String,
    /// Routing channel identifier.
    pub cid: String,
    /// Generation asserted by the backend envelope.
    pub group_generation: u64,
    /// Event epoch, which may be the resulting commit epoch.
    pub epoch: u64,
    /// Unix seconds, assigned by the backend when accepting the operation.
    pub accepted_at: u64,
    /// Lowercase hexadecimal SHA-256 of the exact MLS message bytes.
    pub payload_sha256: String,
    /// Known backend acceptance source; callers must establish source trust.
    pub provenance: String,
}

/// Failures defer replay; none authorize a lifetime fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AcceptanceContextError {
    #[error("acceptance metadata is malformed or unsupported")]
    /// Invalid schema, bounds or encoding.
    Malformed,
    #[error("acceptance metadata provenance is unknown")]
    /// Acceptance source has not been established.
    UnknownProvenance,
    #[error("acceptance metadata does not match the event")]
    /// Context differs from independently supplied envelope or bytes.
    BindingMismatch,
    #[error("acceptance metadata exceeds the future clock bound")]
    /// Acceptance time exceeds the five-minute clock guard.
    FutureTimestamp,
    #[error("acceptance clock is invalid")]
    /// Clock is unavailable, zero or overflowing.
    InvalidClock,
}

impl AcceptanceContext {
    /// Bounded parsing; absent/unknown metadata never falls back to replay time.
    pub fn from_json(json: &str) -> Result<Self, AcceptanceContextError> {
        if json.len() > 4096 {
            return Err(AcceptanceContextError::Malformed);
        }
        serde_json::from_str(json).map_err(|_| AcceptanceContextError::Malformed)
    }

    /// Validate before any group/provider mutation, using one local clock sample.
    pub fn validate(
        &self,
        expected: AcceptanceBinding<'_>,
        message: &[u8],
    ) -> Result<u64, AcceptanceContextError> {
        let now =
            crate::key_packages::unix_time_seconds().ok_or(AcceptanceContextError::InvalidClock)?;
        self.validate_at(expected, message, now)
    }

    /// Deterministic clock entrypoint for tests and callers with a sampled clock.
    pub fn validate_at(
        &self,
        expected: AcceptanceBinding<'_>,
        message: &[u8],
        now: u64,
    ) -> Result<u64, AcceptanceContextError> {
        use AcceptanceContextError::*;
        if now == 0 || self.accepted_at == 0 {
            return Err(InvalidClock);
        }
        let future_limit = now.checked_add(300).ok_or(InvalidClock)?;
        if self.version != 1
            || self.event_id.is_empty()
            || self.event_id.len() > 128
            || self.cid.is_empty()
            || self.cid.len() > 512
            || self.event_id.chars().any(char::is_control)
            || self.cid.chars().any(char::is_control)
            || message.is_empty()
        {
            return Err(Malformed);
        }
        // Legacy source trust must be established by the SDK adapter; this
        // string alone does not authenticate an imported event or backend time.
        if !matches!(
            self.provenance.as_str(),
            "bellboy_transition_v1" | "bellboy_legacy_acceptance_v1"
        ) {
            return Err(UnknownProvenance);
        }
        if self.event_id != expected.event_id
            || self.cid != expected.cid
            || self.group_generation != expected.group_generation
            || self.epoch != expected.epoch
            || self.payload_sha256 != format!("{:x}", Sha256::digest(message))
        {
            return Err(BindingMismatch);
        }
        if self.accepted_at > future_limit {
            return Err(FutureTimestamp);
        }
        Ok(self.accepted_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> AcceptanceBinding<'static> {
        AcceptanceBinding {
            event_id: "event",
            cid: "team:channel",
            group_generation: 2,
            epoch: 8,
        }
    }
    fn context() -> AcceptanceContext {
        AcceptanceContext {
            version: 1,
            event_id: "event".into(),
            cid: "team:channel".into(),
            group_generation: 2,
            epoch: 8,
            accepted_at: 1000,
            payload_sha256: format!("{:x}", Sha256::digest(b"mls")),
            provenance: "bellboy_transition_v1".into(),
        }
    }
    #[test]
    fn context_guards_all_bindings_provenance_digest_and_clock() {
        let valid = context();
        assert_eq!(valid.validate_at(binding(), b"mls", 700), Ok(1000));
        assert_eq!(
            valid.validate_at(binding(), b"mls", 699),
            Err(AcceptanceContextError::FutureTimestamp)
        );
        assert_eq!(
            valid.validate_at(binding(), b"mls", 0),
            Err(AcceptanceContextError::InvalidClock)
        );
        assert_eq!(
            valid.validate_at(binding(), b"mls", u64::MAX),
            Err(AcceptanceContextError::InvalidClock)
        );
        assert_eq!(
            valid.validate_at(binding(), b"tampered", 1000),
            Err(AcceptanceContextError::BindingMismatch)
        );
        for field in 0..4 {
            let mut wrong = context();
            match field {
                0 => wrong.event_id = "other".into(),
                1 => wrong.cid = "other".into(),
                2 => wrong.group_generation += 1,
                _ => wrong.epoch += 1,
            }
            assert_eq!(
                wrong.validate_at(binding(), b"mls", 1000),
                Err(AcceptanceContextError::BindingMismatch)
            );
        }
        let mut unknown = context();
        unknown.provenance = "imported".into();
        assert_eq!(
            unknown.validate_at(binding(), b"mls", 1000),
            Err(AcceptanceContextError::UnknownProvenance)
        );
        assert!(AcceptanceContext::from_json("null").is_err());
        assert!(AcceptanceContext::from_json(&" ".repeat(4097)).is_err());
    }
}
