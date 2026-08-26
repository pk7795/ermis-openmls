//! Binding-neutral OpenMLS mobile API.
//!
//! This crate owns MLS operations, state, persistence, and wire-neutral DTOs.
//! It deliberately contains no UniFFI or flutter_rust_bridge dependencies.

macro_rules! mls_error {
    ($($arg:tt)*) => {
        log::error!($($arg)*);
    };
}

macro_rules! mls_debug {
    ($($arg:tt)*) => {
        log::debug!($($arg)*);
    };
}

pub mod errors;
pub mod group;
pub mod identity;
pub mod provider;
mod storage;
pub mod types;

pub use errors::MlsError;
pub use group::{join_external, Group};
pub use identity::{hash_channel_id, validate_key_package_bytes, Identity, KeyPackage};
pub use provider::Provider;
pub use types::*;

pub type MlsResult<T> = Result<T, MlsError>;
