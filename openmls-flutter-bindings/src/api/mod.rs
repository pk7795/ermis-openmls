//! Public API modules scanned by flutter_rust_bridge codegen.
//!
//! Only `pub` items in these modules are exposed to Dart.

// Logger must come first — its #[macro_export] macros are used by later modules.
#[macro_use]
pub mod logger;

pub mod group;
pub mod identity;
pub mod provider;
pub mod types;

pub use group::join_external;
pub use identity::{hash_channel_id, validate_key_package_bytes};

pub(crate) fn dart_result<T>(result: openmls_bindings_core::MlsResult<T>) -> anyhow::Result<T> {
    result.map_err(Into::into)
}
