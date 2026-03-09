//! OpenMLS UniFFI Bindings for Mobile (iOS / Android)
//!
//! This crate mirrors the API surface of `openmls-wasm` but uses Mozilla UniFFI
//! to generate native Swift and Kotlin bindings instead of wasm-bindgen.

pub mod errors;
pub mod group;
pub mod identity;
pub mod provider;
pub mod types;

pub use errors::*;
pub use group::*;
pub use identity::*;
pub use provider::*;
pub use types::*;

uniffi::include_scaffolding!("openmls_uniffi");
