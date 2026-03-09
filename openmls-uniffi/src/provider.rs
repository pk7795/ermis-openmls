//! Crypto provider for MLS operations

use std::sync::Mutex;

use openmls_rust_crypto::OpenMlsRustCrypto;

/// Crypto provider for MLS operations.
/// Wraps OpenMlsRustCrypto in a Mutex for thread-safe UniFFI usage.
pub struct Provider {
    pub(crate) inner: Mutex<OpenMlsRustCrypto>,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(OpenMlsRustCrypto::default()),
        }
    }

    /// Get a reference to the inner crypto provider (locks the mutex).
    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, OpenMlsRustCrypto> {
        self.inner.lock().unwrap()
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}
