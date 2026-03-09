//! Re-export common types for WASM binding

use openmls::treesync::RatchetTreeIn;
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Ratchet tree for group state synchronization
#[wasm_bindgen]
pub struct RatchetTree(pub(crate) RatchetTreeIn);

#[wasm_bindgen]
impl RatchetTree {
    /// Serialize this RatchetTree to bytes
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.tls_serialize_detached().unwrap()
    }

    /// Deserialize a RatchetTree from bytes
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<RatchetTree, JsError> {
        let mut s = bytes;
        let tree = RatchetTreeIn::tls_deserialize(&mut s)
            .map_err(|e| JsError::new(&format!("RatchetTree deserialization error: {e}")))?;
        Ok(RatchetTree(tree))
    }
}
