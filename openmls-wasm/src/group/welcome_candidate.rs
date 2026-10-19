//! Welcome mutates an isolated provider. The SDK owns its mutation lock and
//! IndexedDB transaction/readback; this producer never claims durability itself.
use crate::{Group, MlsError, MlsErrorCode, Provider, RatchetTree};
use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto};
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::RwLock};
use wasm_bindgen::prelude::*;

// The existing MemoryStorage binary layout is count + repeated key/value
// lengths and bytes. Check every length against remaining input before copying;
// reject duplicate keys/trailing bytes rather than silently changing a map.
fn decode_candidate_snapshot(bytes: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, MlsError> {
    fn invalid() -> MlsError {
        MlsError::new(
            MlsErrorCode::StorageCorruption,
            "Candidate snapshot is invalid",
        )
    }
    fn number(bytes: &[u8], offset: &mut usize) -> Result<usize, MlsError> {
        let end = offset.checked_add(8).ok_or_else(invalid)?;
        let value: [u8; 8] = bytes
            .get(*offset..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?;
        *offset = end;
        usize::try_from(u64::from_be_bytes(value)).map_err(|_| invalid())
    }
    let mut offset = 0;
    let count = number(bytes, &mut offset)?;
    if count > bytes.len().saturating_sub(offset) / 16 {
        return Err(invalid());
    }
    let mut map = HashMap::new();
    for _ in 0..count {
        let key_len = number(bytes, &mut offset)?;
        let value_len = number(bytes, &mut offset)?;
        let key_end = offset.checked_add(key_len).ok_or_else(invalid)?;
        let end = key_end.checked_add(value_len).ok_or_else(invalid)?;
        let key = bytes.get(offset..key_end).ok_or_else(invalid)?;
        let value = bytes.get(key_end..end).ok_or_else(invalid)?;
        if key.is_empty() || map.insert(key.to_vec(), value.to_vec()).is_some() {
            return Err(invalid());
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err(invalid());
    }
    Ok(map)
}

#[wasm_bindgen]
impl Provider {
    /// Rebase a private candidate after HTTP/restart without losing unrelated
    /// current writes. This returns an isolated provider, never mutates active,
    /// and proves neither backend acceptance nor durable client activation.
    pub fn rebase_candidate(&self, base: &[u8], candidate: &[u8]) -> Result<Provider, MlsError> {
        let base = decode_candidate_snapshot(base)?;
        let candidate = decode_candidate_snapshot(candidate)?;
        let current = self.0.storage().values.read().map_err(|_| {
            MlsError::new(MlsErrorCode::StorageError, "Active snapshot unavailable")
        })?;
        let mut result = current.clone();
        for key in base.keys().chain(candidate.keys()) {
            if base.get(key) == candidate.get(key) {
                continue;
            }
            if current.get(key) != base.get(key) {
                return Err(MlsError::new(
                    MlsErrorCode::InvalidState,
                    "Candidate conflicts with current state",
                ));
            }
            match candidate.get(key) {
                Some(value) => {
                    result.insert(key.clone(), value.clone());
                }
                None => {
                    result.remove(key);
                }
            }
        }
        Ok(Provider(OpenMlsRustCrypto::new_with_storage(
            MemoryStorage {
                values: RwLock::new(result),
            },
        )))
    }
}

fn snapshot(provider: &Provider) -> Result<Vec<u8>, MlsError> {
    let mut bytes = Vec::new();
    provider
        .0
        .storage()
        .serialize(&mut bytes)
        .map_err(|_| MlsError::new(MlsErrorCode::StorageError, "Provider snapshot unavailable"))?;
    Ok(bytes)
}

#[wasm_bindgen]
pub struct WelcomeCandidate {
    base_hash: Vec<u8>,
    candidate_bytes: Vec<u8>,
    candidate: Option<Provider>,
    group: Option<Group>,
}

#[wasm_bindgen]
impl WelcomeCandidate {
    /// Public candidate identity for validating the checkpoint before activation.
    pub fn cid(&self) -> Result<String, MlsError> {
        match self.group.as_ref() {
            Some(group) => group.cid().map_err(|_| {
                MlsError::new(MlsErrorCode::InvalidState, "Candidate CID unavailable")
            }),
            None => Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Candidate already activated",
            )),
        }
    }

    /// Public cryptographic group identity; does not publish a usable Group.
    pub fn group_id(&self) -> Result<Vec<u8>, MlsError> {
        match self.group.as_ref() {
            Some(group) => Ok(group.group_id()),
            None => Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Candidate already activated",
            )),
        }
    }

    /// Candidate epoch for the durable group marker.
    pub fn epoch(&self) -> Result<u64, MlsError> {
        match self.group.as_ref() {
            Some(group) => Ok(group.epoch()),
            None => Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Candidate already activated",
            )),
        }
    }

    /// The caller holds the one provider-wide SDK lock across create, save,
    /// readback, activate, checkpoint publication and active-group publication.
    pub fn create(
        active: &Provider,
        welcome: &[u8],
        ratchet_tree: Option<RatchetTree>,
        allow_expired_tree_leaves: bool,
    ) -> Result<WelcomeCandidate, MlsError> {
        let base = snapshot(active)?;
        let base_hash = Sha256::digest(&base).to_vec();
        let storage =
            MemoryStorage::deserialize(&mut std::io::Cursor::new(base)).map_err(|_| {
                MlsError::new(MlsErrorCode::StorageError, "Candidate restore unavailable")
            })?;
        let candidate = Provider(OpenMlsRustCrypto::new_with_storage(storage));
        let group = Group::join_with_welcome_with_policy(
            &candidate,
            welcome,
            ratchet_tree,
            allow_expired_tree_leaves,
        )?;
        let candidate_bytes = snapshot(&candidate)?;
        Ok(WelcomeCandidate {
            base_hash,
            candidate_bytes,
            candidate: Some(candidate),
            group: Some(group),
        })
    }

    /// Private snapshot: persist in the same durable scope, never log/upload.
    pub fn provider_bytes(&self) -> Result<Vec<u8>, MlsError> {
        if self.candidate.is_none() {
            return Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Candidate already activated",
            ));
        }
        Ok(self.candidate_bytes.clone())
    }

    /// Call only after the durable transaction commits and readback succeeds.
    /// Readback mismatch/save failure keeps active provider and candidate intact.
    /// The base check additionally prevents overwriting an intervening mutation.
    pub fn activate(
        &mut self,
        active: &mut Provider,
        persisted_readback: &[u8],
    ) -> Result<Group, MlsError> {
        if self.candidate.is_none() || self.group.is_none() {
            return Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Candidate already activated",
            ));
        }
        if Sha256::digest(persisted_readback) != Sha256::digest(&self.candidate_bytes) {
            return Err(MlsError::new(
                MlsErrorCode::StorageError,
                "Candidate persistence not confirmed",
            ));
        }
        if Sha256::digest(snapshot(active)?).as_slice() != self.base_hash.as_slice() {
            return Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Active provider changed during candidate persistence",
            ));
        }
        match (self.candidate.take(), self.group.take()) {
            (Some(provider), Some(group)) => {
                active.0 = provider.0;
                self.candidate_bytes.clear();
                Ok(group)
            }
            _ => Err(MlsError::new(
                MlsErrorCode::InvalidState,
                "Candidate unavailable",
            )),
        }
    }
}
