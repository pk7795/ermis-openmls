# POC Plan: Epoch Key Archive Recovery

## Goal
Chung minh phuong an Epoch Key Archive co the khoi phuc lich su E2EE bang cach archive fresh MLS epoch secrets, sau do decrypt lai `mls_ciphertext` ma khong can live group state cu.

POC chi tap trung OpenMLS/WASM/UniFFI. Chua implement Bellboy vault/storage production.

## Success Criteria
- Export duoc fresh archive ngay sau khi epoch duoc tao.
- Dung archive decrypt lai historical `mls_ciphertext`.
- Decrypt duoc ca message tu member khac va own sent message.
- Decrypt duoc sau khi live provider/group state bi xoa.
- Decrypt duoc message qua `max_past_epochs(5)`.
- Khong mutate live MLS group trong recovery path.

## Scope

### In Scope
- Core OpenMLS recovery API.
- WASM wrapper API.
- UniFFI wrapper API neu core POC pass.
- Integration tests trong OpenMLS repo.

### Out of Scope
- Bellboy DB/API cho vault.
- PIN/KMS/HSM production.
- UI restore flow.
- Full SDK sync integration.

## Design

### Archive Point
Archive phai chay ngay khi epoch fresh duoc tao, truoc khi app message nao trong epoch do duoc send/decrypt.

Hook points:
- group create
- join with welcome
- external join after merge
- own commit merge: add/remove/key rotation
- received commit merge

### Archive Format
`EpochArchive` can chua:
- `archive_version`
- `group_id`
- `epoch`
- `ciphersuite`
- `protocol_version`
- `sender_ratchet_config`
- `message_secrets`
- `leaves` hoac member snapshot du de verify signature
- `own_leaf_index`

Khong chi export `MessageSecrets`, vi restore can verify sender credential/signature.

### Recovery API
Implement trong `openmls` crate truoc, khong implement truc tiep trong `openmls-wasm`.

Proposed core API:

```rust
pub struct EpochArchive;
pub struct ArchivedPlaintext;
pub struct RecoveryDecryptOptions {
    pub allow_own_messages: bool,
    pub max_forward_distance: Option<u32>,
}

impl MlsGroup {
    pub fn export_current_epoch_archive(&self) -> Result<Vec<u8>, EpochArchiveError>;
}

pub fn decrypt_with_epoch_archive(
    archive_bytes: &[u8],
    ciphertext: &[u8],
    options: RecoveryDecryptOptions,
) -> Result<ArchivedPlaintext, EpochArchiveError>;
```

WASM wrapper:

```rust
group.archive_current_epoch() -> Vec<u8>
decrypt_with_epoch_archive(archive, ciphertext) -> ProcessedMessage
peek_sender_data_from_archive(archive, ciphertext) -> { sender_index, generation, epoch }
```

## Required POC Cases

### Case 1: Basic Historical Decrypt
1. Alice and Bob create MLS group.
2. Export epoch archive immediately.
3. Bob decrypts Alice message normally.
4. Delete/recreate provider state.
5. Decrypt same ciphertext using archive.
6. Assert plaintext matches.

### Case 2: Own Sent Message
1. Alice sends message.
2. Archive is from Alice device.
3. Delete live state.
4. Decrypt Alice's own ciphertext using archive.
5. Assert this bypasses normal `CannotDecryptOwnMessage` safely.

Expected implementation note: own leaf uses `EncryptionRatchet`, so recovery path needs custom derivation for own sender.

### Case 3: Past Epoch Beyond Window
1. Set `max_past_epochs(5)`.
2. Archive epoch 1.
3. Advance to epoch 7.
4. Confirm normal OpenMLS cannot decrypt epoch 1 message.
5. Confirm archive recovery can decrypt epoch 1 message.

### Case 4: Multiple Messages Same Epoch
1. Send many messages in one epoch from same sender.
2. Pre-scan sender data to get generation.
3. Sort by `(sender_index, content_type, generation)`.
4. Decrypt with archive.
5. Assert all plaintexts match.

### Case 5: Out-of-Order Recovery
1. Attempt decrypt generation 3 before generation 1 with one mutable archive state.
2. Confirm expected failure or skipped generation behavior.
3. Implement supported strategy:
   - either fresh archive clone per message, or
   - sorted batch decrypt per sender/generation.
4. Document chosen strategy.

### Case 6: Forward Distance Stress
1. Send more than current `maximum_forward_distance` in one epoch.
2. Test recovery failure mode.
3. Decide mitigation:
   - larger recovery-only forward distance,
   - archive generation checkpoints,
   - or forced epoch rotation.

### Case 7: Archive Does Not Mutate Live State
1. Export archive.
2. Run recovery decrypt.
3. Continue normal send/decrypt on live group.
4. Assert live MLS state still works.

## Implementation Steps

1. Add internal archive structs in `openmls/src/group/mls_group/epoch_archive.rs`.
2. Add `MlsGroup::export_current_epoch_archive()`.
3. Add standalone `decrypt_with_epoch_archive()`.
4. Add tests in `openmls/openmls/tests/epoch_archive.rs`.
5. Add WASM wrapper after core tests pass.
6. Add UniFFI wrapper after WASM/core semantics are stable.
7. Add SDK draft hook only after all POC tests pass.

## Blockers To Resolve
- `MessageSecrets`, `MessageSecretsStore`, `SecretTree`, and sender ratchet internals are `pub(crate)`.
- Recovery must verify signatures using archived member leaves.
- Own messages require custom derivation because own sender uses `EncryptionRatchet`.
- Generation ordering cannot rely on server `created_at`.
- Archive upload failure must be handled later by durable local queue.

## POC Done Definition
- All 7 cases pass in Rust tests.
- WASM wrapper can decrypt archived ciphertext in a browser/node test.
- Recovery API does not require Bellboy changes.
- Risks and remaining production work are documented.

## Implementation Status

Core Rust POC implemented in OpenMLS:
- `openmls/src/group/mls_group/epoch_archive.rs`
- `MlsGroup::export_current_epoch_archive()`
- `decrypt_with_epoch_archive()`
- `peek_sender_data_from_archive()`
- recovery ratchet path for own sent messages via `SecretTree::secret_for_recovery()`
- recovery decrypt path via `PrivateMessageIn::to_verifiable_content_for_recovery()`

Test coverage added in `openmls/src/group/mls_group/tests_and_kats/tests/epoch_archive.rs`:
- basic historical decrypt after live state is dropped
- own sent message recovery, bypassing normal `CannotDecryptOwnMessage`
- epoch 1 recovery after live group advances to epoch 7 with `max_past_epochs(5)`
- multiple messages in the same epoch, sorted by peeked sender generation
- out-of-order recovery with fresh archive clone per message
- forward-distance failure plus recovery-only `max_forward_distance` override
- recovery path does not mutate live MLS group state

Verified commands:
```bash
cargo check -p openmls
cargo test -p openmls epoch_archive --features test-utils
```

Chosen strategy for Case 5:
- `decrypt_with_epoch_archive()` deserializes archive bytes per call, so each message gets a fresh `MessageSecrets` / `SecretTree` clone.
- This makes out-of-order recovery safe for POC and avoids shared mutable archive state.
- A production batch API can still optimize by grouping messages by `(sender_index, content_type, generation)` and reusing one mutable archive per sorted stream.

Remaining work:
- Add WASM wrapper API.
- Add UniFFI wrapper API.
- Decide stable binary archive format instead of JSON if archive size/performance matters.
- Add client-side encryption/PIN vault and durable upload queue.
- Add Bellboy vault/archive storage APIs after client/core semantics are stable.
