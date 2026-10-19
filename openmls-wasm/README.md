# OpenMLS Wasm Bindings Experiment

Release/handoff steps for the generated WASM set are in
[`../MLS_UPGRADE_HANDOFF.md`](../MLS_UPGRADE_HANDOFF.md).

This repo is a step on the way to proper Wasm support for OpenMLS.
The main goals are:

- provide a minimal, but still useful set of bindings
- a starting point for custom bindings with advanced features
- a test bed for measuring the size of the packed

## POC Notes

### 2026-10-09 — Read-only public GroupInfo validation

<details>
<summary>Change log</summary>

- Added `Group.validate_group_info_with_policy(provider, identity, group_info, allow_expired_tree_leaves)` and `GroupInfoValidation` with validated `epoch`/`group_id`/`ratchet_tree_sha256` getters. The tree digest enables consumers to reject same-epoch forks against durable local state. Exact input is bounded to 1 MiB. Existing methods and Verify defaults remain unchanged. Pair generated JS/types/WASM metadata before consuming this additive API.

</details>

Validation uses the same signature, embedded tree, protocol, leaf lifetime and external-public-key checks as production External Join, stopping after `ExternalCommitBuilder.build_group`. It does not build/finalize a commit, write provider state, consume a KeyPackage, change membership, publish Ready or prove a durable client checkpoint. It validates public cryptography; confirmation-tag MAC requires epoch secrets. Explicit AllowExpired applies only the existing locked tree-leaf policy and does not skip other validation. The API returns no private data.

WASM core clock sampling now checks original JS milliseconds before integer conversion; nonfinite, zero, negative, subsecond and overflowing values fail as InvalidClock rather than becoming epoch zero. Native checked SystemTime and single-sample operation semantics remain. Verification, source/artifact identity, failed reports and consumer ACK dependencies are in the [canonical implementation plan](../../bellboy/docs/todo/e2ee_mls_lifetime_ownership_recovery_plan.md) and [authoritative ledger](../../bellboy/docs/todo/e2ee_mls_lifetime_ownership_recovery_ledger.md), LOR-DEC-021/022. Consumer ACK/durable proof/device gates remain open.

### 2026-09-03 - Typed partial-Welcome recovery boundary

- Added `Group.join_with_welcome_typed(...)` without changing the legacy
  `join_with_welcome(...)` API.
- The typed method exposes stable `MlsErrorCode` and `code_name` values. Only
  `NoMatchingKeyPackage` authorizes an automatic external-join fallback;
  malformed input, invalid signatures or suites, and storage failures keep
  their distinct failure path and fail closed.
- This is source-level binding evidence. Generated WASM artifact promotion
  remains a separate client/release task at the external-safe package pin.

### 2026-05-18 - Composite inline group changes

- Mode: POC.
- Goal: prove that pending ghost removals can be bundled with a primary MLS action in one commit for `react-chat-v2`.
- Added `Group.commit_group_changes(provider, sender, remove_user_ids, add_members, force_self_update)` to the WASM bindings.
- Added SDK-facing wrappers: `commit_member_add_with_removals`, `commit_self_update_with_removals`, and `commit_member_removals`.
- Added `Group.delete_state(provider)` so clients can remove stale provider group state after self-leave/removal before a later re-add to the same CID.
- Mirrored the same composite commit wrappers and `delete_state` into `openmls-uniffi` for Swift/Kotlin mobile bindings.
- The API uses `commit_builder().consume_proposal_store(false)` and inline remove/add proposals so receivers process only the commit, without requiring standalone proposal delivery.
- Updated `static/react-chat-v2` to mark local ghosts and exercise composite add, remove, and key rotation flows.
- Polished `react-chat-v2` logs to show `has_welcome`, per-receiver commit processing, and avoid duplicate WASM init logs in React StrictMode.
- Copied rebuilt WASM artifacts into `ermis-chat-monorepo/packages/ermis-chat-sdk/src/wasm`; `ermis-chat-js-sdk` is intentionally out of scope.
- Verification: `cargo check -p openmls-wasm`, targeted composite primitive/wrapper unit tests, `./build.sh`, SDK typecheck/build, `npm run build` for `react-chat-v2`, `cargo test -p openmls-uniffi`, and `./build_mobile.sh ios`.
