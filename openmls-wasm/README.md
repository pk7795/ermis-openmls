# OpenMLS Wasm Bindings Experiment

This repo is a step on the way to proper Wasm support for OpenMLS.
The main goals are:

- provide a minimal, but still useful set of bindings
- a starting point for custom bindings with advanced features
- a test bed for measuring the size of the packed

## POC Notes

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
