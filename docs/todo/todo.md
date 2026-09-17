# OpenMLS TODO

This is the authoritative checklist for OpenMLS-owned rehearsal artifacts. Bellboy environment promotion remains governed by its own [MLS lifecycle ledger](../../../bellboy/docs/todo/e2ee_mls_keypackage_lifecycle_plan.md).

- [x] `KP-TTL-REHEARSAL-001` Produce the internal Web/UHM WASM set with a signed KeyPackage lifetime of 605400 seconds and record source/build provenance. [Canonical plan](key_package_short_ttl_rehearsal_plan.md); [ZIP](../../artifacts/key_package_short_ttl_20260917/bellboy-3a3d81dc-short-ttl-wasm.zip).
- [x] `KP-TTL-REHEARSAL-002` Produce the external SDK/UHM WASM set from its pinned live-only OpenMLS source and matching ABI/lock set, with the same lifetime. [Canonical plan](key_package_short_ttl_rehearsal_plan.md); [ZIP](../../artifacts/key_package_short_ttl_20260917/bellboy-external-d6d2bfec-short-ttl-wasm.zip).
- [ ] `KP-TTL-REHEARSAL-003` Verify the generated packages' lifetime and JS/WASM ABI, ZIP integrity, and consumer integration; retain any gates that require the server as unverified. [Canonical plan](key_package_short_ttl_rehearsal_plan.md).

These are local rehearsal artifacts, not a TEST, STAGING, or PRODUCTION promotion gate.
