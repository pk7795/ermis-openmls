# OpenMLS MLS upgrade artifact runbook

Tài liệu này chỉ dành cho repository **`openmls`**. Owner của repo chịu trách
nhiệm qualify core/bindings và tạo artifact WASM/UniFFI có provenance. Owner
không migrate Bellboy database, không thay config server và không tuyên bố Web
hoặc iOS đã adopt chỉ vì source/binding build thành công.

Canonical product contract và environment order nằm trong
[bundle Bellboy](../bellboy/docs/todo/e2ee_mls_group_rebootstrap_plan.md).
Consumer runbooks:
[Web SDK/UHM](../ermis-chat-monorepo/MLS_UPGRADE_HANDOFF.md) và
[iOS SDK](../ios/ermis-ios-sdk/MLS_UPGRADE_HANDOFF.md).

## 0. Input và release identity

Nhận một reviewed OpenMLS snapshot và ghi:

```bash
git branch --show-current
git rev-parse HEAD
git status --porcelain=v1
git diff --binary | shasum -a 256
git ls-files --others --exclude-standard
shasum -a 256 Cargo.lock
cargo --version
rustc --version
wasm-pack --version
xcodebuild -version
```

`HEAD` không đủ nếu worktree dirty. Build release từ snapshot sạch/cô lập;
không reset hoặc ghi đè user-owned changes để thỏa tool. Không sửa metadata/hash
bằng tay sau build. Output phải gắn với source commit/diff digest, lockfile,
toolchain, timestamp và exact build command.

## 1. Contract phải giữ

Source/bindings/artifact phải cùng hỗ trợ:

- create/load bằng explicit MLS GroupId cho generation mới; generation 0 giữ
  persisted CID-as-GroupId compatibility;
- hai GroupId/generation cùng application CID và cùng epoch không va chạm;
- save/load qua provider restart và receiver-ratchet persistence;
- trusted historical processing dùng server acceptance time, missing/untrusted
  time fail closed, live expired KeyPackage vẫn bị reject;
- typed `NoMatchingKeyPackage`, invalid GroupId và lỗi public khác; không bắt
  consumer parse raw error text;
- archive v2 identity có generation+epoch, không tái tạo historical secrets;
- WASM và UniFFI public surface tương đương ở các contract consumer dùng.

Không đổi CID application thành MLS GroupId generation mới. Không nhầm
`group_generation` với sender ratchet generation. UDL enum mới phải append để
giữ discriminant compatibility.

## 2. Source và binding tests

Chạy tối thiểu trên source release:

```bash
cargo check -p openmls -p openmls-bindings-core -p openmls-wasm -p openmls-uniffi --offline
cargo test -p openmls-bindings-core --test generation_group_id --offline
cargo test -p openmls-wasm generation_tests --offline
cargo test -p openmls-uniffi --offline
cargo test -p openmls delayed_key_package_lifetime --offline
cargo test -p openmls secret_tree_persistence --offline
```

Nếu filter trả 0 test thì gate không đạt; ghi `unverified` và dùng exact test
target/name hiện tại. Kiểm tra scoped rustfmt và scan `unwrap(`, `expect(`,
explicit `panic!(` trên Rust được chạm; không format toàn repo.

## 3. Tạo WASM artifact

Core producer tạo package gốc:

```bash
cd openmls-wasm
wasm-pack build --target web
cd ..
shasum -a 256 openmls-wasm/pkg/openmls_wasm_bg.wasm
```

Handoff toàn bộ set đồng bộ, không chỉ file `.wasm`:

- `openmls_wasm.js`;
- `openmls_wasm.d.ts`;
- `openmls_wasm_bg.wasm`;
- `openmls_wasm_bg.wasm.d.ts`;
- source/lock/toolchain/hash manifest.

Chạy runtime tests bằng generated package; kiểm tra actual exports cho
explicit GroupId, historical processing, typed Welcome và archive. Web/UHM
owner quyết định package nào được copy/publish; OpenMLS build output tự nó
không chứng minh browser đang load artifact này.

## 4. Tạo UniFFI/iOS artifact

`build_mobile.sh ios` generate Swift/C bindings rồi build device và Apple
Silicon simulator slices:

```bash
cd openmls-uniffi
IOS_DEPLOYMENT_TARGET=15.0 ./build_mobile.sh ios
cd ..
shasum -a 256 openmls-uniffi/out/swift/openmls_uniffi.swift
find openmls-uniffi/out/ios/OpenMlsUniFFI.xcframework -type f -print0 \
  | sort -z \
  | xargs -0 shasum -a 256
```

Handoff như một atomic set:

- generated `openmls_uniffi.swift`;
- generated FFI header/module map;
- complete `OpenMlsUniFFI.xcframework`, gồm device và simulator slices;
- checksums và release metadata cùng source/lock/toolchain;
- exact UniFFI integration test results.

Script chỉ ghi output dưới `openmls-uniffi/out`; nó **không** cập nhật
`ios/ermis-ios-sdk/Vendor/open-mls-ios`. iOS owner phải package/copy toàn bộ
set và chạy linked-artifact tests trong repo iOS.

## 5. Performance, compatibility và rollback

Group create/load theo explicit GroupId giữ storage lookup `O(1)` theo key;
serialized tree/GI và provider memory vẫn `O(M)` theo members. Welcome
generation/fan-out là `O(K)`; repeated full-tree joins có thể tạo
`O(K²)` tổng traffic. Historical processing không được clone/persist receiver
state trước validation thành công. Ghi serialized bytes, peak RSS/copies,
provider restart time và artifact sizes cho 100 members/200 devices.

Artifact mới là additive cho generation 0, nhưng một channel đã activate
generation mới không thể dùng lại artifact thiếu explicit GroupId/generation.
Rollback trước adoption bằng cách không promote artifact; sau activation phải
giữ generation-capable artifacts và sửa forward. Không xóa provider/archive
state để “rollback”.

## 6. Handoff record

| Mục | Evidence bắt buộc |
|---|---|
| Source | Commit, diff digest, Cargo.lock/toolchain hashes |
| Core/bindings | Exact commands, pass/fail/ignored counts |
| WASM | Four-file set, runtime exports/tests, SHA-256/size |
| UniFFI | Swift/header/XCFramework slices, tests, SHA-256/size |
| Compatibility | Generation 0, new GroupId, restart, historical-time failures |
| Consumer status | Chỉ ghi “delivered”; adoption do Web/iOS repo chứng minh |

<details>
<summary>Change log</summary>

- `2026-09-15`: Added repository-owned MLS artifact upgrade/handoff steps.
  - Reason: artifact generation and consumer adoption need separate ownership and evidence.
  - Integrator action: OpenMLS owner produces provenance-bound WASM/UniFFI sets; consumers verify their linked copies.
  - Compatibility/default: documentation only; no artifact was regenerated.

</details>
