# OpenMLS UniFFI — Hướng dẫn Tích hợp & Test

## 1. Build thư viện

```bash
cd openmls-uniffi

# Build iOS (device + simulator + XCFramework)
./build_mobile.sh ios

# Build Android (cần export ANDROID_NDK_HOME trước)
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
./build_mobile.sh android

# Chỉ generate bindings (Swift/Kotlin)
./build_mobile.sh bindings
```

Kết quả nằm trong `openmls-uniffi/out/`:
```
out/
├── swift/
│   ├── openmls_uniffi.swift          ← Import vào Swift project
│   ├── openmls_uniffiFFI.h           ← C header
│   └── openmls_uniffiFFI.modulemap   ← Module map
├── kotlin/
│   └── uniffi/openmls_uniffi/openmls_uniffi.kt  ← Import vào Android project
└── ios/
    └── OpenMlsUniFFI.xcframework    ← Drag vào Xcode
```

---

## 2. Tích hợp iOS (Swift)

### Bước 1: Thêm XCFramework
1. Mở Xcode project
2. Kéo `out/ios/OpenMlsUniFFI.xcframework` vào **Frameworks, Libraries, and Embedded Content**
3. Chọn **"Embed & Sign"**

### Bước 2: Thêm Swift binding
- Copy `out/swift/openmls_uniffi.swift` vào project

### Bước 3: Sử dụng trong Swift

```swift
import Foundation

// Tạo provider (1 instance cho mỗi user)
let provider = Provider()

// Tạo identity
let identity = try Identity(provider: provider, userId: "user_abc123")
print("User ID: \(identity.userId())")

// Serialize identity để lưu trữ
let identityBytes = try identity.toBytes()
// Restore lại sau
let restored = try Identity.fromBytes(provider: provider, data: identityBytes)

// Tạo group (E2EE channel)
let group = try Group.createWithCid(
    provider: provider,
    founder: identity,
    cid: "messaging:channel_xyz"
)
print("Channel: \(try group.cid())")
print("Epoch: \(group.epoch())")

// Tạo key package để gửi cho người khác join
let keyPackage = identity.keyPackage(provider: provider)
let kpBytes = keyPackage.toBytes()
// Gửi kpBytes qua server...
```

### Bước 4: Messaging

```swift
// === ALICE GỬI TIN NHẮN ===
let plaintext = "Hello, Bob!".data(using: .utf8)!
let ciphertext = try group.createMessage(
    provider: aliceProvider,
    sender: alice,
    plaintext: Array(plaintext)
)
// Gửi ciphertext qua server...

// === BOB NHẬN TIN NHẮN ===
let processed = try bobGroup.processMessage(
    provider: bobProvider,
    msg: ciphertext
)
if processed.messageType == .applicationMessage,
   let content = processed.content {
    let text = String(data: Data(content), encoding: .utf8)!
    print("Received: \(text)")  // "Hello, Bob!"
}

// === GỬI VỚI AAD (metadata) ===
let aad = "{\"sender\":\"alice\"}".data(using: .utf8)!
let ct = try group.createMessageWithAad(
    provider: aliceProvider,
    sender: alice,
    plaintext: Array(plaintext),
    aad: Array(aad)
)
```

### Bước 5: Quản lý thành viên

```swift
// Thêm member
let bobKp = bob.keyPackage(provider: bobProvider)
let addResult = try group.addMembers(
    provider: aliceProvider,
    sender: alice,
    newMembers: [bobKp]
)
try group.mergePendingCommit(provider: aliceProvider)
// Gửi addResult.welcome cho Bob qua server
// Gửi addResult.commit cho các member hiện tại

// Bob join bằng welcome
let bobGroup = try Group.joinWithWelcome(
    provider: bobProvider,
    welcome: addResult.welcome!,
    ratchetTree: nil  // Embedded trong welcome
)

// Xóa member
let bobInfo = group.memberByUserId(userId: "bob")!
let removeResult = try group.removeMembers(
    provider: aliceProvider,
    sender: alice,
    memberIndices: [bobInfo.index]
)
try group.mergePendingCommit(provider: aliceProvider)

// Key rotation
let updateResult = try group.selfUpdate(
    provider: aliceProvider,
    sender: alice
)
try group.mergePendingCommit(provider: aliceProvider)
```

---

## 3. Tích hợp Android (Kotlin)

### Bước 1: Thêm JNI libraries
Copy thư mục `out/android/jniLibs/` vào `app/src/main/`:
```
app/src/main/jniLibs/
├── arm64-v8a/libopenmls_uniffi.so
├── armeabi-v7a/libopenmls_uniffi.so
└── x86_64/libopenmls_uniffi.so
```

### Bước 2: Thêm Kotlin binding
Copy `out/kotlin/uniffi/openmls_uniffi/openmls_uniffi.kt` vào source tree.

### Bước 3: Thêm dependency trong `build.gradle`
```groovy
android {
    // ...
    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}

dependencies {
    implementation "net.java.dev.jna:jna:5.13.0@aar"
}
```

### Bước 4: Sử dụng trong Kotlin

```kotlin
import uniffi.openmls_uniffi.*

// Tạo provider & identity
val provider = Provider()
val identity = Identity(provider, "user_abc123")
println("User ID: ${identity.userId()}")

// Tạo group
val group = Group.createWithCid(provider, identity, "messaging:channel_xyz")
println("Channel: ${group.cid()}")

// Gửi tin nhắn
val plaintext = "Hello!".toByteArray()
val ciphertext = group.createMessage(provider, identity, plaintext.toList())

// Nhận tin nhắn
val processed = bobGroup.processMessage(bobProvider, ciphertext)
if (processed.messageType == MessageType.APPLICATION_MESSAGE) {
    val text = String(processed.content!!.toByteArray())
    println("Received: $text")
}
```

---

## 4. Test

### Rust Tests (chạy trên host)
```bash
# Chạy toàn bộ test suite
cargo test -p openmls-uniffi

# Chạy test cụ thể
cargo test -p openmls-uniffi test_encrypted_messaging

# Chạy với output
cargo test -p openmls-uniffi -- --nocapture
```

**14 test cases đã bao gồm:**

| Test | Kiểm tra |
|---|---|
| `test_provider_creation` | Tạo Provider |
| `test_identity_creation` | Tạo Identity với user_id |
| `test_identity_serialization` | Serialize/deserialize Identity |
| `test_key_package_serialization` | Serialize/deserialize KeyPackage |
| `test_cid_roundtrip` | Tạo group với CID và đọc lại |
| `test_group_creation_and_join` | Tạo group, thêm member, join, verify shared key |
| `test_encrypted_messaging` | Mã hóa/giải mã tin nhắn |
| `test_encrypted_messaging_with_aad` | Mã hóa với AAD metadata |
| `test_proposal_commit_separation` | Proposal → Commit workflow |
| `test_member_info` | Truy vấn thông tin thành viên |
| `test_group_state` | Kiểm tra trạng thái group |
| `test_ratchet_tree_serialization` | Serialize/deserialize RatchetTree |
| `test_self_update` | Key rotation |
| `test_remove_member` | Xóa thành viên khỏi group |

### iOS Test (trong Xcode)
Tạo unit test target trong Xcode và gọi các API tương tự:
```swift
import XCTest

class OpenMlsTests: XCTestCase {
    func testCreateIdentity() throws {
        let provider = Provider()
        let identity = try Identity(provider: provider, userId: "test")
        XCTAssertEqual(identity.userId(), "test")
    }
    
    func testEncryptedMessaging() throws {
        let aliceProvider = Provider()
        let bobProvider = Provider()
        let alice = try Identity(provider: aliceProvider, userId: "alice")
        let bob = try Identity(provider: bobProvider, userId: "bob")
        
        let group = try Group.createWithCid(
            provider: aliceProvider, founder: alice, cid: "test:channel"
        )
        let bobKp = bob.keyPackage(provider: bobProvider)
        let addResult = try group.addMembers(
            provider: aliceProvider, sender: alice, newMembers: [bobKp]
        )
        try group.mergePendingCommit(provider: aliceProvider)
        
        let bobGroup = try Group.joinWithWelcome(
            provider: bobProvider,
            welcome: addResult.welcome!,
            ratchetTree: group.exportRatchetTree()
        )
        
        let ct = try group.createMessage(
            provider: aliceProvider, sender: alice,
            plaintext: Array("Hello!".utf8)
        )
        let msg = try bobGroup.processMessage(provider: bobProvider, msg: ct)
        XCTAssertEqual(String(data: Data(msg.content!), encoding: .utf8), "Hello!")
    }
}
```

---

## 5. Troubleshooting

| Vấn đề | Giải pháp |
|---|---|
| `Library not found` (iOS) | Kiểm tra XCFramework đã được Embed & Sign |
| `UnsatisfiedLinkError` (Android) | Kiểm tra jniLibs đúng thư mục ABI |
| `Undefined symbol _uniffi_*` | Rebuild: `./build_mobile.sh ios` hoặc `android` |
| iOS Simulator crash | Đảm bảo dùng `aarch64-apple-ios-sim` build cho Apple Silicon |
