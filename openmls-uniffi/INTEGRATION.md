# OpenMLS UniFFI — Integration & Testing Guide

## 1. Build the Library

```bash
cd openmls-uniffi

# Build iOS (device + simulator + XCFramework)
./build_mobile.sh ios

# Build Android (export ANDROID_NDK_HOME first)
export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<version>
./build_mobile.sh android

# Generate bindings only (Swift/Kotlin)
./build_mobile.sh bindings
```

Output is located in `openmls-uniffi/out/`:
```
out/
├── swift/
│   ├── openmls_uniffi.swift          ← Import into Swift project
│   ├── openmls_uniffiFFI.h           ← C header
│   └── openmls_uniffiFFI.modulemap   ← Module map
├── kotlin/
│   └── uniffi/openmls_uniffi/openmls_uniffi.kt  ← Import into Android project
└── ios/
    └── OpenMlsUniFFI.xcframework    ← Drag into Xcode
```

---

## 2. iOS Integration (Swift)

### Step 1: Add XCFramework
1. Open your Xcode project
2. Drag `out/ios/OpenMlsUniFFI.xcframework` into **Frameworks, Libraries, and Embedded Content**
3. Select **"Embed & Sign"**

### Step 2: Add the Swift binding
- Copy `out/swift/openmls_uniffi.swift` into your project

### Step 3: Basic usage in Swift

```swift
import Foundation

// === PROVIDER ===
// Option 1: In-memory (state lost when app closes — for testing only)
let provider = Provider()

// Option 2: Persistent SQLite (RECOMMENDED for production)
let documentsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
let dbPath = documentsDir.appendingPathComponent("openmls.db").path
let provider = try Provider.newWithPath(dbPath: dbPath)
// → MLS state (groups, keys, epochs) automatically saved to openmls.db
// → State persists across app restarts

// Create identity
let identity = try Identity(provider: provider, userId: "user_abc123")
print("User ID: \(identity.userId())")

// Serialize identity for storage
let identityBytes = try identity.toBytes()
// Restore later
let restored = try Identity.fromBytes(provider: provider, data: identityBytes)

// Create group (E2EE channel)
let group = try Group.createWithCid(
    provider: provider,
    founder: identity,
    cid: "messaging:channel_xyz"
)
print("Channel: \(try group.cid())")
print("Epoch: \(group.epoch())")

// Create key package to send to others for joining
let keyPackage = identity.keyPackage(provider: provider)
let kpBytes = keyPackage.toBytes()
// Send kpBytes via server...
```

### Step 4: Messaging

```swift
// === ALICE SENDS A MESSAGE ===
let plaintext = "Hello, Bob!".data(using: .utf8)!
let ciphertext = try group.createMessage(
    provider: aliceProvider,
    sender: alice,
    plaintext: Array(plaintext)
)
// Send ciphertext via server...

// === BOB RECEIVES THE MESSAGE ===
let processed = try bobGroup.processMessage(
    provider: bobProvider,
    msg: ciphertext
)
if processed.messageType == .applicationMessage,
   let content = processed.content {
    let text = String(data: Data(content), encoding: .utf8)!
    print("Received: \(text)")  // "Hello, Bob!"
}

// === SEND WITH AAD (metadata) ===
let aad = "{\"sender\":\"alice\"}".data(using: .utf8)!
let ct = try group.createMessageWithAad(
    provider: aliceProvider,
    sender: alice,
    plaintext: Array(plaintext),
    aad: Array(aad)
)
```

### Step 5: Member Management

```swift
// Add member
let bobKp = bob.keyPackage(provider: bobProvider)
let addResult = try group.addMembers(
    provider: aliceProvider,
    sender: alice,
    newMembers: [bobKp]
)
try group.mergePendingCommit(provider: aliceProvider)
// Send addResult.welcome to Bob via server
// Send addResult.commit to existing members

// Bob joins with welcome
let bobGroup = try Group.joinWithWelcome(
    provider: bobProvider,
    welcome: addResult.welcome!,
    ratchetTree: nil  // Embedded in welcome
)

// Remove member
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

## 3. Android Integration (Kotlin)

### Step 1: Add JNI libraries
Copy the `out/android/jniLibs/` directory into `app/src/main/`:
```
app/src/main/jniLibs/
├── arm64-v8a/libopenmls_uniffi.so
├── armeabi-v7a/libopenmls_uniffi.so
└── x86_64/libopenmls_uniffi.so
```

### Step 2: Add the Kotlin binding
Copy `out/kotlin/uniffi/openmls_uniffi/openmls_uniffi.kt` into your source tree.

### Step 3: Add dependency in `build.gradle`
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

### Step 4: Basic usage in Kotlin

```kotlin
import uniffi.openmls_uniffi.*

// === PROVIDER ===
// Option 1: In-memory (for testing only)
val provider = Provider()

// Option 2: Persistent SQLite (RECOMMENDED for production)
val dbPath = "${context.filesDir}/openmls.db"
val provider = Provider.newWithPath(dbPath)
// → MLS state automatically persisted to SQLite file

// Create identity
val identity = Identity(provider, "user_abc123")
println("User ID: ${identity.userId()}")

// Create group
val group = Group.createWithCid(provider, identity, "messaging:channel_xyz")
println("Channel: ${group.cid()}")

// Send message
val plaintext = "Hello!".toByteArray()
val ciphertext = group.createMessage(provider, identity, plaintext.toList())

// Receive message
val processed = bobGroup.processMessage(bobProvider, ciphertext)
if (processed.messageType == MessageType.APPLICATION_MESSAGE) {
    val text = String(processed.content!!.toByteArray())
    println("Received: $text")
}
```

---

## 4. Testing

### Rust Tests (run on host)
```bash
# Run full test suite
cargo test -p openmls-uniffi

# Run a specific test
cargo test -p openmls-uniffi test_encrypted_messaging

# Run with output
cargo test -p openmls-uniffi -- --nocapture
```

**19 test cases included:**

| Test | Verifies |
|---|---|
| `test_provider_creation` | Provider creation |
| `test_identity_creation` | Identity creation with user_id |
| `test_identity_serialization` | Serialize/deserialize Identity |
| `test_key_package_serialization` | Serialize/deserialize KeyPackage |
| `test_cid_roundtrip` | Create group with CID and read back |
| `test_group_creation_and_join` | Create group, add member, join, verify shared key |
| `test_encrypted_messaging` | Encrypt/decrypt messages |
| `test_encrypted_messaging_with_aad` | Encrypt with AAD metadata |
| `test_proposal_commit_separation` | Proposal → Commit workflow |
| `test_member_info` | Query member information |
| `test_group_state` | Check group state |
| `test_ratchet_tree_serialization` | Serialize/deserialize RatchetTree |
| `test_self_update` | Key rotation |
| `test_remove_member` | Remove member from group |
| `test_persistent_provider_creation` | Create Provider with SQLite file path |
| `test_persistent_provider_full_flow` | Full flow (create, join, message) with persistent storage |

### iOS Tests (in Xcode)
Create a unit test target in Xcode and call the APIs:
```swift
import XCTest

class OpenMlsTests: XCTestCase {
    func testCreateIdentityWithPersistence() throws {
        let tmpDir = NSTemporaryDirectory()
        let dbPath = "\(tmpDir)/openmls_test.db"
        let provider = try Provider.newWithPath(dbPath: dbPath)
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

## 5. Persistent Storage (SQLite)

### Architecture

```
┌─────────────────────────────────┐
│         Mobile App              │
├────────────────┬────────────────┤
│   App SQLite   │  OpenMLS SQLite│
│   (app.db)     │  (openmls.db)  │
│                │                │
│   messages     │  epoch secrets │
│   users        │  ratchet tree  │
│   channels     │  key packages  │
│   settings     │  signature keys│
└────────────────┴────────────────┘
```

- **Separate** app DB and OpenMLS DB — do not share
- OpenMLS manages its own schema and migrations (`openmls_sqlite_storage_migrations`)
- DB file should be placed in **app-internal storage** (not externally accessible)

### Provider API

| Method | Description |
|---|---|
| `Provider()` | In-memory provider (for testing) |
| `Provider.newWithPath(dbPath)` | Persistent SQLite provider **(production)** |
| **Group Management** | |
| `storedGroupIds()` | List all stored group CIDs |
| `groupCount()` | Count stored groups |
| `deleteGroup(cid)` | Delete all data for one group |
| `deleteAllGroups()` | Delete all group data (logout/reset) |
| **Identity Persistence** | |
| `storeIdentity(userId, bytes)` | Store identity in DB (replaces previous) |
| `loadIdentity()` | Load identity bytes (nil if none) |
| `deleteIdentity()` | Delete stored identity (logout) |

### Group API

| Method | Description |
|---|---|
| `Group.createWithCid(provider, founder, cid)` | Create a new group |
| `Group.joinWithWelcome(provider, welcome, ratchetTree)` | Join via welcome message |
| `Group.loadFromStorage(provider, cid)` | **Load existing group from DB** |

---

### 5.1 iOS Guide (Swift)

#### Step 1: Initialize Provider and restore state

```swift
import Foundation

class MlsManager {
    static let shared = MlsManager()
    
    private(set) var provider: Provider!
    private(set) var identity: Identity?
    private(set) var groups: [String: Group] = [:]
    
    /// Call once on app launch
    func initialize() throws {
        let documentsDir = FileManager.default.urls(
            for: .documentDirectory, in: .userDomainMask
        ).first!
        let dbPath = documentsDir.appendingPathComponent("openmls.db").path
        provider = try Provider.newWithPath(dbPath: dbPath)
        
        // Auto-restore identity from DB
        if let bytes = try provider.loadIdentity() {
            identity = try Identity.fromBytes(provider: provider, data: bytes)
        }
        
        // Auto-restore groups from DB
        for cid in try provider.storedGroupIds() {
            groups[cid] = try Group.loadFromStorage(provider: provider, cid: cid)
        }
    }
    
    /// First login: create identity and store in DB
    func createIdentity(userId: String) throws {
        let id = try Identity(provider: provider, userId: userId)
        let bytes = try id.toBytes()
        try provider.storeIdentity(userId: userId, identityBytes: bytes)
        identity = id
    }
    
    /// Logout: clear all MLS data
    func logout() throws {
        try provider.deleteAllGroups()
        try provider.deleteIdentity()
        groups.removeAll()
        identity = nil
    }
}
```

#### Step 2: Use in your app

```swift
// === AppDelegate / @main ===
func application(_ application: UIApplication,
                 didFinishLaunchingWithOptions ...) -> Bool {
    do {
        try MlsManager.shared.initialize()
        if MlsManager.shared.identity == nil {
            try MlsManager.shared.createIdentity(userId: currentUserId)
        }
        print("Groups restored: \(MlsManager.shared.groups.count)")
    } catch {
        print("MLS init failed: \(error)")
    }
    return true
}

// === ViewController / ViewModel ===
let mgr = MlsManager.shared

// Load existing groups from DB (after app restart)
let storedIds = try mgr.provider.storedGroupIds()
for cid in storedIds {
    let group = try Group.loadFromStorage(provider: mgr.provider, cid: cid)
    print("Restored group: \(cid), epoch: \(group.epoch())")
}

// Create a NEW group (first time only)
let group = try Group.createWithCid(
    provider: mgr.provider, founder: mgr.identity!, cid: channelId
)

// Send / receive messages
let ciphertext = try group.createMessage(
    provider: mgr.provider, sender: mgr.identity!, plaintext: Array(text.utf8)
)
let processed = try group.processMessage(provider: mgr.provider, msg: incomingBytes)

// Leave group: clean up DB
try mgr.provider.deleteGroup(cid: channelId)
```

#### App Lifecycle Flow (iOS)

```
App launch ──→ Provider.newWithPath("openmls.db")
            │
            ├──→ provider.loadIdentity() → restore from DB (no Keychain needed!)
            │
            ├──→ provider.storedGroupIds() → ["ch:abc", "ch:xyz"]
            │    └── Group.loadFromStorage(provider, cid) for each
            │
            └──→ Ready: messaging on restored groups
                 └── All state auto-persists to DB
```

---

### 5.2 Android Guide (Kotlin)

#### Step 1: Initialize Provider and restore state

```kotlin
import uniffi.openmls_uniffi.*

class MlsManager private constructor() {
    
    companion object {
        @Volatile private var instance: MlsManager? = null
        fun getInstance(): MlsManager =
            instance ?: synchronized(this) {
                instance ?: MlsManager().also { instance = it }
            }
    }
    
    lateinit var provider: Provider
        private set
    var identity: Identity? = null
        private set
    val groups = mutableMapOf<String, Group>()
    
    /// Call once in Application.onCreate()
    fun initialize(context: Context) {
        val dbPath = "${context.filesDir}/openmls.db"
        provider = Provider.newWithPath(dbPath)
        
        // Auto-restore identity from DB
        provider.loadIdentity()?.let { bytes ->
            identity = Identity.fromBytes(provider, bytes)
        }
        
        // Auto-restore groups from DB
        for (cid in provider.storedGroupIds()) {
            groups[cid] = Group.loadFromStorage(provider, cid)
        }
    }
    
    /// First login: create identity and store in DB
    fun createIdentity(userId: String) {
        val id = Identity(provider, userId)
        val bytes = id.toBytes()
        provider.storeIdentity(userId, bytes)
        identity = id
    }
    
    /// Logout: clear all MLS data
    fun logout() {
        provider.deleteAllGroups()
        provider.deleteIdentity()
        groups.clear()
        identity = null
    }
}
```

#### Step 2: Use in your app

```kotlin
// === In Application class ===
class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val mgr = MlsManager.getInstance()
        mgr.initialize(this)
        if (mgr.identity == null) {
            mgr.createIdentity(currentUserId)
        }
        println("Groups restored: ${mgr.groups.size}")
    }
}

// === In Activity / ViewModel ===
val mgr = MlsManager.getInstance()

// Create a NEW group
val group = Group.createWithCid(mgr.provider, mgr.identity!!, channelId)

// Send / receive messages
val ciphertext = group.createMessage(
    mgr.provider, mgr.identity!!, text.toByteArray().toList()
)
val processed = group.processMessage(mgr.provider, incomingBytes)

// Leave group: clean up DB
mgr.provider.deleteGroup(channelId)
```

#### App Lifecycle Flow (Android)

```
Application.onCreate() ──→ Provider.newWithPath("openmls.db")
                        │
                        ├──→ provider.loadIdentity() → restore from DB
                        │
                        ├──→ provider.storedGroupIds() → ["ch:abc", "ch:xyz"]
                        │    └── Group.loadFromStorage(provider, cid) for each
                        │
                        └──→ Ready: messaging on restored groups
                             └── All state auto-persists to DB
```

---

### Important Notes

| Item | Details |
|---|---|
| **Provider** | Create **once** on app launch, keep for entire app lifecycle |
| **Identity** | Stored in DB via `storeIdentity()` — no Keychain/SharedPrefs needed |
| **DB path** | iOS: `documentDirectory`, Android: `context.filesDir` |
| **Multi-user** | Each user should have a separate DB: `openmls_{userId}.db` |
| **Thread safety** | Provider wraps a Mutex, safe to call from multiple threads |
| **No DB management needed** | OpenMLS auto-creates tables, reads/writes, and runs migrations |
| **Logout** | Call `deleteAllGroups()` + `deleteIdentity()` to clear all data |

---

## 6. Troubleshooting

| Issue | Solution |
|---|---|
| `Library not found` (iOS) | Ensure XCFramework is set to Embed & Sign |
| `UnsatisfiedLinkError` (Android) | Verify jniLibs are in the correct ABI directory |
| `Undefined symbol _uniffi_*` | Rebuild: `./build_mobile.sh ios` or `android` |
| iOS Simulator crash | Make sure to use `aarch64-apple-ios-sim` build for Apple Silicon |
| `StorageError` when creating Provider | Check write permissions for `db_path`; parent directory must exist |
| `StorageError` when restoring Identity | Ensure you use the same Provider instance (or same db_path) |
