# OpenMLS Flutter bindings

One-package OpenMLS bindings for Flutter, generated with
`flutter_rust_bridge` 2.13.0 and built through Flutter/Dart Native Assets.

The public Dart API and the FRB adapter live in this package. MLS, SQLite, and
serialization behavior remains binding-neutral in the sibling
`openmls-bindings-core` crate. This package does not depend on or call
`openmls-uniffi`.

## Consume from Flutter

Use the package through the full OpenMLS repository so Cargo can resolve the
binding-neutral core and the local OpenMLS crates.

Path dependency:

```yaml
dependencies:
  openmls_flutter:
    path: ../openmls/openmls-flutter-bindings
```

Git dependency:

```yaml
dependencies:
  openmls_flutter:
    git:
      url: <openmls-repository-url>
      ref: <pinned-commit-or-tag>
      path: openmls-flutter-bindings
```

Initialize the bridge once before calling the generated API:

```dart
import 'package:openmls_flutter/openmls_flutter.dart';

Future<void> main() async {
  await OpenMlsFlutter.init();
  await initLogger();

  final channelId = await hashChannelId(
    projectId: 'project-id',
    userIds: ['alice', 'bob'],
  );
  print(channelId);
}
```

The consumer declares one Dart dependency. During the app build,
`hook/build.dart` compiles the Rust crate and registers the selected native
asset automatically:

- Android: the `.so` for the selected device ABI.
- iOS: the native library for the selected device or simulator architecture.

There is no shared Android/iOS binary. Native Assets hides the platform builds
behind one package boundary.

The Cargo package and `[lib]` names are both `openmls_flutter`. This alignment
is required by `native_toolchain_rust`, which derives the produced native asset
filename from `package.name`.

## Requirements

- Flutter 3.38 or newer, with Native Assets/build-hook support.
- Dart SDK 3.10 or newer.
- Rustup. The package pins Rust and the supported mobile targets in
  `rust-toolchain.toml`.
- Android builds: Android SDK and NDK.
- iOS builds: macOS and Xcode command-line tools.
- Binding regeneration: `flutter_rust_bridge_codegen` exactly 2.13.0.

`swiftformat` and `ktlint` are not package prerequisites. This bridge generates
Rust and Dart, not Swift or Kotlin source; those formatters remain relevant only
to the separate UniFFI Swift/Kotlin generation pipeline.

Install the pinned generator when changing the Rust API:

```bash
cargo install flutter_rust_bridge_codegen --version 2.13.0 --locked
```

## Layout

```text
openmls-flutter-bindings/
├── pubspec.yaml                Flutter/Dart package manifest
├── hook/build.dart             Native Assets Rust build hook
├── lib/                        Public and generated Dart API
├── src/api/                    Thin flutter_rust_bridge adapter
├── src/frb_generated.rs        Generated Rust bridge glue
├── rust-toolchain.toml         Reproducible Rust/mobile target pin
└── build_flutter.sh            Manual release-artifact verification
```

The package intentionally has `publish_to: none`. Publishing only this folder
to pub.dev would break its sibling Cargo path dependencies. Use a path or Git
dependency from the full repository. Publishing independently requires a
separate release decision to publish or vendor the Rust dependency graph.

## Development and verification

Generate bindings and run checks:

```bash
./build_flutter.sh codegen
./build_flutter.sh verify
```

`verify` runs code generation, Dart analysis, the binding-neutral core and
Flutter adapter tests, strict Clippy, a host release build, and an exported
symbol audit.

The normal Flutter application build invokes Native Assets automatically. The
manual commands below remain release/CI verification tools; consumers do not
copy their output into their application:

```bash
./build_flutter.sh ios
./build_flutter.sh android
./build_flutter.sh all
```

Manual artifact output:

```text
out/ios/OpenMlsFlutter.xcframework
out/android/jniLibs/<abi>/libopenmls_flutter.so
```

The Android verification build also checks every generated library's ELF load
segment alignment and exported-symbol allowlist. The manual XCFramework has an
`ios-arm64` device slice plus an `ios-arm64_x86_64-simulator` universal slice.

## Flutter consumer smoke test

The smoke test creates a temporary Flutter application with only one path
dependency on this package. It calls `OpenMlsFlutter.init()` without an
`ExternalLibrary` override, then calls Rust through `hashChannelId`.

```bash
# macOS desktop runtime
./tool/flutter_consumer_smoke.sh host

# Native Assets packaging builds
./tool/flutter_consumer_smoke.sh android
./tool/flutter_consumer_smoke.sh ios

# Actual Android/iOS emulator, simulator, or physical device runtime
flutter devices
./tool/flutter_consumer_smoke.sh device <device-id>
```

Flutter runtime success, Android APK success, and iOS simulator/device success
are separate release gates. A successful Rust cross-compile or XCFramework
build does not close them.

## Native linking policy

Use the package's default FRB loader and the dynamically bundled Native Asset.
Do not replace it with `ExternalLibrary.process()` when an application contains
multiple flutter_rust_bridge packages. FRB 2.13.0 still exports a small known
set of shared runtime symbols; package-specific opaque symbols are required to
use the `frbgen_openmls_flutter_` prefix and are checked by the build script.

References:

- [Flutter FFI packages and Native Assets](https://docs.flutter.dev/packages-and-plugins/developing-packages#developing-ffi-packages)
- [flutter_rust_bridge Native Assets backend](https://cjycode.com/flutter_rust_bridge/manual/integrate/native-assets)
