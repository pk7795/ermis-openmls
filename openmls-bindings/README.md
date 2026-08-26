# OpenMLS bindings core

Binding-neutral mobile MLS implementation shared by the UniFFI and Flutter
adapters.

Dependency direction:

```text
openmls-uniffi ───────────┐
                         ├──> openmls-bindings-core ──> OpenMLS crates
openmls-flutter-bindings ─┘
```

This crate owns MLS group operations, identities and key packages, SQLite
persistence, stable internal error categories, and wire-neutral DTOs. It must
not depend on `uniffi`, `flutter_rust_bridge`, Swift, Kotlin, Dart, CocoaPods, or
Gradle.

The adapter crates own only their FFI annotations, ownership conventions,
generated code, public DTO conversion, and error mapping.

Run its contract tests with:

```bash
cargo test -p openmls-bindings-core --all-targets
```

