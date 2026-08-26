#!/bin/bash
set -euo pipefail

# ============================================================================
# OpenMLS Flutter Bindings Build Script
#
# Uses flutter_rust_bridge (FRB v2) to generate Dart bindings and compile
# native libraries for iOS and Android.
#
# Usage: ./build_flutter.sh [codegen|verify|ios|android|all]
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
DART_PACKAGE_DIR="$SCRIPT_DIR"
FRB_VERSION="2.13.0"

# Keep build/codegen deterministic and avoid telemetry writes in CI/sandboxes.
export CI="${CI:-true}"
export DART_SUPPRESS_ANALYTICS="${DART_SUPPRESS_ANALYTICS:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[BUILD]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# iOS targets
IOS_TARGETS=(
    "aarch64-apple-ios"          # Physical iPhone/iPad
    "aarch64-apple-ios-sim"      # Simulator on Apple Silicon
    "x86_64-apple-ios"           # Simulator on Intel macOS/CI
)
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-15.0}"

# Android targets (requires NDK)
ANDROID_TARGETS=(
    "aarch64-linux-android"      # ARM64 (most modern devices)
    "armv7-linux-androideabi"    # ARMv7
    "x86_64-linux-android"      # x86_64 emulator
)

install_targets() {
    log "Installing Rust compilation targets..."
    for target in "$@"; do
        if rustup target list --installed | grep -q "$target"; then
            log "  ✓ $target (already installed)"
        else
            log "  Installing $target..."
            rustup target add "$target"
        fi
    done
}

resolve_android_ndk() {
    local configured_ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

    if [ -z "$configured_ndk" ]; then
        local android_sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
        if [ -z "$android_sdk_root" ] && [ "$(uname -s)" = "Darwin" ]; then
            android_sdk_root="$HOME/Library/Android/sdk"
        fi

        local ndk_parent="${android_sdk_root:+$android_sdk_root/ndk}"
        if [ -n "$ndk_parent" ] && [ -d "$ndk_parent" ]; then
            configured_ndk=$(find "$ndk_parent" -mindepth 1 -maxdepth 1 -type d -print \
                | sort -V \
                | tail -n 1)
        fi

        if [ -n "$configured_ndk" ]; then
            warn "ANDROID_NDK_HOME is not set; using detected NDK: $configured_ndk"
        fi
    fi

    if [ -z "$configured_ndk" ] || [ ! -f "$configured_ndk/source.properties" ]; then
        error "Android NDK not found."
        error "Set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT), or install an NDK under the Android SDK's ndk/ directory."
        exit 1
    fi

    RESOLVED_ANDROID_NDK="$configured_ndk"
}

check_prerequisites() {
    log "Checking prerequisites..."

    if ! command -v rustup &> /dev/null; then
        error "rustup is not installed. Please install it from https://rustup.rs/"
        exit 1
    fi

    if ! command -v flutter_rust_bridge_codegen &> /dev/null; then
        error "flutter_rust_bridge_codegen is not installed."
        error "Install the pinned tool: cargo install flutter_rust_bridge_codegen --version $FRB_VERSION --locked"
        exit 1
    fi

    local codegen_version
    codegen_version=$(flutter_rust_bridge_codegen --version 2>/dev/null | awk '{print $2}')
    if [ "$codegen_version" != "$FRB_VERSION" ]; then
        error "flutter_rust_bridge_codegen $FRB_VERSION is required (found: ${codegen_version:-unknown})."
        exit 1
    fi

    if ! command -v dart &> /dev/null; then
        error "dart is not available on PATH. Install Flutter/Dart before running codegen."
        exit 1
    fi

    if [ ! -f "$DART_PACKAGE_DIR/pubspec.yaml" ]; then
        error "Missing Dart package manifest: $DART_PACKAGE_DIR/pubspec.yaml"
        exit 1
    fi

    log "  ✓ flutter_rust_bridge_codegen version: $codegen_version"
    log "  ✓ Dart package: $DART_PACKAGE_DIR"
    log "  ✓ Prerequisites OK"
}

run_codegen() {
    log "========================================="
    log "Running flutter_rust_bridge codegen..."
    log "========================================="

    cd "$SCRIPT_DIR"
    flutter_rust_bridge_codegen generate --config-file flutter_rust_bridge.yaml

    log "✓ Codegen complete"
    log "  Rust glue:  src/frb_generated.rs"
    log "  Dart output: lib/src/generated/"
}

verify_package() {
    log "========================================="
    log "Verifying package contracts..."
    log "========================================="

    cd "$SCRIPT_DIR"
    dart pub get
    dart analyze

    cd "$PROJECT_ROOT"
    cargo test -p openmls-bindings-core -p openmls_flutter --all-targets
    cargo clippy -p openmls-bindings-core -p openmls_flutter --all-targets --no-deps -- -D warnings
    cargo build -p openmls_flutter --release

    local host_library
    case "$(uname -s)" in
        Darwin) host_library="$PROJECT_ROOT/target/release/libopenmls_flutter.dylib" ;;
        Linux) host_library="$PROJECT_ROOT/target/release/libopenmls_flutter.so" ;;
        *) error "Host symbol audit is not supported on $(uname -s)"; exit 1 ;;
    esac

    "$SCRIPT_DIR/tool/audit_dynamic_symbols.sh" "$host_library"
    log "✓ Package verification complete"
}

build_ios() {
    log "========================================="
    log "Building for iOS..."
    log "========================================="

    if [ "$(uname -s)" != "Darwin" ] || ! command -v xcodebuild &> /dev/null; then
        error "The iOS build requires macOS with Xcode command-line tools."
        exit 1
    fi

    install_targets "${IOS_TARGETS[@]}"

    mkdir -p "$OUT_DIR/ios"

    for target in "${IOS_TARGETS[@]}"; do
        log "Building for $target (minimum iOS $IOS_DEPLOYMENT_TARGET)..."
        IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" \
            cargo build -p openmls_flutter --release --target "$target"
        cp "$PROJECT_ROOT/target/$target/release/libopenmls_flutter.a" "$OUT_DIR/ios/libopenmls_flutter-${target}.a"
        log "  ✓ $target built"
    done

    # xcodebuild rejects two libraries for the same simulator platform. Merge
    # both simulator architectures into one universal static library first.
    local simulator_library="$OUT_DIR/ios/libopenmls_flutter-ios-simulator.a"
    log "Creating universal iOS simulator library..."
    xcrun lipo -create \
        "$OUT_DIR/ios/libopenmls_flutter-aarch64-apple-ios-sim.a" \
        "$OUT_DIR/ios/libopenmls_flutter-x86_64-apple-ios.a" \
        -output "$simulator_library"

    local simulator_architectures
    simulator_architectures=$(xcrun lipo -archs "$simulator_library")
    if [ "$simulator_architectures" != "x86_64 arm64" ] && [ "$simulator_architectures" != "arm64 x86_64" ]; then
        error "Unexpected iOS simulator architectures: $simulator_architectures"
        exit 1
    fi
    log "  ✓ simulator architectures: $simulator_architectures"

    # Create XCFramework with one device slice and one universal simulator slice.
    log "Creating XCFramework..."

    rm -rf "$OUT_DIR/ios/OpenMlsFlutter.xcframework"

    xcodebuild -create-xcframework \
        -library "$OUT_DIR/ios/libopenmls_flutter-aarch64-apple-ios.a" \
        -library "$simulator_library" \
        -output "$OUT_DIR/ios/OpenMlsFlutter.xcframework"

    log "✓ iOS XCFramework created at $OUT_DIR/ios/OpenMlsFlutter.xcframework"
}

build_android() {
    log "========================================="
    log "Building for Android..."
    log "========================================="

    resolve_android_ndk
    local android_ndk_home="$RESOLVED_ANDROID_NDK"

    install_targets "${ANDROID_TARGETS[@]}"

    mkdir -p "$OUT_DIR/android"

    local host_tag
    case "$(uname -s)" in
        Darwin) host_tag="darwin-x86_64" ;;
        Linux) host_tag="linux-x86_64" ;;
        *) error "Unsupported Android build host: $(uname -s)"; exit 1 ;;
    esac

    # Setup cargo config for Android cross-compilation.
    local TOOLCHAIN="$android_ndk_home/toolchains/llvm/prebuilt/$host_tag"
    if [ ! -d "$TOOLCHAIN" ]; then
        error "Android NDK LLVM toolchain not found: $TOOLCHAIN"
        exit 1
    fi

    export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android21-clang"
    export CXX_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android21-clang++"
    export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android21-clang"

    export CC_armv7_linux_androideabi="$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang"
    export CXX_armv7_linux_androideabi="$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang++"
    export AR_armv7_linux_androideabi="$TOOLCHAIN/bin/llvm-ar"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang"

    export CC_x86_64_linux_android="$TOOLCHAIN/bin/x86_64-linux-android21-clang"
    export CXX_x86_64_linux_android="$TOOLCHAIN/bin/x86_64-linux-android21-clang++"
    export AR_x86_64_linux_android="$TOOLCHAIN/bin/llvm-ar"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/x86_64-linux-android21-clang"

    for target in "${ANDROID_TARGETS[@]}"; do
        log "Building for $target..."
        cargo build -p openmls_flutter --release --target "$target"

        local abi
        case $target in
            aarch64-linux-android) abi="arm64-v8a" ;;
            armv7-linux-androideabi) abi="armeabi-v7a" ;;
            x86_64-linux-android) abi="x86_64" ;;
        esac

        mkdir -p "$OUT_DIR/android/jniLibs/$abi"
        cp "$PROJECT_ROOT/target/$target/release/libopenmls_flutter.so" "$OUT_DIR/android/jniLibs/$abi/"
        log "  ✓ $target ($abi) built"
    done

    log "Verifying Android ELF load-segment alignment..."
    local readelf="$TOOLCHAIN/bin/llvm-readelf"
    for so_file in "$OUT_DIR"/android/jniLibs/*/libopenmls_flutter.so; do
        local load_alignments
        load_alignments=$("$readelf" -lW "$so_file" | awk '$1 == "LOAD" {print $NF}')
        if [ -z "$load_alignments" ] || printf '%s\n' "$load_alignments" | grep -qv '^0x4000$'; then
            error "Unexpected ELF LOAD alignment in $so_file: ${load_alignments:-missing}"
            exit 1
        fi
        log "  ✓ $(basename "$(dirname "$so_file")") LOAD alignment: 0x4000"
        NM_TOOL="$TOOLCHAIN/bin/llvm-nm" \
            "$SCRIPT_DIR/tool/audit_dynamic_symbols.sh" "$so_file"
    done

    log "✓ Android libraries created at $OUT_DIR/android/jniLibs/"
}

# ============================================================================
# Main
# ============================================================================

COMMAND="${1:-all}"

case "$COMMAND" in
    codegen)
        check_prerequisites
        run_codegen
        ;;
    verify)
        check_prerequisites
        run_codegen
        verify_package
        ;;
    ios)
        check_prerequisites
        run_codegen
        build_ios
        ;;
    android)
        check_prerequisites
        run_codegen
        build_android
        ;;
    all)
        check_prerequisites
        run_codegen
        build_ios
        build_android
        ;;
    *)
        echo "Usage: $0 [codegen|verify|ios|android|all]"
        echo ""
        echo "Commands:"
        echo "  codegen  - Generate Dart bindings + Rust glue only"
        echo "  verify   - Codegen, analyze, test, clippy, and audit host exports"
        echo "  ios      - Build iOS static libs + XCFramework"
        echo "  android  - Build Android .so libs (auto-detects the NDK; env override supported)"
        echo "  all      - Build everything (default)"
        exit 1
        ;;
esac

log "========================================="
log "Build complete!"
log "========================================="
echo ""
echo "Output directory: $OUT_DIR"
echo ""
if [ -d "$OUT_DIR" ]; then
    echo "Files:"
    find "$OUT_DIR" -type f | sort | while read -r f; do
        size=$(du -h "$f" | cut -f1)
        echo "  $size  ${f#$OUT_DIR/}"
    done
else
    echo "No manual artifacts were requested."
fi
