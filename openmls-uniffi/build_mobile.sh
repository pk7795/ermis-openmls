#!/bin/bash
set -euo pipefail

# ============================================================================
# OpenMLS UniFFI Mobile Build Script
#
# Builds the openmls-uniffi library for iOS and generates Swift/Kotlin bindings.
# Usage: ./build_mobile.sh [ios|android|bindings|all]
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/out"

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
)

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

build_ios() {
    log "========================================="
    log "Building for iOS..."
    log "========================================="

    install_targets "${IOS_TARGETS[@]}"

    mkdir -p "$OUT_DIR/ios"

    for target in "${IOS_TARGETS[@]}"; do
        log "Building for $target..."
        cargo build -p openmls-uniffi --release --target "$target"
        cp "$PROJECT_ROOT/target/$target/release/libopenmls_uniffi.a" "$OUT_DIR/ios/libopenmls_uniffi-${target}.a"
        log "  ✓ $target built"
    done

    # Create universal binary for simulator if needed
    log "Creating XCFramework..."
    
    mkdir -p "$OUT_DIR/ios/headers"
    cp "$OUT_DIR/swift/openmls_uniffiFFI.h" "$OUT_DIR/ios/headers/"
    cp "$OUT_DIR/swift/openmls_uniffiFFI.modulemap" "$OUT_DIR/ios/headers/module.modulemap"

    # Remove existing xcframework if present
    rm -rf "$OUT_DIR/ios/OpenMlsUniFFI.xcframework"

    xcodebuild -create-xcframework \
        -library "$OUT_DIR/ios/libopenmls_uniffi-aarch64-apple-ios.a" \
        -headers "$OUT_DIR/ios/headers" \
        -library "$OUT_DIR/ios/libopenmls_uniffi-aarch64-apple-ios-sim.a" \
        -headers "$OUT_DIR/ios/headers" \
        -output "$OUT_DIR/ios/OpenMlsUniFFI.xcframework"

    log "✓ iOS XCFramework created at $OUT_DIR/ios/OpenMlsUniFFI.xcframework"
}

build_android() {
    log "========================================="
    log "Building for Android..."
    log "========================================="

    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
        error "ANDROID_NDK_HOME is not set. Please set it to your Android NDK path."
        error "Example: export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/26.1.10909125"
        exit 1
    fi

    install_targets "${ANDROID_TARGETS[@]}"

    mkdir -p "$OUT_DIR/android"

    # Setup cargo config for Android cross-compilation
    local TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64"
    
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
        cargo build -p openmls-uniffi --release --target "$target"
        
        local abi
        case $target in
            aarch64-linux-android) abi="arm64-v8a" ;;
            armv7-linux-androideabi) abi="armeabi-v7a" ;;
            x86_64-linux-android) abi="x86_64" ;;
        esac
        
        mkdir -p "$OUT_DIR/android/jniLibs/$abi"
        cp "$PROJECT_ROOT/target/$target/release/libopenmls_uniffi.so" "$OUT_DIR/android/jniLibs/$abi/"
        log "  ✓ $target ($abi) built"
    done

    log "✓ Android libraries created at $OUT_DIR/android/jniLibs/"
}

generate_bindings() {
    log "========================================="
    log "Generating bindings..."
    log "========================================="

    # Build for host first to get the library
    log "Building for host target..."
    cargo build -p openmls-uniffi --release

    mkdir -p "$OUT_DIR/swift" "$OUT_DIR/kotlin"

    log "Generating Swift bindings..."
    cargo run -p openmls-uniffi --bin uniffi-bindgen generate \
        --library "$PROJECT_ROOT/target/release/libopenmls_uniffi.dylib" \
        --language swift \
        --out-dir "$OUT_DIR/swift"

    log "Generating Kotlin bindings..."
    cargo run -p openmls-uniffi --bin uniffi-bindgen generate \
        --library "$PROJECT_ROOT/target/release/libopenmls_uniffi.dylib" \
        --language kotlin \
        --out-dir "$OUT_DIR/kotlin"

    log "✓ Swift bindings at $OUT_DIR/swift/"
    log "✓ Kotlin bindings at $OUT_DIR/kotlin/"
}

# ============================================================================
# Main
# ============================================================================

COMMAND="${1:-all}"

case "$COMMAND" in
    ios)
        generate_bindings
        build_ios
        ;;
    android)
        generate_bindings
        build_android
        ;;
    bindings)
        generate_bindings
        ;;
    all)
        generate_bindings
        build_ios
        if [ -n "${ANDROID_NDK_HOME:-}" ]; then
            build_android
        else
            warn "Skipping Android build (ANDROID_NDK_HOME not set)"
        fi
        ;;
    *)
        echo "Usage: $0 [ios|android|bindings|all]"
        echo ""
        echo "Commands:"
        echo "  ios       - Build iOS static libs + XCFramework"
        echo "  android   - Build Android .so libs (requires ANDROID_NDK_HOME)"
        echo "  bindings  - Generate Swift and Kotlin bindings only"
        echo "  all       - Build everything (default)"
        exit 1
        ;;
esac

log "========================================="
log "Build complete!"
log "========================================="
echo ""
echo "Output directory: $OUT_DIR"
echo ""
echo "Files:"
find "$OUT_DIR" -type f | sort | while read -r f; do
    size=$(du -h "$f" | cut -f1)
    echo "  $size  ${f#$OUT_DIR/}"
done
