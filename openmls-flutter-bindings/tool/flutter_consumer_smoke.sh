#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="${1:-all}"
DEVICE_ID="${2:-}"

if ! command -v flutter >/dev/null 2>&1; then
    echo "Flutter is required for the consumer smoke test." >&2
    echo "Install Flutter 3.38 or newer and ensure 'flutter' is on PATH." >&2
    exit 1
fi

SMOKE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/openmls_flutter_consumer.XXXXXX")
trap 'rm -rf "$SMOKE_ROOT"' EXIT
APP_DIR="$SMOKE_ROOT/app"

flutter create \
    --empty \
    --org com.ermis.openmls_smoke \
    --platforms android,ios,macos \
    "$APP_DIR"

cd "$APP_DIR"
dart pub add "openmls_flutter@{path: $PACKAGE_DIR}"
dart pub add "dev:integration_test@{sdk: flutter}"

cp "$SCRIPT_DIR/flutter_smoke/main.dart" lib/main.dart
mkdir -p integration_test
cp "$SCRIPT_DIR/flutter_smoke/openmls_flutter_test.dart" \
    integration_test/openmls_flutter_test.dart

flutter analyze

run_host_smoke() {
    flutter test integration_test/openmls_flutter_test.dart -d macos
}

build_android() {
    flutter build apk --debug
}

build_ios() {
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "iOS smoke build requires macOS." >&2
        exit 1
    fi
    flutter build ios --simulator --no-codesign
}

run_device_smoke() {
    if [ -z "$DEVICE_ID" ]; then
        echo "Usage: $0 device <flutter-device-id>" >&2
        exit 1
    fi
    flutter test integration_test/openmls_flutter_test.dart -d "$DEVICE_ID"
}

case "$MODE" in
    host) run_host_smoke ;;
    android) build_android ;;
    ios) build_ios ;;
    device) run_device_smoke ;;
    all)
        run_host_smoke
        build_android
        build_ios
        ;;
    *)
        echo "Usage: $0 [host|android|ios|all|device <flutter-device-id>]" >&2
        exit 1
        ;;
esac
