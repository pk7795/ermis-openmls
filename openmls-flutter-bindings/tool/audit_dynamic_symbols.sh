#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <dynamic-library>" >&2
    exit 1
fi

LIBRARY="$1"
if [ ! -f "$LIBRARY" ]; then
    echo "Dynamic library not found: $LIBRARY" >&2
    exit 1
fi

SYMBOL_FILE=$(mktemp "${TMPDIR:-/tmp}/openmls_flutter_symbols.XXXXXX")
trap 'rm -f "$SYMBOL_FILE"' EXIT

if [ -n "${NM_TOOL:-}" ]; then
    "$NM_TOOL" --defined-only --extern-only "$LIBRARY" | awk '{print $NF}' | sed 's/^_//' | sort -u > "$SYMBOL_FILE"
elif [ "$(uname -s)" = "Darwin" ]; then
    nm -gU "$LIBRARY" | awk '{print $NF}' | sed 's/^_//' | sort -u > "$SYMBOL_FILE"
else
    nm -D --defined-only "$LIBRARY" | awk '{print $NF}' | sed 's/^_//' | sort -u > "$SYMBOL_FILE"
fi

prefixed_count=0
generic_count=0
unexpected_symbols=""

while IFS= read -r symbol; do
    case "$symbol" in
        frbgen_openmls_flutter_*)
            prefixed_count=$((prefixed_count + 1))
            ;;
        frb_create_shutdown_callback|\
        frb_dart_fn_deliver_output|\
        frb_dart_opaque_dart2rust_encode|\
        frb_dart_opaque_drop_thread_box_persistent_handle|\
        frb_dart_opaque_rust2dart_decode|\
        frb_free_wire_sync_rust2dart_dco|\
        frb_free_wire_sync_rust2dart_sse|\
        frb_get_rust_content_hash|\
        frb_init_frb_dart_api_dl|\
        frb_pde_ffi_dispatcher_primary|\
        frb_pde_ffi_dispatcher_sync|\
        frb_rust_vec_u8_free|\
        frb_rust_vec_u8_new|\
        frb_rust_vec_u8_resize|\
        free_zero_copy_buffer_f32|\
        free_zero_copy_buffer_f64|\
        free_zero_copy_buffer_i16|\
        free_zero_copy_buffer_i32|\
        free_zero_copy_buffer_i64|\
        free_zero_copy_buffer_i8|\
        free_zero_copy_buffer_u16|\
        free_zero_copy_buffer_u32|\
        free_zero_copy_buffer_u64|\
        free_zero_copy_buffer_u8|\
        store_dart_post_cobject)
            generic_count=$((generic_count + 1))
            ;;
        "")
            ;;
        *)
            unexpected_symbols="${unexpected_symbols}${symbol}\n"
            ;;
    esac
done < "$SYMBOL_FILE"

if [ "$prefixed_count" -eq 0 ]; then
    echo "No openmls_flutter-prefixed FRB symbols found in $LIBRARY" >&2
    exit 1
fi

if [ -n "$unexpected_symbols" ]; then
    echo "Unexpected exported symbols in $LIBRARY:" >&2
    printf '%b' "$unexpected_symbols" >&2
    exit 1
fi

echo "Symbol audit passed: $prefixed_count package-prefixed, $generic_count known FRB runtime symbols"
if [ "$generic_count" -gt 0 ]; then
    echo "Note: keep this package dynamically loaded when an app contains multiple FRB packages."
fi
