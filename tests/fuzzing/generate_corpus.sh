#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

clean=0
if [[ "${1:-}" == "--clean" ]]; then
    clean=1
    shift
fi

target="${1:-all}"

generate_one() {
    local fuzz_target="$1"
    local corpus_dir="./corpus/${fuzz_target}"
    local generator=""

    case "$fuzz_target" in
        transaction_trigger_decode_fuzzer)
            generator="generate_transaction_trigger_corpus.py"
            ;;
        fuzz_tip712)
            generator="generate_tip712_corpus.py"
            ;;
        fuzz_handle_sign)
            generator="generate_handle_sign_corpus.py"
            ;;
        fuzz_personal_message)
            generator="generate_personal_message_corpus.py"
            ;;
        fuzz_external_metadata)
            generator="generate_external_metadata_corpus.py"
            ;;
        fuzz_gcs|fuzz_common_utils_address|fuzz_common_utils_numbers)
            ;;
        *)
            echo "Unknown fuzz target: ${fuzz_target}" >&2
            echo "Run '$0 --help' to list supported targets." >&2
            return 2
            ;;
    esac

    if [[ "$clean" -eq 1 ]]; then
        rm -rf "$corpus_dir"
    fi
    mkdir -p "$corpus_dir"

    if [[ -n "$generator" ]]; then
        echo "Generating ${fuzz_target} corpus with ${generator}"
        python3 "$generator"
    else
        echo "${fuzz_target} has no baseline generator; using ${corpus_dir} as-is"
    fi
}

case "$target" in
    --help|-h)
        cat <<'EOF'
Usage: ./generate_corpus.sh [--clean] [target|all]

Generated baseline corpora:
  transaction_trigger_decode_fuzzer
  fuzz_tip712
  fuzz_handle_sign
  fuzz_personal_message
  fuzz_external_metadata

Targets that intentionally start from an empty or fuzzer-populated corpus:
  fuzz_gcs
  fuzz_common_utils_address
  fuzz_common_utils_numbers

Without --clean, generated baseline files are refreshed while fuzzer-discovered
inputs already in the corpus directory are preserved. With --clean, the target
corpus directory is recreated from its generator (or recreated empty).
EOF
        ;;
    all)
        for fuzz_target in \
            transaction_trigger_decode_fuzzer \
            fuzz_tip712 \
            fuzz_handle_sign \
            fuzz_personal_message \
            fuzz_gcs \
            fuzz_external_metadata \
            fuzz_common_utils_address \
            fuzz_common_utils_numbers; do
            generate_one "$fuzz_target"
        done
        ;;
    *)
        generate_one "$target"
        ;;
esac
