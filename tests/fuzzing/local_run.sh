#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FUZZ_TARGET="${FUZZ_TARGET:-fuzz_tip712}"
CORPUS_DIR="${CORPUS_DIR:-}"
FUZZ_RUNS="${FUZZ_RUNS:-}"
SANITIZER="${SANITIZER:-address}"
CLANG="${CC:-clang}"

case "$FUZZ_TARGET" in
    fuzz_common_utils_address|fuzz_common_utils_numbers)
        MAX_LEN=64
        ;;
    transaction_trigger_decode_fuzzer|fuzz_tip712|fuzz_handle_sign|fuzz_personal_message|fuzz_gcs|fuzz_gcs_memory|fuzz_external_metadata)
        MAX_LEN=8192
        ;;
    *)
        echo "Unsupported FUZZ_TARGET: ${FUZZ_TARGET}" >&2
        ./generate_corpus.sh --help >&2
        exit 2
        ;;
esac

if [[ -z "$CORPUS_DIR" ]]; then
    CORPUS_DIR="./corpus/${FUZZ_TARGET}"
    ./generate_corpus.sh "$FUZZ_TARGET"
else
    mkdir -p "$CORPUS_DIR"
    echo "Using custom corpus ${CORPUS_DIR}; automatic baseline generation is disabled"
fi

rm -rf build

cmake -B build -S . -DCMAKE_C_COMPILER="$CLANG" -DSANITIZER="$SANITIZER"
cmake --build build --target "$FUZZ_TARGET"

if ! [ -f "./build/${FUZZ_TARGET}" ]; then
    echo "Build failed, please check the output above."
    exit 1
fi

if command -v nproc >/dev/null 2>&1; then
    ncpus=$(nproc)
elif command -v getconf >/dev/null 2>&1; then
    ncpus=$(getconf _NPROCESSORS_ONLN)
elif command -v sysctl >/dev/null 2>&1; then
    ncpus=$(sysctl -n hw.ncpu)
else
    ncpus=1
fi

jobs=$((ncpus / 2))
if [ "$jobs" -lt 1 ]; then
    jobs=1
fi

if "./build/${FUZZ_TARGET}" -help=1 >/dev/null 2>&1; then
    fuzz_args=(-max_len="$MAX_LEN" -jobs="$jobs")
    if [[ -n "$FUZZ_RUNS" ]]; then
        fuzz_args+=(-runs="$FUZZ_RUNS")
    fi
    if [[ "$FUZZ_TARGET" == "transaction_trigger_decode_fuzzer" ]]; then
        fuzz_args+=(-dict=./dictionaries/transaction_trigger_decode_fuzzer.dict)
    fi
    echo "Starting ${FUZZ_TARGET} in libFuzzer mode. Press Ctrl-C to stop."
    "./build/${FUZZ_TARGET}" "${fuzz_args[@]}" "$CORPUS_DIR"
else
    echo "Starting ${FUZZ_TARGET} in standalone replay mode."
    if [[ -n "$(find "$CORPUS_DIR" -type f -print -quit)" ]]; then
        "./build/${FUZZ_TARGET}" "$CORPUS_DIR"
    else
        echo "Corpus is empty; replaying one empty input."
        "./build/${FUZZ_TARGET}"
    fi
fi
