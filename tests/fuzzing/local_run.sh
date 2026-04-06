#!/bin/bash
set -eu

FUZZ_TARGET="${FUZZ_TARGET:-fuzz_tip712}"

rm -rf build

cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build

if ! [ -f "./build/${FUZZ_TARGET}" ]; then
    echo "Build failed, please check the output above."
    exit 1
fi

mkdir -p corpus

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
    echo "Starting ${FUZZ_TARGET} in libFuzzer mode. Press Ctrl-C to stop."
    "./build/${FUZZ_TARGET}" -max_len=8192 -jobs="$jobs" ./corpus
else
    echo "Starting ${FUZZ_TARGET} in standalone replay mode."
    echo "Populate ./corpus with seed files to replay them through the harness."
    "./build/${FUZZ_TARGET}" ./corpus
fi

read -p "Would you like to compute coverage (y/n)? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

if ! command -v llvm-profdata >/dev/null 2>&1; then
    echo "Skipping coverage: llvm-profdata not found in PATH."
    exit 0
fi

if ! command -v llvm-cov >/dev/null 2>&1; then
    echo "Skipping coverage: llvm-cov not found in PATH."
    exit 0
fi

rm -f default.profdata default.profraw

if "./build/${FUZZ_TARGET}" -help=1 >/dev/null 2>&1; then
    "./build/${FUZZ_TARGET}" -max_len=8192 -runs=0 ./corpus
else
    "./build/${FUZZ_TARGET}" ./corpus
fi

llvm-profdata merge -sparse *.profraw -o default.profdata
llvm-cov show "build/${FUZZ_TARGET}" \
    -instr-profile=default.profdata \
    -format=html > report.html
llvm-cov report "build/${FUZZ_TARGET}" \
    -instr-profile=default.profdata
