#!/bin/bash
set -eu

rm -rf build

cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build

if ! [ -f ./build/transaction_trigger_decode_fuzzer ]; then
    echo "Build failed, please check the output above."
    exit 1
fi

mkdir -p corpus

ncpus=$(nproc)
jobs=$((ncpus / 2))
if [ "$jobs" -lt 1 ]; then
    jobs=1
fi

echo "Starting transaction_trigger_decode fuzzing. Press Ctrl-C to stop."
./build/transaction_trigger_decode_fuzzer -max_len=8192 -jobs="$jobs" ./corpus

read -p "Would you like to compute coverage (y/n)? " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    exit 0
fi

rm -f default.profdata default.profraw

./build/transaction_trigger_decode_fuzzer -max_len=8192 -runs=0 ./corpus

llvm-profdata merge -sparse *.profraw -o default.profdata
llvm-cov show build/transaction_trigger_decode_fuzzer \
    -instr-profile=default.profdata \
    -format=html > report.html
llvm-cov report build/transaction_trigger_decode_fuzzer \
    -instr-profile=default.profdata
