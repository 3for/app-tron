#!/bin/bash -eu

pushd tests/fuzzing
rm -rf build
cmake -B build -S .
cmake --build build
mv ./build/transaction_trigger_decode_fuzzer "${OUT}"
mv ./build/fuzz_external_plugin "${OUT}"
popd
