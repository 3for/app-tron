#!/bin/bash -eu

pushd tests/fuzzing
rm -rf build
cmake -B build -S .
cmake --build build
mv ./build/transaction_trigger_decode_fuzzer "${OUT}"
mv ./build/fuzz_tip712 "${OUT}"
mv ./build/fuzz_handle_sign "${OUT}"
mv ./build/fuzz_personal_message "${OUT}"
mv ./build/fuzz_gcs "${OUT}"
mv ./build/fuzz_external_metadata "${OUT}"
mv ./build/fuzz_common_utils_address "${OUT}"
mv ./build/fuzz_common_utils_numbers "${OUT}"
popd
