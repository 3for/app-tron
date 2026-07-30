#!/bin/bash -eu

pushd tests/fuzzing
rm -rf build
./generate_corpus.sh --clean all
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

# OSS-Fuzz/ClusterFuzzLite automatically discovers archives named
# <target>_seed_corpus.zip in $OUT. Generated corpora stay out of Git and are
# packaged here from their canonical generators instead.
for target in \
    transaction_trigger_decode_fuzzer \
    fuzz_tip712 \
    fuzz_handle_sign \
    fuzz_personal_message \
    fuzz_gcs \
    fuzz_external_metadata; do
    corpus_dir="./corpus/${target}"
    if [[ -n "$(find "$corpus_dir" -type f -print -quit)" ]]; then
        (
            cd "$corpus_dir"
            python3 -m zipfile -c "${OUT}/${target}_seed_corpus.zip" ./*
        )
    fi
done

cp ./dictionaries/transaction_trigger_decode_fuzzer.dict \
   "${OUT}/transaction_trigger_decode_fuzzer.dict"
popd
