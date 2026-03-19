# Fuzzing Tests

This directory contains a `libFuzzer` target dedicated to
[`transaction_trigger_decode.c`](../../src/handlers/transaction_trigger_decode.c),
the streaming protobuf decoder used for oversized `TriggerSmartContract`
transactions.

## Coverage Goals

The harness exercises the decoder through its public API:

- `tron_stream_decoder_init()`
- `tron_stream_decoder_init_raw()`
- `tron_stream_decoder_set_trigger_data_observer()`
- `tron_stream_decoder_feed()`
- `tron_stream_decoder_is_done()`
- `tron_stream_decoder_get_result()`

Each input is replayed through several decoder scenarios:

- top-level transaction mode and raw transaction mode
- exact, truncated, oversized, and zero declared lengths
- whole-buffer feeds, byte-by-byte feeds, and variable chunked feeds
- observer enabled / disabled
- observer success / injected failure at a fuzz-selected offset
- intermediate status/result queries before, during, and after feeding

This is intentionally narrower than generic app-wide fuzzing: the target is to
stress the stream decoder thoroughly without dragging in unrelated app features.

## Manual Usage

From the repository root:

```sh
cd tests/fuzzing
cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build
./build/transaction_trigger_decode_fuzzer -max_len=8192
```

You can also use the helper:

```sh
cd tests/fuzzing
./local_run.sh
```

## ClusterFuzzLite

The repository also provides a matching `.clusterfuzzlite` setup and workflow.
The build only depends on Clang plus the checked-out Tron sources; it does not
need the Ledger secure SDK.

From the repository root:

```sh
mkdir -p tests/fuzzing/out tests/fuzzing/corpus

docker build --no-cache -t app-tron-transaction-trigger-fuzz \
  -f .clusterfuzzlite/Dockerfile .
```

Build the fuzzer artifact inside the ClusterFuzzLite container:

```sh
docker run --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-transaction-trigger-fuzz \
  /bin/bash -lc /src/build.sh
```

Run the fuzzer interactively with the OSS-Fuzz runner:

```sh
docker run --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -v "$(pwd)/tests/fuzzing/corpus:/tmp/fuzz_corpus" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  run_fuzzer transaction_trigger_decode_fuzzer
```

If you want a bounded smoke test instead of an open-ended run, add extra
libFuzzer flags after the target name, for example:

```sh
docker run --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -v "$(pwd)/tests/fuzzing/corpus:/tmp/fuzz_corpus" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  run_fuzzer transaction_trigger_decode_fuzzer -- -runs=10000 -max_len=8192
```

Notes:

- The produced binary is named `transaction_trigger_decode_fuzzer`.
- On some hosts you may see an `amd64` vs `arm64` Docker platform warning. That
  warning does not prevent the build from completing.
- In some ClusterFuzzLite images, `LIB_FUZZING_ENGINE` points to a missing
  `/usr/lib/libFuzzingEngine.a`. The current CMake setup detects this and
  automatically falls back to `-fsanitize=fuzzer`.
