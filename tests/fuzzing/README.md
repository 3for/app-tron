# Fuzzing Tests

This directory contains host-side fuzzing targets for app-tron.

Current targets:

- `transaction_trigger_decode_fuzzer`: fuzzes
  [`transaction_trigger_decode.c`](../../src/handlers/transaction_trigger_decode.c),
  the streaming protobuf decoder used for oversized `TriggerSmartContract`
  transactions.
- `fuzz_tip712`: fuzzes the TIP712 APDU handling pipeline in
  [`src/handlers/signMessageTIP712`](../../src/handlers/signMessageTIP712),
  including struct definition, filtering, struct implementation, hashing, path
  handling, and signing preconditions.

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

`transaction_trigger_decode_fuzzer` is intentionally narrower than generic
app-wide fuzzing: the target is to stress the stream decoder thoroughly without
dragging in unrelated app features.

`fuzz_tip712` follows the same spirit as the Ethereum app's `fuzz_eip712`
harness, but is adapted to Tron TIP712's APDU/state-machine flow. It replays a
compact byte stream as a sequence of:

- `STRUCT_DEF`
- `FILTERING`
- `STRUCT_IMPL`
- `SIGN`
- `RESET`

commands, while running the real TIP712 core logic on a host-side shim layer
for SDK, UI, settings, and signature-verification dependencies.

## Manual Usage

From the repository root:

```sh
cd tests/fuzzing
cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build
./build/fuzz_tip712 -max_len=8192
```

You can also use the helper:

```sh
cd tests/fuzzing
./local_run.sh
```

To build only the TIP712 target explicitly:

```sh
cd tests/fuzzing
cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build --target fuzz_tip712
```

On platforms where the libFuzzer runtime is unavailable (for example some
AppleClang/Xcode setups), the CMake logic automatically falls back to a
standalone replay mode. In that mode the produced binaries still build and can
execute inputs from files or corpus directories:

```sh
./build/fuzz_tip712 ./corpus
./build/transaction_trigger_decode_fuzzer ./corpus
```

## ClusterFuzzLite

The repository also provides a matching `.clusterfuzzlite` setup and workflow.
The build only depends on Clang plus the checked-out Tron sources; it does not
need the Ledger secure SDK.

From the repository root:

```sh
mkdir -p tests/fuzzing/out tests/fuzzing/corpus

docker build --platform linux/amd64 --no-cache -t app-tron-fuzz \
  -f .clusterfuzzlite/Dockerfile .
```

If you are not on Apple Silicon, you can omit `--platform linux/amd64`.

Build the fuzzer artifact inside the ClusterFuzzLite container:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-fuzz \
  /bin/bash -lc /src/build.sh
```

This default helper currently exports only `transaction_trigger_decode_fuzzer`
to `tests/fuzzing/out`.

The repository's default `.clusterfuzzlite/build.sh` currently exports
`transaction_trigger_decode_fuzzer`. To build and export `fuzz_tip712`
explicitly, run:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-fuzz \
  /bin/bash -lc 'cd /src/app-tron/tests/fuzzing && rm -rf build && cmake -B build -S . && cmake --build build --target fuzz_tip712 && cp ./build/fuzz_tip712 /out/'
```

If you are actively editing the source code and want the container build to use
your current workspace without rebuilding the Docker image each time, mount the
repository into `/src/app-tron`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd):/src/app-tron" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-fuzz \
  /bin/bash -lc 'cd /src/app-tron/tests/fuzzing && rm -rf build && cmake -B build -S . && cmake --build build --target fuzz_tip712 && cp ./build/fuzz_tip712 /out/'
```

Run the fuzzer interactively with the OSS-Fuzz runner:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -v "$(pwd)/tests/fuzzing/corpus:/tmp/fuzz_corpus" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  run_fuzzer transaction_trigger_decode_fuzzer
```

To run `fuzz_tip712` instead, first build and export it with one of the
explicit `fuzz_tip712` build commands above, then run:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -v "$(pwd)/tests/fuzzing/corpus:/tmp/fuzz_corpus" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  run_fuzzer fuzz_tip712
```

If you want a bounded smoke test instead of an open-ended run in libFuzzer
mode, add extra libFuzzer flags after the target name, for example:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -v "$(pwd)/tests/fuzzing/corpus:/tmp/fuzz_corpus" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  run_fuzzer transaction_trigger_decode_fuzzer -- -runs=10000 -max_len=8192
```

For `fuzz_tip712`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -v "$(pwd)/tests/fuzzing/corpus:/tmp/fuzz_corpus" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  run_fuzzer fuzz_tip712 -- -runs=10000 -max_len=8192
```

Notes:

- The CMake build can produce both `transaction_trigger_decode_fuzzer` and
  `fuzz_tip712`, but the default `.clusterfuzzlite/build.sh` currently exports
  only `transaction_trigger_decode_fuzzer` to `tests/fuzzing/out`.
- On some hosts you may see an `amd64` vs `arm64` Docker platform warning. That
  warning does not prevent the build from completing, but on Apple Silicon it is
  usually simpler to pass `--platform linux/amd64` explicitly on both `docker build`
  and `docker run`.
- In some ClusterFuzzLite images, `LIB_FUZZING_ENGINE` points to a missing
  `/usr/lib/libFuzzingEngine.a`. The current CMake setup detects this and
  automatically falls back to `-fsanitize=fuzzer`.
- On some macOS/Xcode installations, `libclang_rt.fuzzer_osx.a` is missing.
  The current CMake setup detects this too and falls back to standalone replay
  binaries instead of failing at link time.
