# Fuzzing Tests

This directory contains host-side fuzzing targets for app-tron. The fuzzers are plain CMake targets and do not require the Ledger secure SDK.

## Quick Start

From the repository root:

```sh
cd tests/fuzzing
./local_run.sh
```

`local_run.sh` does the common local workflow:

1. removes and recreates `./build`
2. configures CMake with Clang and AddressSanitizer
3. builds all fuzzing targets
4. runs `fuzz_tip712` by default
5. selects the matching seed corpus automatically

The helper runs open-ended in libFuzzer mode. Stop it with `Ctrl-C`.

To run a different target:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_tip712_legacy ./local_run.sh
```

To use a custom corpus directory:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_tip712 CORPUS_DIR=/path/to/corpus ./local_run.sh
```

## Targets

| Target | What it covers | Default corpus |
| --- | --- | --- |
| `transaction_trigger_decode_fuzzer` | Streaming protobuf decoding in `src/handlers/transaction_trigger_decode.c` | `./corpus` |
| `fuzz_tip712` | Current TIP712 APDU/state-machine flow | `./corpus/fuzz_tip712` |
| `fuzz_tip712_wallet` | Same TIP712 harness with `SCREEN_SIZE_WALLET` enabled | `./corpus/fuzz_tip712` |
| `fuzz_tip712_legacy` | Legacy `SIGN_TIP_712_MESSAGE` pre-hash handler | `./corpus/fuzz_tip712_legacy` |

## Manual Local Runs

Use manual commands when you want a bounded smoke test, a single target build, or a more explicit debugging flow.

Build everything:

```sh
cd tests/fuzzing
cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build
```

Build one target:

```sh
cd tests/fuzzing
cmake -B build -S . -DCMAKE_C_COMPILER=/usr/bin/clang -DSANITIZER=address
cmake --build build --target fuzz_tip712
```

Run a bounded libFuzzer smoke test:

```sh
cd tests/fuzzing
./build/fuzz_tip712 -runs=10000 -max_len=8192 ./corpus/fuzz_tip712
```

Run open-ended libFuzzer:

```sh
cd tests/fuzzing
./build/fuzz_tip712 -max_len=8192 ./corpus/fuzz_tip712
```

Replay a corpus without starting a mutation loop:

```sh
cd tests/fuzzing
./build/fuzz_tip712 -runs=0 ./corpus/fuzz_tip712
```

Some AppleClang/Xcode installations do not ship the libFuzzer runtime `libclang_rt.fuzzer_osx.a`. In that case CMake automatically builds standalone replay binaries instead of failing at link time. Standalone binaries do not accept libFuzzer flags such as `-runs` or `-max_len`; pass files or directories directly:

```sh
cd tests/fuzzing
./build/fuzz_tip712 ./corpus/fuzz_tip712
./build/fuzz_tip712_wallet ./corpus/fuzz_tip712
./build/fuzz_tip712_legacy ./corpus/fuzz_tip712_legacy
./build/transaction_trigger_decode_fuzzer ./corpus
```

To check which mode a binary is in:

```sh
cd tests/fuzzing
./build/fuzz_tip712 -help=1
```

If that command prints libFuzzer help and exits successfully, libFuzzer mode is available. If it fails, use standalone replay syntax.

## Reproduce a Crash

libFuzzer writes crash files as `crash-*` in the current working directory, or in the configured output directory when using the OSS-Fuzz runner. Replay the file with the same target:

```sh
cd tests/fuzzing
./build/fuzz_tip712 ./crash-xxxxxxxx
```

The same replay command also works for standalone binaries.

## Regenerate Seed Corpora

TIP712 seeds:

```sh
cd tests/fuzzing
python3 generate_tip712_corpus.py
```

This refreshes both:

- `./corpus/fuzz_tip712`
- `./corpus/fuzz_tip712_legacy`

## Coverage

`local_run.sh` asks whether to compute coverage after the fuzzing run. Coverage requires `llvm-profdata` and `llvm-cov` in `PATH`, plus a Clang setup that emits `*.profraw` data for the built binary.

If coverage is available, the helper writes:

- `default.profdata`
- `report.html`
- a text summary from `llvm-cov report`

If no `*.profraw` files are produced, the fuzzing run itself can still be valid; only the coverage report step is unavailable for that local toolchain.

## ClusterFuzzLite / Docker

Build the local ClusterFuzzLite image from the repository root:

```sh
mkdir -p tests/fuzzing/out
docker build --platform linux/amd64 --no-cache -t app-tron-fuzz \
  -f .clusterfuzzlite/Dockerfile .
```

On non-Apple-Silicon hosts, `--platform linux/amd64` is usually optional.

The default `.clusterfuzzlite/build.sh` exports only:

- `transaction_trigger_decode_fuzzer`
- `fuzz_tip712`

Run that default build and write artifacts to `tests/fuzzing/out`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd):/src/app-tron" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-fuzz \
  /src/build.sh
```

To export every current target instead:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd):/src/app-tron" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-fuzz \
  /bin/bash -lc 'cd /src/app-tron/tests/fuzzing && rm -rf build && cmake -B build -S . && cmake --build build --target transaction_trigger_decode_fuzzer fuzz_tip712 fuzz_tip712_wallet fuzz_tip712_legacy && cp ./build/transaction_trigger_decode_fuzzer ./build/fuzz_tip712 ./build/fuzz_tip712_wallet ./build/fuzz_tip712_legacy /out/'
```

Run an exported target with the OSS-Fuzz runner. Each target needs the matching
seed corpus:

| Target | Host corpus mount |
| --- | --- |
| `transaction_trigger_decode_fuzzer` | `$(pwd)/tests/fuzzing/corpus` |
| `fuzz_tip712` | `$(pwd)/tests/fuzzing/corpus/fuzz_tip712` |
| `fuzz_tip712_wallet` | `$(pwd)/tests/fuzzing/corpus/fuzz_tip712` |
| `fuzz_tip712_legacy` | `$(pwd)/tests/fuzzing/corpus/fuzz_tip712_legacy` |

The command shape is the same for every target:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_<target>_corpus \
  -v "<host-corpus>:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer <target> -runs=10000 -max_len=8192'
```

Examples for all current targets:

`transaction_trigger_decode_fuzzer`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_transaction_trigger_decode_fuzzer_corpus \
  -v "$(pwd)/tests/fuzzing/corpus:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer transaction_trigger_decode_fuzzer -runs=10000 -max_len=8192'
```

`fuzz_tip712`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_tip712_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_tip712:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_tip712 -runs=10000 -max_len=8192'
```

`fuzz_tip712_wallet`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_tip712_wallet_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_tip712:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_tip712_wallet -runs=10000 -max_len=8192'
```

`fuzz_tip712_legacy`:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_tip712_legacy_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_tip712_legacy:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_tip712_legacy -runs=10000 -max_len=8192'
```

For open-ended Docker fuzzing, remove `-runs=10000` from the selected target
command. For example:

```sh
run_fuzzer fuzz_tip712 -max_len=8192
```

When using `run_fuzzer`, mount the host corpus somewhere other than `/tmp/<target>_corpus`, copy it into a temporary corpus directory inside the container, and set `CORPUS_DIR` to that temporary directory. The runner may delete and recreate its default corpus directory when `CORPUS_DIR` is unset.

## What the Harnesses Exercise

`transaction_trigger_decode_fuzzer` stresses the stream decoder through:

- `tron_stream_decoder_init()`
- `tron_stream_decoder_init_raw()`
- `tron_stream_decoder_set_trigger_data_observer()`
- `tron_stream_decoder_feed()`
- `tron_stream_decoder_is_done()`
- `tron_stream_decoder_get_result()`

Each input is replayed through top-level and raw transaction modes, exact and malformed declared lengths, whole-buffer and chunked feeds, observer success and observer failure paths, and intermediate status queries.

`fuzz_tip712` replays a compact command stream with these operations:

- `STRUCT_DEF`
- `FILTERING`
- `STRUCT_IMPL`
- `SIGN`
- `RESET`
- `SET_SETTINGS`

It runs the production TIP712 core logic on host-side shims for SDK, UI, settings, and signature-verification dependencies. Coverage includes BIP32 path parsing, BASIC and FULL modes, filtering, trusted-name and amount formatting, partial payloads, permit-style token resolution, signed integers, reset/replay flows, and the `SCREEN_SIZE_WALLET` variant.

`fuzz_tip712_legacy` covers the older pre-hashed TIP712 signing handler.

The host fuzz environment uses deterministic stubs for NBGL transitions, approval flows, and certificate/signature verification. These targets are meant to cover high-value parser and handler behavior; they do not emulate the full device UI or cryptographic verification stack.

## Troubleshooting

- `Fuzzer needs to be built with Clang`: pass `-DCMAKE_C_COMPILER=/usr/bin/clang` or another Clang path.
- `Unknown sanitizer type`: use `-DSANITIZER=address` or `-DSANITIZER=memory`.
- macOS standalone fallback: expected when the local Clang does not provide the libFuzzer runtime. Use replay syntax without libFuzzer flags.
- Missing `/usr/lib/libFuzzingEngine.a` in a ClusterFuzzLite image: the CMake setup detects this and falls back to `-fsanitize=fuzzer`.
- Docker `amd64`/`arm64` warnings on Apple Silicon: pass `--platform linux/amd64` to both `docker build` and `docker run`.
