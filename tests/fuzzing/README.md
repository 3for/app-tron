# Fuzzing Tests

This directory contains host-side fuzzing targets for app-tron. They build with
Clang and do not require a Ledger device or secure SDK.

## Corpus policy

Everything under `tests/fuzzing/corpus/` is generated or produced by a fuzzer
and is intentionally ignored by Git. Do not commit generated `.bin`, `.pb`, or
libFuzzer corpus files.

Six targets have deterministic Python seed generators:

| Target | Generator |
| --- | --- |
| `transaction_trigger_decode_fuzzer` | `generate_transaction_trigger_corpus.py` |
| `fuzz_tip712` | `generate_tip712_corpus.py` |
| `fuzz_handle_sign` | `generate_handle_sign_corpus.py` |
| `fuzz_personal_message` | `generate_personal_message_corpus.py` |
| `fuzz_external_metadata` | `generate_external_metadata_corpus.py` |
| `fuzz_gcs` | `generate_gcs_corpus.py` |

The remaining targets intentionally start with an empty corpus, or reuse inputs
previously discovered by libFuzzer:

- `fuzz_common_utils_address`
- `fuzz_common_utils_numbers`
- `fuzz_gcs_memory`

`generate_corpus.sh` is the canonical target-to-generator mapping used by both
local fuzzing and ClusterFuzzLite. The generators require only Python 3's
standard library:

```sh
cd tests/fuzzing

# Generate or refresh every baseline corpus.
./generate_corpus.sh all

# Generate one target's baseline corpus.
./generate_corpus.sh fuzz_handle_sign

# Delete the target corpus first, then recreate only its generated baseline.
./generate_corpus.sh --clean fuzz_handle_sign
```

Without `--clean`, named baseline files are refreshed while additional inputs
found by libFuzzer are preserved. With `--clean`, the selected corpus directory
is removed and recreated. For targets without a generator, `--clean` recreates
an empty directory.

When a discovered input must become a permanent regression case, encode it in
the corresponding generator or add a focused unit/functional test. Do not make
an exception in `.gitignore` for the generated binary.

## Quick start

From the repository root:

```sh
tests/fuzzing/local_run.sh
```

The helper:

1. selects `fuzz_tip712` unless `FUZZ_TARGET` is set;
2. generates the target's default baseline corpus when one exists;
3. recreates `tests/fuzzing/build`;
4. builds only the selected target with Clang and AddressSanitizer;
5. adds the transaction decoder dictionary when applicable;
6. starts libFuzzer, or performs a one-pass replay on AppleClang installations
   without a libFuzzer runtime.

Select another target:

```sh
FUZZ_TARGET=fuzz_handle_sign tests/fuzzing/local_run.sh
```

Run a bounded smoke test instead of an open-ended session:

```sh
FUZZ_TARGET=fuzz_handle_sign FUZZ_RUNS=10000 \
  tests/fuzzing/local_run.sh
```

Supported environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `FUZZ_TARGET` | `fuzz_tip712` | CMake/libFuzzer target to build and run |
| `FUZZ_RUNS` | unset | In libFuzzer mode, adds `-runs=<value>`; unset means open-ended fuzzing |
| `CORPUS_DIR` | target-specific directory | Uses a custom corpus and disables automatic generation |
| `SANITIZER` | `address` | `address` or `memory`, matching `CMakeLists.txt` |
| `CC` | `clang` | Clang executable passed to CMake |

For example, fuzz a custom corpus without touching the generated default:

```sh
FUZZ_TARGET=fuzz_tip712 \
CORPUS_DIR=/tmp/my-tip712-corpus \
FUZZ_RUNS=10000 \
tests/fuzzing/local_run.sh
```

The custom directory is created if missing. Because generators write to their
target-specific default directories, automatic generation is deliberately
disabled whenever `CORPUS_DIR` is supplied.

## Targets

| Target | Default corpus | Max length used by `local_run.sh` | Main coverage |
| --- | --- | ---: | --- |
| `transaction_trigger_decode_fuzzer` | `corpus/transaction_trigger_decode_fuzzer` | 8192 | Streaming raw/wrapped transaction decoding |
| `fuzz_tip712` | `corpus/fuzz_tip712` | 8192 | TIP-712 command stream and signing state |
| `fuzz_handle_sign` | `corpus/fuzz_handle_sign` | 8192 | Legacy `INS_SIGN` APDU/state-machine flow |
| `fuzz_personal_message` | `corpus/fuzz_personal_message` | 8192 | Legacy and full-display personal messages |
| `fuzz_gcs` | `corpus/fuzz_gcs` | 8192 | Generic Clear Signing commands and descriptors |
| `fuzz_gcs_memory` | `corpus/fuzz_gcs_memory` | 8192 | GCS allocator bookkeeping, budget boundaries, and invariant checks |
| `fuzz_external_metadata` | `corpus/fuzz_external_metadata` | 8192 | Trusted-name, proxy, enum, TRC20, and NFT metadata commands |
| `fuzz_common_utils_address` | `corpus/fuzz_common_utils_address` | 64 | TRON address and Base58Check conversions |
| `fuzz_common_utils_numbers` | `corpus/fuzz_common_utils_numbers` | 64 | uint128/uint256 and amount formatting |

## Manual local builds

Use manual commands for a single replay, explicit sanitizer configuration, or
dictionary-guided options beyond those in `local_run.sh`.

Generate all baseline corpora and build every target:

```sh
cd tests/fuzzing
./generate_corpus.sh all
cmake -B build -S . -DCMAKE_C_COMPILER=clang -DSANITIZER=address
cmake --build build
```

Build and run only `fuzz_handle_sign`:

```sh
cd tests/fuzzing
./generate_corpus.sh fuzz_handle_sign
cmake -B build -S . -DCMAKE_C_COMPILER=clang -DSANITIZER=address
cmake --build build --target fuzz_handle_sign
./build/fuzz_handle_sign -runs=10000 -max_len=8192 \
  ./corpus/fuzz_handle_sign
```

Build and run only `fuzz_gcs_memory`:

```sh
cd tests/fuzzing
./generate_corpus.sh --clean fuzz_gcs_memory
cmake -B build -S . -DCMAKE_C_COMPILER=clang -DSANITIZER=address
cmake --build build --target fuzz_gcs_memory
./build/fuzz_gcs_memory -runs=10000 -max_len=8192 \
  ./corpus/fuzz_gcs_memory
```

Build the transaction decoder with its dictionary:

```sh
cd tests/fuzzing
./generate_corpus.sh transaction_trigger_decode_fuzzer
cmake -B build -S . -DCMAKE_C_COMPILER=clang -DSANITIZER=address
cmake --build build --target transaction_trigger_decode_fuzzer
./build/transaction_trigger_decode_fuzzer \
  -runs=10000 \
  -max_len=8192 \
  -dict=./dictionaries/transaction_trigger_decode_fuzzer.dict \
  ./corpus/transaction_trigger_decode_fuzzer
```

The common-utility harnesses derive valid and invalid cases from arbitrary
bytes, so an empty starting corpus is sufficient:

```sh
cd tests/fuzzing
./generate_corpus.sh --clean fuzz_common_utils_address
cmake -B build -S . -DCMAKE_C_COMPILER=clang -DSANITIZER=address
cmake --build build --target fuzz_common_utils_address
./build/fuzz_common_utils_address \
  -runs=10000 -max_len=64 ./corpus/fuzz_common_utils_address
```

Remove `-runs=10000` from a libFuzzer command for an open-ended run.

### Standalone replay mode on macOS

Some AppleClang/Xcode installations do not include
`libclang_rt.fuzzer_osx.a`. CMake then builds standalone replay binaries. These
binaries accept files and directories, but not libFuzzer flags:

```sh
cd tests/fuzzing
./generate_corpus.sh all
./build/fuzz_tip712 ./corpus/fuzz_tip712
./build/fuzz_handle_sign ./corpus/fuzz_handle_sign
./build/transaction_trigger_decode_fuzzer \
  ./corpus/transaction_trigger_decode_fuzzer
```

If an empty corpus directory is passed, there are no files to replay. Invoke
the binary without arguments to exercise one empty input:

```sh
./build/fuzz_gcs
./build/fuzz_gcs_memory
```

`local_run.sh` detects this mode and handles the empty-input fallback
automatically.

## Reproducing crashes

libFuzzer writes artifacts such as `crash-*`, `timeout-*`, and `slow-unit-*` in
its artifact directory. Replay one with the same target:

```sh
cd tests/fuzzing
./build/fuzz_handle_sign ./out/crash-xxxxxxxx
```

The same syntax works for libFuzzer and standalone replay binaries. Keep crash
artifacts under an ignored directory while investigating them. If the issue is
fixed and needs permanent coverage, translate the artifact into a generator
case or focused regression test.

## ClusterFuzzLite and OSS-Fuzz-compatible builds

The repository workflow uses `.clusterfuzzlite/build.sh`. That script now:

1. runs `generate_corpus.sh --clean all` inside the builder;
2. builds and exports all nine fuzz targets;
3. packages each generated baseline as
   `<target>_seed_corpus.zip` in `$OUT`;
4. exports `transaction_trigger_decode_fuzzer.dict` under the standard name.

Generated corpus files therefore do not need to exist in the Git checkout.
ClusterFuzzLite/OSS-Fuzz tooling discovers the seed archives and dictionary from
the build output.

Build the local ClusterFuzzLite image from the repository root:

```sh
mkdir -p tests/fuzzing/out
docker build --platform linux/amd64 --no-cache -t app-tron-fuzz \
  -f .clusterfuzzlite/Dockerfile .
```

Export the binaries, generated seed archives, and dictionary:

```sh
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_LANGUAGE=c \
  -e OUT=/out \
  -v "$(pwd):/src/app-tron" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  app-tron-fuzz \
  /src/build.sh
```

Expected generated seed archives:

```text
transaction_trigger_decode_fuzzer_seed_corpus.zip
fuzz_tip712_seed_corpus.zip
fuzz_handle_sign_seed_corpus.zip
fuzz_personal_message_seed_corpus.zip
fuzz_external_metadata_seed_corpus.zip
fuzz_gcs_seed_corpus.zip
```

`fuzz_gcs_memory` and the two common-utility targets have no baseline archive
because they can start from an empty corpus.

### Running every target with Docker

After exporting the build output, define this helper from the repository root.
The optional third argument limits the number of inputs; omitting it leaves
libFuzzer running until interrupted:

```bash
run_fuzzer_target() {
  target="$1"
  max_len="$2"
  runs="${3:-}"
  fuzz_options=(-max_len="$max_len")
  if [[ -n "$runs" ]]; then
    fuzz_options+=(-runs="$runs")
  fi

  docker run --platform linux/amd64 --rm --privileged \
    -e FUZZING_ENGINE=libfuzzer \
    -e RUN_FUZZER_MODE=interactive \
    -v "$(pwd)/tests/fuzzing/out:/out" \
    gcr.io/oss-fuzz-base/base-runner \
    run_fuzzer "$target" "${fuzz_options[@]}"
}
```

Run one of the following for an open-ended session, stopping it with `Ctrl-C`:

```sh
run_fuzzer_target transaction_trigger_decode_fuzzer 8192
run_fuzzer_target fuzz_tip712 8192
run_fuzzer_target fuzz_handle_sign 8192
run_fuzzer_target fuzz_personal_message 8192
run_fuzzer_target fuzz_gcs 8192
run_fuzzer_target fuzz_gcs_memory 8192
run_fuzzer_target fuzz_external_metadata 8192
run_fuzzer_target fuzz_common_utils_address 64
run_fuzzer_target fuzz_common_utils_numbers 64
```

Pass a third argument for a bounded run instead:

```sh
# Set libFuzzer's run limit to 10,000, then exit.
run_fuzzer_target fuzz_handle_sign 8192 10000
```

Invoke the target commands individually. An open-ended invocation does not
return until interrupted, so pasting all nine lines will only start the first
target.

The base runner discovers target-specific build artifacts by filename:

| Target | Generated seed archive | Dictionary |
| --- | --- | --- |
| `transaction_trigger_decode_fuzzer` | yes | `transaction_trigger_decode_fuzzer.dict` |
| `fuzz_tip712` | yes | none |
| `fuzz_handle_sign` | yes | none |
| `fuzz_personal_message` | yes | none |
| `fuzz_gcs` | no; starts empty | none |
| `fuzz_gcs_memory` | no; starts empty | none |
| `fuzz_external_metadata` | yes | none |
| `fuzz_common_utils_address` | no; starts empty | none |
| `fuzz_common_utils_numbers` | no; starts empty | none |

The matching seed archive and dictionary are loaded automatically. Targets
without a generated seed archive are still valid: libFuzzer initializes their
working corpus and begins from an empty input.

### Running with a custom corpus

To run any target with additional local inputs, set `TARGET`, `MAX_LEN`, and an
absolute `CUSTOM_CORPUS` path. Leave `RUNS` empty for an open-ended session, or
set it to a number for a bounded run. The example below uses `fuzz_gcs`:

```bash
TARGET=fuzz_gcs
MAX_LEN=8192
CUSTOM_CORPUS=/absolute/path/to/custom-corpus
RUNS=

docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/custom-corpus \
  -e FUZZ_TARGET="$TARGET" \
  -e MAX_LEN="$MAX_LEN" \
  -e FUZZ_RUNS="$RUNS" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  -v "$CUSTOM_CORPUS:/mnt/custom-corpus:ro" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc '
    mkdir -p "$CORPUS_DIR"
    cp -R /mnt/custom-corpus/. "$CORPUS_DIR"/
    fuzz_options=(-max_len="$MAX_LEN")
    if [[ -n "$FUZZ_RUNS" ]]; then
      fuzz_options+=(-runs="$FUZZ_RUNS")
    fi
    run_fuzzer "$FUZZ_TARGET" "${fuzz_options[@]}"
  '
```

## Harness input formats

### Transaction decoder

Each input is a raw `protocol.Transaction.raw` protobuf message. The harness
constructs the equivalent top-level `Transaction` wrapper and compares raw and
wrapped decoding. It exercises whole-buffer, byte-at-a-time, and deterministic
pseudo-random chunking, decoder reuse, truncation, oversized declarations,
observer failures, trailing data, and result stability.

### TIP-712

Each input is a compact command stream containing operations such as
`STRUCT_DEF`, `FILTERING`, `STRUCT_IMPL`, `SIGN`, `RESET`, and `SET_SETTINGS`.
The harness covers BIP32 paths, BASIC/FULL modes, filtering, trusted names,
amount formatting, arrays, partial values, signed integers, and reset/replay
flows.

### Legacy transaction signing

`fuzz_handle_sign` interprets the first byte as settings. It then reads zero or
more records containing `p1` (1 byte), `p2` (1 byte), little-endian payload
length (2 bytes), and payload bytes. This covers valid multi-frame signing,
TRC-10 metadata frames, restarts, invalid continuation ordering, truncated
payloads, and contract-specific validation through production `handleSign()`.

### Personal messages

`fuzz_personal_message` interprets the first byte as public-key status. Each
following record contains `ins`, `p1`, `p2`, one-byte payload length, and the
payload. It dispatches legacy and full-display personal-message instructions,
including fragmentation, instruction interleaving, invalid continuation,
binary messages, and public-key failures.

### Generic Clear Signing

`fuzz_gcs` starts with one settings byte. Each following record contains `ins`,
`p1`, `p2`, one-byte payload length, and payload. It dispatches `INS_SIGN_GCS`,
`INS_GTP_TRANSACTION_INFO`, and `INS_GTP_FIELD` to exercise transaction storage,
signed descriptors, field hashes, review startup, restarts, ordering failures,
and truncated streams.

### GCS memory bookkeeping

`fuzz_gcs_memory` starts from an empty corpus and interprets each input byte as
an allocator op. It exercises `gcs_mem_alloc()`, `gcs_mem_calloc()`,
`gcs_mem_calloc_into()`, `gcs_mem_strdup()`, `gcs_mem_free()`,
`gcs_mem_free_and_null()`, `gcs_budget_begin()`, `gcs_budget_end()`, and
`gcs_mem_reset_phase_peaks()` while checking the tracked, session, category,
and peak counters against an independent host-side model. It also has
expected-failure ops for live allocations at session end, stale generation
frees, and category/session accounting mismatches, and verifies the sticky
invariant-failure flag without treating those paths as fuzzer crashes.

### External metadata

`fuzz_external_metadata` starts with a certificate-status control byte. APDU
records dispatch trusted-name, proxy-info, and enum-value commands. The status
byte selects PKI success, missing certificate, wrong usage, wrong curve, wrong
signature, or unknown PKI error. Seeds include complete, fragmented, truncated,
and invalid descriptors.

### Common utilities

`fuzz_common_utils_address` derives TRON addresses from arbitrary input and
checks payload, checksum, Base58 round trips, invalid prefixes/lengths, and
output-buffer guards.

`fuzz_common_utils_numbers` compares uint128/uint256 formatting against an
independent base-256 division implementation and checks decimal placement,
zero trimming, short buffers, and ticker limits.

Host fuzzing uses deterministic shims for device UI, settings, and selected
cryptographic/PKI dependencies. It targets parser and state-machine behavior;
it is not a full device emulator.

## Troubleshooting

- `Fuzzer needs to be built with Clang`: set `CC=clang` or pass a Clang path.
- `Unknown sanitizer type`: use `SANITIZER=address` or `SANITIZER=memory`.
- macOS standalone fallback: expected when AppleClang lacks the libFuzzer
  runtime; use replay syntax without `-runs`, `-jobs`, or `-max_len`.
- Empty generated corpus after cloning: run `./generate_corpus.sh all`, or use
  `local_run.sh`, which generates the selected default automatically.
- Missing `/usr/lib/libFuzzingEngine.a`: the CMake configuration falls back to
  `-fsanitize=fuzzer` when the path supplied by the environment does not exist.
- Docker `amd64`/`arm64` warning on Apple Silicon: pass
  `--platform linux/amd64` to both `docker build` and `docker run`.
