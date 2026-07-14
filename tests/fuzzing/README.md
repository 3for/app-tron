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
python3 generate_transaction_trigger_corpus.py
FUZZ_TARGET=transaction_trigger_decode_fuzzer ./local_run.sh
```

The generated seeds are raw `protocol.Transaction.raw` protobuf messages in
`./corpus/transaction_trigger_decode_fuzzer`. The harness constructs the
equivalent top-level `Transaction` wrapper internally and checks that both
decoder entry modes produce the same result.

To run the `handleSign` fuzzer:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_handle_sign ./local_run.sh
```

By default it uses `./corpus` as its seed corpus. To keep its generated inputs
separate from other targets that use the shared corpus, pass a dedicated
directory:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_handle_sign CORPUS_DIR=./corpus/fuzz_handle_sign ./local_run.sh
```

To run the Generic Clear Signing (GCS) fuzzer:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_gcs CORPUS_DIR=./corpus/fuzz_gcs ./local_run.sh
```

To run the external metadata fuzzer:

```sh
cd tests/fuzzing
python3 generate_external_metadata_corpus.py
FUZZ_TARGET=fuzz_external_metadata ./local_run.sh
```

To run the personal-message fuzzer:

```sh
cd tests/fuzzing
python3 generate_personal_message_corpus.py
FUZZ_TARGET=fuzz_personal_message ./local_run.sh
```

To run the common utility fuzzers, use separate corpus directories so their
generated inputs do not mix with the protocol fuzzers:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_common_utils_address \
  CORPUS_DIR=./corpus/fuzz_common_utils_address ./local_run.sh
```

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_common_utils_numbers \
  CORPUS_DIR=./corpus/fuzz_common_utils_numbers ./local_run.sh
```

`local_run.sh` creates the corpus directory when needed and builds all targets
with AddressSanitizer. It starts an open-ended mutation loop when libFuzzer is
available; on AppleClang installations without the libFuzzer runtime, it replays
the corpus once in standalone mode. Stop an open-ended run with `Ctrl-C`.

To use a custom corpus directory:

```sh
cd tests/fuzzing
FUZZ_TARGET=fuzz_tip712 CORPUS_DIR=/path/to/corpus ./local_run.sh
```

## Targets

| Target | What it covers | Default corpus |
| --- | --- | --- |
| `transaction_trigger_decode_fuzzer` | Streaming protobuf decoding in `src/handlers/transaction_trigger_decode.c` | `./corpus/transaction_trigger_decode_fuzzer` |
| `fuzz_tip712` | Current TIP712 APDU/state-machine flow | `./corpus/fuzz_tip712` |
| `fuzz_handle_sign` | Transaction-signing APDU flow through `handleSign()` | `./corpus` |
| `fuzz_personal_message` | TIP-191 legacy and full-display personal-message signing flows | `./corpus/fuzz_personal_message` |
| `fuzz_gcs` | Generic Clear Signing APDU flow through `handleSignGcs()`, `handle_tx_info()`, and `handle_field()` | `./corpus` |
| `fuzz_external_metadata` | External metadata APDU flows for trusted names, proxy info, and enum values | `./corpus/fuzz_external_metadata` |
| `fuzz_common_utils_address` | TRON Base58Check address conversion, checksum/prefix rejection, and output boundaries | `./corpus` |
| `fuzz_common_utils_numbers` | uint128/uint256 decimal formatting, token decimals/tickers, and output boundaries | `./corpus` |

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

Build and run the transaction decoder target with its generated seeds and
protobuf dictionary:

```sh
cd tests/fuzzing
python3 generate_transaction_trigger_corpus.py
cmake --build build --target transaction_trigger_decode_fuzzer
./build/transaction_trigger_decode_fuzzer \
  -runs=10000 -max_len=8192 \
  -dict=./dictionaries/transaction_trigger_decode_fuzzer.dict \
  ./corpus/transaction_trigger_decode_fuzzer
```

`local_run.sh` automatically selects the target-specific corpus after it has
been generated, but it does not add the dictionary option. Use the manual
command above when dictionary-guided mutations are required.

The equivalent commands for `handleSign` are:

```sh
cd tests/fuzzing
cmake --build build --target fuzz_handle_sign
mkdir -p corpus/fuzz_handle_sign
./build/fuzz_handle_sign -runs=10000 -max_len=8192 ./corpus/fuzz_handle_sign
```

Remove `-runs=10000` for an open-ended run.

The equivalent commands for GCS are:

```sh
cd tests/fuzzing
cmake --build build --target fuzz_gcs
mkdir -p corpus/fuzz_gcs
./build/fuzz_gcs -runs=10000 -max_len=8192 ./corpus/fuzz_gcs
```

Remove `-runs=10000` for an open-ended run.

The equivalent commands for external metadata are:

```sh
cd tests/fuzzing
cmake --build build --target fuzz_external_metadata
python3 generate_external_metadata_corpus.py
./build/fuzz_external_metadata -runs=10000 -max_len=8192 ./corpus/fuzz_external_metadata
```

Remove `-runs=10000` for an open-ended run.

The equivalent commands for personal messages are:

```sh
cd tests/fuzzing
cmake --build build --target fuzz_personal_message
python3 generate_personal_message_corpus.py
./build/fuzz_personal_message -runs=10000 -max_len=8192 ./corpus/fuzz_personal_message
```

Remove `-runs=10000` for an open-ended run.

Build and run the common utility targets with bounded smoke tests:

```sh
cd tests/fuzzing
cmake --build build --target fuzz_common_utils_address fuzz_common_utils_numbers
mkdir -p corpus/fuzz_common_utils_address corpus/fuzz_common_utils_numbers
./build/fuzz_common_utils_address \
  -runs=10000 -max_len=64 ./corpus/fuzz_common_utils_address
./build/fuzz_common_utils_numbers \
  -runs=10000 -max_len=64 ./corpus/fuzz_common_utils_numbers
```

Both harnesses derive valid cases and boundary values from arbitrary input, so
they can start with empty corpus directories. Remove `-runs=10000` for an
open-ended run.

Replay a corpus without starting a mutation loop:

```sh
cd tests/fuzzing
./build/fuzz_tip712 -runs=0 ./corpus/fuzz_tip712
```

Some AppleClang/Xcode installations do not ship the libFuzzer runtime `libclang_rt.fuzzer_osx.a`. In that case CMake automatically builds standalone replay binaries instead of failing at link time. Standalone binaries do not accept libFuzzer flags such as `-runs` or `-max_len`; pass files or directories directly:

```sh
cd tests/fuzzing
./build/fuzz_tip712 ./corpus/fuzz_tip712
./build/transaction_trigger_decode_fuzzer ./corpus/transaction_trigger_decode_fuzzer
./build/fuzz_handle_sign ./corpus/fuzz_handle_sign
./build/fuzz_personal_message ./corpus/fuzz_personal_message
./build/fuzz_gcs ./corpus/fuzz_gcs
./build/fuzz_external_metadata ./corpus/fuzz_external_metadata
./build/fuzz_common_utils_address ./corpus/fuzz_common_utils_address
./build/fuzz_common_utils_numbers ./corpus/fuzz_common_utils_numbers
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

Transaction decoder seeds:

```sh
cd tests/fuzzing
python3 generate_transaction_trigger_corpus.py
```

This refreshes:

- `./corpus/transaction_trigger_decode_fuzzer`

Each seed is a raw `protocol.Transaction.raw` protobuf message. The generated
corpus directory is ignored by Git and can be recreated from the script.

TIP712 seeds:

```sh
cd tests/fuzzing
python3 generate_tip712_corpus.py
```

This refreshes:

- `./corpus/fuzz_tip712`

External metadata seeds:

```sh
cd tests/fuzzing
python3 generate_external_metadata_corpus.py
```

This refreshes:

- `./corpus/fuzz_external_metadata`

Personal-message seeds:

```sh
cd tests/fuzzing
python3 generate_personal_message_corpus.py
```

This refreshes:

- `./corpus/fuzz_personal_message`

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
- `fuzz_handle_sign`
- `fuzz_personal_message`
- `fuzz_gcs`
- `fuzz_external_metadata`
- `fuzz_common_utils_address`
- `fuzz_common_utils_numbers`

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

All eight targets are exported by the default build, so no separate "export everything" command is needed.

Run an exported target with the OSS-Fuzz runner. Each target needs the matching seed corpus:

| Target | Host corpus mount |
| --- | --- |
| `transaction_trigger_decode_fuzzer` | `$(pwd)/tests/fuzzing/corpus/transaction_trigger_decode_fuzzer` |
| `fuzz_tip712` | `$(pwd)/tests/fuzzing/corpus/fuzz_tip712` |
| `fuzz_handle_sign` | `$(pwd)/tests/fuzzing/corpus/fuzz_handle_sign` |
| `fuzz_personal_message` | `$(pwd)/tests/fuzzing/corpus/fuzz_personal_message` |
| `fuzz_gcs` | `$(pwd)/tests/fuzzing/corpus/fuzz_gcs` |
| `fuzz_external_metadata` | `$(pwd)/tests/fuzzing/corpus/fuzz_external_metadata` |
| `fuzz_common_utils_address` | `$(pwd)/tests/fuzzing/corpus/fuzz_common_utils_address` |
| `fuzz_common_utils_numbers` | `$(pwd)/tests/fuzzing/corpus/fuzz_common_utils_numbers` |

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
python3 tests/fuzzing/generate_transaction_trigger_corpus.py
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_transaction_trigger_decode_fuzzer_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/transaction_trigger_decode_fuzzer:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/dictionaries/transaction_trigger_decode_fuzzer.dict:/mnt/transaction_trigger_decode_fuzzer.dict:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer transaction_trigger_decode_fuzzer -runs=10000 -max_len=8192 -dict=/mnt/transaction_trigger_decode_fuzzer.dict'
```

The default ClusterFuzzLite build exports the target binary but does not copy
its dictionary into `/out`, so the example mounts the dictionary separately.

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

`fuzz_handle_sign`:

```sh
mkdir -p tests/fuzzing/corpus/fuzz_handle_sign
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_handle_sign_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_handle_sign:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_handle_sign -runs=10000 -max_len=8192'
```

`fuzz_gcs`:

```sh
mkdir -p tests/fuzzing/corpus/fuzz_gcs
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_gcs_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_gcs:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_gcs -runs=10000 -max_len=8192'
```

`fuzz_personal_message`:

```sh
python3 tests/fuzzing/generate_personal_message_corpus.py
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_personal_message_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_personal_message:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_personal_message -runs=10000 -max_len=8192'
```

`fuzz_external_metadata`:

```sh
python3 tests/fuzzing/generate_external_metadata_corpus.py
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_external_metadata_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_external_metadata:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_external_metadata -runs=10000 -max_len=8192'
```

`fuzz_common_utils_address`:

```sh
mkdir -p tests/fuzzing/corpus/fuzz_common_utils_address
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_common_utils_address_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_common_utils_address:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_common_utils_address -runs=10000 -max_len=64'
```

`fuzz_common_utils_numbers`:

```sh
mkdir -p tests/fuzzing/corpus/fuzz_common_utils_numbers
docker run --platform linux/amd64 --rm --privileged \
  -e FUZZING_ENGINE=libfuzzer \
  -e RUN_FUZZER_MODE=interactive \
  -e CORPUS_DIR=/tmp/seed_fuzz_common_utils_numbers_corpus \
  -v "$(pwd)/tests/fuzzing/corpus/fuzz_common_utils_numbers:/mnt/host_corpus:ro" \
  -v "$(pwd)/tests/fuzzing/out:/out" \
  gcr.io/oss-fuzz-base/base-runner \
  /bin/bash -lc 'rm -rf "$CORPUS_DIR" && mkdir -p "$CORPUS_DIR" && cp -R /mnt/host_corpus/. "$CORPUS_DIR"/ && run_fuzzer fuzz_common_utils_numbers -runs=10000 -max_len=64'
```

These two targets can start from empty host corpus directories because each
input is expanded into valid round-trip cases and boundary variants by the
harness itself. Their inputs are small, so `-max_len=64` is sufficient.

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

Each input is interpreted as a raw `protocol.Transaction.raw` protobuf message.
The harness constructs an equivalent top-level `Transaction` wrapper, then
checks that raw and wrapped decoding expose identical fields and trigger-data
observer streams. It also compares whole-buffer, byte-at-a-time, and
deterministic pseudo-random chunking, including reuse of the same decoder
object. Additional runs cover truncated and oversized declared lengths,
zero-length feeds, observer failure, terminal-state rejection of trailing data,
and result stability after completion.

`fuzz_tip712` replays a compact command stream with these operations:

- `STRUCT_DEF`
- `FILTERING`
- `STRUCT_IMPL`
- `SIGN`
- `RESET`
- `SET_SETTINGS`

It runs the production TIP712 core logic on host-side shims for SDK, UI, settings, and signature-verification dependencies. Coverage includes BIP32 path parsing, BASIC and FULL modes, filtering, trusted-name and amount formatting, partial payloads, permit-style token resolution, signed integers, and reset/replay flows.

`fuzz_handle_sign` treats each input as one settings byte followed by zero or
more APDU records. Each record contains `p1` (1 byte), `p2` (1 byte), a
little-endian payload length (2 bytes), and the payload. This exercises valid
multi-frame transaction signing along with restarts, out-of-order continuation
frames, TRC10 metadata frames, truncated payloads, and invalid parameter
combinations through the production `handleSign()` entry point.

`fuzz_personal_message` treats each input as one public-key status control byte
followed by zero or more APDU records. Each record contains `ins` (1 byte),
`p1` (1 byte), `p2` (1 byte), a payload length (1 byte), and the payload. It
dispatches `INS_SIGN_PERSONAL_MESSAGE` and
`INS_SIGN_PERSONAL_MESSAGE_FULL_DISPLAY` records through the production
handlers. Bit 0 of the control byte selects whether public-key initialization
succeeds or fails. The harness covers legacy hash display, full-message display,
valid and invalid multi-frame messages, instruction interleaving, restarts,
invalid continuations, truncated APDUs, and binary message data.

`fuzz_gcs` treats each input as one settings byte followed by zero or more APDU
records. Each record contains `ins` (1 byte), `p1` (1 byte), `p2` (1 byte), a
payload length (1 byte), and the payload. It dispatches `INS_SIGN_GCS`,
`INS_GTP_TRANSACTION_INFO`, and `INS_GTP_FIELD` records through the production
handlers to exercise transaction storage, signed descriptors, field-hash
validation, review startup, restarts, invalid ordering, and truncated streams.

`fuzz_external_metadata` treats each input as one certificate-status control
byte followed by zero or more APDU records. Each record contains `ins` (1 byte),
`p1` (1 byte), `p2` (1 byte), a payload length (1 byte), and the payload. It
dispatches `INS_PROVIDE_TRUSTED_NAME`, `INS_PROVIDE_PROXY_INFO`, and
`INS_PROVIDE_ENUM_VALUE` records through the production handlers. First chunks
include the production two-byte total TLV length prefix. The control byte modulo
6 selects PKI success, missing certificate, wrong certificate usage, wrong
curve, wrong signature, or an unknown PKI error. The harness covers complete
and fragmented descriptors, instruction interleaving, restarts, oversized or
truncated streams, and challenge checks.

`fuzz_common_utils_address` derives valid 20-byte addresses from every input and
checks the complete 20-byte -> 21-byte payload -> 25-byte checksummed payload ->
34-character Base58 path in both directions. It also verifies rejection of bad
checksums, non-TRON prefixes, invalid lengths and arbitrary Base58 input, with
guard bytes around all output buffers.

`fuzz_common_utils_numbers` compares uint128 and uint256 decimal formatting with
an independent base-256 long-division implementation. It checks exact and short
buffers, amount decimal placement and zero trimming for all uint8 decimal values,
and ticker concatenation up to `MAX_TICKER_LEN`.

The host fuzz environment uses deterministic stubs for NBGL transitions, approval flows, and certificate/signature verification. These targets are meant to cover high-value parser and handler behavior; they do not emulate the full device UI or cryptographic verification stack.

## Troubleshooting

- `Fuzzer needs to be built with Clang`: pass `-DCMAKE_C_COMPILER=/usr/bin/clang` or another Clang path.
- `Unknown sanitizer type`: use `-DSANITIZER=address` or `-DSANITIZER=memory`.
- macOS standalone fallback: expected when the local Clang does not provide the libFuzzer runtime. Use replay syntax without libFuzzer flags.
- Missing `/usr/lib/libFuzzingEngine.a` in a ClusterFuzzLite image: the CMake setup detects this and falls back to `-fsanitize=fuzzer`.
- Docker `amd64`/`arm64` warnings on Apple Silicon: pass `--platform linux/amd64` to both `docker build` and `docker run`.
