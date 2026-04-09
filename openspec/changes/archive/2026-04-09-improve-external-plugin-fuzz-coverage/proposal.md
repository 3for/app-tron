## Why

The current host-side fuzzing suite does not provide meaningful sanitizer-backed coverage for the external plugin signing flow.

Today the repository ships fuzz targets for `transaction_trigger_decode` and TIP712 only, while the external plugin path is covered only by a few Ragger regression tests. Those tests are useful for protocol sanity, but they do not stress hostile inputs, chunking, plugin callback failures, or UI-cache edge cases under sanitizers.

This leaves several production-relevant areas effectively unfuzzed:

- `SET_EXTERNAL_PLUGIN` payload parsing, plugin name bounds, signature-validation outcomes, and plugin-presence handling
- `SIGN_EXTERNAL_PLUGIN` APDU sequencing, BIP32/path preconditions, protobuf stream chunking, selector/contract matching, and parameter flush behavior
- plugin callback result handling for init, parameter delivery, finalize, provide-info, contract-id, and UI queries
- plugin UI cache sizing and failure behavior, including `numScreens` aggregation and query failures
- CI/export coverage, because the default ClusterFuzzLite build currently exports only the decoder fuzzer

This change proposes a dedicated external plugin fuzzing capability so these paths are covered by the same sanitizer-backed workflow already used elsewhere in the app.

## What Changes

- Add a dedicated host fuzz target for the external plugin APDU flow that compiles and executes the production `handleSetExternalPlugin` and `handleSignExternalPlugin` logic.
- Introduce deterministic host stubs for `os_lib_call` and related device/plugin boundaries so fuzz input can drive plugin presence, callback outcomes, and UI-query behavior.
- Add a curated corpus of semantic external-plugin seeds that exercise positive and negative setup/signing flows rather than relying only on mutation.
- Update fuzzing documentation and specifications to describe the new target, its intended boundaries, and its CI/export expectations.
- Extend the ClusterFuzzLite/export workflow so external plugin fuzzing is not a local-only target.

## Capabilities

### New Capabilities
- `external-plugin-fuzz-coverage`: The host fuzzing suite SHALL exercise the external plugin setup, signing, callback, and UI-cache control flow with sanitizer-backed coverage.

## Impact

- Affected code:
  - `tests/fuzzing/CMakeLists.txt`
  - `tests/fuzzing/src/*`
  - `tests/fuzzing/include/*`
  - `tests/fuzzing/corpus/*`
  - `tests/fuzzing/README.md`
  - `.clusterfuzzlite/build.sh`
  - `src/handlers/set_external_plugin.c`
  - `src/handlers/sign_external_plugin.c`
- Affected systems:
  - host-side fuzz harness construction
  - external plugin host stubs
  - fuzz corpus maintenance
  - ClusterFuzzLite artifact export
- No public app APDU changes are expected.
