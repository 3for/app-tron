## Why

The current `fuzz_tip712` target is effective at exercising the core TIP712 parsing, hashing, and path-management code, but several important runtime variants remain uncovered. In particular, the host harness replaces some production helpers with stubs, fixes settings to a single value, and compiles only one conditional-build path, which leaves meaningful TIP712 behavior untested.

## What Changes

- Expand the TIP712 fuzz harness so it can execute both BASIC and FULL filtering flows under multiple settings combinations.
- Add coverage for the production `read_bip32_path_712` implementation instead of only the host stub.
- Add a wallet-screen build variant so `SCREEN_SIZE_WALLET` TIP712 branches are fuzzed.
- Improve host-side trusted-name and token-metadata behavior so positive formatting paths are reachable.
- Add stable, semantics-aware TIP712 seed corpus inputs to improve reachability of multi-step states such as amount-join and struct-review flows.
- Add coverage assertions or regression checks that make future coverage regressions visible in CI or local fuzz review.

## Capabilities

### New Capabilities
- `tip712-fuzz-coverage`: The host fuzzing suite SHALL exercise the major TIP712 parsing, settings, UI-state, and conditional-build paths that exist in production code.

### Modified Capabilities

## Impact

- Affected code:
  - `tests/fuzzing/CMakeLists.txt`
  - `tests/fuzzing/src/fuzz_tip712.c`
  - `tests/fuzzing/src/tip712_fuzz_support.c`
  - `tests/fuzzing/include/*.h`
  - `src/helpers.c`
  - `src/handlers/signMessageTIP712/*`
- Affected systems:
  - Host-side fuzz harness construction
  - TIP712 seed corpus management
  - Optional wallet-screen build variant for fuzzing
- No public app API changes are expected.
