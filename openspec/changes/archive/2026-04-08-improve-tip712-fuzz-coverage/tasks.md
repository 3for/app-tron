## 1. Align host fuzz execution with production TIP712 code

- [x] 1.1 Replace the host `read_bip32_path_712` stub with the production implementation in the TIP712 fuzz build
- [x] 1.2 Verify that `fuzz_tip712` still builds and that sign operations execute through the production BIP32 parser

## 2. Expand branch reachability in the TIP712 harness

- [x] 2.1 Extend the harness so `g_fuzz_settings` can cover relevant TIP712 settings combinations
- [x] 2.2 Add a `SCREEN_SIZE_WALLET` TIP712 fuzz build variant and confirm it compiles cleanly
- [x] 2.3 Improve the trusted-name and token-metadata host stubs so positive TIP712 formatting paths are reachable

## 3. Improve semantic fuzz input quality

- [x] 3.1 Create a curated TIP712 seed corpus from existing JSON and regression flows
- [x] 3.2 Add seeds or harness guidance for amount-join, empty-array, and trusted-name scenarios

## 4. Verify and document the new coverage

- [x] 4.1 Run local sanitizer-backed fuzz smoke tests for both the default and wallet TIP712 targets
- [x] 4.2 Update fuzzing documentation with the new TIP712 target behavior, seed workflow, and known coverage goals
