## 1. Align trusted-name v2 parsing and validation

- [x] 1.1 Add support for `TN_SOURCE_MAB` and the `OWNER` / `OWNER_DERIV_PATH` TLVs in `provideTrustedName`
- [x] 1.2 Accept `TN_TYPE_TOKEN` in v2 parsing and verification
- [x] 1.3 Align name validation with `app-ethereum` so only `ACCOUNT + ENS` requires `.eth` and ENS charset, while other v2 names use the generic trusted-name charset
- [x] 1.4 Keep existing v1 behavior unchanged while refactoring the v2 validation path

## 2. Refactor trusted-name storage and lookup

- [x] 2.1 Replace the single global trusted-name slot with owned multi-entry storage
- [x] 2.2 Make `get_trusted_name()` non-destructive so multiple lookups can happen in one session
- [x] 2.3 Add an explicit cleanup path for trusted-name state at the right signing/session boundary
- [x] 2.4 Preserve compatibility for existing transaction-review and TIP712 consumers

## 3. Port the MAB proof-of-ownership logic

- [x] 3.1 Derive the owner public key from `OWNER_DERIV_PATH`
- [x] 3.2 Convert the derived key to a wallet address and compare it with the provided `OWNER`
- [x] 3.3 Reject MAB payloads with missing owner metadata or mismatching owner information

## 4. Add automated coverage

- [x] 4.1 Extend `tests/ragger/test_trusted_name.py` with MAB positive and negative cases mirroring the `app-ethereum` coverage shape
- [ ] 4.2 Extend TIP712 regression coverage to exercise token trusted-name substitution and multi-name sessions
- [x] 4.3 Add a cmocka unit-test target for trusted-name validation, lookup, and storage behavior
- [x] 4.4 Add unit cases for ENS-account validation, generic-name validation, token acceptance, MAB rejection, and repeated lookup behavior

## 5. Record the remaining parity gap explicitly

- [ ] 5.1 Document that proxy-aware trusted-name remapping remains deferred until `app-tron` gains `provide_proxy_info` support
- [ ] 5.2 Document which `app-ethereum` tests were mirrored directly and which ones were adapted to `app-tron` flows
