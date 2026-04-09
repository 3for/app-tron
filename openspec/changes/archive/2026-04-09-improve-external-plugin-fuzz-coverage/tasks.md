## 1. Add handler-level external plugin fuzz coverage

- [x] 1.1 Add a sanitizer-backed fuzz target that compiles and executes `src/handlers/set_external_plugin.c` and `src/handlers/sign_external_plugin.c`
- [x] 1.2 Add host-side support code so fuzz input can drive deterministic `os_lib_call` outcomes for plugin presence and callback messages
- [x] 1.3 Verify that the target can replay multi-APDU setup/sign sequences, including reset and invalid ordering flows

## 2. Cover the high-value external plugin branches

- [x] 2.1 Make the harness reach contract/selector match and mismatch cases, partial parameter flushes, and plugin callback failures
- [x] 2.2 Make the harness reach finalize/provide-info/query-contract-id/query-contract-ui flows, including fallback and rejected outcomes
- [x] 2.3 Make the harness exercise UI-cache bounds such as zero screens, oversized screen counts, and query failure in the middle of cache preparation

## 3. Add and maintain a semantic external plugin corpus

- [x] 3.1 Add curated corpus seeds for positive setup/sign flow, selector mismatch, contract mismatch, parameter-chunk failure, finalize fallback, and UI-query failure
- [x] 3.2 Add at least one seed with non-32-byte tail parameters and at least one seed with multi-chunk `P1_MORE` / `P1_LAST` delivery
- [x] 3.3 Replay the maintained corpus successfully against the new external plugin target in a local smoke run

## 4. Document and operationalize the new coverage

- [x] 4.1 Update `tests/fuzzing/README.md` to describe the new target, corpus, and explicit host-stub boundaries
- [x] 4.2 Update the ClusterFuzzLite/export workflow so the external plugin target is exported by a supported build path
- [x] 4.3 Record any remaining out-of-scope boundaries, especially real plugin binaries, full device runtime behavior, and real cryptographic verification
