## 1. Expand the semantic TIP712 corpus

- [x] 1.1 Extend `generate_tip712_corpus.py` to emit seeds for datetime filters, permit-style `token_idx == 0xFF` amount joins, signed integers, and trusted-name fallback
- [x] 1.2 Add or derive seeds that force `P1_PARTIAL` chunked field payloads and `OP_RESET` followed by a second complete session
- [x] 1.3 Replay the updated corpus successfully against `fuzz_tip712` and `fuzz_tip712_wallet`

## 2. Add legacy TIP712 fuzz coverage

- [x] 2.1 Add a sanitizer-backed fuzz target that compiles and executes `src/handlers/sign_tip712_message.c`
- [x] 2.2 Add at least one curated legacy TIP712 replay input and verify that the legacy target consumes it successfully

## 3. Document the remaining coverage boundaries

- [x] 3.1 Update TIP712 fuzzing documentation to describe the newly covered corpus scenarios and the legacy target
- [x] 3.2 Document that NBGL interaction and real certificate/signature verification remain host-stubbed and are out of scope for this change
- [x] 3.3 Run a local smoke verification pass across modern, wallet, and legacy TIP712 fuzz targets and record the outcome
