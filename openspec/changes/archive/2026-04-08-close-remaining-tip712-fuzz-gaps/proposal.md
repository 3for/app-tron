## Why

The previous TIP712 fuzzing change closed the biggest host-versus-production gaps in the modern `signMessageTIP712` pipeline, but two follow-up audits still found meaningful blind spots.

At the corpus level, the current curated seeds do not reliably exercise several hard-to-reach but production-relevant flows: datetime filters, `token_idx == 0xFF` permit-style amount-join resolution, `P1_PARTIAL` chunked field payloads, signed integers, reset-and-replay lifecycles, and trusted-name fallback behavior. These paths remain mutation-dependent today, which makes coverage fragile and regressions easy to miss.

At the suite level, the host fuzz setup still does not cover the legacy `sign_tip712_message` handler at all. That leaves one TIP712 signing path outside sanitizer-backed fuzzing even though the modern path is now well covered.

This change closes the highest-value remaining corpus and handler coverage gaps, but does not claim full host-side emulation of NBGL or cryptographic verification paths.

## What Changes

- Extend the TIP712 semantic seed corpus and its generator to cover the remaining high-value scenarios identified by the audits:
  - datetime filter formatting
  - `token_idx == 0xFF` permit/domain-address amount join
  - multi-chunk `P1_PARTIAL` field payloads
  - negative signed integer encoding
  - `OP_RESET` followed by a second full session
  - trusted-name fallback paths
- Add sanitizer-backed fuzz coverage for the legacy `sign_tip712_message` handler instead of limiting TIP712 fuzzing to the modern streamed pipeline.
- Update the TIP712 fuzz coverage specification so these scenarios are explicit requirements rather than implicit goals.
- Document the remaining host-only boundaries that this change still does not attempt to emulate fully, especially NBGL UI integration and real certificate/signature verification.

## Capabilities

### New Capabilities

### Modified Capabilities
- `tip712-fuzz-coverage`: The TIP712 fuzz suite SHALL cover the remaining high-value semantic corpus gaps in the modern handler and SHALL add sanitizer-backed coverage for the legacy TIP712 signing handler.

## Impact

- Affected code:
  - `tests/fuzzing/generate_tip712_corpus.py`
  - `tests/fuzzing/corpus/fuzz_tip712/*`
  - `tests/fuzzing/CMakeLists.txt`
  - `tests/fuzzing/src/*`
  - `src/handlers/sign_tip712_message.c`
  - `tests/fuzzing/README.md`
- Affected systems:
  - TIP712 host fuzz corpus generation
  - TIP712 fuzz target layout
  - TIP712 coverage documentation
- No public app API changes are expected.
