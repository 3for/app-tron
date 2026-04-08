## Context

The current TIP712 fuzz suite already exercises the modern `signMessageTIP712` code well enough to find real parsing, hashing, path, and UI bugs. It now includes settings variation, a wallet-screen build, and a semantic corpus for nested arrays, empty arrays, amount joins, and trusted-name hits.

Two remaining coverage gaps matter:

- The curated corpus is still missing several structured flows that are hard to reach by mutation alone: datetime filters, permit-style `token_idx == 0xFF` resolution, long payload chunking through `P1_PARTIAL`, negative signed integers, reset-and-replay sessions, and trusted-name fallback behavior.
- The legacy TIP712 handler in `src/handlers/sign_tip712_message.c` still has no sanitizer-backed fuzz target.

The audits also noted that host fuzzing still relies on device-facing stubs for NBGL transitions and signature verification. Those are real boundaries, but they are not the most cost-effective next target for this change.

This design therefore aims to close the highest-value remaining corpus and handler coverage gaps, not to claim full host-side emulation of NBGL or cryptographic verification behavior.

## Goals / Non-Goals

**Goals:**
- Make the remaining high-value semantic corpus scenarios explicit and replayable.
- Add legacy TIP712 handler coverage so both production signing paths are fuzzed.
- Update the coverage spec so future regressions in these scenarios are visible.
- Keep the host fuzz environment maintainable by reusing existing JSON fixtures and deterministic synthetic helpers where possible.

**Non-Goals:**
- Full emulation of NBGL UI behavior in host fuzzing.
- Replacing Ragger integration tests for UI or certificate behavior.
- Adding real network-backed metadata or cryptographic certificate validation to the fuzz harness.
- Broadening this change to non-TIP712 handlers.

## Decisions

### 1. Close the remaining corpus gaps with curated semantic seeds

The missing scenarios should be added as curated seeds generated from maintainable sources, not left to chance mutation.

Why:
- The missing paths all depend on coordinated multi-step state, not single malformed bytes.
- Stable seeds make replay and regression checks straightforward.
- The generator already supports most of the needed encodings; the gap is mostly seed selection, not harness redesign.

Alternatives considered:
- Rely on longer mutation runs to reach these paths.
Why rejected:
- It does not provide stable regression coverage and leaves important logic effectively untested in bounded smoke runs.

### 2. Add a separate legacy TIP712 fuzz target instead of overloading the modern stream harness

The legacy `sign_tip712_message` path should get its own target or dedicated mode, rather than being bolted awkwardly onto the streamed APDU model used for `signMessageTIP712`.

Why:
- The legacy handler has a different control surface and does not naturally fit the current multi-op stream format.
- A separate target makes it obvious which code path is being exercised and keeps corpus expectations clearer.

Alternatives considered:
- Extend `fuzz_tip712` with additional operation types for legacy signing.
Why rejected:
- It mixes two different protocol models in one harness and makes corpus maintenance harder.

### 3. Treat NBGL and real signature verification as explicit boundaries, not implicit coverage claims

This change should document that host fuzzing still uses stubs for NBGL transitions and certificate/signature verification, rather than pretending those branches are fully covered.

Why:
- The recent audits correctly observed that these areas remain stub-backed.
- Explicitly documenting the boundary prevents overclaiming TIP712 fuzz coverage.
- Full UI and crypto emulation would meaningfully increase complexity without closing the highest-value current gaps.

Alternatives considered:
- Expand this change to emulate full NBGL review flow and real signature verification.
Why rejected:
- Too large for the current scope, and better handled by dedicated integration testing or a later focused change.

### 4. Prefer fixture-derived seeds over opaque handcrafted blobs when possible

New seeds should be derived from existing `tests/ragger/tip712_input_files` data where practical, with only the synthetic flows kept as small handwritten fixtures.

Why:
- Existing regression fixtures already encode realistic type graphs and user-visible flows.
- Reusing them reduces drift between integration tests and fuzz regression seeds.

Alternatives considered:
- Hand-maintain all new seeds as binary blobs.
Why rejected:
- Harder to review, harder to extend, and easier to break accidentally.

## Risks / Trade-offs

- [Larger corpus slows startup and reduction] → Keep new seeds minimal and scenario-specific; do not mirror the entire Ragger fixture set.
- [Legacy target increases maintenance cost] → Keep the target narrow and focused on the production legacy handler only.
- [Documented stub boundaries may be mistaken for “won’t fix”] → State them as explicit non-goals for this change, not permanent exclusions.
- [Fixture-derived seeds may still miss some edge combinations] → Keep the generator extensible and allow targeted synthetic seeds for protocol-specific flows such as reset/replay.

## Migration Plan

1. Extend the corpus generator and seed set to cover the remaining semantic scenarios.
2. Add and build a legacy TIP712 fuzz target.
3. Replay the updated corpus against modern, wallet, and legacy targets.
4. Update README/spec text to describe the newly covered scenarios and the remaining host-only boundaries.

Rollback:
- Remove the legacy target if it destabilizes the host fuzz build.
- Keep the new semantic seeds that still apply to the modern targets.

## Open Questions

- Should the legacy TIP712 target reuse the existing corpus directory with a subfolder, or keep a separate corpus for clarity?
- Is one legacy build variant enough, or should legacy wallet-screen behavior also be compiled if conditional branches exist there?
- Should a later follow-up change target NBGL interaction emulation, or is Ragger sufficient for that layer?
