## Context

The external plugin flow is security-relevant input handling that sits on top of parsing, APDU state management, and plugin-controlled callback responses. It covers two production handlers:

- `src/handlers/set_external_plugin.c`
- `src/handlers/sign_external_plugin.c`

Those handlers currently have no dedicated sanitizer-backed fuzz target. The only nearby coverage comes from:

- `transaction_trigger_decode_fuzzer`, which exercises the protobuf stream decoder in isolation but does not execute the external plugin handlers
- a small set of Ragger tests, which mostly cover negative-path protocol behavior and do not stress mutation-heavy hostile input under ASan/MSan

The result is a real blind spot: the repo fuzzes the decoder subcomponent, but not the higher-level external plugin orchestration that wires APDU sequencing, selector/contract matching, plugin callback contracts, and UI-cache preparation together.

The goal of this change is to close that gap with a maintainable host fuzz harness, not to emulate the full device or plugin runtime perfectly.

## Goals / Non-Goals

**Goals:**
- Add sanitizer-backed coverage for the production external plugin setup and signing handlers.
- Exercise cross-APDU state transitions, not just individual packet parsing.
- Make plugin callback outcomes fuzz-selectable through deterministic host stubs.
- Add a semantic seed corpus that reaches the main positive and negative external plugin flows.
- Ensure the new target is documented and exported by the repository's supported fuzz workflow.

**Non-Goals:**
- Full emulation of a real plugin binary or the Ledger secure runtime.
- Replacing Ragger integration tests for end-to-end UI review behavior.
- Real cryptographic verification of external plugin certificates in the host fuzz harness.
- Broadening this proposal to all custom contract signing code outside the external plugin path.

## Decisions

### 1. Add a dedicated APDU-state-machine fuzz target

The main target should fuzz the external plugin flow through the production handlers, not through a synthetic helper layer.

Why:
- The risk is in the orchestration between `handleSetExternalPlugin` and `handleSignExternalPlugin`, including shared context and APDU sequencing.
- A handler-level target can exercise production error-code mapping, reset behavior, and stream-observer integration.
- This is the narrowest target that still covers the real control flow.

Alternatives considered:
- Fuzz only `external_plugin_feed_data_chunk` or only the decoder.
Why rejected:
- That would miss setup/sign sequencing, plugin state initialization, and post-decode UI preparation.

### 2. Model plugin behavior with deterministic scripted stubs

The harness should replace `os_lib_call` with a host stub whose behavior is driven by fuzz input, rather than hard-coding a single success path.

Why:
- The production logic branches heavily on callback outcomes such as `TRON_PLUGIN_RESULT_OK`, `FALLBACK`, and unavailable/error states.
- Scripted stubs allow bounded, reproducible coverage of callback contracts without requiring a real plugin binary.
- This approach keeps the harness self-contained and suitable for sanitizers.

Alternatives considered:
- Always return success from plugin callbacks.
Why rejected:
- That would leave most of the riskier external plugin error handling unfuzzed.

### 3. Encode the fuzz input as a sequence of operations, not a single blob

The APDU harness should replay a compact operation stream with setup, sign, chunking, and reset operations.

Why:
- The external plugin path depends on cross-request state and `P1_FIRST`/`P1_MORE`/`P1_LAST` sequencing.
- A sequence-based format makes it easy to reach setup-then-sign, wrong-order, reset, and replay scenarios.
- This mirrors the successful TIP712 approach while staying tailored to the external plugin control surface.

Alternatives considered:
- Feed one opaque buffer directly into a single handler invocation.
Why rejected:
- Too weak for a stateful multi-APDU protocol and would miss the most important sequencing bugs.

### 4. Seed the corpus with semantic scenarios instead of relying on mutation only

The initial corpus should include realistic setup and signing scenarios that cover both success and failure behavior.

Why:
- The highest-value branches depend on coordinated state: matching contract/selector, chunk boundaries, plugin callback scripts, and UI query counts.
- Mutation alone is unlikely to reach these paths reliably in bounded smoke runs.
- Curated seeds make regressions visible and replayable.

Alternatives considered:
- Start with an empty corpus.
Why rejected:
- Coverage would be too fragile, especially for multi-step state-machine paths.

### 5. Make CI/export coverage explicit

The supported fuzz workflow should export the new target instead of leaving it as a local-only harness.

Why:
- A target that exists only in local builds does not provide reliable ongoing protection.
- The current default ClusterFuzzLite export already under-exports app-relevant fuzz targets; the new target should not repeat that pattern.

Alternatives considered:
- Document the target but keep default export unchanged.
Why rejected:
- That would preserve the current operational gap and make regressions easy to miss.

## Risks / Trade-offs

- [Host stubs drift from production plugin semantics] → Keep the stubs narrow and document that they are reachability shims, not full plugin emulation.
- [Sequence-based inputs increase harness complexity] → Use a compact, well-bounded operation format with a small fixed config header.
- [Semantic corpus maintenance cost grows] → Keep the seed set focused on distinct control-flow scenarios rather than mirroring all Ragger fixtures.
- [Adding the target to export increases fuzz build time] → Prefer exporting a small set of high-value app fuzzers rather than every experimental target.

## Migration Plan

1. Add a host fuzz target that links the production external plugin handlers with deterministic host stubs.
2. Define a compact operation format for setup, sign chunks, and reset flows.
3. Add curated corpus inputs that exercise the main positive and negative plugin flows.
4. Update fuzzing docs and the capability spec.
5. Extend the default ClusterFuzzLite/export workflow to include the new target.

Rollback:
- Remove the new external plugin target from the build/export workflow if it destabilizes host fuzzing.
- Keep any reusable host-stub improvements that also benefit future fuzz targets.

## Open Questions

- Should the default ClusterFuzzLite export include the external plugin target alone, or also export the existing TIP712 targets at the same time?
- Is a single APDU-state-machine target enough, or does the UI-cache/query layer eventually warrant a second narrowly focused helper target?
- Should the external plugin corpus reuse any existing protobuf transaction fixtures, or stay fully synthetic for tighter reviewability?
