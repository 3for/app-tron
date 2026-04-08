## Context

`fuzz_tip712` already compiles the full `src/handlers/signMessageTIP712/` directory and has uncovered real bugs in typed-data access, path traversal, schema hashing, and UI formatting. However, the current harness does not approximate production execution closely enough in several places:

- `read_bip32_path_712` is provided by a host stub instead of the production implementation.
- Host settings are fixed to `g_fuzz_settings = 0`, which suppresses important BASIC-mode UI paths.
- The fuzz build does not compile a `SCREEN_SIZE_WALLET` variant, so wallet-specific conditional branches are absent.
- Trusted-name behavior is stubbed to always miss, and token/trusted-name positive flows are therefore weakly covered.
- Some multi-step states, especially amount-join and struct-review flows, are technically reachable but poorly seeded.

The goal is not to make fuzzing behave exactly like device firmware, but to eliminate the biggest mismatches between host fuzz behavior and production TIP712 control flow.

## Goals / Non-Goals

**Goals:**
- Fuzz the production `read_bip32_path_712` code path.
- Exercise TIP712 BASIC-mode flows under multiple settings combinations.
- Exercise both non-wallet and wallet-screen conditional branches.
- Make trusted-name-hit and amount-join states realistically reachable.
- Provide a maintainable seed corpus and basic regression checks for reachability.

**Non-Goals:**
- Perfect emulation of Ledger device UI behavior.
- Replacing Ragger integration tests with fuzzing.
- Full coverage of unrelated handlers outside TIP712.
- Introducing network-backed metadata or certificate validation into the host harness.

## Decisions

### 1. Replace the stubbed BIP32 path parser with the production implementation

The fuzz target should compile and link `src/helpers.c` and stop redefining `read_bip32_path_712` in the TIP712 host support layer.

Why:
- The current stub differs from production behavior.
- The parser is security-relevant input handling and should not be exempt from fuzzing.

Alternative considered:
- Keep the stub and add unit tests for `src/helpers.c`.
Why rejected:
- It preserves a divergence between fuzz and production exactly where parsing bugs are likely to hide.

### 2. Model settings as fuzz-controlled state, not a constant zero

The harness should derive `g_fuzz_settings` from fuzz input or from explicit operation bytes in the APDU stream, rather than pinning all settings off.

Why:
- BASIC-mode display logic depends directly on `S_SIGN_BY_HASH` and `S_VERBOSE_TIP712`.
- A constant zero setting collapses a large branch space.

Alternative considered:
- Build multiple dedicated fuzz binaries, each with one fixed setting combination.
Why rejected:
- It increases maintenance cost and still leaves per-input settings transitions unavailable.

### 3. Add a wallet-screen fuzz build variant

The fuzz suite should compile an additional TIP712 target with `SCREEN_SIZE_WALLET` enabled.

Why:
- The code contains meaningful compile-time branching for wallet devices.
- Runtime input mutation cannot reach code that was never compiled.

Alternative considered:
- Rely only on Ragger tests for wallet-specific branches.
Why rejected:
- Ragger is useful for behavior regression but not a substitute for sanitizer-backed hostile-input fuzzing.

### 4. Keep host stubs, but make them semantically richer where reachability depends on them

The harness should continue stubbing device-only behavior, but selected helpers should support positive cases:
- trusted-name lookup may return deterministic synthetic hits for selected inputs
- token metadata may be seeded or injected
- UI callbacks may remain non-interactive, but state progression should remain observable

Why:
- The goal is reachability of production logic, not full device emulation.

Alternative considered:
- Re-implement the whole device-side UI stack.
Why rejected:
- Too expensive and unnecessary for the missing coverage identified here.

### 5. Add semantics-aware seed corpus rather than relying on mutation alone

Seed generation should be based on existing TIP712 JSON inputs and known filtering cases, including empty arrays, trusted-name flows, amount joins, and nested structs.

Why:
- Several uncovered states require coordinated sequences that mutation alone reaches inefficiently.

Alternative considered:
- Keep an empty corpus and wait for long fuzz runs to discover the states.
Why rejected:
- It wastes compute and makes regression verification weaker.

## Risks / Trade-offs

- [Richer host stubs drift from production semantics] → Keep stubs narrow, deterministic, and explicitly documented as fuzz reachability shims.
- [Extra build variants increase maintenance cost] → Limit the scope to the existing non-wallet target plus one `SCREEN_SIZE_WALLET` variant.
- [Settings controlled by fuzz input may create unrealistic sequences] → Use constrained encoding or explicit setup operations rather than unconstrained global bit flipping.
- [Larger corpus slows fuzz startup] → Keep only high-signal semantic seeds and deduplicate regularly.

## Migration Plan

1. Update the host fuzz build to compile the production BIP32 helper and add a wallet-screen variant.
2. Extend the harness input format or setup logic to vary settings safely.
3. Improve selected host stubs for trusted-name and token-driven positive paths.
4. Add a curated corpus derived from current TIP712 regression inputs.
5. Validate with local `fuzz_tip712` runs and confirm that sanitizer-enabled builds still compile cleanly.

Rollback:
- Revert the new variant target and host-harness changes if they destabilize local fuzzing.
- Retain the seed corpus even if some richer stubs are rolled back.

## Open Questions

- Should settings variation be encoded as dedicated harness operations or as a pre-stream header byte block?
- Is one wallet-screen build variant enough, or do Flex/Stax differences justify separate targets later?
- Should coverage regression checking be purely documented/manual, or enforced in CI with a bounded smoke corpus?
