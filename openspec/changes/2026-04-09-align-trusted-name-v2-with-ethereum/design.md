## Context

`app-tron` and `app-ethereum` currently share the same trusted-name TLV family, but they do not share the same v2 behavior.

The main gaps in `app-tron` today are:

- source/type support is narrower:
  - `app-tron` accepts only `ACCOUNT` and `CONTRACT`
  - `app-tron` accepts only `CAL` and `ENS`
- storage is weaker:
  - `app-tron` keeps one trusted name in `g_trusted_name_info`
  - `get_trusted_name()` wipes the stored value after the first lookup
- name validation is stricter than intended:
  - every v2 account name is parsed like ENS
  - this rejects valid MAB-style display names such as `MyLedger`
- there is no MAB proof-of-ownership validation path
- tests do not cover token names, MAB names, or multiple-name sessions

`app-ethereum` already solved these problems in a way that fits the same Ledger metadata model, so it is the right reference for parity.

At the same time, not every `app-ethereum` behavior can be copied mechanically. The biggest example is proxy-aware trusted-name matching, which depends on `provide_proxy_info` support that `app-tron` does not currently expose.

The design goal is therefore:

- bring over the v2 trusted-name logic that is self-contained inside the trusted-name feature
- keep existing `app-tron` consumers working
- explicitly defer proxy-specific parity until `app-tron` has the required upstream feature

## Goals / Non-Goals

**Goals:**
- Support the `app-ethereum` v2 source/type combinations that do not depend on missing `app-tron` features.
- Align v2 validation semantics for ENS versus non-ENS names.
- Support multiple trusted names per session.
- Add dedicated unit and regression coverage for the new behavior.

**Non-Goals:**
- Add full proxy-aware address remapping in this change.
- Introduce a new trusted-name consumer outside the existing transaction-review and TIP712 flows.
- Expand the feature to NFT trusted names.

## Decisions

### 1. Port the `TOKEN` and `MAB` source/type support, not only the tests

The parity target is behavioral, not cosmetic.

Why:
- `app-tron` tests cannot meaningfully mirror `app-ethereum` unless the production parser and verifier accept the same v2 payload categories.
- `TOKEN` and `MAB` support are self-contained inside trusted-name parsing, verification, and lookup.

Implications:
- `TN_SOURCE_MAB` must be added to the enum and accepted in v2 source parsing.
- `TN_TYPE_TOKEN` must be accepted in v2 type parsing and matching.
- Input builders used by tests must be able to serialize owner metadata for MAB.

### 2. Align validation semantics with `app-ethereum`

Only `ACCOUNT + ENS` names should be forced through ENS validation. Non-ENS v2 names should use the generic trusted-name charset.

Why:
- `app-ethereum` already uses this split because MAB and CAL names are display labels, not ENS names.
- Reusing the current `app-tron` rule would keep rejecting valid MAB labels and preserve the parity gap.

Implications:
- the current parser-time `.eth` enforcement for every account name must move or be relaxed
- the verifier must distinguish:
  - `v1`
  - `v2 ACCOUNT + ENS`
  - all other v2 combinations

### 3. Replace single-slot storage with multi-entry storage

`app-tron` should stop using a single global trusted-name slot for v2 behavior and adopt a list-backed store similar to `app-ethereum`.

Why:
- `app-ethereum` supports multiple names loaded in the same session
- token and MAB scenarios are more likely to need multiple lookups before session cleanup
- a destructive `get_trusted_name()` API makes order-dependent bugs hard to reason about and hard to test

Implications:
- introduce owned storage for trusted-name entries
- add an explicit cleanup path instead of wiping on first lookup
- update current callers to rely on the returned object/string without destructive side effects

### 4. Defer proxy remapping to a follow-up change

The `app-ethereum` matcher remaps `CONTRACT` and `TOKEN` lookups through proxy metadata when available. `app-tron` currently has no `provide_proxy_info` implementation, and the current source already documents that gap.

Why:
- porting proxy-aware matching without the underlying metadata feature would produce dead code or fake parity
- the current user request is about trusted-name v2 logic and tests, not introducing a new APDU feature surface

Implications:
- this proposal will document proxy remapping as deferred parity
- tests added in this change will cover direct-match behavior only

### 5. Add both cmocka unit tests and Ragger regression tests

Regression tests alone are not enough because the risky logic is partly in internal validation and storage behavior.

Why:
- parser/validator edge cases are easier and faster to exercise in cmocka
- end-to-end lookup and UI substitution still need Ragger coverage
- the repo already has both testing frameworks available

Test split:
- cmocka:
  - type/source acceptance
  - ENS versus generic charset decisions
  - MAB owner validation
  - multiple trusted-name registration and lookup lifetime
- Ragger:
  - MAB accepted and rejected flows
  - v2 token trusted-name substitution in TIP712
  - multiple trusted-name session behavior

## Risks / Trade-offs

- [Storage refactor touches multiple consumers] → Keep the public lookup API stable where possible and isolate storage ownership inside `provideTrustedName`.
- [MAB validation introduces derivation dependencies] → Reuse the same BIP32 and address derivation helpers already used elsewhere in the app.
- [Tests become slower or more complex] → Push parsing/matching edge cases into cmocka and keep Ragger focused on user-visible scenarios.
- [Proxy parity remains incomplete] → Document it explicitly as deferred so future work is not blocked by ambiguity.

## Migration Plan

1. Extend trusted-name enums, context, and TLV tags to cover MAB metadata.
2. Refactor storage from a single global slot to owned multi-entry state.
3. Align v2 validation rules with the `app-ethereum` ENS/generic split.
4. Add MAB owner verification and token acceptance.
5. Update current trusted-name consumers to work with non-destructive lookup.
6. Add cmocka unit tests for validation and lookup behavior.
7. Add Ragger regression tests for MAB and token scenarios.

Rollback:
- revert to the previous single-entry implementation if the storage refactor destabilizes existing flows
- keep new tests that describe intended parity behavior, marking blocked scenarios explicitly if needed

## Open Questions

- Should the storage cleanup be tied to the same lifecycle event as today, or should it be made explicit at the end of each signing flow?
- Do we want one shared trusted-name unit-test target, or separate white-box and black-box test files?
- Should proxy-aware matching be proposed immediately as a follow-up change once the core parity work lands?
