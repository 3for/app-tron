## Why

`app-tron` already supports trusted name v2, but its implementation is still a reduced subset of the `app-ethereum` behavior.

Compared with `app-ethereum`, the current `app-tron` implementation is missing several production-relevant capabilities:

- no support for `TN_TYPE_TOKEN`
- no support for `TN_SOURCE_MAB`
- no support for `OWNER` / `OWNER_DERIV_PATH` validation for MAB payloads
- account-name parsing is overly strict for v2 because every account name is treated like ENS and forced to end with `.eth`
- trusted names are stored in a single global slot and are wiped after the first lookup, which prevents multi-name sessions and diverges from `app-ethereum`
- the existing automated coverage only exercises the ENS-account and CAL-contract happy paths plus a few negative cases

This leaves `app-tron` behind the reference behavior already shipped in `app-ethereum`, and it blocks parity for workflows that need:

- MAB-style named accounts
- token trusted names in filtered TIP712 flows
- multiple trusted names loaded in the same session
- unit-level regression coverage for matching and validation behavior

This change proposes bringing `app-tron` trusted name v2 behavior to parity with the `app-ethereum` logic where that logic is meaningful for `app-tron`, and adding the missing automated coverage.

## What Changes

- Extend `app-tron` trusted name v2 parsing and validation to support the same type/source matrix already accepted by `app-ethereum`:
  - `ACCOUNT` from `ENS`
  - `ACCOUNT` from `MAB`
  - `CONTRACT` from `CAL`
  - `TOKEN` from `CAL`
- Add `OWNER` and `OWNER_DERIV_PATH` TLVs and enforce owner-address validation for `TN_SOURCE_MAB`.
- Align v2 name validation rules with `app-ethereum`:
  - only `ACCOUNT + ENS` names are forced to `.eth` + ENS charset
  - non-ENS v2 names use the generic trusted-name charset
- Replace the single-use trusted-name slot with multi-entry storage so multiple trusted names can be registered and queried in one session.
- Preserve compatibility with existing `app-tron` consumers in:
  - TIP712 filtering/UI substitution
  - transaction review flows that currently use trusted-name lookup
- Add Ragger regression tests and cmocka unit tests that cover the newly supported logic and the storage/matching behavior.

## Capabilities

### New Capabilities
- `trusted-name-v2-parity`: `app-tron` SHALL support the `app-ethereum` trusted name v2 feature set for supported TRON flows, including MAB and token trusted names, multi-entry lookup, and regression coverage.

## Impact

- Affected code:
  - `app-tron/src/handlers/provideTrustedName/*`
  - `app-tron/src/handlers/signMessageTIP712/*`
  - `app-tron/src/ui/*`
  - `app-tron/tests/ragger/test_trusted_name.py`
  - `app-tron/tests/ragger/test_tip712.py`
  - `app-tron/tests/ragger/client/tip712/InputData.py`
  - `app-tron/tests/unit/*`
- Affected systems:
  - trusted-name parsing and validation
  - trusted-name storage lifetime
  - TIP712 trusted-name lookup behavior
  - host-side regression and unit test coverage
- No public APDU opcode changes are required for the core parity work.

## Non-Goals

- Adding `INS_PROVIDE_PROXY_INFO` to `app-tron` as part of this change
- Reproducing `app-ethereum` GCS-specific trusted-name behavior that has no `app-tron` equivalent
- Full NFT trusted-name support
