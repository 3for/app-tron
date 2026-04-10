# trusted-name-v2-parity Specification

## Purpose

Define the `app-tron` trusted name v2 behavior required to align with the supported `app-ethereum` feature set, including accepted sources and types, validation semantics, storage lifetime, and automated coverage.

## Requirements

### Requirement: Trusted name v2 SHALL support the app-ethereum source/type matrix that is self-contained in app-tron

`app-tron` trusted name v2 SHALL accept the same v2 source/type combinations as `app-ethereum` for flows that do not depend on unsupported proxy metadata.

#### Scenario: ENS account trusted name is accepted
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_ACCOUNT`, `TN_SOURCE_ENS`, a matching challenge, and a matching chain ID
- **THEN** the payload MUST be accepted when its name passes ENS validation

#### Scenario: MAB account trusted name is accepted
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_ACCOUNT`, `TN_SOURCE_MAB`, a matching challenge, a matching chain ID, and valid owner metadata
- **THEN** the payload MUST be accepted

#### Scenario: CAL contract trusted name is accepted
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_CONTRACT`, `TN_SOURCE_CAL`, and a matching chain ID
- **THEN** the payload MUST be accepted

#### Scenario: CAL token trusted name is accepted
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_TOKEN`, `TN_SOURCE_CAL`, and a matching chain ID
- **THEN** the payload MUST be accepted

### Requirement: Trusted name v2 SHALL distinguish ENS and generic name validation

`app-tron` SHALL validate ENS account names differently from non-ENS v2 names.

#### Scenario: ENS account name requires ENS formatting
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_ACCOUNT` with `TN_SOURCE_ENS`
- **THEN** the name MUST end with `.eth` and MUST satisfy the ENS trusted-name charset rules

#### Scenario: MAB account name uses generic validation
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_ACCOUNT` with `TN_SOURCE_MAB`
- **THEN** the name MUST be validated with the generic trusted-name charset and MUST NOT be forced to end with `.eth`

#### Scenario: CAL token or contract name uses generic validation
- **WHEN** a v2 trusted-name payload uses `TN_TYPE_CONTRACT` or `TN_TYPE_TOKEN` with `TN_SOURCE_CAL`
- **THEN** the name MUST be validated with the generic trusted-name charset

### Requirement: Trusted name v2 SHALL validate MAB ownership metadata

`app-tron` SHALL reject `TN_SOURCE_MAB` payloads unless the supplied owner metadata proves ownership of the named address.

#### Scenario: MAB payload with missing owner metadata is rejected
- **WHEN** a v2 trusted-name payload uses `TN_SOURCE_MAB` but omits `OWNER` or `OWNER_DERIV_PATH`
- **THEN** the payload MUST be rejected

#### Scenario: MAB payload with mismatching owner is rejected
- **WHEN** a v2 trusted-name payload uses `TN_SOURCE_MAB` and the address derived from `OWNER_DERIV_PATH` does not match `OWNER`
- **THEN** the payload MUST be rejected

### Requirement: Trusted name lookup SHALL support multiple registered entries in one session

`app-tron` trusted-name lookup SHALL not be limited to a single destructive global slot.

#### Scenario: Multiple trusted names can be registered before signing
- **WHEN** the client provides more than one valid trusted-name payload before a signing flow consumes them
- **THEN** the app MUST retain each entry until the relevant cleanup boundary

#### Scenario: Lookup is non-destructive
- **WHEN** a trusted-name lookup succeeds for one field
- **THEN** the lookup MUST NOT implicitly erase all registered trusted names needed for subsequent fields in the same session

### Requirement: Trusted name v2 SHALL have dedicated regression and unit coverage

The repository SHALL include automated coverage for the parity behavior added by this change.

#### Scenario: Ragger covers MAB positive and negative flows
- **WHEN** the Ragger suite is executed
- **THEN** it MUST include trusted-name v2 cases for accepted MAB payloads and rejected MAB payloads with wrong or missing owner metadata

#### Scenario: Ragger covers token trusted-name substitution
- **WHEN** the Ragger suite exercises TIP712 trusted-name substitution
- **THEN** it MUST include at least one v2 `TN_TYPE_TOKEN` scenario sourced from `TN_SOURCE_CAL`

#### Scenario: cmocka covers validation and repeated lookup behavior
- **WHEN** the unit-test suite is executed
- **THEN** it MUST include cases for ENS validation, generic-name validation, MAB owner validation, and repeated lookup across multiple registered trusted names
