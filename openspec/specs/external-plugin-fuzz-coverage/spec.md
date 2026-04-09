# external-plugin-fuzz-coverage Specification

## Purpose
Define the required sanitizer-backed fuzz coverage for the external plugin setup and signing flow so the repository continuously exercises the production handler control flow, plugin callback contracts, and UI-cache edge cases.

## Requirements

### Requirement: External plugin fuzzing SHALL execute the production setup and signing handlers

The host fuzz suite SHALL include a target or equivalent harness mode that compiles and executes the production `handleSetExternalPlugin` and `handleSignExternalPlugin` logic.

#### Scenario: External plugin fuzz target is available
- **WHEN** the host fuzz suite is built
- **THEN** there MUST be a sanitizer-backed target that links `src/handlers/set_external_plugin.c` and `src/handlers/sign_external_plugin.c`

### Requirement: External plugin fuzzing SHALL cover stateful APDU sequencing

The external plugin fuzz harness SHALL support replaying stateful multi-APDU flows rather than only isolated single-call parsing.

#### Scenario: Setup then sign flow is replayable
- **WHEN** fuzz input performs a valid setup operation followed by one or more sign operations
- **THEN** the harness MUST be able to execute the shared external plugin state transition from setup into signing

#### Scenario: Invalid APDU ordering is replayable
- **WHEN** fuzz input performs sign continuation operations without a valid initialized signing session, or mixes reset and continuation operations incorrectly
- **THEN** the harness MUST be able to execute the production error-handling path without crashing

### Requirement: External plugin fuzzing SHALL model plugin callback outcomes

The host fuzz environment SHALL allow fuzz input to control deterministic plugin callback outcomes for the production external plugin call sites.

#### Scenario: Plugin presence can succeed or fail
- **WHEN** fuzz input selects plugin presence success, absence, or host-call failure during setup
- **THEN** the harness MUST be able to execute the corresponding production `SET_EXTERNAL_PLUGIN` branch

#### Scenario: Runtime plugin callbacks can succeed or fail
- **WHEN** fuzz input selects success, fallback, unavailable, or rejected outcomes for init, parameter, finalize, provide-info, contract-id, or UI-query callbacks
- **THEN** the harness MUST be able to execute the corresponding production signing branch without requiring a real plugin binary

### Requirement: External plugin fuzzing SHALL cover selector, contract, and parameter-chunk behavior

The external plugin fuzz target SHALL exercise the main trigger-data matching and parameter delivery branches used before plugin finalization.

#### Scenario: Contract and selector match is reachable
- **WHEN** fuzz input provides trigger data whose contract address and selector match the configured external plugin expectation
- **THEN** the harness MUST be able to execute plugin initialization and parameter delivery

#### Scenario: Contract or selector mismatch is reachable
- **WHEN** fuzz input provides trigger data whose contract address or selector does not match the configured external plugin expectation
- **THEN** the harness MUST be able to execute the non-plugin path without incorrectly initializing the plugin

#### Scenario: Partial parameter tail is reachable
- **WHEN** fuzz input ends trigger data with a final parameter chunk that is smaller than 32 bytes
- **THEN** the harness MUST be able to execute the tail flush path without crashing or corrupting state

### Requirement: External plugin fuzzing SHALL cover UI-cache preparation bounds

The external plugin fuzz target SHALL reach the cache-building logic that runs after finalize and provide-info.

#### Scenario: Valid UI cache build is reachable
- **WHEN** fuzz input drives plugin finalization to a supported generic UI response with a bounded number of screens
- **THEN** the harness MUST be able to execute contract-id and contract-UI queries and populate the cached UI state

#### Scenario: Invalid UI cache sizes are reachable
- **WHEN** fuzz input drives plugin metadata that yields zero screens or more than `EXTERNAL_PLUGIN_UI_MAX_ITEMS`
- **THEN** the harness MUST be able to execute the corresponding rejection path without crashing

#### Scenario: Mid-cache UI query failure is reachable
- **WHEN** fuzz input drives contract-id lookup success but forces contract-UI query failure for one of the requested screens
- **THEN** the harness MUST be able to execute the cache reset and error path without leaving stale UI state behind

### Requirement: External plugin fuzzing SHALL include semantic seed corpus inputs

The external plugin fuzz suite SHALL include a maintained corpus that exercises representative structured flows beyond trivial malformed bytes.

#### Scenario: Corpus includes positive and mismatch flows
- **WHEN** the external plugin corpus is prepared for local or CI fuzzing
- **THEN** it MUST include seeds covering a successful setup/sign path, contract mismatch, and selector mismatch

#### Scenario: Corpus includes callback-failure and chunking flows
- **WHEN** the external plugin corpus is prepared for local or CI fuzzing
- **THEN** it MUST include seeds covering parameter callback failure, finalize or provide-info fallback, non-32-byte parameter tail, and multi-chunk sign delivery

#### Scenario: Corpus includes UI-query failure flow
- **WHEN** the external plugin corpus is prepared for local or CI fuzzing
- **THEN** it MUST include at least one seed that reaches contract-id success and then fails during contract-UI query or cache preparation

### Requirement: External plugin fuzzing SHALL be exportable in supported fuzz workflows

The repository's supported fuzz workflow SHALL provide a documented and maintained path to build and export the external plugin fuzz target for local or CI fuzzing.

#### Scenario: Supported export path is documented
- **WHEN** contributors follow the repository fuzzing documentation
- **THEN** they MUST be able to build and export the external plugin fuzz target through a documented supported workflow
