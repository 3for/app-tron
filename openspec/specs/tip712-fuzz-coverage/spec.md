# tip712-fuzz-coverage Specification

## Purpose
TBD - created by archiving change improve-tip712-fuzz-coverage. Update Purpose after archive.
## Requirements
### Requirement: TIP712 fuzzing SHALL exercise the production BIP32 parser
The host TIP712 fuzz target SHALL execute the same `read_bip32_path_712` implementation that production TIP712 signing uses.

#### Scenario: Fuzz input reaches BIP32 parsing
- **WHEN** the TIP712 fuzz target processes a sign operation that contains a BIP32 path payload
- **THEN** the production `src/helpers.c` implementation of `read_bip32_path_712` MUST be the code that parses the path

### Requirement: TIP712 fuzzing SHALL cover settings-dependent BASIC mode behavior
The host TIP712 fuzz target SHALL support executing TIP712 flows under multiple relevant settings combinations, including combinations that enable BASIC-mode UI progression.

#### Scenario: BASIC mode with sign-by-hash enabled
- **WHEN** fuzz input selects BASIC filtering mode and enables `S_SIGN_BY_HASH`
- **THEN** the harness MUST allow execution to progress through BASIC-mode display logic without being forced into the blind-signing error path

#### Scenario: BASIC mode with verbose mode enabled
- **WHEN** fuzz input selects BASIC filtering mode and enables `S_VERBOSE_TIP712`
- **THEN** the harness MUST allow execution to progress through BASIC-mode display logic without being forced into the blind-signing error path

### Requirement: TIP712 fuzzing SHALL cover wallet-screen conditional branches
The TIP712 fuzz suite SHALL compile and run at least one variant that enables `SCREEN_SIZE_WALLET`.

#### Scenario: Wallet build is available
- **WHEN** the fuzz suite is built for TIP712
- **THEN** there MUST be a fuzz target or build configuration that compiles the `SCREEN_SIZE_WALLET` branches used by TIP712 handlers and UI logic

### Requirement: TIP712 fuzzing SHALL reach positive trusted-name and amount-join flows
The host TIP712 fuzz environment SHALL make both positive and fallback trusted-name behavior reachable, and SHALL make amount-join flows reachable for both direct token-index lookup and permit-style domain-address lookup.

#### Scenario: Trusted name hit is reachable
- **WHEN** fuzz input and host stubs describe a matching trusted-name condition
- **THEN** the TIP712 UI formatting logic MUST be able to execute the trusted-name-hit path rather than always falling back to raw address handling

#### Scenario: Trusted name fallback is reachable
- **WHEN** fuzz input describes a trusted-name filter but the lookup intentionally misses, including all-zero-address fallback cases
- **THEN** the TIP712 UI formatting logic MUST be able to execute the fallback path without crashing or skipping subsequent field handling

#### Scenario: Amount join completion is reachable
- **WHEN** fuzz input provides the coordinated filtering and field data needed for token/value amount-join processing
- **THEN** the TIP712 UI formatting logic MUST be able to execute the completed amount-join formatting path

#### Scenario: Permit-style token resolution is reachable
- **WHEN** fuzz input uses `token_idx == 0xFF` for an amount-join token flow and the domain contract address matches seeded token metadata
- **THEN** the TIP712 filtering and UI logic MUST be able to resolve token metadata through the domain contract address path

### Requirement: TIP712 fuzzing SHALL include semantic seed corpus inputs
The TIP712 fuzz suite SHALL include a maintained seed corpus that exercises representative structured flows beyond trivial parser setup, including the remaining hard-to-reach scenarios identified by coverage audit.

#### Scenario: Seed corpus includes known filtering and join flows
- **WHEN** the TIP712 corpus is prepared for local or CI fuzzing
- **THEN** it MUST include seeds covering nested arrays, empty arrays, filtering flows, trusted-name hit flows, trusted-name fallback flows, and amount-join flows

#### Scenario: Seed corpus includes chunked and signed payload flows
- **WHEN** the TIP712 corpus is prepared for local or CI fuzzing
- **THEN** it MUST include seeds covering multi-chunk `P1_PARTIAL` field payloads and negative signed integer values

#### Scenario: Seed corpus includes datetime and permit flows
- **WHEN** the TIP712 corpus is prepared for local or CI fuzzing
- **THEN** it MUST include seeds covering datetime filters and `token_idx == 0xFF` permit-style domain token resolution

#### Scenario: Seed corpus includes lifecycle reset flow
- **WHEN** the TIP712 corpus is prepared for local or CI fuzzing
- **THEN** it MUST include at least one seed that performs a complete session, issues `OP_RESET`, and then performs a second complete TIP712 session

### Requirement: TIP712 fuzzing SHALL cover the legacy signing handler
The TIP712 fuzz suite SHALL include sanitizer-backed coverage for the legacy `sign_tip712_message` production handler in addition to the modern streamed `signMessageTIP712` flow.

#### Scenario: Legacy TIP712 fuzz target is available
- **WHEN** the TIP712 fuzz suite is built
- **THEN** there MUST be a fuzz target or equivalent harness mode that compiles and executes `src/handlers/sign_tip712_message.c`

#### Scenario: Legacy TIP712 seeds are replayable
- **WHEN** the maintained TIP712 corpus is replayed in a local or CI smoke run
- **THEN** the legacy TIP712 target MUST be able to consume at least one curated legacy signing scenario without crashing

