## ADDED Requirements

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
The host TIP712 fuzz environment SHALL make positive trusted-name and amount-join formatting paths reachable.

#### Scenario: Trusted name hit is reachable
- **WHEN** fuzz input and host stubs describe a matching trusted-name condition
- **THEN** the TIP712 UI formatting logic MUST be able to execute the trusted-name-hit path rather than always falling back to raw address handling

#### Scenario: Amount join completion is reachable
- **WHEN** fuzz input provides the coordinated filtering and field data needed for token/value amount-join processing
- **THEN** the TIP712 UI formatting logic MUST be able to execute the completed amount-join formatting path

### Requirement: TIP712 fuzzing SHALL include semantic seed corpus inputs
The TIP712 fuzz suite SHALL include a maintained seed corpus that exercises representative structured flows beyond trivial parser setup.

#### Scenario: Seed corpus includes known hard-to-reach flows
- **WHEN** the TIP712 corpus is prepared for local or CI fuzzing
- **THEN** it MUST include seeds covering nested arrays, empty arrays, filtering flows, trusted-name flows, and amount-join flows
