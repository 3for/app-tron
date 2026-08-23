# Release checklist

Every unchecked item in a **Blocking** or **Unresolved security blocker** section
must be completed before the affected feature is released, or covered by an
explicit Ledger-approved risk acceptance and mitigation. Conditional blockers
apply only to the scope stated in their section.

## Common release gates

- [ ] Bump `VERSION` and pin the release commit, Ledger SDK versions, and every
      app-exchange, host, CAL, or signed-list revision used by the release.
- [ ] Require green application builds and Ragger tests for every target in
      `ledger_app.toml`, lint and unit tests, the protobuf regeneration check,
      and the official TRON app-exchange Swap workflow.
- [ ] Confirm tracked generated protobuf files match their schemas and options,
      generated release artifacts are reproducible from the recorded inputs,
      and the release worktree contains no unexplained changes.
- [ ] Review security-relevant UI changes on the applicable BAGL and NBGL
      devices, and run the section-specific Speculos and physical-device tests
      below.

## Conditional blocker: immutable CI and development dependencies

The repository currently executes mutable external identities in build,
test, static-analysis, and developer environments. Direct instances include
`:latest` Ledger containers, GitHub actions selected by major tags, Ledger
reusable workflows selected by `@v1`, the app-exchange Swap workflow selected
by `@develop`, and incompletely locked Python tooling. The Coverity job also
injects its submission credentials into a mutable scanner container.

Pinning only the caller's reusable-workflow reference is insufficient when the
called Ledger workflow still resolves transitive actions or build images through
mutable tags. Treat this section as a blocker before CI-produced binaries,
test results, or static-analysis results are accepted as release evidence.

- [ ] Pin every repository-controlled `uses:` reference to a reviewed full
      40-character commit SHA and every job or documented development container
      to a reviewed `@sha256:` digest. Cover checkout, lint, protobuf, Coverity,
      build/Ragger, guidelines, and Swap workflows.
- [ ] Lock direct Python build/test tools to reviewed versions and hashes,
      including packages currently installed without versions or through open
      ranges. Update all pins only through dependency-review pull requests.
- [ ] Coordinate with the Ledger `ledger-app-workflows` and `app-exchange`
      maintainers to publish approved immutable workflow revisions and remove
      transitive branch, tag, and `:latest` resolution, or expose reviewed image
      digests as supported inputs. Preserve the mandatory app-store guideline
      checks while using immutable references.
- [ ] Coordinate with the Ledger `ledger-app-builder` maintainers to publish and
      record supported digests and provenance attestations for the builder,
      scanner, and development images, together with an auditable update policy.
- [ ] Split Coverity analysis from credential-bearing submission so the scanner
      image never receives `COVERITY_SCAN_TOKEN` or `COVERITY_SCAN_EMAIL`.
      Declare explicit least-privilege permissions, disable persisted checkout
      credentials where unnecessary, and rotate configured Coverity credentials
      after the hardened workflow is deployed.
- [ ] Replace the documented blanket `--privileged` development invocation with
      the minimum devices, capabilities, and writable mounts required for each
      build, test, or hardware-loading task. Verify the supported commands with
      the Ledger app-builder maintainers.
- [ ] Add a policy check that rejects unapproved mutable workflow, action,
      container, and dependency references, and add an automated reviewed update
      process so immutable pins do not silently become stale.
- [ ] Run the complete build, Ragger, protobuf, lint, Swap, and Coverity matrix
      with the pinned dependency set; independently reproduce release binaries
      and compare hashes before they are promoted.

These changes do not alter APDUs, transaction encoding, or old-firmware
compatibility. The compatibility tradeoff is operational: immutable pins stop
automatic upstream updates, so Ledger security fixes must be adopted through
explicitly reviewed pin-update changes.

## Deferred security coordination: Exchange swap source-account binding

The legacy Exchange `SIGN_TRANSACTION` ABI authenticates the asset, amount, fee,
and destination, but not the source owner, permission ID, or signer identity.
The host later supplies both the transaction and BIP32 path. Checking only that
the transaction owner matches the host-selected path would still allow the host
to switch owner and path together, and would break valid TRON active permissions
where owner and signer differ.

This issue remains deferred pending coordination with Ledger Secure SDK,
app-exchange, app-tron, and the host/account-selection owner. This section
records the unresolved risk and the work required to close it; it does not by
itself block an unrelated firmware release. Any release that changes the legacy
Swap behavior or claims this issue is resolved must complete these items or
record an explicit Ledger-approved disposition.
The current product constraint is to keep the app-exchange approval as the only
user confirmation; adding a second coin-app review would be a separate,
compatibility-affecting Ledger product decision.

- [ ] Define the trusted source of the approved `(owner, permission_id, signer)`
      identity with Ledger Security. Merely adding host-controlled fields to the
      shared structure does not create an authorization binding.
- [ ] Introduce a versioned Exchange-to-coin signing ABI that carries the
      approved source triple and binds it to the app-exchange review without
      adding an unapproved silent fallback.
- [ ] Have app-tron compare the approved owner with `txContent.account`, the
      approved permission with `txContent.permission_id`, and the approved signer
      with the address derived from the signing path. Preserve legitimate active
      permissions where owner and signer are different.
- [ ] Define capability negotiation, minimum compatible versions, rollout order,
      and anti-downgrade behavior for app-tron, app-exchange, the Ledger SDK, and
      relevant hosts.
- [ ] Define the legacy policy. If authenticated source identity is unavailable,
      fail closed or obtain an explicitly approved second coin-app review; never
      silently retain automatic signing with incomplete authorization.
- [ ] Run TRX and TRC20 regressions covering account A success, simultaneous
      owner/path substitution to account B, each source field mismatching
      independently, and a valid active-permission owner/signer split.
- [ ] Verify every failure returns an unsuccessful Exchange result and releases
      no signature on Speculos and a physical device.

The migration may intentionally break legacy Swap combinations that cannot
provide authenticated source identity. Ordinary non-Swap signing is unaffected.

## Blocking for metadata publication: safe generated-source output

`signed_list/getTRC10Exchanges.py` currently inserts remote token names into a
JavaScript source literal without output encoding. `getTRC20Tokens.py` similarly
inserts remote symbols into C source; its output format is also stale relative
to the current `tokens.c` table, and the committed fragment already contains a
malformed quoted symbol.

This section blocks regeneration or publication of the affected metadata, and
blocks copying the TRC20 fragment into firmware. It does not block a firmware-only
release that neither regenerates nor republishes these artifacts.

- [ ] Encode the `exchanges10.js` `pair` field with a target-language-safe
      serializer. Preserve the CommonJS export, object schema, runtime string
      value, protobuf `message`, signature payload, and signature version unless
      downstream consumers explicitly approve a format migration.
- [ ] Add malicious-name regressions for single and double quotes, backslashes,
      comment delimiters, control characters, invalid encoding, and length
      boundaries. Require `node --check` and an isolated module-load test that
      proves the decoded values are unchanged and no injected expression runs.
- [ ] Identify the actual downstream `exchanges10.js` consumer and verify the
      safely encoded artifact with it. Changing to JSON or another file schema,
      rather than only encoding literals, requires a coordinated consumer
      migration.
- [ ] Decide whether to retire `getTRC20Tokens.py` and
      `signedList_TRC20.txt` or replace them with a generator matching the current
      `tokenDefinition_t` and `tokens.c` format. Do not copy the current fragment
      into firmware.
- [ ] If the C generator is retained, validate address, ticker representation and
      destination-buffer length (including terminator and any prefix/suffix),
      decimals, and contract uniqueness; encode C strings with a dedicated
      encoder and compile the complete generated declaration with warnings as
      errors.
- [ ] Capture and review the upstream metadata snapshot and a semantic artifact
      diff before signing or publication. Audit and replace any already-published
      generated artifact that fails the new checks.

Output encoding alone does not change the firmware protocol and is compatible
with old firmware. However, `getTRC10Exchanges.py` also creates v1-signed
ExchangeDetails metadata, so an actual republication must still follow the
firmware-first v1 migration below.

## Blocking for metadata publication: independently approved provenance

The TRC10 token and exchange generators currently fetch display-critical names,
precisions, exchange membership, and pair data from a single live TronGrid
source in the same network-connected process that loads `TRONLEDGER_SIGN` and
signs the results. TLS and canonical signatures authenticate transport and the
Ledger metadata authority; they do not prove that the upstream values are
semantically correct. A valid authority signature over false metadata can still
produce a misleading asset label, pair, or displayed amount on the device.

This section blocks regeneration, signing, or publication of TokenDetails and
ExchangeDetails metadata. It does not block a firmware-only release that uses
already-approved metadata and does not republish the lists.

- [ ] Coordinate with Ledger Security, Release, and the metadata-signing owner
      to define the authoritative data sources, approval quorum, signing-key
      custody, revocation procedure, and evidence retained for each publication.
- [ ] Split acquisition, semantic approval, and signing. Fetch an unsigned,
      deterministic canonical manifest without access to `TRONLEDGER_SIGN`; the
      production key must be used only by an offline or equivalently isolated
      signer against an already-approved manifest digest.
- [ ] Record source identities, block heights or immutable snapshot revisions,
      response hashes, and every signed ID, name, precision, exchange membership,
      and pair. Reproduce or verify the records against at least one independent
      full node or an independently maintained approved manifest.
- [ ] Fail closed on source disagreement, duplicate IDs, unexpected deletions or
      list-size changes, invalid field ranges, unapproved semantic changes, and
      any mismatch between the approved manifest digest and the signing input.
- [ ] Require a complete machine-readable semantic diff and two-person or
      multiparty approval of the exact manifest digest before signing. Account
      explicitly for every addition, deletion, name or precision change, and
      exchange-pair change rather than relying on spot checks.
- [ ] Make every published JavaScript/list artifact traceable to the approved
      manifest, generator revision, signature format, approvals, and output
      hashes; monitor published metadata for unexpected churn and exercise the
      documented key-revocation and replacement procedure.
- [ ] Add regressions proving that an independently sourced disagreement, a
      post-approval record change, a digest mismatch, duplicate ID, missing or
      changed precision, unexpected deletion, and provider failure cannot reach
      the signing operation. Verify a valid approved manifest end to end on
      Speculos and a physical device.

These controls do not change protobuf/APDU schemas or the signed payload format,
so they are compatible with old firmware. They change the publication ceremony
and require coordination with Ledger's signing and release owners; TronGrid or
java-tron changes are not required as long as an independent verification source
and immutable provenance can be established.

## Blocking: signed metadata v1 migration

`ExchangeDetails` and `TokenDetails` now use canonical, domain-separated v1
signed payloads. Updated firmware verifies v1 first and accepts only each
record type's restricted legacy grammar during migration. Layout approval and
schema/options review below block the supporting firmware release; regeneration
and publication occur only after that firmware is available. The shared
requirements are consolidated here to avoid contradictory rollout instructions.

- [ ] Share both canonical layouts and legacy validation rules with Ledger
      Security and Release and obtain approval:
      `TRON-EXCHANGE-DETAILS || 0x01 || uint64be(exchange_id) || length-prefixed token fields`
      and
      `TRON-TOKEN-DETAILS || 0x01 || id_len || id || name_len || name || precision`.
- [ ] Confirm that protobuf field numbers, field types, and chain wire encodings
      remain unchanged, and that v1 markers exist only inside authenticated
      payloads. Review the changed nanopb options and generated C buffer sizes.
- [ ] Release firmware supporting v1 and the restricted legacy formats before
      publishing v1 metadata. Old firmware rejects v1 signatures, so publishing
      new lists first would break compatibility.
- [ ] Complete the safe generated-source output and independently approved
      provenance requirements above. Then have the authorized
      `TRONLEDGER_SIGN` holder regenerate and record
      `signed_list/signedList_Exchanges.txt`,
      `signed_list/exchanges10.js`, `signed_list/signedList_TRC10.txt`, and
      `signed_list/tokens10.js` with the recorded generator revision, and publish
      only the artifacts required by the documented Ledger delivery process.
      Never expose the signing key to the repository, CI, or logs. Retiring or
      rewriting the unrelated TRC20 C generator is not a v1 prerequisite.
- [ ] Validate regenerated ExchangeDetails and TokenDetails v1 records and
      representative existing legacy records on Speculos and physical devices,
      including displayed names, precisions, and a synthetic eight-digit token ID.
- [ ] Obtain Ledger approval for canonical TRC10 IDs of one through nineteen
      decimal digits with no multi-digit leading zero. Keep legacy verification
      limited to `TRX` or exactly seven digits for TokenDetails, and to `_` or
      exactly seven digits for ExchangeDetails. Legacy acceptance exists only
      for already-published signatures.
- [ ] Re-scan regenerated lists for records exceeding the 31-byte decoded-name
      limit and resolve every result. The current baseline includes exchange 103
      and token IDs 1001788, 1000825, and 1000748; do not assume this list remains
      exhaustive after regeneration.
- [ ] Run the cross-type replay regression using the recorded published
      exchange-166 fixture and confirm the metadata APDU returns `INCORRECT_DATA`
      before any approval screen.
- [ ] Agree on criteria and timing for retiring each legacy verifier, and decide
      whether ExchangeDetails and TokenDetails receive distinct keys at the next
      metadata-key rotation.

## Conditional blocker: TRC20 swap contract binding

The Swap signer binds a TRC20 approval to the token's 21-byte Tron contract
address. Existing app-exchange configurations using
`[ticker length][ticker][decimals]` remain compatible when that metadata maps to
exactly one contract in the trusted token table. Metadata shared by multiple
contracts is intentionally rejected unless the signed Tron sub-configuration
appends the explicit contract address:

`[ticker length][ticker][decimals][21-byte contract address]`

Complete these items with the Ledger app-exchange and CAL owners before enabling
or releasing Swap support for an asset with ambiguous metadata:

- [ ] Confirm the optional Tron sub-configuration extension and rollout plan
      with the app-exchange and CAL owners.
- [ ] Publish a signed CAL configuration containing the exact 21-byte Tron
      contract address for every ambiguous asset that must remain swappable.
- [ ] Run the official app-exchange integration tests for native TRX, legacy
      unique-metadata tokens, and the extended address-bound format.
- [ ] Verify that approving contract A and submitting otherwise identical token
      calldata for contract B is rejected on Speculos and a physical device.

Unique-metadata legacy configurations do not require a CAL format migration, but
release evidence must include at least one successful legacy TRC20 Swap.

## Blocking: protobuf forward-compatibility review

The decoder prevents clear signing whenever signed transaction bytes contain
fields omitted from the trusted review model. Those transactions can still use
the existing full-hash review when blind signing is enabled, while Swap mode
must fail closed. `DelegateResourceContract.lock_period` field 6 is modeled and
displayed directly.

- [ ] Approve the policy that unmodeled transaction fields force full-hash
      review instead of being silently clear-signed or rejected outright.
- [ ] Verify app-tron Swap mode rejects every transaction with an unmodeled field,
      app-exchange propagates the unsuccessful result, and no signature is
      returned. app-exchange is not responsible for parsing TRON protobuf.
- [ ] Capture the release-time mainnet values of `getAllowProtoFilterNum`,
      `getMaxDelegateLockPeriod`, and the delegate-lock feature gate, and re-check
      current java-tron schemas and actuators for newly meaningful fields.
- [ ] Verify ordinary vote transactions remain clear-signed, while
      `VoteWitnessContract.support`, nonempty `raw.auths`/`raw.scripts`,
      permission-update contents, `Contract.provider`, and `ContractName` force
      full-hash review.
- [ ] Verify canonical or omitted legacy `Any.type_url` values remain
      clear-signable, while mismatched, noncanonical, duplicate, or unsupported
      type URLs force full-hash review and fail closed in Swap mode.
- [ ] Verify a missing or empty final `Any.value` is rejected before decoding,
      rather than entering clear-sign or full-hash approval.
- [ ] Verify locked delegation with nonzero and zero/default `lock_period` and an
      unlocked legacy delegation, including the exact displayed period and
      resulting transaction signatures.

## Release evidence

- [ ] Record the firmware version and commit, device and SDK versions, CI run
      links, Speculos and physical-device results, and every applicable
      app-exchange, host, CAL, generator, upstream snapshot, and signed-list
      revision.
- [ ] Record every action and reusable-workflow commit SHA, container digest,
      dependency lock revision, provenance-verification result, and independently
      reproduced release-artifact hash used by the release.
- [ ] Record Ledger approval references, artifact hashes, successful v1 and
      legacy compatibility results, rejection of replay and downgrade fixtures,
      and the disposition of every malformed or over-limit metadata record.
- [ ] Record completion, continued deferral, or explicit Ledger-approved risk
      acceptance for every applicable deferred, unresolved, or conditional item
      above.
