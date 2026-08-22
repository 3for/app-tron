# Release checklist

## Blocking: signed metadata migration

The fix for the non-canonical `ExchangeDetails` signature encoding introduces
a canonical, domain-separated v1 signed payload without changing any protobuf
schema. Updated firmware verifies v1 first and then accepts only the restricted,
unambiguous legacy grammar during migration.

Complete the following items with Ledger before releasing this change:

- [ ] Share the canonical v1 byte layout and legacy validation rules with the
      Ledger security and release teams and obtain approval for the migration.
- [ ] Confirm that the `.proto` schemas, field numbers, and wire types remain
      unchanged and that the v1 marker exists only inside the authenticated
      payload. The nanopb `.options` and generated C buffer sizes do change.
- [ ] Agree on the rollout order: release supporting firmware first, then
      publish canonical v1 exchange metadata. Old firmware safely rejects v1
      signatures, so publishing the list first would break compatibility.
- [ ] Have the authorized holder of `TRONLEDGER_SIGN` regenerate
      `signed_list/signedList_Exchanges.txt` and `signed_list/exchanges10.js`
      with `signed_list/getTRC10Exchanges.py`. Never copy the signing key into
      the repository or CI logs.
- [ ] Validate a regenerated v1 record on Speculos and a physical Ledger device,
      including the displayed token names and precisions.
- [ ] Decide with Ledger whether exchange ID 103 should be removed, corrected,
      or reissued: its 32-byte token name exceeds the existing protobuf field's
      31-byte decoded limit and was already unusable before this fix.
- [ ] Agree on criteria and timing for retiring the legacy verification path
      after supported hosts and published metadata have migrated to v1.
- [ ] Share the canonical TokenDetails v1 layout with Ledger and obtain approval:
      `TRON-TOKEN-DETAILS || 0x01 || id_len || id || name_len || name || precision`.
      Confirm that this changes only the authenticated bytes and local nanopb
      buffer sizes; no `.proto` field number, type, or chain wire encoding changes.
- [ ] Agree on the TokenDetails rollout order with Ledger: release firmware that
      verifies v1 and the restricted seven-digit legacy format first, then have
      the authorized holder of `TRONLEDGER_SIGN` regenerate and publish
      `signed_list/tokens10.js` with `signed_list/getTRC10Tokens.py`. Publishing
      v1 token metadata before supporting firmware would break old devices.
- [ ] Obtain and record Ledger's approval for widening accepted canonical TRC10
      IDs to one through nineteen decimal digits without multi-digit leading
      zeros, covering java-tron's decimal `long` ID representation. Legacy
      verification remains limited to `TRX` or exactly seven digits and exists
      only for already-published signatures.
- [ ] Validate both a regenerated TokenDetails v1 record and an existing legacy
      token record on Speculos and a physical Ledger device. Include a synthetic
      eight-digit ID case to prove future java-tron IDs are not rejected.
- [ ] Agree with Ledger on criteria and timing for retiring legacy TokenDetails
      verification and whether TokenDetails and ExchangeDetails should receive
      distinct verification keys during the next metadata-key rotation.
- [ ] Run the cross-type replay regression using the published exchange-166
      signature and confirm that the metadata APDU returns `INCORRECT_DATA`
      before any approval screen is displayed.
- [ ] Decide whether token IDs 1001788, 1000825, and 1000748 should be removed
      or reissued: their 32-byte names exceed the existing TokenDetails protobuf
      field's 31-byte decoded limit and were already unusable before this fix.

Release evidence must include the firmware version, signed-list revision,
Ledger approval reference, successful v1 verification, successful legacy
compatibility verification, and rejection of all documented replay payloads.

## Blocking for ambiguous assets: TRC20 swap contract binding

The swap signer now binds a TRC20 approval to the token's 21-byte Tron contract
address. Existing app-exchange configurations using
`[ticker length][ticker][decimals]` remain compatible when that metadata maps to
exactly one contract in the app's trusted token table. Metadata shared by
multiple contracts is intentionally rejected unless the signed Tron
sub-configuration appends the explicit contract address:

`[ticker length][ticker][decimals][21-byte contract address]`

Complete the following items with the Ledger app-exchange and CAL owners before
enabling or releasing swap support for an asset with ambiguous metadata:

- [ ] Confirm the optional Tron sub-configuration extension and rollout plan
      with the Ledger app-exchange and CAL owners.
- [ ] Publish a signed CAL configuration containing the exact 21-byte Tron
      contract address for every ambiguous asset that must remain swappable.
- [ ] Run the official app-exchange integration tests for native TRX, existing
      legacy unique-metadata tokens, and the extended address-bound format.
- [ ] Verify that approving contract A and submitting otherwise identical token
      calldata for contract B is rejected on Speculos and a physical device.
- [ ] Record the app-exchange revision, CAL record revision, firmware version,
      and Ledger approval reference in the release evidence.

Unique-metadata legacy configurations do not require a CAL format migration,
but the release evidence should still include at least one successful legacy
TRC20 swap to guard the existing app-exchange flow.
