# Release checklist

## Blocking: ExchangeDetails signature migration

The fix for the non-canonical `ExchangeDetails` signature encoding introduces
a canonical, domain-separated v1 signed payload without changing any protobuf
schema. Updated firmware verifies v1 first and then accepts only the restricted,
unambiguous legacy grammar during migration.

Complete the following items with Ledger before releasing this change:

- [ ] Share the canonical v1 byte layout and legacy validation rules with the
      Ledger security and release teams and obtain approval for the migration.
- [ ] Confirm that `proto/core/*` and `proto/misc/*` remain unchanged and that
      the v1 marker exists only inside the authenticated payload.
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

Release evidence must include the firmware version, signed-list revision,
Ledger approval reference, successful v1 verification, successful legacy
compatibility verification, and rejection of both documented replay payloads.
