# TODO

## Security

- [ ] Bind Exchange swap approval to the account that is actually debited.
  - Status: deferred pending coordination with the app-exchange and Ledger SDK maintainers.
  - Constraint: swap signing must remain automatic in the coin app; app-tron must not add a
    second transaction approval screen after the app-exchange review.
  - Current limitation: the legacy `SIGN_TRANSACTION` ABI provides the asset, amount, fee and
    destination, but does not provide an authenticated expected owner, permission ID or signing
    identity. Checking only that the transaction owner matches the host-supplied signing path does
    not prevent a host from selecting account/path B together.
  - Proposed direction: introduce a versioned Exchange-to-coin signing ABI that carries the
    approved source owner, permission ID and signer identity. Have app-tron compare all three with
    `txContent.account`, `txContent.permission_id` and the address derived from the signing path,
    while allowing the owner and signer to differ for valid TRON active permissions.
  - Compatibility: keep the existing app-exchange review/signing UX, define an explicit migration
    policy for legacy `SIGN_TRANSACTION`, and fail closed when the source identity is unavailable
    rather than silently retaining the incomplete authorization binding.
  - Required regressions: account A succeeds; matching payment from account/path B fails; active
    permissions preserve distinct owner and signer identities; failure returns an unsuccessful
    Exchange result and no signature.
