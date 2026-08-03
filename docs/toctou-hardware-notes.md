# Review-context TOCTOU: hardware behaviour and severity notes

App: Tron Ledger wallet (VERSION 0.7.6). Companion to
`tests/test_toctou.py` (Speculos) and the interactive hardware PoCs in
`examples/`.

## Summary

`apdu_dispatcher()` keeps accepting and dispatching APDUs while an approval
review is displayed on screen. Every operation shares the same globals
(`transactionContext`, `publicKeyContext`, `G_io_apdu_buffer`, and the display
buffers `fromAddress` / `toAddress` / `fullContract` / `fullHash`), so a
malicious host can start operation A, let the device show A's review, then send
operation B while the user is still reading. B overwrites the shared state, and
the approve callback runs against B's context or a corrupted display.

This is a genuine time-of-check / time-of-use flaw and a WYSIWYS ("what you see
is what you sign") violation. Its *exploitability on a physical device*, though,
depends on a transport detail described below, and differs sharply between the
variants. This note records that split so the severity is assessed correctly.

## Why the outcome differs on physical hardware

The device has a single global `G_io_apdu_buffer` shared by all channels, and
`io_exchange` services exactly one APDU at a time. A handler either:

- replies **synchronously** (`io_send_sw` / `helper_send_response_pubkey`
  return a result immediately), or
- **defers** — it calls `ux_flow_display(...)` and `return 0` without sending,
  so the reply is produced later by the approve callback
  (`ui_callback_tx_ok` / `ui_callback_address_ok` →
  `io_send_response_pointer(...)`).

The interleave attack always leaves the *reviewed* command (A) deferred; that
deferred reply is the one the attacker ultimately wants (a signature, or a
confirmed address). The problem is the *injected* command (B):

- If B replies **synchronously**, that reply consumes the transport's single
  exchange cycle and drives `io_exchange` back into a fresh receive-wait. When
  the user later approves, A's deferred reply is written into `G_io_apdu_buffer`
  but there is no outstanding exchange to flush it — and the next inbound APDU
  overwrites the buffer on receipt. A's reply is silently destroyed. It never
  reaches the wire, so no host-side read strategy can recover it. This was
  confirmed empirically: a 20-second pure-read window after approval sees
  nothing, and the subsequent `GET_APP_CONFIGURATION` pumps come back normally
  (the device is idle), proving the signature was never emitted.

- If B also **defers** (it is itself an approval-gated command that sends no
  early reply), then exactly one reply stays pending, approval flushes it, and
  the host receives it normally.

So the determining factor is the **injection type, not the transport medium**.
The shared-buffer / single-`io_exchange` model sits above HID, BLE and NFC
alike, so BLE and NFC drop the synchronous-injection reply the same way HID
does. Speculos is the exception: its emulated raw-socket I/O does not reproduce
the hardware single-buffer overwrite timing, so on the emulator the synchronous
variants *do* return their reply. That is why the Speculos suite can assert the
receivable outcome that physical hardware refuses.

## Variant matrix

| Variant (test / example) | Injected APDU | Injection reply | Overwrites | Post-approval reply on HW | Hardware impact |
|---|---|---|---|---|---|
| Address-verification swap (`run_addr`) | `GET_PUBLIC_KEY` non-confirm B | **synchronous** (B's pubkey) | `publicKeyContext`, `toAddress` | **dropped** | Not demonstrated on HW; B seen only in the injection's own reply |
| UI-buffer clobbering (`toctouUiClobber.py`) | `GET_PUBLIC_KEY` non-confirm B | **synchronous** (B's pubkey) | `toAddress` (display) | **dropped** | Display corrupted (proven on device); no signature exfiltrated |
| Signing-key substitution (`keysub`) | `SIGN_PERSONAL_MESSAGE` first-chunk B | **synchronous** (`0x9000`) | `transactionContext.bip32_path` | **dropped** | Device signs with B internally; signature not returned |
| Pending-hash replacement (`test_toctou_pending_hash_replacement`) | second `SIGN_TXN_HASH` H2 | **deferred** | `transactionContext.hash` | **returned** | Signature over the injected hash is receivable |
| Signing-key substitution, deferred (`keysub2`) | second `SIGN_TXN_HASH` (path B, hash H) | **deferred** | `transactionContext` (restarts review) | **returned** | Receivable signature; review redraws with B's context |

Note the recurring detail for the synchronous variants: the injected
non-confirming `GET_PUBLIC_KEY` returns B's public key *in its own synchronous
reply*. That is a normal query available at any time and is not itself evidence
of the swap. The swap is only demonstrated if the **confirmed** (post-approval)
reply returns B — which is exactly the deferred reply the transport drops. The
updated `run_addr` therefore only declares VULNERABLE when B appears
post-approval, and otherwise reports "inconclusive on hardware".

## Empirical hardware results (Nano S+, app 0.7.6)

- `toctouUiClobber.py`: the transfer review's destination changed on the trusted
  screen from the real `THChUb7p2bwY6ReAiJXao6qc2ZGn88T46v` to account B's
  `TRjM7cVvUGMn8k9xJW2avfFgfwKpWfVHLS` after the injection, while the parsed and
  signed transaction (`txContent`) was untouched. No signature was returned.
- `keysub`: injected `0x9000` seen pre-approval; no signature after approval.
- `run_addr`: B returned only in the pre-approval injection reply; the confirmed
  reply never came back.

All three are consistent with the mechanism above: state/display corruption
succeeds, but the deferred reply that would make it exfiltratable is swallowed.

## Severity assessment

- **Display-only and synchronous-injection variants** (UI clobbering,
  address-swap, keysub): on physical HID (and, by the shared-buffer argument,
  BLE/NFC) the corrupted result is not returned to the host, so no broadcastable
  transaction or completed address handshake is produced. The realised impact is
  device-side display/state deception without exfiltration — a real integrity
  defect, but not a direct fund-theft primitive over a physical transport. Rated
  **low-to-moderate** on hardware; the full receivable break exists on Speculos.

- **Deferred-injection signing substitution** (hash replacement, `keysub2`): a
  signature over content the user never reviewed is returned to the host on
  physical hardware. Rated **high**.

Treat the transport drop as safety-by-accident, not a control. It is an artifact
of the current shared-buffer I/O model; a future SDK change (e.g. per-channel
buffering) could make the synchronous variants exfiltratable too, and the
deferred path is already exploitable today.

## Recommended fix

Add a "one approval flow at a time" guard so the dispatcher refuses interleaved
commands while a review is pending, independent of transport:

1. Set a global "review pending" flag when an approval UX starts
   (`ux_flow_display`).
2. Clear it in every approve/reject callback.
3. In `apdu_dispatcher()`, reject a newly received command with a busy/denied
   status (e.g. `0x6985`) while the flag is set.

Pitfall to get right: do **not** reject APDUs that are part of legitimate
multi-chunk assembly (large transactions split across several APDUs arrive
*before* the review is displayed). Gate the rejection on "an approval flow is
actually on screen", not "a transaction is in progress", or large transfers
will break. Once fixed, the `security_poc` tests in `tests/test_toctou.py`
should be inverted to assert the interleaved APDU is refused.

## Getting a receivable proof for the synchronous variants

Because the synchronous-injection signature never leaves a physical device, use
Speculos to confirm the device *does* act on B's context:

```
speculos --model nanos2 -d 1234 bin/app.elf
gdb-multiarch bin/app.elf -ex 'target remote :1234'
(gdb) b signTransaction
(gdb) c
# run the keysub / clobber flow, approve on screen
(gdb) finish
(gdb) p/x transactionContext.bip32_path       # == account B
(gdb) x/72bx &transactionContext.signature    # 65-byte sig over the reviewed hash
```

Recover the signer from those bytes off-device to confirm the substitution. On
hardware the same bytes are unreachable by design (there is no host-visible RAM
read), which is the root reason the synchronous variants cannot be weaponised
over a physical transport.

## PoC index

- `examples/toctouInterleave.py` — `addr` (default), `keysub`, `keysub2`.
- `examples/toctouUiClobber.py` — transfer destination display clobbering.
- `tests/test_toctou.py` — Speculos suite (`security_poc` marker); the
  receivable proofs for the synchronous variants live here.
