#!/usr/bin/env python3
"""Functional tests for the opt-in, random-key ML-DSA-44 PoC build."""

import hashlib
import struct
import sys
import time
from pathlib import Path

import pytest
from Crypto.Hash import keccak

from client.command_builder import CLA
from client.status_word import StatusWord
from ragger.error import ExceptionRAPDU
from tron import TronClient


PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract  # noqa: E402
from core import Tron_pb2 as tron  # noqa: E402


INS_GET_PQ_CAPABILITIES = 0x30
INS_GENERATE_PQ_KEY = 0x32
INS_SIGN_PQ = 0x34
INS_GET_PQ_RESULT = 0x36
INS_ABORT_PQ_SESSION = 0x3A

PQ_SCHEME_ML_DSA_44 = 2
PQ_RESULT_PUBLIC_KEY = 1
PQ_RESULT_SIGNATURE = 2
PQ_PUBLIC_KEY_SIZE = 1312
PQ_SIGNATURE_SIZE = 2420
PQ_MAX_CHUNK = 220


def _approve_nano_mldsa_review(backend, timeout: float = 30) -> None:
    """Approve without polling the async APDU after the final button press.

    ML-DSA sign plus device-side verify runs synchronously in the confirmation
    callback. Ragger's generic Nano review helper waits for another screen
    change after that press; during the long crypto operation it may consume
    the completed async response as "early data" through Speculos' streaming
    HTTP endpoint. Leave final response collection to exchange_async instead.
    """
    deadline = time.monotonic() + timeout
    # Poll like the standalone probe instead of using
    # wait_for_screen_change(): that helper owns a screenshot baseline and also
    # probes the pending async APDU, both of which are undesirable here.
    time.sleep(0.2)
    while True:
        events = backend.get_current_screen_content().get("events", [])
        screen_text = "\n".join(event.get("text", "") for event in events).lower()
        if "sign with" in screen_text and "ml-dsa-44" in screen_text:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("ML-DSA review confirmation screen not found")
        backend.right_click()
        time.sleep(0.2)

    # Do not call wait_for_screen_change() after this click. The surrounding
    # exchange_async context waits for and records the final APDU response.
    backend.both_click()


def _capabilities_or_skip(backend):
    try:
        response = backend.exchange(CLA, INS_GET_PQ_CAPABILITIES, 0, 0, b"")
    except ExceptionRAPDU:
        pytest.skip("application was built without MLDSA_POC=1")
    if response.status != StatusWord.OK:
        pytest.skip("application was built without MLDSA_POC=1")
    assert response.data == bytes.fromhex("01020520097407")


def _generate_key(backend):
    response = backend.exchange(CLA,
                                INS_GENERATE_PQ_KEY,
                                0,
                                PQ_SCHEME_ML_DSA_44,
                                b"")
    assert response.status == StatusWord.OK
    assert len(response.data) == 63
    assert response.data[:2] == bytes([1, PQ_SCHEME_ML_DSA_44])
    session_id = response.data[2:6]
    address = response.data[6:27]
    assert struct.unpack(">H", response.data[27:29])[0] == PQ_PUBLIC_KEY_SIZE
    assert struct.unpack(">H", response.data[29:31])[0] == 0
    return session_id, address, response.data[31:63]


def _get_result(backend, session_id: bytes, obj: int, expected_size: int) -> bytes:
    result = bytearray()
    offset = 0
    while offset < expected_size:
        request = session_id + bytes([obj]) + struct.pack(">H", offset) + bytes(
            [PQ_MAX_CHUNK])
        response = backend.exchange(CLA, INS_GET_PQ_RESULT, 0, 0, request)
        assert response.status == StatusWord.OK
        assert response.data[:2] == bytes([1, PQ_SCHEME_ML_DSA_44])
        assert response.data[2:6] == session_id
        assert response.data[6] == obj
        assert struct.unpack(">H", response.data[7:9])[0] == offset
        assert struct.unpack(">H", response.data[9:11])[0] == expected_size
        chunk_length = response.data[12]
        assert chunk_length == len(response.data[13:])
        result.extend(response.data[13:])
        offset += chunk_length
        assert response.data[11] == (offset == expected_size)
    return bytes(result)


def test_mldsa_poc_transfer(backend, device, scenario_navigator):
    _capabilities_or_skip(backend)
    session_id, pq_address, fingerprint = _generate_key(backend)

    client = TronClient(backend)
    tx = client.packContract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=pq_address,
            to_address=bytes.fromhex(
                client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
            amount=100_000_000))
    assert len(session_id + tx) <= 255

    with backend.exchange_async(CLA, INS_SIGN_PQ, 0x10, 0, session_id + tx):
        if device.is_nano:
            _approve_nano_mldsa_review(backend)
        else:
            scenario_navigator.review_approve(
                test_name="test_mldsa_poc_transfer", do_comparison=False)

    response = backend.last_async_response
    assert response.status == StatusWord.OK
    assert response.data[:6] == bytes([1, PQ_SCHEME_ML_DSA_44]) + session_id
    assert struct.unpack(">H", response.data[29:31])[0] == PQ_SIGNATURE_SIZE

    public_key = _get_result(backend, session_id, PQ_RESULT_PUBLIC_KEY,
                             PQ_PUBLIC_KEY_SIZE)
    signature = _get_result(backend, session_id, PQ_RESULT_SIGNATURE,
                            PQ_SIGNATURE_SIZE)
    assert len(public_key) == PQ_PUBLIC_KEY_SIZE
    assert len(signature) == PQ_SIGNATURE_SIZE
    assert hashlib.sha256(public_key).digest() == fingerprint
    address_hash = keccak.new(digest_bits=256, data=public_key).digest()
    assert pq_address == b"\x41" + address_hash[-20:]
    assert fingerprint == response.data[31:63]

    abort = backend.exchange(CLA, INS_ABORT_PQ_SESSION, 0, 0, session_id)
    assert abort.status == StatusWord.OK


def test_mldsa_poc_transaction_error_preserves_key(backend):
    _capabilities_or_skip(backend)
    session_id, _, fingerprint = _generate_key(backend)

    # Ragger raises ExceptionRAPDU for non-0x9000 status words instead of
    # returning a response object. The malformed transaction is expected to be
    # rejected with 0x6a80 while preserving the active PQ key.
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, INS_SIGN_PQ, 0x10, 0, session_id + b"\x00")
    assert error.value.status == StatusWord.INVALID_DATA

    public_key = _get_result(backend, session_id, PQ_RESULT_PUBLIC_KEY,
                             PQ_PUBLIC_KEY_SIZE)
    assert len(public_key) == PQ_PUBLIC_KEY_SIZE

    # A parser error must not silently rotate or destroy the random session key.
    retry_fingerprint = hashlib.sha256(public_key).digest()
    assert retry_fingerprint == fingerprint

    abort = backend.exchange(CLA, INS_ABORT_PQ_SESSION, 0, 0, session_id)
    assert abort.status == StatusWord.OK
