#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/test_trx.py
'''
from decimal import Decimal

import pytest
import sys
import struct
import re
import binascii
from ragger.error import ExceptionRAPDU
from contextlib import contextmanager
from pathlib import Path
from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric import ec
from inspect import currentframe
from tron import TronClient, Errors, CLA, InsType, P1, MAX_APDU_LEN
from ragger.navigator import NavInsID, NavIns
from ragger.bip import pack_derivation_path
from utils import check_tx_signature, check_hash_signature, build_trc20_calldata
from eth_keys import KeyAPI
'''
Tron Protobuf
'''
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/proto")
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron


def encode_length_delimited_field(field_number, value):
    """Encode the small length-delimited fields used by malformed-input tests."""
    assert field_number < 16
    assert len(value) < 128
    return bytes([(field_number << 3) | 2, len(value)]) + value


def encode_varint(value):
    """Encode a non-negative protobuf varint without enum validation."""
    assert value >= 0
    encoded = bytearray()
    while value > 0x7f:
        encoded.append((value & 0x7f) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def pack_contract_with_raw_resource(client, contract_type, message,
                                    resource_field, resource):
    """Inject a raw enum value so tests also cover unknown wire values."""
    raw_data = tron.Transaction.raw()
    raw_data.ParseFromString(client.packContract(contract_type, message))
    raw_contract = message.SerializeToString(deterministic=True)
    raw_contract += encode_varint(resource_field << 3)
    raw_contract += encode_varint(resource)
    raw_data.contract[0].parameter.value = raw_contract
    return raw_data.SerializeToString(deterministic=True)


def make_resource_contract(client, contract_type, receiver_address=b''):
    owner_address = bytes.fromhex(client.getAccount(0)['addressHex'])
    if contract_type == tron.Transaction.Contract.FreezeBalanceContract:
        return contract.FreezeBalanceContract(
            owner_address=owner_address,
            frozen_balance=100000000,
            frozen_duration=3,
            receiver_address=receiver_address), 10
    if contract_type == tron.Transaction.Contract.UnfreezeBalanceContract:
        return contract.UnfreezeBalanceContract(
            owner_address=owner_address, receiver_address=receiver_address), 10
    if contract_type == tron.Transaction.Contract.FreezeBalanceV2Contract:
        return contract.FreezeBalanceV2Contract(owner_address=owner_address,
                                                frozen_balance=100000000), 3
    if contract_type == tron.Transaction.Contract.UnfreezeBalanceV2Contract:
        return contract.UnfreezeBalanceV2Contract(
            owner_address=owner_address, unfreeze_balance=100000000), 3

    if not receiver_address:
        receiver_address = bytes.fromhex(
            client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"))
    if contract_type == tron.Transaction.Contract.DelegateResourceContract:
        return contract.DelegateResourceContract(
            owner_address=owner_address,
            balance=100000000,
            receiver_address=receiver_address), 2
    if contract_type == tron.Transaction.Contract.UnDelegateResourceContract:
        return contract.UnDelegateResourceContract(
            owner_address=owner_address,
            balance=100000000,
            receiver_address=receiver_address), 2
    raise AssertionError(
        f"unsupported resource contract type: {contract_type}")


@pytest.mark.parametrize("p1", [P1.FIRST, P1.SIGN])
def test_personal_message_requires_blind_signing(backend, firmware, navigator,
                                                 p1):
    client = TronClient(backend, firmware, navigator)
    message = b"blind message"
    data = pack_derivation_path(client.getAccount(0)['path'])
    data += struct.pack(">I", len(message)) + message

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, p1, 0x00, data)
    assert error.value.status == Errors.MISSING_SETTING_SIGN_BY_HASH


def test_unreviewed_transaction_requires_blind_signing(backend, firmware,
                                                        navigator):
    client = TronClient(backend, firmware, navigator)
    tx = client.packContract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(client.getAccount(0)['addressHex']),
            to_address=bytes.fromhex(client.address_hex(
                "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
            amount=100000000))
    payload = pack_derivation_path(client.getAccount(0)['path'])
    payload += tx + b'\xf8\x01\x01'

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
    assert error.value.status == Errors.MISSING_SETTING_SIGN_BY_HASH


@pytest.mark.parametrize(("wrapper_field", "wrapper_value"), [
    ("provider", b"attacker-provider"),
    ("ContractName", b"hidden-contract-name"),
    ("type_url", "type.googleapis.com/protocol.VoteWitnessContract"),
    ("type_url", "https://type.googleapis.com/protocol.TransferContract"),
])
def test_unreviewed_contract_wrapper_requires_blind_signing(
        backend, firmware, navigator, wrapper_field, wrapper_value):
    client = TronClient(backend, firmware, navigator)
    tx = tron.Transaction.raw()
    tx.ParseFromString(
        client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(client.address_hex(
                    "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000)))
    if wrapper_field == "type_url":
        tx.contract[0].parameter.type_url = wrapper_value
    else:
        setattr(tx.contract[0], wrapper_field, wrapper_value)

    payload = pack_derivation_path(client.getAccount(0)['path'])
    payload += tx.SerializeToString(deterministic=True)

    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
    assert error.value.status == Errors.MISSING_SETTING_SIGN_BY_HASH


def test_duplicate_contract_type_url_requires_blind_signing(
        backend, firmware, navigator):
    client = TronClient(backend, firmware, navigator)
    raw_tx = tron.Transaction.raw()
    raw_tx.timestamp = 1575712492061
    raw_tx.expiration = 1575712551000
    raw_tx.ref_block_hash = bytes.fromhex("95DA42177DB00507")
    raw_tx.ref_block_bytes = bytes.fromhex("3DCE")

    type_url = b"type.googleapis.com/protocol.TransferContract"
    value = contract.TransferContract(
        owner_address=bytes.fromhex(client.getAccount(0)['addressHex']),
        to_address=bytes.fromhex(client.address_hex(
            "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
        amount=100000000).SerializeToString()
    any_fields = encode_length_delimited_field(1, type_url)
    any_fields += encode_length_delimited_field(1, type_url)
    any_fields += encode_length_delimited_field(2, value)
    contract_fields = b'\x08\x01'
    contract_fields += b'\x12' + encode_varint(len(any_fields)) + any_fields
    serialized_tx = raw_tx.SerializeToString()
    serialized_tx += b'\x5a' + encode_varint(len(contract_fields))
    serialized_tx += contract_fields

    payload = pack_derivation_path(client.getAccount(0)['path'])
    payload += serialized_tx
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
    assert error.value.status == Errors.MISSING_SETTING_SIGN_BY_HASH


@pytest.mark.usefixtures('configuration')
class TestTRX():
    '''Test TRX client.'''

    def sign_and_validate(self,
                          client,
                          firmware,
                          text_index,
                          tx,
                          signatures=[],
                          warning_approve=False):
        path = Path(currentframe().f_back.f_code.co_name)
        text = None
        if firmware.is_nano:
            if text_index == 0:
                text = "Sign"
            elif text_index == 1:
                text = "Accept"
        else:
            if text_index == 0 or text_index == 1:
                text = "Hold to sign"
        assert text
        resp = client.sign(client.getAccount(0)['path'],
                           tx,
                           signatures=signatures,
                           snappath=path,
                           text=text,
                           warning_approve=warning_approve)
        assert check_tx_signature(tx, resp.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def sign_unreviewed_and_validate(self, backend, client, firmware,
                                     navigator, tx):
        path = pack_derivation_path(client.getAccount(0)['path'])
        chunks = []
        current_chunk = path
        remaining = tx
        while remaining:
            field_length = client.get_next_length(remaining)
            field = remaining[:field_length]
            assert len(field) <= MAX_APDU_LEN
            if len(current_chunk) + len(field) > MAX_APDU_LEN:
                chunks.append(current_chunk)
                current_chunk = b''
            current_chunk += field
            remaining = remaining[field_length:]
        chunks.append(current_chunk)

        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"

        if len(chunks) == 1:
            final_p1 = P1.SIGN
        else:
            backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, chunks[0])
            for chunk in chunks[1:-1]:
                backend.exchange(CLA, InsType.SIGN, P1.MORE, 0x00, chunk)
            final_p1 = P1.LAST

        with backend.exchange_async(CLA, InsType.SIGN, final_p1, 0x00,
                                    chunks[-1]):
            navigator.navigate_until_text(
                navigate_instruction, [], "Hash",
                screen_change_before_first_instruction=True)
            navigator.navigate_until_text(
                navigate_instruction, validation_instructions, approval_text,
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_get_version(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        resp = client.getVersion()
        expected_settings = (1 << 0) | (1 << 1) | (1 << 3)
        assert resp.data[0] == expected_settings
        major, minor, patch = client.unpackGetVersionResponse(resp.data)
        path = str(Path(__file__).parent.parent.resolve()) + "/VERSION"
        version_file = open(path, "r").read()
        version = re.findall(r"(\d)\.(\d)\.(\d)", version_file)
        assert (major == int(version[0][0]))
        assert (minor == int(version[0][1]))
        assert (patch == int(version[0][2]))

    def test_trx_rejects_contracts_split_across_apdus(self, backend, firmware,
                                                      navigator):
        client = TronClient(backend, firmware, navigator)

        def transfer(to_address, amount):
            return client.packContract(
                tron.Transaction.Contract.TransferContract,
                contract.TransferContract(owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                                          to_address=bytes.fromhex(
                                              client.address_hex(to_address)),
                                          amount=amount))

        hidden_tx = transfer("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M", 100000000)
        visible_tx = transfer("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16", 1)
        first_payload = pack_derivation_path(
            client.getAccount(0)['path']) + hidden_tx

        backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, first_payload)
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.MORE, 0x00, visible_tx)
        assert error.value.status == Errors.INCORRECT_DATA

        # A rejected fragment must poison the signing session. Otherwise a
        # host could continue and sign bytes that were already rejected.
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.LAST, 0x00, b"")
        assert error.value.status == Errors.INCORRECT_P2

    def test_trx_rejects_multiple_contracts_in_one_apdu(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)

        def transfer(to_address, amount):
            return client.packContract(
                tron.Transaction.Contract.TransferContract,
                contract.TransferContract(owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                                          to_address=bytes.fromhex(
                                              client.address_hex(to_address)),
                                          amount=amount))

        def contract_field(raw_tx):
            remaining = raw_tx
            while remaining:
                field_length = client.get_next_length(remaining)
                field = remaining[:field_length]
                if field[0] == ((11 << 3) | 2):
                    return field
                remaining = remaining[field_length:]
            raise AssertionError(
                "serialized transaction has no Contract field")

        raw_tx = contract_field(
            transfer("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M", 100000000))
        raw_tx += contract_field(
            transfer("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16", 1))
        payload = pack_derivation_path(client.getAccount(0)['path']) + raw_tx
        assert len(payload) <= 255

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
        assert error.value.status == Errors.INCORRECT_DATA

    @pytest.mark.parametrize("parameter_encoding", [
        "empty_parameter",
        "type_url_only",
        "empty_value",
        "nonempty_then_empty_value",
    ])
    def test_trx_rejects_contract_parameter_without_nonempty_final_value(
            self, backend, firmware, navigator, parameter_encoding):
        client = TronClient(backend, firmware, navigator)

        raw_tx = tron.Transaction.raw()
        raw_tx.timestamp = 1575712492061
        raw_tx.expiration = 1575712551000
        raw_tx.ref_block_hash = bytes.fromhex("95DA42177DB00507")
        raw_tx.ref_block_bytes = bytes.fromhex("3DCE")

        type_url = b"type.googleapis.com/protocol.TransferContract"
        valid_value = contract.TransferContract(
            owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
            to_address=bytes.fromhex(
                client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
            amount=100000000).SerializeToString()

        if parameter_encoding == "empty_parameter":
            any_fields = b""
        elif parameter_encoding == "type_url_only":
            any_fields = encode_length_delimited_field(1, type_url)
        elif parameter_encoding == "empty_value":
            any_fields = encode_length_delimited_field(2, b"")
        else:
            # Singular protobuf fields use the final occurrence. Ensure an
            # earlier valid value cannot leave a stale callback buffer behind.
            any_fields = encode_length_delimited_field(2, valid_value)
            any_fields += encode_length_delimited_field(2, b"")

        contract_fields = b'\x08\x01'  # TransferContract enum value.
        contract_fields += encode_length_delimited_field(2, any_fields)
        serialized_tx = raw_tx.SerializeToString()
        serialized_tx += encode_length_delimited_field(11, contract_fields)

        payload = pack_derivation_path(client.getAccount(0)['path'])
        payload += serialized_tx
        assert len(payload) <= 255

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
        assert error.value.status == Errors.INCORRECT_DATA

        # Malformed input must be rejected without terminating the app.
        response = client.getVersion()
        assert response.status == Errors.OK

    @pytest.mark.parametrize("unknown_field", [
        b'\x08\x01',                       # known tag, alternate wire type
        b'\x4a\x00',                       # unmodeled auths field 9
        b'\x62\x00',                       # unmodeled scripts field 12
        b'\xf8\x01\x01',                  # field 31, varint
        b'\xf9\x01' + (b'\x00' * 8),     # field 31, fixed64
        b'\xfa\x01\x01x',                # field 31, length-delimited
        b'\xfd\x01' + (b'\x00' * 4),     # field 31, fixed32
    ])
    def test_trx_accepts_unknown_raw_fields_for_hash_review(
            self, backend, firmware, navigator, unknown_field):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))

        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        payload += unknown_field
        assert len(payload) <= 255

        # FIRST proves that all java-tron-supported unknown wire classes pass
        # decoding. A final fragment would enter full-hash review, covered by
        # the focused tests below.
        response = backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00,
                                    payload)
        assert response.status == Errors.OK

    def test_trx_unknown_contract_parameter_uses_hash_review(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        owner = bytes.fromhex(client.getAccount(0)['addressHex'])
        recipient = bytes.fromhex(
            client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"))
        transfer = contract.TransferContract(owner_address=owner,
                                             to_address=recipient,
                                             amount=100000000)

        tx = tron.Transaction.raw()
        tx.timestamp = 1575712492061
        tx.expiration = 1575712551000
        tx.ref_block_hash = bytes.fromhex("95DA42177DB00507")
        tx.ref_block_bytes = bytes.fromhex("3DCE")
        wrapper = tx.contract.add()
        wrapper.type = tron.Transaction.Contract.TransferContract
        wrapper.parameter.type_url = \
            "type.googleapis.com/protocol.TransferContract"
        wrapper.parameter.value = transfer.SerializeToString() + b'\xf8\x01\x01'

        serialized_tx = tx.SerializeToString()
        self.sign_unreviewed_and_validate(backend, client, firmware, navigator,
                                          serialized_tx)

    @pytest.mark.parametrize(("wrapper_field", "wrapper_value"), [
        ("provider", b"attacker-provider"),
        ("ContractName", b"hidden-contract-name"),
        ("type_url", "type.googleapis.com/protocol.VoteWitnessContract"),
    ])
    def test_trx_unreviewed_contract_wrapper_uses_hash_review(
            self, backend, firmware, navigator, wrapper_field, wrapper_value):
        client = TronClient(backend, firmware, navigator)
        tx = tron.Transaction.raw()
        tx.ParseFromString(
            client.packContract(
                tron.Transaction.Contract.TransferContract,
                contract.TransferContract(
                    owner_address=bytes.fromhex(
                        client.getAccount(0)['addressHex']),
                    to_address=bytes.fromhex(client.address_hex(
                        "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                    amount=100000000)))
        if wrapper_field == "type_url":
            tx.contract[0].parameter.type_url = wrapper_value
        else:
            setattr(tx.contract[0], wrapper_field, wrapper_value)
        serialized_tx = tx.SerializeToString(deterministic=True)

        self.sign_unreviewed_and_validate(backend, client, firmware, navigator,
                                          serialized_tx)

    def test_trx_legacy_parameter_without_type_url_remains_clear_signed(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = tron.Transaction.raw()
        tx.ParseFromString(
            client.packContract(
                tron.Transaction.Contract.TransferContract,
                contract.TransferContract(
                    owner_address=bytes.fromhex(
                        client.getAccount(0)['addressHex']),
                    to_address=bytes.fromhex(client.address_hex(
                        "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                    amount=100000000)))
        tx.contract[0].parameter.type_url = ""
        serialized_tx = tx.SerializeToString(deterministic=True)

        approval_text = "Sign" if firmware.is_nano else "Hold to sign"
        response = client.sign(client.getAccount(0)['path'],
                               serialized_tx,
                               snappath=Path("test_trx_send"),
                               text=approval_text)
        assert check_tx_signature(serialized_tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_vote_support_uses_hash_review(self, backend, firmware,
                                               navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(client.address_hex(
                            "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                ],
                support=True))
        self.sign_unreviewed_and_validate(backend, client, firmware, navigator,
                                          tx)

    def test_trx_account_permission_fields_use_hash_review(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        owner_address = bytes.fromhex(client.getAccount(0)['addressHex'])
        key = tron.Key(address=owner_address, weight=1)
        tx = client.packContract(
            tron.Transaction.Contract.AccountPermissionUpdateContract,
            contract.AccountPermissionUpdateContract(
                owner_address=owner_address,
                owner=tron.Permission(type=tron.Permission.Owner,
                                      id=0,
                                      permission_name="owner",
                                      threshold=1,
                                      keys=[key]),
                actives=[
                    tron.Permission(type=tron.Permission.Active,
                                    id=2,
                                    permission_name="active",
                                    threshold=1,
                                    operations=b'\xff' * 32,
                                    keys=[key]),
                ]))
        self.sign_unreviewed_and_validate(backend, client, firmware, navigator,
                                          tx)

    def test_trx_accepts_one_contract_in_separate_apdu(self, backend, firmware,
                                                       navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))

        fields = []
        remaining = tx
        while remaining:
            field_length = client.get_next_length(remaining)
            fields.append(remaining[:field_length])
            remaining = remaining[field_length:]

        contract_index = next(i for i, field in enumerate(fields)
                              if field[0] == ((11 << 3) | 2))
        assert 0 < contract_index < len(fields) - 1

        first_payload = pack_derivation_path(client.getAccount(0)['path'])
        first_payload += b''.join(fields[:contract_index])
        backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, first_payload)
        backend.exchange(CLA, InsType.SIGN, P1.MORE, 0x00,
                         fields[contract_index])

        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"

        with backend.exchange_async(CLA, InsType.SIGN, P1.LAST, 0x00,
                                    b''.join(fields[contract_index + 1:])):
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=True)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_vote_details_survive_trailing_field_apdu(
            self, backend, firmware, navigator):
        if firmware.device != "flex":
            pytest.skip("Direct vote-field assertion is calibrated for Flex")

        client = TronClient(backend, firmware, navigator)
        vote_address = "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF"
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(vote_address)),
                        vote_count=100),
                ]))

        fields = []
        remaining = tx
        while remaining:
            field_length = client.get_next_length(remaining)
            fields.append(remaining[:field_length])
            remaining = remaining[field_length:]

        contract_index = next(i for i, field in enumerate(fields)
                              if field[0] == ((11 << 3) | 2))
        assert 0 < contract_index < len(fields) - 1

        first_payload = pack_derivation_path(client.getAccount(0)['path'])
        first_payload += b''.join(fields[:contract_index])
        backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, first_payload)
        backend.exchange(CLA, InsType.SIGN, P1.MORE, 0x00,
                         fields[contract_index])

        with backend.exchange_async(CLA, InsType.SIGN, P1.LAST, 0x00,
                                    b''.join(fields[contract_index + 1:])):
            navigator.navigate([NavIns(NavInsID.SWIPE_CENTER_TO_LEFT)])
            assert backend.compare_screen_with_text(vote_address[:24]), \
                backend.get_current_screen_content()
            assert backend.compare_screen_with_text(r"^1: 100$"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Hold to sign",
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize("contract_kind", ["trx", "trc10"])
    @pytest.mark.parametrize("amount", [-1, -(1 << 63)])
    def test_trx_rejects_negative_transfer_amounts(self, backend, firmware,
                                                   navigator, contract_kind,
                                                   amount):
        client = TronClient(backend, firmware, navigator)
        owner = bytes.fromhex(client.getAccount(0)['addressHex'])
        recipient = bytes.fromhex(
            client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"))
        if contract_kind == "trx":
            contract_type = tron.Transaction.Contract.TransferContract
            message = contract.TransferContract(owner_address=owner,
                                                to_address=recipient,
                                                amount=amount)
        else:
            contract_type = tron.Transaction.Contract.TransferAssetContract
            message = contract.TransferAssetContract(asset_name=b"1000166",
                                                     owner_address=owner,
                                                     to_address=recipient,
                                                     amount=amount)

        tx = client.packContract(contract_type, message)

        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_formats_maximum_int64_transfer_amount(self, backend, firmware,
                                                       navigator):
        if firmware.device != "flex":
            pytest.skip(
                "Direct maximum-amount assertion is calibrated for Flex")

        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=(1 << 63) - 1))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00, payload):
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [],
                "Amount",
                screen_change_before_first_instruction=True)
            assert backend.compare_screen_with_text(
                r"^9223372036854\.77580$"), \
                backend.get_current_screen_content()
            assert backend.compare_screen_with_text(r"^7$"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Hold to sign",
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize("case", [
        "vote_count",
        "freeze_balance",
        "freeze_balance_v2",
        "unfreeze_balance_v2",
        "delegate_balance",
        "undelegate_balance",
        "exchange_create_first",
        "exchange_create_second",
        "exchange_inject_id",
        "exchange_inject_quant",
        "exchange_withdraw_id",
        "exchange_withdraw_quant",
        "exchange_transaction_id",
        "exchange_transaction_quant",
        "exchange_transaction_expected",
        "proposal_delete_id",
    ])
    def test_trx_rejects_negative_displayed_values(self, backend, firmware,
                                                   navigator, case):
        client = TronClient(backend, firmware, navigator)
        owner = bytes.fromhex(client.getAccount(0)['addressHex'])
        recipient = bytes.fromhex(
            client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"))

        cases = {
            "vote_count": (tron.Transaction.Contract.VoteWitnessContract,
                           contract.VoteWitnessContract(
                               owner_address=owner,
                               votes=[
                                   contract.VoteWitnessContract.Vote(
                                       vote_address=recipient, vote_count=-1)
                               ])),
            "freeze_balance": (tron.Transaction.Contract.FreezeBalanceContract,
                               contract.FreezeBalanceContract(
                                   owner_address=owner,
                                   frozen_balance=-1,
                                   frozen_duration=3,
                                   resource=contract.BANDWIDTH)),
            "freeze_balance_v2":
            (tron.Transaction.Contract.FreezeBalanceV2Contract,
             contract.FreezeBalanceV2Contract(owner_address=owner,
                                              frozen_balance=-1,
                                              resource=contract.BANDWIDTH)),
            "unfreeze_balance_v2":
            (tron.Transaction.Contract.UnfreezeBalanceV2Contract,
             contract.UnfreezeBalanceV2Contract(owner_address=owner,
                                                unfreeze_balance=-1,
                                                resource=contract.BANDWIDTH)),
            "delegate_balance":
            (tron.Transaction.Contract.DelegateResourceContract,
             contract.DelegateResourceContract(owner_address=owner,
                                               resource=contract.BANDWIDTH,
                                               balance=-1,
                                               receiver_address=recipient)),
            "undelegate_balance":
            (tron.Transaction.Contract.UnDelegateResourceContract,
             contract.UnDelegateResourceContract(owner_address=owner,
                                                 resource=contract.BANDWIDTH,
                                                 balance=-1,
                                                 receiver_address=recipient)),
            "exchange_create_first":
            (tron.Transaction.Contract.ExchangeCreateContract,
             contract.ExchangeCreateContract(owner_address=owner,
                                             first_token_id=b"_",
                                             first_token_balance=-1,
                                             second_token_id=b"1000166",
                                             second_token_balance=1)),
            "exchange_create_second":
            (tron.Transaction.Contract.ExchangeCreateContract,
             contract.ExchangeCreateContract(owner_address=owner,
                                             first_token_id=b"_",
                                             first_token_balance=1,
                                             second_token_id=b"1000166",
                                             second_token_balance=-1)),
            "exchange_inject_id":
            (tron.Transaction.Contract.ExchangeInjectContract,
             contract.ExchangeInjectContract(owner_address=owner,
                                             exchange_id=-1,
                                             token_id=b"1000166",
                                             quant=1)),
            "exchange_inject_quant":
            (tron.Transaction.Contract.ExchangeInjectContract,
             contract.ExchangeInjectContract(owner_address=owner,
                                             exchange_id=1,
                                             token_id=b"1000166",
                                             quant=-1)),
            "exchange_withdraw_id":
            (tron.Transaction.Contract.ExchangeWithdrawContract,
             contract.ExchangeWithdrawContract(owner_address=owner,
                                               exchange_id=-1,
                                               token_id=b"1000166",
                                               quant=1)),
            "exchange_withdraw_quant":
            (tron.Transaction.Contract.ExchangeWithdrawContract,
             contract.ExchangeWithdrawContract(owner_address=owner,
                                               exchange_id=1,
                                               token_id=b"1000166",
                                               quant=-1)),
            "exchange_transaction_id":
            (tron.Transaction.Contract.ExchangeTransactionContract,
             contract.ExchangeTransactionContract(owner_address=owner,
                                                  exchange_id=-1,
                                                  token_id=b"1000166",
                                                  quant=1,
                                                  expected=1)),
            "exchange_transaction_quant":
            (tron.Transaction.Contract.ExchangeTransactionContract,
             contract.ExchangeTransactionContract(owner_address=owner,
                                                  exchange_id=1,
                                                  token_id=b"1000166",
                                                  quant=-1,
                                                  expected=1)),
            "exchange_transaction_expected":
            (tron.Transaction.Contract.ExchangeTransactionContract,
             contract.ExchangeTransactionContract(owner_address=owner,
                                                  exchange_id=1,
                                                  token_id=b"1000166",
                                                  quant=1,
                                                  expected=-1)),
            "proposal_delete_id":
            (tron.Transaction.Contract.ProposalDeleteContract,
             contract.ProposalDeleteContract(owner_address=owner,
                                             proposal_id=-1)),
        }

        contract_type, message = cases[case]
        tx = client.packContract(contract_type, message)
        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    @contextmanager
    def test_trx_send(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_send_with_data_field(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000),
            b'CryptoChain-TronSR Ledger Transactions Tests')
        self.sign_and_validate(client, firmware, 0, tx, warning_approve=True)

    def test_trx_send_wrong_path(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        if firmware.is_nano:
            text = "Sign"
        else:
            text = "Hold to sign"
        path = Path(currentframe().f_code.co_name)
        resp = client.sign("m/44'/195'/1'/1/0", tx, snappath=path, text=text)
        assert not check_tx_signature(tx, resp.data[0:65],
                                      client.getAccount(0)['publicKey'][2:])

    def test_trx_send_asset_without_name(self, backend, configuration,
                                         firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_accepts_eight_digit_trc10_id(self, backend, firmware,
                                              navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name=b"10000000"))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx

        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00,
                                    payload):
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=True)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_send_asset_with_name(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        # BTT token ID 1002000 - 6 decimals
        tokenSignature = [
            "0a0a426974546f7272656e7410061a46304402202e2502f36b00e57be785fc79ec4043abcdd4fdd1b58d737ce123599dffad2cb602201702c307f009d014a553503b499591558b3634ceee4c054c61cedd8aca94c02b"
        ]
        self.sign_and_validate(client, firmware, 0, tx, tokenSignature)

    def test_trx_send_asset_with_name_wrong_signature(self, backend, firmware,
                                                      navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        # BTT token ID 1002000 - 6 decimals
        tokenSignature = [
            "0a0a4e6577416765436f696e10001a473045022100d8d73b4fad5200aa40b5cdbe369172b5c3259c10f1fb17dfb9c3fa6aa934ace702204e7ef9284969c74a0e80b7b7c17e027d671f3a9b3556c05269e15f7ce45986c8"
        ]
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'],
                        tx,
                        tokenSignature,
                        navigate=False)
        assert e.value.status == Errors.INCORRECT_DATA

    def test_trx_rejects_legacy_exchange_signature_as_token_metadata(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name=b"1661002"))
        # The signature is valid for legacy exchange 166 over
        # b"1661002000BitTorrent\\x06_TRX\\x06", but must not authenticate
        # TokenDetails(id="1661002", name="000BitTorrent\\x06_TRX", precision=6).
        replayed_exchange_signature = [
            "0a12303030426974546f7272656e74065f54525810061a473045022100ba57d12e19f4f621780ae98430b5bbdcb7c8fa4fbdf6d957f43ca5813fd25bd702207698adb892771b71417f09e7ce6de7b773e5cb5717ddf71fb63bd7890513fd9b"
        ]

        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'],
                        tx,
                        replayed_exchange_signature,
                        navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    @pytest.mark.parametrize("token_id", [
        b"",
        b"01002000",
        b"123456A",
        b"TRX\x00bad",
        b"12345678901234567890",
    ])
    def test_trx_rejects_invalid_trc10_token_id(self, backend, firmware,
                                                navigator, token_id):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name=token_id))

        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_exchange_create(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        self.sign_and_validate(client, firmware, 1, tx)

    def test_trx_exchange_create_accepts_eight_digit_trc10_id(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id=b"_",
                                            first_token_balance=10000000000,
                                            second_token_id=b"10000000",
                                            second_token_balance=10000000))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx

        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Accept"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00,
                                    payload):
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=True)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_exchange_create_with_token_name(self, backend, configuration,
                                                 firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        tokenSignature = [
            "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c0a6371adcb6992db94487f66c7",
            "0a0b43727970746f436861696e10001a4730450221008417d04d1caeae31f591ae50f7d19e53e0dfb827bd51c18e66081941bf04639802203c73361a521c969e3fd7f62e62b46d61aad00e47d41e7da108546d954278a6b1"
        ]

        self.sign_and_validate(client, firmware, 1, tx, tokenSignature)

    @pytest.mark.parametrize("exchange_operation", [
        "create_first",
        "create_second",
        "create_precision_five",
        "inject",
        "withdraw",
    ])
    def test_trx_exchange_trx_prefixed_trc10_uses_authenticated_precision(
            self, backend, firmware, navigator, exchange_operation):
        if firmware.device != "flex":
            pytest.skip(
                "Direct exchange amount assertion is calibrated for Flex")

        trx_signature = (
            "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc"
            "0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c"
            "0a6371adcb6992db94487f66c7")
        trx_market_signature = (
            "0a095452584d61726b657410001a473045022100e24a62c1a5413f509efc0c6a344"
            "b6c3e205534ed58ea7a6df4797aff64a185f302200c6309324d161da1559e62ef0"
            "a5bf08de6a082215333e417817a5540e62952a9")
        trx_lsilver_signature = (
            "0a0a5452584c53696c76657210051a46304402205bbc4995abbef4dec85d7e498e"
            "9538cd8f82936fbbebe10511ea152cce4f772902207d0bce8a77784c53b53ae0a"
            "b4b52595fe4c337f91a812fff7ce8d94512f5baae")
        exchange_signature = (
            "088b011207313030313233371a095452584d61726b657420002a015f320354525838"
            "0642473045022100e470c4c1ff5b69bf17521d8ca24dc7ccd1dd76319dd3767164"
            "762fab1cb5b02b0220663de69c36a2e7c05ee708617fc5c03b71253ab452a14812"
            "4d86dc93bb749e97")

        client = TronClient(backend, firmware, navigator)
        owner = bytes.fromhex(client.getAccount(0)['addressHex'])
        if exchange_operation.startswith("create"):
            trc10_is_first = exchange_operation != "create_second"
            precision_five = exchange_operation == "create_precision_five"
            trc10_id = b"1002531" if precision_five else b"1001237"
            trc10_amount = 1234567 if precision_five else 1000000
            trc10_amount_text = "12.34567" if precision_five else "1000000"
            trc10_signature = (trx_lsilver_signature
                               if precision_five else trx_market_signature)
            tx = client.packContract(
                tron.Transaction.Contract.ExchangeCreateContract,
                contract.ExchangeCreateContract(
                    owner_address=owner,
                    first_token_id=trc10_id if trc10_is_first else b"_",
                    first_token_balance=(trc10_amount
                                         if trc10_is_first else 123456000000),
                    second_token_id=b"_" if trc10_is_first else trc10_id,
                    second_token_balance=(123456000000 if trc10_is_first else
                                          trc10_amount)))
            signatures = ([trc10_signature, trx_signature] if trc10_is_first
                          else [trx_signature, trc10_signature])
            expected_amounts = ([trc10_amount_text, "123456"] if trc10_is_first
                                else ["123456", trc10_amount_text])
        else:
            contract_type = (
                tron.Transaction.Contract.ExchangeInjectContract
                if exchange_operation == "inject" else
                tron.Transaction.Contract.ExchangeWithdrawContract)
            contract_class = (contract.ExchangeInjectContract
                              if exchange_operation == "inject" else
                              contract.ExchangeWithdrawContract)
            tx = client.packContract(
                contract_type,
                contract_class(owner_address=owner,
                               exchange_id=139,
                               token_id=b"1001237",
                               quant=1000000))
            signatures = [exchange_signature]
            expected_amounts = ["1000000"]

        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN
        backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, payload)
        for signature_index, signature in enumerate(signatures[:-1]):
            backend.exchange(CLA, InsType.SIGN,
                             P1.TRC10_NAME | signature_index, 0x00,
                             bytes.fromhex(signature))

        final_p1 = (P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE |
                    (len(signatures) - 1))
        with backend.exchange_async(CLA, InsType.SIGN, final_p1, 0x00,
                                    bytes.fromhex(signatures[-1])):
            for amount_index, expected_amount in enumerate(expected_amounts):
                amount_label = (f"Amount {amount_index + 1}"
                                if len(expected_amounts) == 2 else "Amount")
                navigator.navigate_until_text(
                    NavInsID.SWIPE_CENTER_TO_LEFT, [],
                    amount_label,
                    screen_change_before_first_instruction=(amount_index == 0))
                assert backend.compare_screen_with_text(expected_amount), \
                    backend.get_current_screen_content()

            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS,
                ],
                "Hold to sign",
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize(("second_token_id", "second_token_signature"), [
        (b"1002035",
         bytes.fromhex(
             "0a1f4c6f63616c697a655363616d427952454b54436f696e4265686176696f757210001a463044022068fec7768e3e09a0b74dfe6f1d7a297198e162d8e24922ea4d73fcc859383a710220625793998f64be4d0a087eb14ba188cd4d230b3d6a43536e9dc881e3d398efac"
         )),
        (b"1000932",
         bytes.fromhex(
             "0a1f47616d696e67456d706f7765726d656e744d6174657269616c536f7572636510001a463044022044444220afac6892a55b59a815e45725e53e321cea1535ececeb166a632cc6e402201f461c78b2b8d5433f2c984066c7aecf571fb5b4260f892492f1dd79ac5c0c33"
         )),
    ])
    def test_trx_exchange_create_with_max_length_second_token_name(
            self, backend, firmware, navigator, second_token_id,
            second_token_signature):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id=b"_",
                                            first_token_balance=10000000000,
                                            second_token_id=second_token_id,
                                            second_token_balance=1))
        token_signatures = [
            bytes.fromhex(
                "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c0a6371adcb6992db94487f66c7"
            ),
            second_token_signature,
        ]

        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN
        backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, payload)
        backend.exchange(CLA, InsType.SIGN, P1.TRC10_NAME, 0x00,
                         token_signatures[0])

        final_p1 = P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE | 1
        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Accept"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ]
            approval_text = "Hold to sign"

        with backend.exchange_async(CLA, InsType.SIGN, final_p1, 0x00,
                                    token_signatures[1]):
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=True)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_exchange_inject(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeInjectContract,
            contract.ExchangeInjectContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            exchange_id=6,
                                            token_id="1000166".encode(),
                                            quant=10000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_exchange_withdraw(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeWithdrawContract,
            contract.ExchangeWithdrawContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                              exchange_id=6,
                                              token_id="1000166".encode(),
                                              quant=1000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_exchange_transaction(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeTransactionContract,
            contract.ExchangeTransactionContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                                 exchange_id=6,
                                                 token_id="1000166".encode(),
                                                 quant=10000,
                                                 expected=100))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    @pytest.mark.parametrize(
        ("exchange_id", "token_id", "exchange_details"),
        [
            (
                6 + (1 << 32),
                "1000166",
                # Valid exchange-6 metadata and authority signature with only the
                # protobuf exchange ID changed. The legacy verifier narrowed this
                # value back to 6 when reconstructing the signed bytes.
                "0886808080101207313030303136361a0b43727970746f436861696e20002a015f"
                "3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b"
                "61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb1"
                "36f910b9a1f37bfde192fc448793",
            ),
            (
                166,
                "1002000",
                # The fields below concatenate to the authentic exchange-166
                # payload, but repartition BitTorrent/6/_/TRX/6 as
                # BitTorrent\\x06/95/T/RX/6.
                "08a6011207313030323030301a0b426974546f7272656e7406205f2a0154320252"
                "58380642473045022100ba57d12e19f4f621780ae98430b5bbdcb7c8fa4fbdf6d"
                "957f43ca5813fd25bd702207698adb892771b71417f09e7ce6de7b773e5cb5717d"
                "df71fb63bd7890513fd9b",
            ),
        ])
    def test_trx_exchange_rejects_signature_replay(self, backend, firmware,
                                                   navigator, exchange_id,
                                                   token_id, exchange_details):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeTransactionContract,
            contract.ExchangeTransactionContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                                 exchange_id=exchange_id,
                                                 token_id=token_id.encode(),
                                                 quant=1000000,
                                                 expected=1))

        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'],
                        tx, [exchange_details],
                        navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_vote_witness(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TTcYhypP8m4phDhN6oRexz2174zAerjEWP")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9")),
                        vote_count=100),
                ]))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_vote_witness_displays_full_addresses(self, backend, firmware,
                                                      navigator):
        if not firmware.is_nano:
            pytest.skip("BAGL witness-address paging is Nano-specific")

        client = TronClient(backend, firmware, navigator)
        vote_addresses = [
            "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF",
            "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt",
            "TTcYhypP8m4phDhN6oRexz2174zAerjEWP",
            "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9",
        ]
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(vote_address)),
                        vote_count=100)
                    for vote_address in vote_addresses
                ]))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00,
                                    payload):
            navigator.navigate(
                [NavInsID.RIGHT_CLICK],
                screen_change_before_first_instruction=True)
            for index, vote_address in enumerate(vote_addresses):
                if index > 0:
                    navigator.navigate(
                        [NavInsID.RIGHT_CLICK],
                        screen_change_before_first_instruction=False)
                screen = backend.get_current_screen_content()
                displayed_text = "".join(event.get("text", "")
                                         for event in screen["events"])
                assert vote_address in displayed_text, screen

            navigator.navigate_until_text(
                NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], r"^Sign$",
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize("vote_counts, expected_total", [
        ([], "0: 0"),
        ([0], "1: 0"),
        ([5_000_000_000], "1: 5000000000"),
        ([3_000_000_000, 3_000_000_000], "2: 6000000000"),
        ([(1 << 63) - 1, (1 << 63) - 1, 1],
         "3: 18446744073709551615"),
    ])
    def test_trx_vote_witness_formats_64_bit_total(
            self, backend, firmware, navigator, vote_counts, expected_total):
        if firmware.device != "flex":
            pytest.skip("Direct vote-total assertion is calibrated for Flex")

        client = TronClient(backend, firmware, navigator)
        vote_addresses = [
            "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF",
            "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt",
            "TTcYhypP8m4phDhN6oRexz2174zAerjEWP",
        ]
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(vote_addresses[index])),
                        vote_count=vote_count)
                    for index, vote_count in enumerate(vote_counts)
                ]))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00,
                                    payload):
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [],
                "Total Vote Count",
                screen_change_before_first_instruction=True)
            screen = backend.get_current_screen_content()
            displayed_text = "".join(event.get("text", "")
                                     for event in screen["events"])
            assert expected_total.replace(" ", "") in displayed_text.replace(
                " ", ""), screen
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Hold to sign",
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_vote_witness_rejects_64_bit_total_overflow(
            self, backend, firmware, navigator):
        if firmware.device != "flex":
            pytest.skip("Vote-total aggregation is only used on NBGL devices")

        client = TronClient(backend, firmware, navigator)
        vote_addresses = [
            "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF",
            "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt",
            "TTcYhypP8m4phDhN6oRexz2174zAerjEWP",
        ]
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(vote_address)),
                        vote_count=(1 << 63) - 1)
                    for vote_address in vote_addresses
                ]))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_vote_witness_more_than_5(self, backend, configuration,
                                          firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TTcYhypP8m4phDhN6oRexz2174zAerjEWP")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TSzoLaVCdSNDpNxgChcFt9rSRF5wWAZiR4")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TSNbzxac4WhxN91XvaUfPTKP2jNT18mP6T")),
                        vote_count=100),
                ]))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == Errors.INCORRECT_DATA

    def test_trx_freeze_balance_bw(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.BANDWIDTH))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_freeze_balance_energy(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.ENERGY))

        self.sign_and_validate(client, firmware, 0, tx)

    @pytest.mark.parametrize("contract_type", [
        tron.Transaction.Contract.FreezeBalanceContract,
        tron.Transaction.Contract.UnfreezeBalanceContract,
        tron.Transaction.Contract.FreezeBalanceV2Contract,
        tron.Transaction.Contract.UnfreezeBalanceV2Contract,
    ])
    def test_trx_tron_power_resource_is_clear_signed_exactly(
            self, backend, firmware, navigator, contract_type):
        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        elif firmware.device == "flex":
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"
        else:
            pytest.skip(
                "Direct resource-label assertion is calibrated for Flex and Nano"
            )

        client = TronClient(backend, firmware, navigator)
        message, resource_field = make_resource_contract(client, contract_type)
        tx = pack_contract_with_raw_resource(client, contract_type, message,
                                             resource_field,
                                             contract.TRON_POWER)
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00, payload):
            navigator.navigate_until_text(
                navigate_instruction, [],
                "Tron Power",
                screen_change_before_first_instruction=True)
            assert backend.compare_screen_with_text("Tron Power"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize(("contract_type", "resource"), [
        *[(contract_type, resource) for contract_type in (
            tron.Transaction.Contract.FreezeBalanceContract,
            tron.Transaction.Contract.UnfreezeBalanceContract,
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            tron.Transaction.Contract.DelegateResourceContract,
            tron.Transaction.Contract.UnDelegateResourceContract,
        ) for resource in (3, 256)],
        (tron.Transaction.Contract.DelegateResourceContract,
         contract.TRON_POWER),
        (tron.Transaction.Contract.UnDelegateResourceContract,
         contract.TRON_POWER),
    ])
    def test_trx_rejects_unsupported_raw_resource(self, backend, firmware,
                                                  navigator, contract_type,
                                                  resource):
        client = TronClient(backend, firmware, navigator)
        message, resource_field = make_resource_contract(client, contract_type)
        tx = pack_contract_with_raw_resource(client, contract_type, message,
                                             resource_field, resource)
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
        assert error.value.status == Errors.INCORRECT_DATA

    @pytest.mark.parametrize("contract_type", [
        tron.Transaction.Contract.FreezeBalanceContract,
        tron.Transaction.Contract.UnfreezeBalanceContract,
    ])
    def test_trx_rejects_legacy_tron_power_delegation(self, backend, firmware,
                                                      navigator,
                                                      contract_type):
        client = TronClient(backend, firmware, navigator)
        receiver_address = bytes.fromhex(client.getAccount(1)['addressHex'])
        message, resource_field = make_resource_contract(
            client, contract_type, receiver_address)
        tx = pack_contract_with_raw_resource(client, contract_type, message,
                                             resource_field,
                                             contract.TRON_POWER)
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN, P1.SIGN, 0x00, payload)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_freeze_balance_delegate_energy(self, backend, configuration,
                                                firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                frozen_balance=10000000000,
                frozen_duration=3,
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreeze_balance_bw(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.BANDWIDTH,
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreeze_balance_delegate_energy(self, backend, configuration,
                                                  firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_withdraw_balance(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawBalanceContract,
            contract.WithdrawBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_create(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={
                                                1: 100000,
                                                2: 400000
                                            }))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_approve(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=10,
                                             is_add_approval=True))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_delete(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                proposal_id=10,
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_account_update(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'CryptoChainTest',
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_send(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=tx_calldata))
        self.sign_and_validate(client, firmware, 0, tx)

    @pytest.mark.parametrize(("fee_limit", "expected_fee"), [
        (123456789, r"^123\.456789$"),
        (100000000000000000, r"^100000000000$"),
    ])
    def test_trx_trc20_displays_fee_limit_from_separate_apdu(
            self, backend, firmware, navigator, fee_limit, expected_fee):
        if firmware.device == "flex":
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"
        elif firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        else:
            pytest.skip(
                "Direct semantic UI assertion is calibrated for Flex and Nano")

        client = TronClient(backend, firmware, navigator)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=tx_calldata),
            fee_limit=fee_limit)

        fields = []
        remaining = tx
        while remaining:
            field_length = client.get_next_length(remaining)
            fields.append(remaining[:field_length])
            remaining = remaining[field_length:]

        fee_index = next(i for i, field in enumerate(fields)
                         if field.startswith(b'\x90\x01'))
        fee_field = fields.pop(fee_index)
        first_payload = pack_derivation_path(client.getAccount(0)['path'])
        first_payload += b''.join(fields)
        assert len(first_payload) < MAX_APDU_LEN

        backend.exchange(CLA, InsType.SIGN, P1.FIRST, 0x00, first_payload)
        with backend.exchange_async(CLA, InsType.SIGN, P1.LAST, 0x00,
                                    fee_field):
            navigator.navigate_until_text(
                navigate_instruction, [],
                r"Max fee \(TRX\)",
                screen_change_before_first_instruction=True)
            assert backend.compare_screen_with_text(expected_fee), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize("fee_limit", [
        -1,
        100000000000000001,
    ])
    def test_trx_trc20_rejects_invalid_fee_limit(self, backend, firmware,
                                                 navigator, fee_limit):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=tx_calldata),
            fee_limit=fee_limit)

        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_trc20_send_zero_amount(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(0))
        print(tx_calldata)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")),
                data=tx_calldata))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_send_e20_amount(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7",
            Decimal(3.1415 * 10**21))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")),
                data=tx_calldata))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_approve(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=tx_calldata))
        self.sign_and_validate(client, firmware, 0, tx)

    @pytest.mark.parametrize("selector", ["a9059cbb", "095ea7b3"])
    @pytest.mark.parametrize(("token_contract", "other_contract"), [
        ("TVuYcDgE1hPDR78RR6T5CcFe2iyD5XKKQz",
         "TNo59Khpq46FGf4sD7XSWYFNfYfbc8CqNK"),
        ("TNo59Khpq46FGf4sD7XSWYFNfYfbc8CqNK",
         "TVuYcDgE1hPDR78RR6T5CcFe2iyD5XKKQz"),
    ])
    def test_trx_trc20_disambiguates_identical_known_token_labels(
            self, backend, firmware, navigator, selector, token_contract,
            other_contract):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = bytearray(
            build_trc20_calldata("364b03e0815687edaf90b81ff58e496dea7383d7",
                                 Decimal(1000000)))
        tx_calldata[:4] = bytes.fromhex(selector)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex(token_contract)),
                data=bytes(tx_calldata)))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx

        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = r"^Sign$"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00,
                                    payload):
            navigator.navigate_until_text(
                navigate_instruction, [], "Token contract",
                screen_change_before_first_instruction=True)
            screen = backend.get_current_screen_content()
            displayed_text = "".join(event.get("text", "")
                                     for event in screen["events"])
            assert token_contract in displayed_text, screen
            assert other_contract not in displayed_text, screen
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize("selector", ["a9059cbb", "095ea7b3"])
    @pytest.mark.parametrize("attached", ["trx", "trc10", "token_id_only"])
    def test_trx_trc20_rejects_hidden_attached_assets(self, backend, firmware,
                                                      navigator, selector,
                                                      attached):
        client = TronClient(backend, firmware, navigator)
        tx_calldata = bytearray(
            build_trc20_calldata("364b03e0815687edaf90b81ff58e496dea7383d7",
                                 Decimal(1000000)))
        tx_calldata[:4] = bytes.fromhex(selector)

        values = {
            "owner_address":
            bytes.fromhex(client.getAccount(0)['addressHex']),
            "contract_address":
            bytes.fromhex(
                client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
            "data":
            bytes(tx_calldata),
        }
        if attached == "trx":
            values["call_value"] = 1
        elif attached == "trc10":
            values["call_token_value"] = 1
            values["token_id"] = 1000001
        else:
            values["token_id"] = 1000001

        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(**values))
        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    @pytest.mark.parametrize("field",
                             ["call_value", "call_token_value", "token_id"])
    def test_trx_trigger_rejects_negative_attached_values(
            self, backend, firmware, navigator, field):
        client = TronClient(backend, firmware, navigator)
        values = {
            "owner_address":
            bytes.fromhex(client.getAccount(0)['addressHex']),
            "contract_address":
            bytes.fromhex(
                client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
            "data":
            bytes.fromhex("0a857040"),
            field:
            -1,
        }
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(**values))
        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    @pytest.mark.parametrize("attached", [
        {
            "call_token_value": 1,
        },
        {
            "token_id": 1,
        },
        {
            "token_id": 1000000,
        },
    ])
    def test_trx_trigger_rejects_invalid_trc10_values(self, backend, firmware,
                                                      navigator, attached):
        client = TronClient(backend, firmware, navigator)
        values = {
            "owner_address":
            bytes.fromhex(client.getAccount(0)['addressHex']),
            "contract_address":
            bytes.fromhex(
                client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
            "data":
            bytes.fromhex("0a857040"),
        }
        values.update(attached)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(**values))
        with pytest.raises(ExceptionRAPDU) as error:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert error.value.status == Errors.INCORRECT_DATA

    def test_trx_sign_message(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        # Magic define
        SIGN_MAGIC = b'\x19TRON Signed Message:\n'
        message = 'CryptoChain-TronSR Ledger Transactions Tests'.encode()
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += struct.pack(">I", len(message)) + message

        with backend.exchange_async(CLA, InsType.SIGN_PERSONAL_MESSAGE, 0x00,
                                    0x00, data):
            if firmware.is_nano:
                text = "message"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        signedMessage = SIGN_MAGIC + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signedMessage)
        hash_to_sign = keccak_hash.digest()

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_sign_message_across_three_chunks(self, backend, firmware,
                                                  navigator):
        if firmware.device != "flex":
            pytest.skip("Direct multi-chunk assertion is calibrated for Flex")

        client = TronClient(backend, firmware, navigator)
        sign_magic = b'\x19TRON Signed Message:\n'
        message = bytes(range(200)) + bytes(range(200))
        first = pack_derivation_path(client.getAccount(0)['path'])
        first += struct.pack(">I", len(message)) + message[:100]

        backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.FIRST, 0x00,
                         first)
        backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                         message[100:200])
        with backend.exchange_async(CLA, InsType.SIGN_PERSONAL_MESSAGE,
                                    P1.MORE, 0x00, message[200:]):
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Hold to sign",
                screen_change_before_first_instruction=True)

        response = backend.last_async_response
        signed_message = sign_magic + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signed_message)
        assert check_hash_signature(keccak_hash.digest(), response.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                             b"after-finalization")
        assert error.value.status == Errors.INCORRECT_P2

    def test_trx_personal_message_rejects_invalid_continuations(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                             b"without-first")
        assert error.value.status == Errors.INCORRECT_P2

        first = pack_derivation_path(client.getAccount(0)['path'])
        first += struct.pack(">I", 1) + b"too long"
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.FIRST,
                             0x00, first)
        assert error.value.status == Errors.INCORRECT_LENGTH

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                             b"x")
        assert error.value.status == Errors.INCORRECT_P2

        first = pack_derivation_path(client.getAccount(0)['path'])
        first += struct.pack(">I", 2) + b"a"
        backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.FIRST, 0x00,
                         first)
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x01,
                             b"b")
        assert error.value.status == Errors.INCORRECT_P2

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                             b"b")
        assert error.value.status == Errors.INCORRECT_P2

    @pytest.mark.parametrize("p1", [P1.FIRST, P1.SIGN])
    @pytest.mark.parametrize("length_prefix_size", range(4))
    def test_trx_personal_message_rejects_truncated_length_prefix(
            self, backend, firmware, navigator, length_prefix_size, p1):
        client = TronClient(backend, firmware, navigator)
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += b"\xff" * length_prefix_size

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, p1, 0x00,
                             data)
        assert error.value.status == Errors.INCORRECT_LENGTH

        # Every framing error must clear the stream before a continuation.
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                             b"x")
        assert error.value.status == Errors.INCORRECT_P2

    def test_trx_personal_message_rejects_interleaved_stream(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        first = pack_derivation_path(client.getAccount(0)['path'])
        first += struct.pack(">I", 4) + b"a"
        backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.FIRST, 0x00,
                         first)

        client.getVersion()
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.MORE, 0x00,
                             b"bcd")
        assert error.value.status == Errors.INCORRECT_P2

    def test_trx_personal_message_first_restarts_abandoned_stream(
            self, backend, firmware, navigator):
        if firmware.device != "flex":
            pytest.skip("Direct restart assertion is calibrated for Flex")

        client = TronClient(backend, firmware, navigator)
        abandoned = pack_derivation_path(client.getAccount(0)['path'])
        abandoned += struct.pack(">I", 10) + b"old"
        backend.exchange(CLA, InsType.SIGN_PERSONAL_MESSAGE, P1.FIRST, 0x00,
                         abandoned)

        message = b"replacement message"
        replacement = pack_derivation_path(client.getAccount(0)['path'])
        replacement += struct.pack(">I", len(message)) + message
        with backend.exchange_async(CLA, InsType.SIGN_PERSONAL_MESSAGE,
                                    P1.FIRST, 0x00, replacement):
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Hold to sign",
                screen_change_before_first_instruction=True)

        response = backend.last_async_response
        signed_message = (b'\x19TRON Signed Message:\n' +
                          str(len(message)).encode() + message)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signed_message)
        assert check_hash_signature(keccak_hash.digest(), response.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_sign_hash(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        hash_to_sign = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                     "101112131415161718191a1b1c1d1e1f")
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += hash_to_sign

        with backend.exchange_async(CLA, InsType.SIGN_TXN_HASH, 0x00, 0x00,
                                    data):
            if firmware.is_nano:
                text = "Sign"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    @pytest.mark.parametrize("account_number", [0, 1])
    def test_trx_sign_tip712_displays_signing_account(self, backend, firmware,
                                                      navigator,
                                                      account_number):
        client = TronClient(backend, firmware, navigator)
        domainHash = bytes.fromhex(
            '6137beb405d9ff777172aa879e33edb34a1460e701802746c5ef96e741710e59')
        messageHash = bytes.fromhex(
            'eb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8')
        account = client.getAccount(account_number)
        data = pack_derivation_path(account['path'])
        data += domainHash
        data += messageHash
        signer_public_key = b'\x04' + bytes.fromhex(account['publicKey'][2:])
        signer_address = client.compute_address_from_public_key(
            signer_public_key)

        with backend.exchange_async(CLA, InsType.SIGN_TIP_712_MESSAGE, 0x00,
                                    0x00, data):
            if firmware.is_nano:
                navigate_instruction = NavInsID.RIGHT_CLICK
                validation_instructions = [NavInsID.BOTH_CLICK]
                approval_text = r"^Sign$"
            else:
                navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
                validation_instructions = [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
                approval_text = "Hold to sign"

            navigator.navigate_until_text(
                navigate_instruction, [],
                "Sign with",
                screen_change_before_first_instruction=True,
                screen_change_after_last_instruction=False)
            displayed_address = (signer_address[:12]
                                 if firmware.is_nano else signer_address)
            screen = backend.get_current_screen_content()
            displayed_text = "".join(event.get("text", "")
                                     for event in screen["events"])
            assert displayed_address in displayed_text, screen
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=False)

        resp = backend.last_async_response

        # Magic define
        SIGN_MAGIC = b'\x19\x01'
        msg_to_sign = SIGN_MAGIC + domainHash + messageHash
        hash = keccak.new(digest_bits=256, data=msg_to_sign).digest()

        assert check_hash_signature(hash, resp.data[0:65],
                                    account['publicKey'][2:])

    @pytest.mark.parametrize(("payload", "expected_status"), [
        (b'\x00' + (b'\x00' * 64), Errors.INCORRECT_BIP32_PATH),
        (pack_derivation_path("m/44'/195'/0'/0/0") +
         (b'\x00' * 65), Errors.INCORRECT_LENGTH),
    ])
    def test_trx_sign_tip712_rejects_malformed_payload(self, backend, payload,
                                                       expected_status):
        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.SIGN_TIP_712_MESSAGE, 0x00, 0x00,
                             payload)
        assert error.value.status == expected_status

    def test_trx_send_permissioned(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000), None, 2)
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_ecdh_key(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        # get ledger public key
        data = pack_derivation_path(client.getAccount(0)['path'])
        resp = backend.exchange(CLA, InsType.GET_PUBLIC_KEY, 0x00, 0x00, data)
        assert (resp.data[0] == 65)
        pubKey = bytes(resp.data[1:66])

        # get pair key
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += bytearray.fromhex(f"04{client.getAccount(1)['publicKey'][2:]}")
        with backend.exchange_async(CLA, InsType.GET_ECDH_SECRET, 0x00, 0x01,
                                    data):
            if firmware.is_nano:
                text = "Accept"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)
        resp = backend.last_async_response

        # check if pair key matchs
        pubKeyDH = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pubKey)
        shared_key = client.getAccount(1)['dh'].exchange(ec.ECDH(), pubKeyDH)
        assert (shared_key.hex() == resp.data[1:33].hex())

    @pytest.mark.parametrize(("peer_public_key", "expected_status"), [
        pytest.param(b'\x00', Errors.INCORRECT_LENGTH,
                     id="infinity-encoding"),
        pytest.param(
            bytes.fromhex(
                "03"
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
            Errors.INCORRECT_DATA,
            id="wrong-prefix"),
        pytest.param(b'\x04' + (b'\x00' * 64), Errors.INCORRECT_DATA,
                     id="zero-coordinates"),
        pytest.param(
            b'\x04' +
            bytes.fromhex(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f") +
            (b'\x00' * 31) + b'\x01',
            Errors.INCORRECT_DATA,
            id="coordinate-outside-field"),
        pytest.param(
            b'\x04' + (b'\x00' * 31) + b'\x01' +
            (b'\x00' * 31) + b'\x01',
            Errors.INCORRECT_DATA,
            id="off-curve"),
    ])
    def test_trx_ecdh_rejects_invalid_peer_key(self, backend, peer_public_key,
                                               expected_status):
        path = pack_derivation_path("m/44'/195'/0'/0/0")

        with pytest.raises(ExceptionRAPDU) as error:
            backend.exchange(CLA, InsType.GET_ECDH_SECRET, 0x00, 0x01,
                             path + peer_public_key)
        assert error.value.status == expected_status

        # Rejection must not leave a pending review or poison the next APDU.
        response = backend.exchange(CLA, InsType.GET_PUBLIC_KEY, 0x00, 0x00,
                                    path)
        assert response.status == Errors.OK
        assert response.data[0] == 65

    def test_trx_custom_contract(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
                data=bytes.fromhex('{:08x}{:064x}'.format(
                    0x0a857040, int(10001)))))
        self.sign_and_validate(client, firmware, 0, tx, warning_approve=True)

    def test_trx_custom_contract_displays_all_attached_values(
            self, backend, firmware, navigator):
        if firmware.device == "flex":
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"
        elif firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        else:
            pytest.skip(
                "Direct semantic UI assertion is calibrated for Flex and Nano")

        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
                data=bytes.fromhex('{:08x}{:064x}'.format(
                    0x0a857040, int(10001))),
                call_value=1000000,
                call_token_value=123,
                token_id=1000001))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00, payload):
            if firmware.device == "flex":
                navigator.navigate([NavIns(NavInsID.TOUCH, (200, 445))])
            navigator.navigate_until_text(
                navigate_instruction, [],
                "Attached TRX",
                screen_change_before_first_instruction=False)
            assert backend.compare_screen_with_text(r"^1$"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                navigate_instruction, [],
                "TRC10 ID",
                screen_change_before_first_instruction=False)
            assert backend.compare_screen_with_text(r"^1000001$"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                navigate_instruction, [],
                "TRC10 Amount",
                screen_change_before_first_instruction=False)
            assert backend.compare_screen_with_text(r"^123$"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                navigate_instruction,
                validation_instructions,
                approval_text,
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_unknown_trc20_send(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TVGLX58e3uBx1fmmwLCENkrgKqmpEjhtfG")),
                data=bytes.fromhex(
                    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx, warning_approve=True)

    def test_trx_freezeV2_balance(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             frozen_balance=100000000,
                                             resource=contract.ENERGY))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreezeV2_balance(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                               unfreeze_balance=100000000,
                                               resource=contract.ENERGY))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_delegate_resource(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.DelegateResourceContract,
            contract.DelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
                lock=0))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_delegate_resource_displays_mainnet_lock_period(
            self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.DelegateResourceContract,
            contract.DelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(client.address_hex(
                    "TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
                lock=True,
                lock_period=864000))
        payload = pack_derivation_path(client.getAccount(0)['path']) + tx
        assert len(payload) <= MAX_APDU_LEN

        if firmware.is_nano:
            navigate_instruction = NavInsID.RIGHT_CLICK
            validation_instructions = [NavInsID.BOTH_CLICK]
            approval_text = "Sign"
        else:
            navigate_instruction = NavInsID.SWIPE_CENTER_TO_LEFT
            validation_instructions = [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS
            ]
            approval_text = "Hold to sign"

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00,
                                    payload):
            navigator.navigate_until_text(
                navigate_instruction, [], "Lock period",
                screen_change_before_first_instruction=True)
            assert backend.compare_screen_with_text("864000 blocks"), \
                backend.get_current_screen_content()
            navigator.navigate_until_text(
                navigate_instruction, validation_instructions, approval_text,
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_undelegate_resource(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnDelegateResourceContract,
            contract.UnDelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"))))
        self.sign_and_validate(client, firmware, 0, tx)

    @pytest.mark.parametrize(("resource", "receiver_address"), [
        (contract.ENERGY, "TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"),
        (contract.BANDWIDTH, "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"),
    ])
    def test_trx_undelegate_resource_displays_semantic_address_roles(
            self, backend, firmware, navigator, resource, receiver_address):
        if firmware.device != "flex":
            pytest.skip(
                "Direct undelegation role assertion is calibrated for Flex")

        client = TronClient(backend, firmware, navigator)
        account = client.getAccount(0)
        owner_address = client.compute_address_from_public_key(
            b'\x04' + bytes.fromhex(account['publicKey'][2:]))
        tx = client.packContract(
            tron.Transaction.Contract.UnDelegateResourceContract,
            contract.UnDelegateResourceContract(
                owner_address=bytes.fromhex(account['addressHex']),
                resource=resource,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex(receiver_address))))
        payload = pack_derivation_path(account['path']) + tx
        assert len(payload) < MAX_APDU_LEN

        with backend.exchange_async(CLA, InsType.SIGN, P1.SIGN, 0x00, payload):
            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [],
                "Undelegate To",
                screen_change_before_first_instruction=True)
            assert backend.compare_screen_with_text(owner_address[:12]), \
                backend.get_current_screen_content()
            assert not backend.compare_screen_with_text(receiver_address[:12]), \
                backend.get_current_screen_content()

            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [],
                "Undelegate From",
                screen_change_before_first_instruction=False)
            assert backend.compare_screen_with_text(receiver_address[:12]), \
                backend.get_current_screen_content()
            assert not backend.compare_screen_with_text(owner_address[:12]), \
                backend.get_current_screen_content()

            navigator.navigate_until_text(
                NavInsID.SWIPE_CENTER_TO_LEFT, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                "Hold to sign",
                screen_change_before_first_instruction=False)

        response = backend.last_async_response
        assert check_tx_signature(tx, response.data[0:65],
                                  account['publicKey'][2:])

    def test_trx_withdraw_unfreeze(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawExpireUnfreezeContract,
            contract.WithdrawExpireUnfreezeContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_cancel_all_unfreeze_v2(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.CancelAllUnfreezeV2Contract,
            contract.CancelAllUnfreezeV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, firmware, 0, tx)
