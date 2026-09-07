import pytest
from google.protobuf.any_pb2 import Any
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.tron_command_sender import Errors, TronCommandSender
from application_client.tron_transaction import address_hex, contract, tron
from utils import check_tx_signature


def _encode_varint(value: int) -> bytes:
    assert value >= 0
    encoded = bytearray()
    while value > 0x7f:
        encoded.append((value & 0x7f) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _lock_period_field(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    return b"\x30" + _encode_varint(value)


def _build_delegate_with_lock(owner_address: bytes,
                              lock_fields: bytes,
                              lock_period_fields: bytes = b"") -> bytes:
    delegate = contract.DelegateResourceContract(
        owner_address=owner_address,
        resource=contract.ENERGY,
        balance=100000000,
        receiver_address=bytes.fromhex(address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
        lock=False,
    )
    inner = delegate.SerializeToString(deterministic=True)
    # Preserve the wire encoding inside Any.value, without reserializing the bool.
    inner += lock_fields + lock_period_fields

    tx = tron.Transaction()
    tx.raw_data.timestamp = 1575712492061
    tx.raw_data.expiration = 1575712551000
    tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
    tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")

    wrapped = tx.raw_data.contract.add()
    wrapped.type = tron.Transaction.Contract.DelegateResourceContract
    parameter = Any()
    parameter.type_url = "type.googleapis.com/protocol.DelegateResourceContract"
    parameter.value = inner
    wrapped.parameter.CopyFrom(parameter)
    return tx.raw_data.SerializeToString(deterministic=True)


@pytest.mark.parametrize("lock_fields", [
    pytest.param(b"\x28\x80\x80\x80\x80\x90\x00", id="reported-six-byte-value"),
    pytest.param(b"\x28\x80\x80\x80\x80\x10", id="five-byte-overflow"),
    pytest.param(b"\x28\x80\x80\x80\x80\xF0\x80\x80\x80\x80\x00",
                 id="ten-byte-zero-extension"),
    pytest.param(b"\x28\x80\x80\x80\x80\x80\x01", id="nonzero-sixth-byte"),
    pytest.param(b"\x28" + b"\x80" * 9 + b"\x01", id="bit-63"),
    pytest.param(b"\x28" + b"\x80" * 10 + b"\x00", id="overlong"),
    pytest.param(b"\x28\x80", id="truncated"),
    pytest.param(b"\x28\x00\x28\x80\x80\x80\x80\x90\x00",
                 id="false-before-overflow"),
    pytest.param(b"\x28\x80\x80\x80\x80\x90\x00\x28\x00",
                 id="false-after-overflow"),
])
def test_rejects_invalid_lock(backend, accounts, lock_fields):
    tx = _build_delegate_with_lock(bytes.fromhex(accounts[0]["addressHex"]), lock_fields)
    with pytest.raises(ExceptionRAPDU) as error:
        TronCommandSender(backend).sign(accounts[0]["path"], tx)
    assert error.value.status == Errors.INCORRECT_DATA


@pytest.mark.parametrize("lock_period_fields", [
    pytest.param(_lock_period_field(-1), id="negative"),
    pytest.param(b"\x30\x80", id="truncated"),
    pytest.param(b"\x30" + b"\x80" * 10 + b"\x00", id="overlong"),
    pytest.param(b"\x32\x01\x01", id="wrong-wire-type"),
])
def test_rejects_invalid_active_lock_period(backend, accounts, lock_period_fields):
    tx = _build_delegate_with_lock(bytes.fromhex(accounts[0]["addressHex"]),
                                   b"\x28\x01", lock_period_fields)
    with pytest.raises(ExceptionRAPDU) as error:
        TronCommandSender(backend).sign(accounts[0]["path"], tx)
    assert error.value.status == Errors.INCORRECT_DATA


@pytest.mark.parametrize(("lock_fields", "lock_period_fields", "expected_lock",
                          "expected_period"), [
    pytest.param(b"", b"", False, "Not applied", id="omitted-false"),
    pytest.param(b"\x28\x00", _lock_period_field(86400), False, "Not applied",
                 id="inactive-period-ignored"),
    pytest.param(b"\x28\x00", _lock_period_field(-1), False, "Not applied",
                 id="inactive-negative-period-ignored"),
    pytest.param(b"\x28\x01", b"", True, "Network default",
                 id="active-default-period"),
    pytest.param(b"\x28\x01", _lock_period_field(0), True, "Network default",
                 id="active-zero-period"),
    pytest.param(b"\x28\x01", _lock_period_field(1), True, "1 block",
                 id="active-one-block"),
    pytest.param(b"\x28\x01", _lock_period_field(86400), True, "86400 blocks",
                 id="active-explicit-period"),
    pytest.param(b"\x28\x01", _lock_period_field(1) + _lock_period_field(86400), True,
                 "86400 blocks", id="active-duplicate-period-last-wins"),
    pytest.param(b"\x28\x01", _lock_period_field(86400) + _lock_period_field(1), True,
                 "1 block", id="active-duplicate-period-reverse-last-wins"),
    pytest.param(b"\x28\x01", _lock_period_field((1 << 63) - 1), True,
                 "922337", id="active-int64-max"),
    pytest.param(b"\x28\x02", _lock_period_field(7), True, "7 blocks",
                 id="noncanonical-true"),
    pytest.param(b"\x28" + b"\x80" * 9 + b"\x00", b"", False, "Not applied",
                 id="padded-false"),
    pytest.param(b"\x28\x81" + b"\x80" * 8 + b"\x00", _lock_period_field(42),
                 True, "42 blocks", id="padded-true"),
])
def test_signs_matching_lock(backend, accounts, device, navigator, lock_fields,
                             lock_period_fields, expected_lock, expected_period):
    tx = _build_delegate_with_lock(bytes.fromhex(accounts[0]["addressHex"]), lock_fields,
                                   lock_period_fields)
    raw = tron.Transaction.raw.FromString(tx)
    decoded = contract.DelegateResourceContract.FromString(raw.contract[0].parameter.value)
    assert decoded.lock == expected_lock

    client = TronCommandSender(backend)
    scenario = NavigationScenarioData(device, backend, UseCase.TX_REVIEW, True)
    with client.sign_tx(accounts[0]["path"], tx):
        # Check the actual displayed lock value, then complete the approval.
        navigator.navigate_until_text(scenario.navigation, [], str(expected_lock),
                                      screen_change_after_last_instruction=False)
        navigator.navigate_until_text(scenario.navigation, [], expected_period,
                                      screen_change_before_first_instruction=False,
                                      screen_change_after_last_instruction=False)
        navigator.navigate_until_text(
            scenario.navigation, scenario.validation,
            "Sign [Tt]ransaction" if device.is_nano else scenario.pattern,
            screen_change_before_first_instruction=False)
    signature = client.get_async_response().data
    assert check_tx_signature(tx, signature[:65], accounts[0]["publicKey"][2:])
