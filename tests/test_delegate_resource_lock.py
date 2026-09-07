import pytest
from google.protobuf.any_pb2 import Any
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.tron_command_sender import Errors, TronCommandSender
from application_client.tron_transaction import address_hex, contract, tron
from utils import check_tx_signature


def _build_delegate_with_lock(owner_address: bytes, lock_fields: bytes) -> bytes:
    delegate = contract.DelegateResourceContract(
        owner_address=owner_address,
        resource=contract.ENERGY,
        balance=100000000,
        receiver_address=bytes.fromhex(address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
        lock=False,
    )
    inner = delegate.SerializeToString(deterministic=True)
    # Preserve the wire encoding inside Any.value, without reserializing the bool.
    inner += lock_fields

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


@pytest.mark.parametrize(("lock_fields", "expected_lock"), [
    pytest.param(b"", False, id="omitted-false"),
    pytest.param(b"\x28\x00", False, id="canonical-false"),
    pytest.param(b"\x28\x01", True, id="canonical-true"),
    pytest.param(b"\x28\x02", True, id="nonzero-true"),
    pytest.param(b"\x28" + b"\x80" * 9 + b"\x00", False, id="padded-false"),
    pytest.param(b"\x28\x81" + b"\x80" * 8 + b"\x00", True, id="padded-true"),
])
def test_signs_matching_lock(backend, accounts, device, navigator, lock_fields, expected_lock):
    tx = _build_delegate_with_lock(bytes.fromhex(accounts[0]["addressHex"]), lock_fields)
    raw = tron.Transaction.raw.FromString(tx)
    decoded = contract.DelegateResourceContract.FromString(raw.contract[0].parameter.value)
    assert decoded.lock == expected_lock

    client = TronCommandSender(backend)
    scenario = NavigationScenarioData(device, backend, UseCase.TX_REVIEW, True)
    with client.sign_tx(accounts[0]["path"], tx):
        # Check the actual displayed lock value, then complete the approval.
        navigator.navigate_until_text(scenario.navigation, [], str(expected_lock),
                                      screen_change_after_last_instruction=False)
        navigator.navigate_until_text(
            scenario.navigation, scenario.validation,
            "Sign [Tt]ransaction" if device.is_nano else scenario.pattern,
            screen_change_before_first_instruction=False)
    signature = client.get_async_response().data
    assert check_tx_signature(tx, signature[:65], accounts[0]["publicKey"][2:])
