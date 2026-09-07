import pytest
from google.protobuf.any_pb2 import Any
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigationScenarioData, UseCase

from application_client.tron_command_sender import Errors, TronCommandSender
from application_client.tron_transaction import address_hex, contract, tron
from utils import check_tx_signature


SUPPORTED_TRON_POWER_CONTRACTS = (
    tron.Transaction.Contract.FreezeBalanceContract,
    tron.Transaction.Contract.UnfreezeBalanceContract,
    tron.Transaction.Contract.FreezeBalanceV2Contract,
    tron.Transaction.Contract.UnfreezeBalanceV2Contract,
)

ALL_RESOURCE_CONTRACTS = SUPPORTED_TRON_POWER_CONTRACTS + (
    tron.Transaction.Contract.DelegateResourceContract,
    tron.Transaction.Contract.UnDelegateResourceContract,
)


def _encode_varint(value: int) -> bytes:
    assert value >= 0
    encoded = bytearray()
    while value > 0x7f:
        encoded.append((value & 0x7f) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _resource_contract(contract_type, owner_address: bytes, receiver_address: bytes = b""):
    if contract_type == tron.Transaction.Contract.FreezeBalanceContract:
        return contract.FreezeBalanceContract(owner_address=owner_address,
                                              frozen_balance=100000000,
                                              frozen_duration=3,
                                              receiver_address=receiver_address), 10
    if contract_type == tron.Transaction.Contract.UnfreezeBalanceContract:
        return contract.UnfreezeBalanceContract(owner_address=owner_address,
                                                receiver_address=receiver_address), 10
    if contract_type == tron.Transaction.Contract.FreezeBalanceV2Contract:
        return contract.FreezeBalanceV2Contract(owner_address=owner_address,
                                                frozen_balance=100000000), 3
    if contract_type == tron.Transaction.Contract.UnfreezeBalanceV2Contract:
        return contract.UnfreezeBalanceV2Contract(owner_address=owner_address,
                                                  unfreeze_balance=100000000), 3

    if not receiver_address:
        receiver_address = bytes.fromhex(address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"))
    if contract_type == tron.Transaction.Contract.DelegateResourceContract:
        return contract.DelegateResourceContract(owner_address=owner_address,
                                                 balance=100000000,
                                                 receiver_address=receiver_address), 2
    if contract_type == tron.Transaction.Contract.UnDelegateResourceContract:
        return contract.UnDelegateResourceContract(owner_address=owner_address,
                                                   balance=100000000,
                                                   receiver_address=receiver_address), 2
    raise AssertionError(f"unsupported resource contract type: {contract_type}")


def _pack_with_raw_resource(contract_type, message, resource_field: int, resource: int) -> bytes:
    raw_message = message.SerializeToString(deterministic=True)
    raw_message += _encode_varint(resource_field << 3) + _encode_varint(resource)

    tx = tron.Transaction()
    tx.raw_data.timestamp = 1575712492061
    tx.raw_data.expiration = 1575712551000
    tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
    tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")

    wrapped = tx.raw_data.contract.add()
    wrapped.type = contract_type
    parameter = Any()
    parameter.type_url = f"type.googleapis.com/{message.DESCRIPTOR.full_name}"
    parameter.value = raw_message
    wrapped.parameter.CopyFrom(parameter)
    return tx.raw_data.SerializeToString(deterministic=True)


@pytest.mark.parametrize("contract_type", SUPPORTED_TRON_POWER_CONTRACTS)
def test_tron_power_is_clear_signed_exactly(backend, accounts, device, navigator, contract_type):
    message, resource_field = _resource_contract(
        contract_type, bytes.fromhex(accounts[0]["addressHex"]))
    tx = _pack_with_raw_resource(contract_type, message, resource_field, contract.TRON_POWER)

    client = TronCommandSender(backend)
    scenario = NavigationScenarioData(device, backend, UseCase.TX_REVIEW, True)
    with client.sign_tx(accounts[0]["path"], tx):
        navigator.navigate_until_text(scenario.navigation, [], "Tron Power",
                                      screen_change_after_last_instruction=False)
        navigator.navigate_until_text(
            scenario.navigation, scenario.validation,
            "Sign [Tt]ransaction" if device.is_nano else scenario.pattern,
            screen_change_before_first_instruction=False)
    signature = client.get_async_response().data
    assert check_tx_signature(tx, signature[:65], accounts[0]["publicKey"][2:])


@pytest.mark.parametrize("contract_type", ALL_RESOURCE_CONTRACTS)
@pytest.mark.parametrize("resource", (3, 255, 256))
def test_unknown_resource_is_rejected_before_narrowing(backend, accounts, contract_type,
                                                        resource):
    message, resource_field = _resource_contract(
        contract_type, bytes.fromhex(accounts[0]["addressHex"]))
    tx = _pack_with_raw_resource(contract_type, message, resource_field, resource)

    with pytest.raises(ExceptionRAPDU) as error:
        TronCommandSender(backend).sign(accounts[0]["path"], tx)
    assert error.value.status == Errors.INCORRECT_DATA


@pytest.mark.parametrize("contract_type", (
    tron.Transaction.Contract.DelegateResourceContract,
    tron.Transaction.Contract.UnDelegateResourceContract,
))
def test_tron_power_delegation_is_rejected(backend, accounts, contract_type):
    message, resource_field = _resource_contract(
        contract_type, bytes.fromhex(accounts[0]["addressHex"]))
    tx = _pack_with_raw_resource(contract_type, message, resource_field, contract.TRON_POWER)

    with pytest.raises(ExceptionRAPDU) as error:
        TronCommandSender(backend).sign(accounts[0]["path"], tx)
    assert error.value.status == Errors.INCORRECT_DATA


@pytest.mark.parametrize("contract_type", (
    tron.Transaction.Contract.FreezeBalanceContract,
    tron.Transaction.Contract.UnfreezeBalanceContract,
))
def test_legacy_tron_power_receiver_is_rejected(backend, accounts, contract_type):
    message, resource_field = _resource_contract(
        contract_type,
        bytes.fromhex(accounts[0]["addressHex"]),
        bytes.fromhex(accounts[1]["addressHex"]))
    tx = _pack_with_raw_resource(contract_type, message, resource_field, contract.TRON_POWER)

    with pytest.raises(ExceptionRAPDU) as error:
        TronCommandSender(backend).sign(accounts[0]["path"], tx)
    assert error.value.status == Errors.INCORRECT_DATA
