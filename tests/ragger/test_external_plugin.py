import sys
from pathlib import Path

import pytest

import keychain
from ledgered.devices import Device
from client.command_builder import (
    CommandBuilder,
    InsType as BuilderInsType,
    encode_tron_base58_metadata_address,
)
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from tron import CLA, Errors, InsType, TronClient
from client.tip712.InputData import send_coin_meta_certificate

PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

TRC20_CONTRACT_B58 = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
TRC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
TRC20_TRANSFER_CALLDATA = bytes.fromhex(
    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d7"
    "00000000000000000000000000000000000000000000000000000000000f4240")
MISSING_PLUGIN_NAME = "missingPlugin"
SPECULOS_MISSING_PLUGIN_XFAIL_REASON = (
    "Speculos crashes when checking presence of a missing external plugin")


def build_trc20_transfer_tx(client: TronClient) -> bytes:
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes.fromhex(
                client.address_hex(TRC20_CONTRACT_B58)),
            data=TRC20_TRANSFER_CALLDATA))


def build_external_plugin_payload(plugin_name: str, contract_address: bytes,
                                  selector: bytes) -> bytes:
    payload = bytearray()
    payload.append(len(plugin_name))
    payload += plugin_name.encode()
    payload += encode_tron_base58_metadata_address(contract_address)
    payload += selector
    return bytes(payload)


def build_signed_external_plugin_setup(plugin_name: str,
                                       contract_address: bytes,
                                       selector: bytes) -> bytes:
    payload = build_external_plugin_payload(plugin_name, contract_address,
                                            selector)
    signature = keychain.sign_data(keychain.Key.CAL, payload)
    return CommandBuilder().set_external_plugin(plugin_name, contract_address,
                                                selector, signature)


def assert_plugin_not_found_or_speculos_crash(client: TronClient,
                                              setup_apdu: bytes) -> None:
    try:
        client.exchange_raw(setup_apdu)
    except ExceptionRAPDU as error:
        assert error.status == Errors.PLUGIN_NOT_FOUND
        return
    except Exception as error:
        if (isinstance(error, TimeoutError)
                or error.__class__.__name__ == "ChunkedEncodingError"):
            pytest.xfail(SPECULOS_MISSING_PLUGIN_XFAIL_REASON)
        raise

    pytest.fail("external plugin lookup unexpectedly succeeded")


@pytest.fixture(name="tron_client")
def tron_client_fixture(device: Device,
                        backend: BackendInterface) -> TronClient:
    return TronClient(backend, device, None)


@pytest.fixture(name="trc20_contract_address")
def trc20_contract_address_fixture(tron_client: TronClient) -> bytes:
    return bytes.fromhex(tron_client.address_hex(TRC20_CONTRACT_B58))


@pytest.fixture(name="trc20_transfer_tx")
def trc20_transfer_tx_fixture(tron_client: TronClient) -> bytes:
    return build_trc20_transfer_tx(tron_client)


def test_set_external_plugin_rejects_short_payload(backend: BackendInterface):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, BuilderInsType.EXTERNAL_PLUGIN_SETUP, 0x00, 0x00,
                         b"\x00")
    assert e.value.status == Errors.INCORRECT_DATA


def test_set_external_plugin_returns_plugin_not_found(
        tron_client: TronClient, trc20_contract_address: bytes):
    send_coin_meta_certificate(tron_client)
    assert_plugin_not_found_or_speculos_crash(
        tron_client,
        build_signed_external_plugin_setup(MISSING_PLUGIN_NAME,
                                           trc20_contract_address,
                                           TRC20_TRANSFER_SELECTOR))


def test_sign_external_plugin_without_external_plugin_returns_invalid_data(
        tron_client: TronClient, trc20_transfer_tx: bytes):

    with pytest.raises(ExceptionRAPDU) as e:
        tron_client.sign(tron_client.getAccount(0)["path"],
                         trc20_transfer_tx,
                         navigate=False,
                         ins=InsType.SIGN_EXTERNAL_PLUGIN,
                         include_tx_len=True)
    assert e.value.status == Errors.INCORRECT_DATA
