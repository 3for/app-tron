import pytest

from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware

from tron import CLA, Errors, InsType, TronClient
from client.command_builder import CommandBuilder, InsType as BuilderInsType
import keychain

import sys
from pathlib import Path
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/proto")
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron


TRC20_CONTRACT_B58 = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
TRC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
TRC20_TRANSFER_CALLDATA = bytes.fromhex(
    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d7"
    "00000000000000000000000000000000000000000000000000000000000f4240")


def build_trc20_transfer_tx(client: TronClient) -> bytes:
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes.fromhex(
                client.address_hex(TRC20_CONTRACT_B58)),
            data=TRC20_TRANSFER_CALLDATA))


def test_set_external_plugin_rejects_short_payload(backend: BackendInterface):
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(CLA, BuilderInsType.EXTERNAL_PLUGIN_SETUP, 0x00, 0x00,
                         b"\x00")
    assert e.value.status == Errors.INCORRECT_DATA


def test_set_external_plugin_returns_plugin_not_found(
        firmware: Firmware, backend: BackendInterface):
    client = TronClient(backend, firmware, None)
    builder = CommandBuilder()
    plugin_name = "missingPlugin"
    contract_addr = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))

    payload = bytearray()
    payload.append(len(plugin_name))
    payload += plugin_name.encode()
    payload += contract_addr
    payload += TRC20_TRANSFER_SELECTOR
    # set_external_plugin validates COIN_META signatures (CAL key in test setup)
    signature = keychain.sign_data(keychain.Key.CAL, bytes(payload))

    try:
        client.exchange_raw(
            builder.set_external_plugin(plugin_name, contract_addr,
                                        TRC20_TRANSFER_SELECTOR, signature))
    except ExceptionRAPDU as e:
        assert e.status == Errors.PLUGIN_NOT_FOUND
    except Exception as e:
        # Known Speculos issue:
        # missing plugin lookup can crash launcher instead of returning an APDU.
        if (isinstance(e, TimeoutError)
                or e.__class__.__name__ == "ChunkedEncodingError"):
            pytest.xfail(
                "Speculos crashes when checking presence of a missing external plugin"
            )
        raise


def test_clear_sign_without_external_plugin_returns_invalid_data(
        firmware: Firmware, backend: BackendInterface):
    client = TronClient(backend, firmware, None)
    tx = build_trc20_transfer_tx(client)

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(client.getAccount(0)["path"],
                    tx,
                    navigate=False,
                    ins=InsType.CLEAR_SIGN,
                    include_tx_len=True)
    assert e.value.status == Errors.INCORRECT_DATA
