"""
P1 skeleton for Generic Clear Signing (generic_tx_parser) on app-tron.

Pipeline under test:

    0xC4 (P2=STORE)  -> stream TriggerSmartContract, park EVM calldata + tx_ctx
    0x26 TX_INFO     -> CAL-signed descriptor (selector + fields_hash commitment)
    0x28 FIELD x N   -> per-field render rules; running hash must equal fields_hash

`test_gcs_store_parks_calldata` is fully runnable today (it only exercises the
0xC4/P2=STORE bridge, which returns 0x9000 once the calldata is parked).

`test_gcs_p1_end_to_end` is a scaffold: the exact TX_INFO/FIELD serialization,
the fields_hash algorithm and the signature key-usage must be confirmed against
the Ledger backend before it can pass. It is skipped until then.
"""
import sys
from pathlib import Path
from struct import pack

import pytest
from Crypto.Hash import keccak

import keychain
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from tron import CLA, Errors, InsType, TronClient, MAX_APDU_LEN
from client.tip712.InputData import format_tlv

PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

# --- APDU constants (mirror src/apdu_constants.h) ---------------------------
P1_FIRST = 0x00
P1_MORE = 0x80
P1_LAST = 0x90
P2_GCS_STORE = 0x10

INS_GTP_TRANSACTION_INFO = 0x26
INS_GTP_FIELD = 0x28
P1_FIRST_CHUNK = 0x01

# TRON mainnet chain id used by the GCS descriptors (chain_config.h).
TRON_MAINNET_CHAINID = 728126428

# A simple TRC20 `transfer(address,uint256)` call: selector + 2 ABI words.
TRC20_CONTRACT_B58 = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
TRC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
TRC20_TRANSFER_CALLDATA = bytes.fromhex(
    "a9059cbb"
    "000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d7"
    "00000000000000000000000000000000000000000000000000000000000f4240")


@pytest.fixture(name="tron_client")
def tron_client_fixture(device: Device, backend: BackendInterface) -> TronClient:
    return TronClient(backend, device, None)


def build_trc20_transfer_tx(client: TronClient) -> bytes:
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58)),
            data=TRC20_TRANSFER_CALLDATA))


def gcs_store_calldata(client: TronClient, backend: BackendInterface, path: str,
                       tx: bytes) -> int:
    """Stream a TriggerSmartContract through 0xC4 with P2=STORE.

    Mirrors TronClient.sign()'s external-plugin branch, but with P2=GCS_STORE so
    the firmware parks the calldata into the generic_tx_parser context instead of
    showing the external-plugin UI. Returns the final status word.
    """
    data = bytearray(pack_derivation_path(path))
    data += pack(">I", len(tx))  # include_tx_len
    max_first = MAX_APDU_LEN - len(data)
    assert max_first >= 0
    data += tx[:max_first]
    rest = tx[max_first:]

    messages = [bytes(data)]
    while rest:
        messages.append(rest[:MAX_APDU_LEN])
        rest = rest[MAX_APDU_LEN:]

    for i, msg in enumerate(messages[:-1]):
        p1 = P1_FIRST if i == 0 else P1_MORE
        backend.exchange(CLA, InsType.SIGN_EXTERNAL_PLUGIN, p1, P2_GCS_STORE, msg)
    p1 = P1_FIRST if len(messages) == 1 else P1_LAST
    return backend.exchange(CLA, InsType.SIGN_EXTERNAL_PLUGIN, p1, P2_GCS_STORE,
                            messages[-1]).status


def test_gcs_store_parks_calldata(tron_client: TronClient,
                                  backend: BackendInterface):
    """0xC4/P2=STORE on a TRC20 transfer parks the calldata and returns 0x9000."""
    tx = build_trc20_transfer_tx(tron_client)
    status = gcs_store_calldata(tron_client, backend,
                                tron_client.getAccount(0)["path"], tx)
    assert status == Errors.OK


# --- Descriptor builders (scaffold) -----------------------------------------
# Tag values mirror gtp_tx_info.c (TX_INFO_TAGS) and gtp_field.c (FIELD_TAGS).
TX_INFO_VERSION = 0x00
TX_INFO_CHAIN_ID = 0x01
TX_INFO_CONTRACT_ADDR = 0x02
TX_INFO_SELECTOR = 0x03
TX_INFO_FIELDS_HASH = 0x04
TX_INFO_OPERATION_TYPE = 0x05
TX_INFO_SIGNATURE = 0xFF

FIELD_VERSION = 0x00
FIELD_NAME = 0x01
FIELD_PARAM_TYPE = 0x02
FIELD_PARAM = 0x03

PARAM_TYPE_RAW = 0
VALUE_VERSION = 0x00
VALUE_TYPE_FAMILY = 0x01
VALUE_TYPE_SIZE = 0x02
VALUE_DATA_PATH = 0x03
PARAM_RAW_VERSION = 0x00
PARAM_RAW_VALUE = 0x01
TF_UINT = 1


def build_field_raw(name: str, type_size: int, data_path: bytes) -> bytes:
    """Build one FIELD (0x28) struct rendering a RAW uint value from calldata.

    NOTE: `data_path` (gtp_data_path TLV) is left to the caller because its
    element encoding (tuple/array/ref/leaf/slice) must match gtp_data_path.c.
    """
    value = (format_tlv(VALUE_VERSION, 1) +
             format_tlv(VALUE_TYPE_FAMILY, TF_UINT) +
             format_tlv(VALUE_TYPE_SIZE, type_size) +
             format_tlv(VALUE_DATA_PATH, data_path))
    param = format_tlv(PARAM_RAW_VERSION, 1) + format_tlv(PARAM_RAW_VALUE, value)
    field = (format_tlv(FIELD_VERSION, 1) +
             format_tlv(FIELD_NAME, name) +
             format_tlv(FIELD_PARAM_TYPE, PARAM_TYPE_RAW) +
             format_tlv(FIELD_PARAM, param))
    return field


def build_tx_info(contract_addr20: bytes, selector: bytes, fields: list[bytes],
                  operation: str) -> bytes:
    """Build the TX_INFO (0x26) descriptor and CAL-sign it.

    fields_hash = keccak256(concat(field_payload_i)) -- must match the firmware's
    running cx_sha3 over each 0x28 payload (cmd_field.c + tx_ctx fields_hash_ctx).
    The signature covers sha256(all tags except 0xFF) with the CALLDATA key usage.
    """
    fields_hash = keccak.new(digest_bits=256, data=b"".join(fields)).digest()
    body = (format_tlv(TX_INFO_VERSION, 1) +
            format_tlv(TX_INFO_CHAIN_ID, pack(">Q", TRON_MAINNET_CHAINID)) +
            format_tlv(TX_INFO_CONTRACT_ADDR, contract_addr20) +
            format_tlv(TX_INFO_SELECTOR, selector) +
            format_tlv(TX_INFO_FIELDS_HASH, fields_hash) +
            format_tlv(TX_INFO_OPERATION_TYPE, operation))
    # TODO(backend): confirm signed digest (sha256 of `body`) and key usage.
    signature = keychain.sign_data(keychain.Key.CAL, body)
    return body + format_tlv(TX_INFO_SIGNATURE, signature)


def send_tlv(backend: BackendInterface, ins: int, payload: bytes) -> int:
    # The generic_tx_parser commands use chunked TLV (P1=FIRST_CHUNK then 0x00).
    chunks = [payload[i:i + MAX_APDU_LEN] for i in range(0, len(payload), MAX_APDU_LEN)]
    status = Errors.OK
    for i, chunk in enumerate(chunks):
        p1 = P1_FIRST_CHUNK if i == 0 else 0x00
        status = backend.exchange(CLA, ins, p1, 0x00, chunk).status
    return status


@pytest.mark.skip(reason="P1: TX_INFO/FIELD serialization, fields_hash and CAL "
                         "key-usage must be aligned with the Ledger backend")
def test_gcs_p1_end_to_end(tron_client: TronClient, backend: BackendInterface):
    """store -> 0x26 -> 0x28(raw) -> expect 0x9000 (fields_hash validated)."""
    tx = build_trc20_transfer_tx(tron_client)
    assert gcs_store_calldata(tron_client, backend,
                              tron_client.getAccount(0)["path"], tx) == Errors.OK

    contract_addr20 = bytes.fromhex(tron_client.address_hex(TRC20_CONTRACT_B58))[1:]
    # TODO: real gtp_data_path bytes pointing at the `amount` arg (2nd ABI word).
    amount_field = build_field_raw("Amount", 32, data_path=b"")
    fields = [amount_field]

    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")
    assert send_tlv(backend, INS_GTP_TRANSACTION_INFO, tx_info) == Errors.OK
    for field in fields:
        assert send_tlv(backend, INS_GTP_FIELD, field) == Errors.OK
