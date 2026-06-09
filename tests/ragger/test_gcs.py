"""
P1 skeleton for Generic Clear Signing (generic_tx_parser) on app-tron.

Pipeline under test:

    0xC4 (P2=STORE)  -> stream TriggerSmartContract, park EVM calldata + tx_ctx
    0x26 TX_INFO     -> CAL-signed descriptor (selector + fields_hash commitment)
    0x28 FIELD x N   -> per-field render rules; running hash must equal fields_hash

`test_gcs_store_parks_calldata` exercises only the 0xC4/P2=STORE bridge, which
returns 0x9000 once the calldata is parked.

`test_gcs_p1_end_to_end` drives the full skeleton: STORE -> 0x26 -> 0x28(raw) and
asserts the firmware validates the running fields_hash. The serialization mirrors
the app-ethereum GCS contract (the same Ledger backend / CAL key) verbatim:

  * TX_INFO struct hash  : SHA-256 over every tag except 0xFF, verified against the
                           CALLDATA PKI public key (CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA).
  * fields_hash          : SHA3-256 (NIST, cx_sha3_init(...,256)) over the raw bytes
                           of each 0x28 FIELD payload -- NOT keccak256.
  * signature            : SECP256K1 over the struct hash, signed with the CALLDATA
                           test key (keychain/calldata.pem); the device is first sent
                           the matching CALLDATA PKI certificate.
"""
import sys
import hashlib
from pathlib import Path
from struct import pack

import pytest

import keychain
from ledgered.devices import Device, DeviceType
from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.navigator import Navigator, NavIns, NavInsID
from tron import (CLA, Errors, InsType, TronClient, MAX_APDU_LEN,
                  ROOT_SCREENSHOT_PATH)
from utils import check_tx_signature
from client.tip712.InputData import format_tlv as _raw_format_tlv


def format_tlv(tag, value) -> bytes:
    """TLV-encode one field, returning ``bytes``.

    app-tron's InputData.format_tlv emits a ``bytearray`` and only accepts
    int/str/bytes values, so feeding a nested TLV (itself a ``bytearray``) back in
    trips its ``isinstance(value, bytes)`` assertion. Coerce both sides to bytes
    so descriptors can be composed by nesting (data_path -> value -> param ->
    field), matching app-ethereum's TlvSerializable behaviour.
    """
    if isinstance(value, bytearray):
        value = bytes(value)
    return bytes(_raw_format_tlv(tag, value))

PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

# --- APDU constants (mirror src/apdu_constants.h) ---------------------------
P1_FIRST = 0x00
P1_SIGN = 0x10
P1_MORE = 0x80
P1_LAST = 0x90
P2_GCS_STORE = 0x10
P2_GCS_START_FLOW = 0x11

INS_GTP_TRANSACTION_INFO = 0x26
INS_GTP_FIELD = 0x28
P1_FIRST_CHUNK = 0x01

# TRON mainnet chain id used by the GCS descriptors (chain_config.h).
TRON_MAINNET_CHAINID = 728126428
# TRON mainnet address prefix byte (parse.h ADD_PRE_FIX_BYTE_MAINNET).
ADD_PRE_FIX_BYTE_MAINNET = 0x41

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
    # The last chunk must trigger the GCS finalize so the firmware registers the
    # parked calldata as the root tx context and enters APP_STATE_SIGNING_TX.
    # P1_LAST finalizes a multi-chunk stream; a single chunk must use P1_SIGN,
    # which both initializes *and* finalizes in one APDU (sign_external_plugin.c).
    p1 = P1_SIGN if len(messages) == 1 else P1_LAST
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
PARAM_TYPE_AMOUNT = 1
PARAM_TYPE_TOKEN_AMOUNT = 2
PARAM_TYPE_DATETIME = 4
PARAM_TYPE_TRUSTED_NAME = 8
VALUE_VERSION = 0x00
VALUE_TYPE_FAMILY = 0x01
VALUE_TYPE_SIZE = 0x02
VALUE_DATA_PATH = 0x03
PARAM_RAW_VERSION = 0x00
PARAM_RAW_VALUE = 0x01
TF_UINT = 1
TF_ADDRESS = 5

# gtp_data_path.c node tags (mirror app-ethereum client/gcs.py DataPath).
DATA_PATH_VERSION = 0x00
DATA_PATH_TUPLE = 0x01
DATA_PATH_LEAF = 0x04
PATH_LEAF_STATIC = 0x03


def build_data_path_static(tuple_index: int) -> bytes:
    """gtp_data_path TLV selecting one top-level static ABI word.

    For a flat signature like `transfer(address,uint256)`, argument N is reached
    with [TUPLE(N), LEAF(STATIC)] -- the same encoding app-ethereum's
    fields_utils.build_path() emits for a non-dynamic parameter.
    """
    return (format_tlv(DATA_PATH_VERSION, 1) +
            format_tlv(DATA_PATH_TUPLE, pack(">H", tuple_index)) +
            format_tlv(DATA_PATH_LEAF, pack("B", PATH_LEAF_STATIC)))


# --- CALLDATA PKI certificate ------------------------------------------------
# TX_INFO (0x26) is verified against CERTIFICATE_PUBLIC_KEY_USAGE_CALLDATA. The
# device gets the matching public key (private half: keychain/calldata.pem) from
# this Ledger-test-root certificate, exactly as app-ethereum does. P1 of the
# Ledger-PKI APDU (CLA 0xB0 / INS 0x06) is the usage id below.
PUBKEY_USAGE_CALLDATA = 0x0b

# Per-device CALLDATA certificates (copied verbatim from app-ethereum
# client/ledger_pki.py PKI_CERTIFICATES[PUBKEY_USAGE_CALLDATA]).
CALLDATA_CERTIFICATES = {
    DeviceType.NANOSP: "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B434010135010315463044022076DD2EAB72E69D440D6ED8290C8C37E39F54294C23FF0F8520F836E7BE07455C02201D9A8A75223C1ADA1D9D00966A12EBB919D0BBF2E66F144C83FADCAA23672566",  # noqa: E501
    DeviceType.NANOX: "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B434010135010215463044022077FF9625006CB8A4AD41A4B04FF2112E92A732BD263CCE9B97D8E7D2536D04300220445B8EE3616FB907AA5E68359275E94D0A099C3E32A4FC8B3669C34083671F2F",  # noqa: E501
    DeviceType.STAX: "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B434010135010415473045022100A88646AD72CA012D5FDAF8F6AE0B7EBEF079212768D57323CB5B57CADD9EB20D022005872F8EA06092C9783F01AF02C5510588FB60CBF4BA51FB382B39C1E060BB6B",  # noqa: E501
    DeviceType.FLEX: "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B43401013501051546304402205305BDDDAD0284A2EAC2A9BE4CEF6604AE9415C5F46883448F5F6325026234A3022001ED743BCF33CCEB070FDD73C3D3FCC2CEE5AB30A5C3EB7D2A8D21C6F58D493F",  # noqa: E501
    DeviceType.APEX_P: "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B4340101350106154730450221009F5EDA5B6ED34FA9F1C44B1CC234BE5FE6C0DD4655F42EE50CA6201F59491E5A02206E055F490F56F42B625F2B5772AE860CAC6848B6C5AC8E44BC529A959249FC37",  # noqa: E501
}


def send_calldata_certificate(client: TronClient, device: Device) -> None:
    """Load the CALLDATA PKI certificate so the device can verify TX_INFO.

    No-op on devices without a published test certificate; the test is then
    skipped rather than failing on a missing trust anchor.
    """
    cert = CALLDATA_CERTIFICATES.get(device.type)
    if not cert:
        pytest.skip(f"No CALLDATA test certificate for device {device.type.name}")
    client._pki_client.send_certificate(PUBKEY_USAGE_CALLDATA, bytes.fromhex(cert))


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


# --- Rich field-type descriptor builders ------------------------------------
# PARAM_DATETIME type tag values (mirror gtp_param_datetime.h).
PARAM_DT_VERSION = 0x00
PARAM_DT_VALUE = 0x01
PARAM_DT_TYPE = 0x02
DT_UNIX = 0


def _build_value(type_size: int, data_path: bytes) -> bytes:
    """The shared VALUE struct (gtp_value.c) selecting one calldata word."""
    return (format_tlv(VALUE_VERSION, 1) +
            format_tlv(VALUE_TYPE_FAMILY, TF_UINT) +
            format_tlv(VALUE_TYPE_SIZE, type_size) +
            format_tlv(VALUE_DATA_PATH, data_path))


def build_field_amount(name: str, type_size: int, data_path: bytes) -> bytes:
    """FIELD (0x28) rendering a native-currency AMOUNT (gtp_param_amount.c).

    The firmware formats it with SUN_TO_TRX (6) decimals + the "TRX" ticker, so a
    calldata word of 1_000_000 renders as "1 TRX" -- the regression guard for the
    TRON native-decimals divergence from app-ethereum's WEI_TO_ETHER (18).
    """
    # PARAM_AMOUNT tags mirror RAW: 0x00 version, 0x01 value.
    param = format_tlv(PARAM_DT_VERSION, 1) + format_tlv(PARAM_DT_VALUE,
                                                         _build_value(type_size, data_path))
    return (format_tlv(FIELD_VERSION, 1) +
            format_tlv(FIELD_NAME, name) +
            format_tlv(FIELD_PARAM_TYPE, PARAM_TYPE_AMOUNT) +
            format_tlv(FIELD_PARAM, param))


def build_field_datetime(name: str, type_size: int, data_path: bytes) -> bytes:
    """FIELD (0x28) rendering a Unix DATETIME (gtp_param_datetime.c)."""
    param = (format_tlv(PARAM_DT_VERSION, 1) +
             format_tlv(PARAM_DT_VALUE, _build_value(type_size, data_path)) +
             format_tlv(PARAM_DT_TYPE, DT_UNIX))
    return (format_tlv(FIELD_VERSION, 1) +
            format_tlv(FIELD_NAME, name) +
            format_tlv(FIELD_PARAM_TYPE, PARAM_TYPE_DATETIME) +
            format_tlv(FIELD_PARAM, param))


# PARAM_TOKEN_AMOUNT tags (mirror gtp_param_token_amount.c).
PARAM_TA_VERSION = 0x00
PARAM_TA_VALUE = 0x01
PARAM_TA_TOKEN = 0x02


def build_field_token_amount(name: str, value_path: bytes,
                             token_path: bytes) -> bytes:
    """FIELD (0x28) rendering a TOKEN_AMOUNT (gtp_param_token_amount.c).

    `value_path` selects the amount word; `token_path` selects the token address
    word, which the firmware resolves to a ticker/decimals via the TRC20 registry
    (get_asset_info_by_addr -> "token via trc_tokens").
    """
    value = _build_value(32, value_path)  # TF_UINT amount
    token = (format_tlv(VALUE_VERSION, 1) +
             format_tlv(VALUE_TYPE_FAMILY, TF_ADDRESS) +
             format_tlv(VALUE_TYPE_SIZE, 32) +
             format_tlv(VALUE_DATA_PATH, token_path))
    param = (format_tlv(PARAM_TA_VERSION, 1) +
             format_tlv(PARAM_TA_VALUE, value) +
             format_tlv(PARAM_TA_TOKEN, token))
    return (format_tlv(FIELD_VERSION, 1) +
            format_tlv(FIELD_NAME, name) +
            format_tlv(FIELD_PARAM_TYPE, PARAM_TYPE_TOKEN_AMOUNT) +
            format_tlv(FIELD_PARAM, param))


# PARAM_TRUSTED_NAME tags (mirror gtp_param_trusted_name.c).
PARAM_TN_VERSION = 0x00
PARAM_TN_VALUE = 0x01
PARAM_TN_TYPES = 0x02
PARAM_TN_SOURCES = 0x03
TN_TYPE_ACCOUNT = 1
TN_SOURCE_ENS = 2


def build_field_trusted_name(name: str, addr_path: bytes,
                             types: list[int], sources: list[int]) -> bytes:
    """FIELD (0x28) rendering a TRUSTED_NAME (gtp_param_trusted_name.c).

    `addr_path` selects the address word; the firmware resolves it against the
    trusted names provided via INS_PROVIDE_TRUSTED_NAME, filtered by the allowed
    `types`/`sources`.
    """
    value = (format_tlv(VALUE_VERSION, 1) +
             format_tlv(VALUE_TYPE_FAMILY, TF_ADDRESS) +
             format_tlv(VALUE_TYPE_SIZE, 32) +
             format_tlv(VALUE_DATA_PATH, addr_path))
    param = (format_tlv(PARAM_TN_VERSION, 1) +
             format_tlv(PARAM_TN_VALUE, value) +
             format_tlv(PARAM_TN_TYPES, bytes(types)) +
             format_tlv(PARAM_TN_SOURCES, bytes(sources)))
    return (format_tlv(FIELD_VERSION, 1) +
            format_tlv(FIELD_NAME, name) +
            format_tlv(FIELD_PARAM_TYPE, PARAM_TYPE_TRUSTED_NAME) +
            format_tlv(FIELD_PARAM, param))


def build_tx_info(contract_addr20: bytes, selector: bytes, fields: list[bytes],
                  operation: str) -> bytes:
    """Build the TX_INFO (0x26) descriptor and CALLDATA-sign it.

    fields_hash = SHA3-256(concat(field_payload_i)) -- matches the firmware's
    running cx_sha3_init(...,256) fed with each raw 0x28 payload (cmd_field.c +
    tx_ctx fields_hash_ctx). This is NIST SHA3-256, *not* keccak256.

    The signature covers SHA-256(all tags except 0xFF) -- keychain.sign_data()
    hashes with SHA-256 internally -- using the CALLDATA key, whose public key is
    delivered to the device through the CALLDATA PKI certificate.
    """
    fields_hash = hashlib.sha3_256(b"".join(fields)).digest()
    body = (format_tlv(TX_INFO_VERSION, 1) +
            format_tlv(TX_INFO_CHAIN_ID, pack(">Q", TRON_MAINNET_CHAINID)) +
            format_tlv(TX_INFO_CONTRACT_ADDR, contract_addr20) +
            format_tlv(TX_INFO_SELECTOR, selector) +
            format_tlv(TX_INFO_FIELDS_HASH, fields_hash) +
            format_tlv(TX_INFO_OPERATION_TYPE, operation))
    signature = keychain.sign_data(keychain.Key.CALLDATA, body)
    return body + format_tlv(TX_INFO_SIGNATURE, signature)


def send_tlv(backend: BackendInterface, ins: int, payload: bytes) -> int:
    # The generic_tx_parser commands (0x26 / 0x28) use chunked TLV: the FIRST
    # chunk is prefixed with the total TLV length as a 2-byte big-endian integer
    # (tlv_apdu.c reads it with read_u16_be), continuation chunks are raw. The
    # firmware strips this prefix before parsing/hashing, so it is not part of
    # the descriptor or the fields_hash.
    framed = pack(">H", len(payload)) + payload
    chunks = [framed[i:i + MAX_APDU_LEN] for i in range(0, len(framed), MAX_APDU_LEN)]
    status = Errors.OK
    for i, chunk in enumerate(chunks):
        p1 = P1_FIRST_CHUNK if i == 0 else 0x00
        status = backend.exchange(CLA, ins, p1, 0x00, chunk).status
    return status


def test_gcs_p1_end_to_end(tron_client: TronClient, backend: BackendInterface,
                           device: Device):
    """store -> 0x26 -> 0x28(raw) -> expect 0x9000 (fields_hash validated)."""
    tx = build_trc20_transfer_tx(tron_client)
    assert gcs_store_calldata(tron_client, backend,
                              tron_client.getAccount(0)["path"], tx) == Errors.OK

    # generic_tx_parser works on 20-byte EVM addresses (0x41 prefix stripped).
    contract_addr20 = bytes.fromhex(tron_client.address_hex(TRC20_CONTRACT_B58))[1:]

    # `transfer(address _to, uint256 _amount)`: _amount is arg index 1, static.
    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]

    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")

    # TX_INFO is signed by the CALLDATA key: load its PKI certificate first.
    send_calldata_certificate(tron_client, device)
    assert send_tlv(backend, INS_GTP_TRANSACTION_INFO, tx_info) == Errors.OK
    for field in fields:
        assert send_tlv(backend, INS_GTP_FIELD, field) == Errors.OK


def _approve_review(navigator: Navigator, device: Device, test_name: str) -> None:
    """Walk the GCS review screen to its sign confirmation and approve it.

    Uses snapshot comparison so the functional signing test also records the
    rendered GCS review flow.
    """
    if device.is_nano:
        navigator.navigate_until_text_and_compare(NavIns(NavInsID.RIGHT_CLICK),
                                                  [NavIns(NavInsID.BOTH_CLICK)],
                                                  "Sign",
                                                  ROOT_SCREENSHOT_PATH,
                                                  test_name)
    else:
        navigator.navigate_until_text_and_compare(
            NavInsID.SWIPE_CENTER_TO_LEFT,
            [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ],
            "Hold to sign",
            ROOT_SCREENSHOT_PATH,
            test_name)


def test_gcs_sign(backend: BackendInterface, navigator: Navigator,
                  device: Device, test_name: str):
    """Full keystone flow: STORE -> cert -> 0x26 -> 0x28 -> START_FLOW -> approve.

    Asserts the firmware renders the GCS review and returns a signature over
    sha256(tx) recoverable to the device key -- the first real end-to-end GCS
    signature (this is also the first execution of ui_gcs()).
    """
    client = TronClient(backend, device, navigator)
    tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == Errors.OK

    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")

    send_calldata_certificate(client, device)
    assert send_tlv(backend, INS_GTP_TRANSACTION_INFO, tx_info) == Errors.OK
    for field in fields:
        assert send_tlv(backend, INS_GTP_FIELD, field) == Errors.OK

    # START_FLOW triggers the async GCS review; approve it, then collect the reply.
    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)
    resp = backend.last_async_response
    assert resp.status == Errors.OK

    # The returned signature must verify over sha256(tx) against the device key.
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def _gcs_send_descriptor(client: TronClient, backend: BackendInterface,
                         device: Device, fields: list[bytes],
                         provision=None) -> bytes:
    """STORE -> [provision] -> cert -> 0x26 -> 0x28(xN); returns the parked tx.

    `provision` (optional) runs after the calldata is parked but before the
    fields are streamed, so token/trusted-name metadata is in place by the time
    each FIELD's formatter (format_field) looks it up at 0x28 time.
    """
    tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == Errors.OK
    if provision is not None:
        provision()
    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")
    send_calldata_certificate(client, device)
    assert send_tlv(backend, INS_GTP_TRANSACTION_INFO, tx_info) == Errors.OK
    for field in fields:
        assert send_tlv(backend, INS_GTP_FIELD, field) == Errors.OK
    return tx


def provide_trc20_token(backend: BackendInterface, client: TronClient,
                        addr20: bytes, ticker: str, decimals: int) -> None:
    """Register a TRC20 token (ticker/decimals) for `addr20` via INS 0xCA.

    Mirrors InputData.provide_token_metadata: the COIN_META PKI certificate
    delivers the CAL public key, then the token info is CAL-signed over the
    payload (minus the ticker-length byte and the trailing signature).
    """
    from client.command_builder import CommandBuilder
    from client.tip712.InputData import send_coin_meta_certificate

    # cmd_provideTokenInfo.c requires the TRON 0x41-prefixed 21-byte address; it
    # stores only the canonical 20-byte form for get_asset_info_by_addr lookups.
    addr21 = bytes([ADD_PRE_FIX_BYTE_MAINNET]) + addr20
    send_coin_meta_certificate(client)
    cmd = CommandBuilder()
    unsigned = cmd.provide_trc20_token_information(ticker, addr21, decimals,
                                                   TRON_MAINNET_CHAINID, b"")
    # The firmware hashes ticker+addr+decimals+chain (payload minus the
    # ticker-length byte and trailing sig); keychain.sign_data sha256s internally.
    sig = keychain.sign_data(keychain.Key.CAL, unsigned[6:])
    apdu = cmd.provide_trc20_token_information(ticker, addr21, decimals,
                                               TRON_MAINNET_CHAINID, sig)
    assert backend.exchange_raw(apdu).status == Errors.OK


def provide_trusted_name(client: TronClient, addr20: bytes, name: str) -> None:
    """Register an account trusted name for `addr20` via INS 0x22 (v2/ENS).

    Delegates to InputData.provide_trusted_name_v2, which sends the TRUSTED_NAME
    PKI certificate and the challenge-bound, signed trusted-name descriptor.
    TRON's firmware only accepts CAL/ENS/MAB sources; ACCOUNT + ENS is the
    simplest (a ".eth" name + the device challenge, no MAB owner).
    """
    from client.command_builder import CommandBuilder
    from client.tip712 import InputData
    import response_parser as ResponseParser

    cmd = CommandBuilder()
    challenge = ResponseParser.challenge(
        client.exchange_raw(cmd.get_challenge()).data)
    InputData.provide_trusted_name_v2(client, cmd, addr20, name,
                                      InputData.TrustedNameType.ACCOUNT,
                                      InputData.TrustedNameSource.ENS,
                                      TRON_MAINNET_CHAINID, challenge=challenge)


def test_gcs_amount_decimals(backend: BackendInterface, navigator: Navigator,
                             device: Device, test_name: str):
    """AMOUNT field renders native TRX with 6 decimals (SUN_TO_TRX), not 18.

    Calldata _amount = 0xf4240 = 1_000_000; with TRON's 6 decimals this is
    "1 TRX". The old app-ethereum WEI_TO_ETHER (18) bug would render
    "0.000000000001 TRX", so the snapshot is the regression guard for the fix.
    """
    client = TronClient(backend, device, navigator)
    amount_field = build_field_amount("Amount", 32,
                                      data_path=build_data_path_static(1))
    tx = _gcs_send_descriptor(client, backend, device, [amount_field])

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == Errors.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def test_gcs_datetime(backend: BackendInterface, navigator: Navigator,
                      device: Device, test_name: str):
    """DATETIME (DT_UNIX) field renders the calldata word as a UTC timestamp.

    Calldata word = 0xf4240 = 1_000_000 seconds since the epoch, which
    time_format_to_utc() renders as "1970-01-12 ... UTC" in the snapshot.
    """
    client = TronClient(backend, device, navigator)
    dt_field = build_field_datetime("Deadline", 32,
                                    data_path=build_data_path_static(1))
    tx = _gcs_send_descriptor(client, backend, device, [dt_field])

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == Errors.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


# `transfer(address _to, uint256 _amount)` arg0 (_to) doubles as a stand-in token
# address: we register it via INS_PROVIDE_TRC20_TOKEN_INFORMATION so the
# TOKEN_AMOUNT formatter resolves it to a ticker/decimals from the TRC20 registry.
TKN_ADDR20 = bytes.fromhex("364b03e0815687edaf90b81ff58e496dea7383d7")


def test_gcs_token_amount(backend: BackendInterface, navigator: Navigator,
                          device: Device, test_name: str):
    """TOKEN_AMOUNT resolves the token via the TRC20 registry (trc_tokens).

    arg0 is registered as "TKN" with 6 decimals; the amount word arg1 =
    1_000_000 then renders as "1 TKN" in the snapshot using the registry's
    decimals/ticker.
    """
    client = TronClient(backend, device, navigator)
    field = build_field_token_amount("Amount",
                                     value_path=build_data_path_static(1),
                                     token_path=build_data_path_static(0))

    def provision() -> None:
        provide_trc20_token(backend, client, TKN_ADDR20, "TKN", 6)

    tx = _gcs_send_descriptor(client, backend, device, [field],
                              provision=provision)

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == Errors.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def test_gcs_trusted_name(backend: BackendInterface, navigator: Navigator,
                          device: Device, test_name: str):
    """TRUSTED_NAME resolves a calldata address via provideTrustedName (0x22).

    arg0 is registered as the account name "alice.eth"; the GCS TRUSTED_NAME
    field over arg0 then renders that name in the snapshot instead of the raw
    address -- the provideTrustedName path unblocked by get_public_key().
    """
    client = TronClient(backend, device, navigator)
    field = build_field_trusted_name("To",
                                     addr_path=build_data_path_static(0),
                                     types=[TN_TYPE_ACCOUNT],
                                     sources=[TN_SOURCE_ENS])

    def provision() -> None:
        provide_trusted_name(client, TKN_ADDR20, "alice.eth")

    tx = _gcs_send_descriptor(client, backend, device, [field],
                              provision=provision)

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == Errors.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])
