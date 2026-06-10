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
                           test key (keychain/calldata.pem); TronClient loads the
                           matching CALLDATA PKI certificate.
"""
import sys
import hashlib
import json
from pathlib import Path
from struct import pack

import pytest
from web3 import Web3

from client.command_builder import (CLA, MAX_APDU_LEN, CommandBuilder, InsType,
                                    P1Type, P2Type)
from client.enum_value import EnumValue
from client.proxy_info import ProxyInfo
from client.gcs import (ContainerPath, DataPath, DatetimeType, Field, ParamAmount,
                        ParamCalldata, ParamDatetime, ParamEnum, ParamRaw,
                        ParamNetwork, ParamNFT, ParamToken, ParamTokenAmount,
                        ParamTrustedName, PathLeaf, PathLeafType, PathTuple,
                        TxInfo, TypeFamily, Value, VisibleType)
from client.trusted_name import TrustedName, TrustedNameSource, TrustedNameType
from fields_utils import (get_all_paths, get_all_tuple_array_paths,
                          get_all_tuple_paths)
from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.navigator import Navigator, NavIns, NavInsID
import response_parser as ResponseParser
from client.status_word import StatusWord
from tron import TronClient, ROOT_SCREENSHOT_PATH
from utils import check_tx_signature, get_selector_from_data

PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

# --- APDU constants (mirror src/apdu_constants.h) ---------------------------
P1_FIRST = P1Type.FIRST
P1_SIGN = P1Type.SIGN
P1_MORE = P1Type.MORE
P1_LAST = P1Type.LAST
P2_GCS_STORE = P2Type.GCS_STORE
P2_GCS_START_FLOW = P2Type.GCS_START_FLOW

# TRON mainnet chain id used by the GCS descriptors (chain_config.h).
TRON_MAINNET_CHAINID = 728126428
# TRON mainnet address prefix byte (parse.h ADD_PRE_FIX_BYTE_MAINNET).
ADD_PRE_FIX_BYTE_MAINNET = 0x41
ABIS_FOLDER = Path(__file__).parent / "abis"

# A simple TRC20 `transfer(address,uint256)` call: selector + 2 ABI words.
TRC20_CONTRACT_B58 = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
TRC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
TRC20_TRANSFER_CALLDATA = bytes.fromhex(
    "a9059cbb"
    "000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d7"
    "00000000000000000000000000000000000000000000000000000000000f4240")
BATCH_CONTRACT20 = bytes.fromhex("2cc8475177918e8c4d840150b68815a4b6f0f5f3")


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


def build_trigger_smart_contract_tx(client: TronClient,
                                    contract_addr20: bytes,
                                    calldata: bytes) -> bytes:
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes([ADD_PRE_FIX_BYTE_MAINNET]) + contract_addr20,
            data=calldata))


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
    assert status == StatusWord.OK


# --- Descriptor builders -----------------------------------------------------
# Keep the host-side GCS serialization in client.gcs, matching app-ethereum.


def build_data_path_static(tuple_index: int) -> DataPath:
    """Select one top-level static ABI word from calldata."""
    return DataPath(1, [PathTuple(tuple_index), PathLeaf(PathLeafType.STATIC)])


def _uint_value(type_size: int, data_path: DataPath) -> Value:
    return Value(1, TypeFamily.UINT, type_size=type_size, data_path=data_path)


def _address_value(data_path: DataPath) -> Value:
    return Value(1, TypeFamily.ADDRESS, type_size=32, data_path=data_path)


def build_field_raw(name: str, type_size: int, data_path: DataPath) -> Field:
    return Field(1, name, ParamRaw(1, _uint_value(type_size, data_path)))


def build_field_amount(name: str, type_size: int, data_path: DataPath) -> Field:
    return Field(1, name, ParamAmount(1, _uint_value(type_size, data_path)))


def build_field_datetime(name: str, type_size: int, data_path: DataPath) -> Field:
    return Field(1,
                 name,
                 ParamDatetime(1,
                               _uint_value(type_size, data_path),
                               DatetimeType.DT_UNIX))


def build_field_token_amount(name: str, value_path: DataPath,
                             token_path: DataPath) -> Field:
    return Field(1,
                 name,
                 ParamTokenAmount(1,
                                  value=_uint_value(32, value_path),
                                  token=_address_value(token_path)))


def build_field_trusted_name(name: str, addr_path: DataPath,
                             types: list[TrustedNameType],
                             sources: list[TrustedNameSource]) -> Field:
    return Field(1,
                 name,
                 ParamTrustedName(1,
                                  _address_value(addr_path),
                                  types,
                                  sources))


def build_field_enum(name: str, enum_id: int, value_path: DataPath) -> Field:
    return Field(1,
                 name,
                 ParamEnum(1, enum_id, _uint_value(32, value_path)))


def build_enum_value(contract_addr20: bytes, selector: bytes, enum_id: int,
                     value: int, name: str) -> bytes:
    return EnumValue(1,
                     TRON_MAINNET_CHAINID,
                     contract_addr20,
                     selector,
                     enum_id,
                     value,
                     name).serialize()


def compute_inst_hash(fields: list[Field]) -> bytes:
    inst_hash = hashlib.sha3_256()
    for field in fields:
        inst_hash.update(field.serialize())
    return inst_hash.digest()


def build_tx_info(contract_addr20: bytes, selector: bytes, fields: list[Field],
                  operation: str) -> bytes:
    return TxInfo(1,
                  TRON_MAINNET_CHAINID,
                  contract_addr20,
                  selector,
                  compute_inst_hash(fields),
                  operation).serialize()


def test_gcs_p1_end_to_end(tron_client: TronClient, backend: BackendInterface):
    """store -> 0x26 -> 0x28(raw) -> expect 0x9000 (fields_hash validated)."""
    tx = build_trc20_transfer_tx(tron_client)
    assert gcs_store_calldata(tron_client, backend,
                              tron_client.getAccount(0)["path"], tx) == StatusWord.OK

    # generic_tx_parser works on 20-byte EVM addresses (0x41 prefix stripped).
    contract_addr20 = bytes.fromhex(tron_client.address_hex(TRC20_CONTRACT_B58))[1:]

    # `transfer(address _to, uint256 _amount)`: _amount is arg index 1, static.
    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]

    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")

    tron_client.provide_transaction_info(tx_info)
    for field in fields:
        tron_client.provide_transaction_field_desc(field.serialize())


def _approve_review(navigator: Navigator, device: Device, test_name: str) -> None:
    """Walk the GCS review screen to its sign confirmation and approve it.

    Uses snapshot comparison so the functional signing test also records the
    rendered GCS review flow.
    """
    if device.is_nano:
        navigator.navigate_until_text_and_compare(NavIns(NavInsID.RIGHT_CLICK),
                                                  [NavIns(NavInsID.BOTH_CLICK)],
                                                  "Sign transaction",
                                                  ROOT_SCREENSHOT_PATH,
                                                  test_name)
    else:
        navigator.navigate_until_text_and_compare(
            NavInsID.USE_CASE_REVIEW_TAP,
            [
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ],
            "Hold to sign",
            ROOT_SCREENSHOT_PATH,
            test_name)


def _start_gcs_flow_and_assert(backend: BackendInterface, navigator: Navigator,
                               device: Device, test_name: str,
                               client: TronClient, tx: bytes) -> None:
    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def _get_challenge(client: TronClient) -> int:
    return ResponseParser.challenge(
        client.exchange_raw(CommandBuilder().get_challenge()).data)


def test_gcs_sign(backend: BackendInterface, navigator: Navigator,
                  device: Device, test_name: str):
    """Full keystone flow: STORE -> 0x26 -> 0x28 -> START_FLOW -> approve.

    Asserts the firmware renders the GCS review and returns a signature over
    sha256(tx) recoverable to the device key -- the first real end-to-end GCS
    signature (this is also the first execution of ui_gcs()).
    """
    client = TronClient(backend, device, navigator)
    tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    amount_field = build_field_raw("Amount", 32,
                                   data_path=build_data_path_static(1))
    fields = [amount_field]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")

    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    # START_FLOW triggers the async GCS review; approve it, then collect the reply.
    _start_gcs_flow_and_assert(backend, navigator, device, test_name, client, tx)


def test_gcs_batch_empty_tx(backend: BackendInterface, navigator: Navigator,
                            device: Device, test_name: str):
    """batchExecute(calls[].data=b"") exercises ParamCalldata empty nested tx."""
    client = TronClient(backend, device, navigator)

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=BATCH_CONTRACT20,
        )

    data = contract.encode_abi("batchExecute", [[
        (
            bytes.fromhex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
            Web3.to_wei(0.0, "ether"),
            b"",
        ),
    ]])

    # Same batchExecute calldata as app-ethereum, but carried by a TRON protobuf
    # TriggerSmartContract transaction (not an ETH RLP one); park it via the 0xC4
    # STORE bridge instead of app_client.sign(mode=STORE).
    tx = build_trigger_smart_contract_tx(client, BATCH_CONTRACT20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute",
                                            "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(
                    1,
                    TypeFamily.BYTES,
                    data_path=DataPath(1, param_paths["data"]),
                ),
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["to"]),
                ),
            ),
        ),
    ]

    # compute instructions hash
    inst_hash = compute_inst_hash(fields)

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        BATCH_CONTRACT20,
        get_selector_from_data(data),
        inst_hash,
        "Batch transaction",
        creator_name="Ledger Multisig",
        creator_legal_name="Ledger",
    )

    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def test_gcs_nft(backend: BackendInterface, navigator: Navigator,
                 device: Device, test_name: str):
    client = TronClient(backend, device, navigator)

    with Path(f"{ABIS_FOLDER}/erc1155.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )

    data = contract.encode_abi("safeBatchTransferFrom", [
        bytes.fromhex("1111111111111111111111111111111111111111"),
        bytes.fromhex("d8da6bf26964af9d7eed9e03e53415d37aa96045"),
        [
            2,
            4,
            8,
            16,
        ],
        [
            1,
            2,
            3,
            4,
        ],
        bytes.fromhex("deadbeef1337cafe"),
    ])

    collection_addr20 = bytes.fromhex(
        "495f947276749ce646f68ac8c248420045cb7b5e")
    tx = build_trigger_smart_contract_tx(client, collection_addr20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc1155.json",
                                "safeBatchTransferFrom")
    fields = [
        Field(
            1,
            "From",
            ParamTrustedName(
                1,
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["_from"]),
                ),
                [
                    TrustedNameType.ACCOUNT,
                ],
                [
                    TrustedNameSource.UD,
                    TrustedNameSource.ENS,
                    TrustedNameSource.FN,
                ],
                [
                    bytes.fromhex("0000000000000000000000000000000000000000"),
                    bytes.fromhex("1111111111111111111111111111111111111111"),
                    bytes.fromhex("2222222222222222222222222222222222222222"),
                ],
            ),
        ),
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["_to"]),
                ),
            ),
        ),
        Field(
            1,
            "NFTs",
            ParamNFT(
                1,
                Value(
                    1,
                    TypeFamily.UINT,
                    type_size=32,
                    data_path=DataPath(1, param_paths["_ids"]),
                ),
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    container_path=ContainerPath.TO,
                ),
            ),
        ),
        Field(
            1,
            "Values",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.UINT,
                    type_size=32,
                    data_path=DataPath(1, param_paths["_values"]),
                ),
            ),
        ),
        Field(
            1,
            "Data",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.BYTES,
                    data_path=DataPath(1, param_paths["_data"]),
                ),
            ),
        ),
    ]

    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        collection_addr20,
        get_selector_from_data(data),
        inst_hash,
        "batch transfer NFTs",
    )

    client.provide_transaction_info(tx_info.serialize())
    device_addr20 = bytes.fromhex(client.getAccount(0)["addressHex"])[1:]
    client.provide_trusted_name(
        TrustedName(2,
                    device_addr20,
                    "gerard.eth",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=_get_challenge(client)))
    client.provide_nft_metadata("OpenSea Shared Storefront", collection_addr20,
                                TRON_MAINNET_CHAINID)

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def _poap_data() -> str:
    with Path(f"{ABIS_FOLDER}/poap.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    return contract.encode_abi("mintToken", [
        175676,
        7163978,
        bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
        1730621615,
        bytes.fromhex(
            "8991da687cff5300959810a08c4ec183bb2a56dc82f5aac2b24f1106c2d"
            "983ac6f7a6b28700a236724d814000d0fd8c395fcf9f87c4424432ebf30"
            "c9479201d71c"),
    ])


POAP_CONTRACT20 = bytes.fromhex("0bb4D3e88243F4A057Db77341e6916B0e449b158")


def _store_poap_tx(client: TronClient,
                   backend: BackendInterface) -> tuple[str, bytes]:
    data = _poap_data()
    tx = build_trigger_smart_contract_tx(client, POAP_CONTRACT20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    return data, tx


def _provide_gcs_descriptor(client: TronClient, contract_addr20: bytes,
                            data: str, fields: list[Field],
                            operation: str, **tx_info_kwargs) -> None:
    tx_info = TxInfo(1,
                     TRON_MAINNET_CHAINID,
                     contract_addr20,
                     get_selector_from_data(data),
                     compute_inst_hash(fields),
                     operation,
                     **tx_info_kwargs)

    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())


def test_gcs_poap(backend: BackendInterface, navigator: Navigator,
                  device: Device, test_name: str):
    client = TronClient(backend, device, navigator)
    data, tx = _store_poap_tx(client, backend)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/poap.abi.json", "mintToken")
    fields = [
        Field(
            1,
            "Event ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["eventId"])),
            ),
        ),
        Field(
            1,
            "Token ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["tokenId"])),
            ),
        ),
        Field(
            1,
            "Receiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
        ),
        Field(
            1,
            "Expiration time",
            ParamDatetime(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["expirationTime"])),
                DatetimeType.DT_UNIX,
            ),
        ),
        Field(
            1,
            "Signature",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["signature"])),
            ),
        ),
    ]

    _provide_gcs_descriptor(client,
                            POAP_CONTRACT20,
                            data,
                            fields,
                            "mint POAP",
                            creator_name="POAP",
                            creator_legal_name="Proof of Attendance Protocol",
                            creator_url="poap.xyz",
                            contract_name="PoapBridge",
                            deploy_date=1646305200)
    _start_gcs_flow_and_assert(backend, navigator, device, test_name, client, tx)


@pytest.mark.parametrize("test_config", ["chain_id", "network"])
def test_gcs_formatter(backend: BackendInterface, navigator: Navigator,
                       device: Device, test_name: str, test_config: str):
    client = TronClient(backend, device, navigator)
    data, tx = _store_poap_tx(client, backend)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/poap.abi.json", "mintToken")
    fields = [
        Field(
            1,
            "Token ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["tokenId"])),
            ),
        ),
        Field(
            1,
            "Receiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
        ),
        Field(
            1,
            "Expiration time",
            ParamDatetime(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["expirationTime"])),
                DatetimeType.DT_UNIX,
            ),
        ),
    ]
    if test_config == "chain_id":
        fields.append(
            Field(
                1,
                "Chain ID",
                ParamRaw(
                    1,
                    Value(1,
                          TypeFamily.UINT,
                          container_path=ContainerPath.CHAIN_ID),
                ),
            ))
    else:
        fields.append(
            Field(
                1,
                "Custom Network",
                ParamNetwork(
                    1,
                    Value(1,
                          TypeFamily.UINT,
                          container_path=ContainerPath.CHAIN_ID),
                ),
            ))

    _provide_gcs_descriptor(client,
                            POAP_CONTRACT20,
                            data,
                            fields,
                            "mint POAP",
                            creator_name="POAP",
                            creator_legal_name="Proof of Attendance Protocol",
                            creator_url="poap.xyz",
                            contract_name="PoapBridge",
                            deploy_date=1646305200)
    _start_gcs_flow_and_assert(backend, navigator, device,
                               f"{test_name}_{test_config}", client, tx)


@pytest.mark.parametrize(
    "test_config, visible, constraints",
    [
        ("if_not_0", VisibleType.IF_NOT_IN,
         [bytes.fromhex("0000000000000000000000000000000000000000")]),
        ("if_not_addr", VisibleType.IF_NOT_IN,
         [bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D")]),
        ("must_be_addr", VisibleType.MUST_BE,
         [bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D")]),
        ("must_be_0", VisibleType.MUST_BE,
         [bytes.fromhex("00"),
          bytes.fromhex("01"),
          bytes.fromhex("02")]),
    ],
)
def test_gcs_constraints(backend: BackendInterface, navigator: Navigator,
                         device: Device, test_name: str, test_config: str,
                         visible: VisibleType, constraints: list[bytes]):
    client = TronClient(backend, device, navigator)
    data, tx = _store_poap_tx(client, backend)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/poap.abi.json", "mintToken")
    fields = [
        Field(
            1,
            "Token ID",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["tokenId"])),
            ),
        ),
        Field(
            1,
            "Receiver",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
                [
                    TrustedNameType.ACCOUNT,
                    TrustedNameType.WALLET,
                ],
                [
                    TrustedNameSource.UD,
                    TrustedNameSource.ENS,
                    TrustedNameSource.FN,
                ],
            ),
            visible,
            constraints,
        ),
        Field(
            1,
            "Receiver uint",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
            visible,
            constraints,
        ),
        Field(
            1,
            "Receiver addr",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      type_size=32,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
            visible,
            constraints,
        ),
        Field(
            1,
            "Expiration time",
            ParamDatetime(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["expirationTime"])),
                DatetimeType.DT_UNIX,
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        POAP_CONTRACT20,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "mint POAP",
        creator_name="POAP",
        creator_legal_name="Proof of Attendance Protocol",
        creator_url="poap.xyz",
        contract_name="PoapBridge",
        deploy_date=1646305200,
    )
    client.provide_transaction_info(tx_info.serialize())

    if test_config == "must_be_0":
        with pytest.raises((ExceptionRAPDU, AssertionError)) as err:
            for field in fields:
                client.provide_transaction_field_desc(field.serialize())
        if isinstance(err.value, ExceptionRAPDU):
            assert err.value.status == StatusWord.INVALID_DATA
        return

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(backend, navigator, device,
                               f"{test_name}_{test_config}", client, tx)


def test_gcs_1inch(backend: BackendInterface, navigator: Navigator,
                   device: Device, test_name: str):
    client = TronClient(backend, device, navigator)

    with Path(f"{ABIS_FOLDER}/1inch.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    data = contract.encode_abi("swap", [
        bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
        [
            bytes.fromhex("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
            bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
            bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
            bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
            Web3.to_wei(0.22, "ether"),
            682119805,
            0,
        ],
        bytes(),
    ])
    contract_addr20 = bytes.fromhex("111111125421cA6dc452d289314280a0f8842A65")
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    param_paths = get_all_paths(f"{ABIS_FOLDER}/1inch.abi.json", "swap")
    tuple_paths = get_all_tuple_paths(f"{ABIS_FOLDER}/1inch.abi.json", "swap",
                                      "desc")
    fields = [
        Field(
            1,
            "Executor",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["executor"])),
            ),
        ),
        Field(
            1,
            "Send",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, tuple_paths["amount"])),
                token=Value(1,
                            TypeFamily.ADDRESS,
                            data_path=DataPath(1, tuple_paths["srcToken"])),
                native_currency=[
                    bytes.fromhex("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
                ],
            ),
        ),
        Field(
            1,
            "Receive",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, tuple_paths["minReturnAmount"])),
                token=Value(1,
                            TypeFamily.ADDRESS,
                            data_path=DataPath(1, tuple_paths["dstToken"])),
                native_currency=[
                    bytes.fromhex("EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
                ],
            ),
        ),
    ]

    client.provide_transaction_info(
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               contract_addr20,
               get_selector_from_data(data),
               compute_inst_hash(fields),
               "swap",
               creator_name="1inch",
               creator_legal_name="1inch Network",
               creator_url="1inch.io",
               contract_name="Aggregation Router V6",
               deploy_date=1707724800).serialize())
    client.provide_token_metadata(
        "USDC", bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), 6,
        TRON_MAINNET_CHAINID)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(backend, navigator, device, test_name, client, tx)


def test_gcs_proxy(backend: BackendInterface, navigator: Navigator,
                   device: Device, test_name: str):
    client = TronClient(backend, device, navigator)
    new_owner = bytes.fromhex("2222222222222222222222222222222222222222")

    with Path(f"{ABIS_FOLDER}/proxy_implem.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    data = contract.encode_abi("transferOwnership", [new_owner])
    proxy_addr20 = bytes.fromhex("39053d51b77dc0d36036fc1fcc8cb819df8ef37a")
    impl_addr20 = bytes.fromhex("1784be6401339fc0fedf7e9379409f5c1bfe9dda")
    tx = build_trigger_smart_contract_tx(client, proxy_addr20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    param_paths = get_all_paths(f"{ABIS_FOLDER}/proxy_implem.abi.json",
                                "transferOwnership")
    fields = [
        Field(
            1,
            "New owner",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["newOwner"])),
                [TrustedNameType.CONTRACT],
                [TrustedNameSource.CAL],
            ),
        ),
    ]

    tx_info = TxInfo(1,
                     TRON_MAINNET_CHAINID,
                     impl_addr20,
                     get_selector_from_data(data),
                     compute_inst_hash(fields),
                     "transfer ownership",
                     creator_name="EigenLayer",
                     creator_legal_name="Eigen Labs",
                     creator_url="https://eigenlayer.xyz",
                     contract_name="Delegation Manager",
                     deploy_date=1711098731)

    client.provide_proxy_info(
        ProxyInfo(_get_challenge(client),
                  proxy_addr20,
                  tx_info.chain_id,
                  tx_info.contract_addr,
                  selector=tx_info.selector).serialize())
    client.provide_transaction_info(tx_info.serialize())

    impl_contract = bytes.fromhex("1111111111111111111111111111111111111111")
    client.provide_proxy_info(
        ProxyInfo(_get_challenge(client), new_owner, tx_info.chain_id,
                  impl_contract).serialize())
    client.provide_trusted_name(
        TrustedName(2,
                    impl_contract,
                    "some contract",
                    tn_type=TrustedNameType.CONTRACT,
                    tn_source=TrustedNameSource.CAL,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=_get_challenge(client)))

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(backend, navigator, device, test_name, client, tx)


def test_gcs_4226(backend: BackendInterface, navigator: Navigator,
                  device: Device, test_name: str):
    client = TronClient(backend, device, navigator)

    with Path(f"{ABIS_FOLDER}/rSWELL.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(
            abi=json.load(f),
            address=None,
        )
    data = contract.encode_abi("deposit", [
        Web3.to_wei(4.20, "ether"),
        bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
    ])
    contract_addr20 = bytes.fromhex("358d94b5b2F147D741088803d932Acb566acB7B6")
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK

    swell_token_addr = bytes.fromhex("0a6e7ba5042b38349e437ec6db6214aec7b35676")
    param_paths = get_all_paths(f"{ABIS_FOLDER}/rSWELL.abi.json", "deposit")
    fields = [
        Field(
            1,
            "Deposit asset",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["assets"])),
                token=Value(1, TypeFamily.ADDRESS, constant=swell_token_addr),
            ),
        ),
        Field(
            1,
            "Receive shares",
            ParamToken(
                1,
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
        Field(
            1,
            "Send shares to",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["receiver"])),
            ),
        ),
    ]

    client.provide_transaction_info(
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               contract_addr20,
               get_selector_from_data(data),
               compute_inst_hash(fields),
               "deposit",
               creator_name="Swell",
               creator_legal_name="Swell Network",
               creator_url="www.swellnetwork.io",
               contract_name="rSWELL Token",
               deploy_date=1726817291).serialize())
    client.provide_token_metadata("rSWELL", contract_addr20, 18,
                                  TRON_MAINNET_CHAINID)
    client.provide_token_metadata("SWELL", swell_token_addr, 18,
                                  TRON_MAINNET_CHAINID)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    _start_gcs_flow_and_assert(backend, navigator, device, test_name, client, tx)


def _gcs_send_descriptor(client: TronClient, backend: BackendInterface,
                         fields: list[Field],
                         provision=None) -> bytes:
    """STORE -> [provision] -> 0x26 -> 0x28(xN); returns the parked tx.

    `provision` (optional) runs after the calldata is parked but before the
    fields are streamed, so token/trusted-name metadata is in place by the time
    each FIELD's formatter (format_field) looks it up at 0x28 time.
    """
    tx = build_trc20_transfer_tx(client)
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    if provision is not None:
        provision()
    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    tx_info = build_tx_info(contract_addr20, TRC20_TRANSFER_SELECTOR, fields,
                            "transfer")
    client.provide_transaction_info(tx_info)
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
    return tx

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
    tx = _gcs_send_descriptor(client, backend, [amount_field])

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
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
    tx = _gcs_send_descriptor(client, backend, [dt_field])

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
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
        client.provide_token_metadata("TKN", TKN_ADDR20, 6,
                                      TRON_MAINNET_CHAINID)

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
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
                                     types=[TrustedNameType.ACCOUNT],
                                     sources=[TrustedNameSource.ENS])

    def provision() -> None:
        client.provide_trusted_name(
            TrustedName(2,
                        TKN_ADDR20,
                        "alice.eth",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=TRON_MAINNET_CHAINID,
                        challenge=_get_challenge(client)))

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def test_gcs_enum(backend: BackendInterface, navigator: Navigator,
                  device: Device, test_name: str):
    """ENUM field resolves a calldata byte via provide_enum_value (INS 0x24).

    arg1's low byte is 0x40 (0xf4240 & 0xff); an enum descriptor maps
    (contract, selector, id=0, value=0x40) -> "Deposit", which the ENUM field
    then renders in the snapshot instead of the raw value.
    """
    client = TronClient(backend, device, navigator)
    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    field = build_field_enum("Action", enum_id=0,
                             value_path=build_data_path_static(1))

    def provision() -> None:
        enum_desc = build_enum_value(contract_addr20, TRC20_TRANSFER_SELECTOR,
                                     enum_id=0, value=0x40, name="Deposit")
        client.provide_enum_value(enum_desc)

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        _approve_review(navigator, device, test_name)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])
