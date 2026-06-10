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
                        ParamTrustedName, ParamType, PathLeaf, PathLeafType,
                        PathTuple, TxInfo, TypeFamily, Value, VisibleType)
from client.trusted_name import TrustedName, TrustedNameSource, TrustedNameType
from fields_utils import (get_all_paths, get_all_tuple_array_paths,
                          get_all_tuple_paths)
from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.navigator.navigation_scenario import NavigateWithScenario
import response_parser as ResponseParser
from client.status_word import StatusWord
from tron import TronClient
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
ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

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


def _client_from_scenario(scenario_navigator: NavigateWithScenario) -> TronClient:
    return TronClient(scenario_navigator.backend, scenario_navigator.device,
                      scenario_navigator.navigator)


def _start_gcs_flow_and_assert(scenario_navigator: NavigateWithScenario,
                               client: TronClient, tx: bytes,
                               test_name: str | None = None) -> None:
    backend = scenario_navigator.backend
    custom_screen_text = ("Sign transaction"
                          if scenario_navigator.device.is_nano else None)
    with backend.exchange_async(CLA, InsType.SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                P2_GCS_START_FLOW, b""):
        scenario_navigator.review_approve(path=ROOT_SCREENSHOT_PATH,
                                          test_name=test_name,
                                          custom_screen_text=custom_screen_text)

    resp = backend.last_async_response
    assert resp.status == StatusWord.OK
    assert check_tx_signature(tx, resp.data[0:65],
                              client.getAccount(0)["publicKey"][2:])


def _get_challenge(client: TronClient) -> int:
    return ResponseParser.challenge(
        client.exchange_raw(CommandBuilder().get_challenge()).data)


def test_gcs_sign(scenario_navigator: NavigateWithScenario):
    """Full keystone flow: STORE -> 0x26 -> 0x28 -> START_FLOW -> approve.

    Asserts the firmware renders the GCS review and returns a signature over
    sha256(tx) recoverable to the device key -- the first real end-to-end GCS
    signature (this is also the first execution of ui_gcs()).
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
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
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch_empty_tx(scenario_navigator: NavigateWithScenario):
    """batchExecute(calls[].data=b"") exercises ParamCalldata empty nested tx."""
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

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

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_nft(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

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

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


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


def _store_contract_call(client: TronClient, backend: BackendInterface,
                         contract_addr20: bytes, data: str) -> bytes:
    tx = build_trigger_smart_contract_tx(client, contract_addr20,
                                         bytes.fromhex(data[2:]))
    assert gcs_store_calldata(client, backend,
                              client.getAccount(0)["path"], tx) == StatusWord.OK
    return tx


def test_gcs_poap(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
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
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


@pytest.mark.parametrize("test_config", ["chain_id", "network"])
def test_gcs_formatter(scenario_navigator: NavigateWithScenario,
                       test_config: str):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
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
    _start_gcs_flow_and_assert(
        scenario_navigator, client, tx,
        f"{scenario_navigator.test_name}_{test_config}")


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
def test_gcs_constraints(scenario_navigator: NavigateWithScenario,
                         test_config: str,
                         visible: VisibleType, constraints: list[bytes]):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
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
    _start_gcs_flow_and_assert(
        scenario_navigator, client, tx,
        f"{scenario_navigator.test_name}_{test_config}")


def test_gcs_1inch(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

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
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_proxy(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
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
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_4226(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

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
    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0x07a80f1b359146129f3369af39e7eb2457581109c8300fc2ef81e997a07cf3f0
def test_gcs_nested_createProxyWithNonce(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    safe_l2_setup_addr = bytes.fromhex(
        "BD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54")
    with Path(f"{ABIS_FOLDER}/safe_l2_setup_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        safe_l2_setup = Web3().eth.contract(abi=json.load(f),
                                            address=safe_l2_setup_addr)
    safe_l2_setup_data = safe_l2_setup.encode_abi("setupToL2", [
        bytes.fromhex("29fcB43b46531BcA003ddC8FCB67FFE91900C762")
    ])

    safe_addr = bytes.fromhex("41675C099F32341bf84BFc5382aF534df5C7461a")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        safe = Web3().eth.contract(abi=json.load(f), address=safe_addr)
    safe_data = safe.encode_abi("setup", [
        [
            bytes.fromhex("6535d5F76F021FE65E2ac73D086dF4b4Bd7ee5D9"),
            bytes.fromhex("3fB2C8699C3D0Cedde210F383435C537C86D91B8"),
        ],
        2,
        safe_l2_setup_addr,
        safe_l2_setup_data,
        bytes.fromhex("fd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        0,
        bytes.fromhex("5afe7A11E7000000000000000000000000000000"),
    ])

    safe_proxy_factory_addr = bytes.fromhex(
        "4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67")
    with Path(f"{ABIS_FOLDER}/safe_proxy_factory_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        safe_proxy_factory = Web3().eth.contract(
            abi=json.load(f), address=safe_proxy_factory_addr)
    data = safe_proxy_factory.encode_abi("createProxyWithNonce",
                                         [safe_addr, safe_data, 0])
    tx = _store_contract_call(client, backend, safe_proxy_factory_addr, data)

    param_paths = get_all_paths(
        f"{ABIS_FOLDER}/safe_proxy_factory_1.4.1.abi.json",
        "createProxyWithNonce")
    fields = [
        Field(
            1,
            "_singleton",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_singleton"])),
            ),
        ),
        Field(
            1,
            "initializer",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["initializer"])),
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["_singleton"])),
            ),
        ),
        Field(
            1,
            "saltNonce",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["saltNonce"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        safe_proxy_factory_addr,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "create a Safe account",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    client.provide_transaction_info(tx_info.serialize())

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json", "setup")
    sub_fields = [
        Field(
            1,
            "_owners",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_owners"])),
            ),
        ),
        Field(
            1,
            "_threshold",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["_threshold"])),
            ),
        ),
        Field(
            1,
            "to",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "fallbackHandler",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["fallbackHandler"])),
            ),
        ),
        Field(
            1,
            "paymentToken",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["paymentToken"])),
            ),
        ),
        Field(
            1,
            "payment",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["payment"])),
            ),
        ),
        Field(
            1,
            "paymentReceiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["paymentReceiver"])),
            ),
        ),
    ]
    sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, safe_addr,
                         get_selector_from_data(safe_data),
                         compute_inst_hash(sub_fields), "setup")

    param_paths = get_all_paths(
        f"{ABIS_FOLDER}/safe_l2_setup_1.4.1.abi.json", "setupToL2")
    sub_sub_fields = [
        Field(
            1,
            "l2Singleton",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["l2Singleton"])),
            ),
        ),
    ]
    sub_sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, safe_l2_setup_addr,
                             get_selector_from_data(safe_l2_setup_data),
                             compute_inst_hash(sub_sub_fields), "L2 setup")

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())
                if sub_field.param.type == ParamType.CALLDATA:
                    client.provide_transaction_info(sub_sub_tx_info.serialize())
                    for sub_sub_field in sub_sub_fields:
                        client.provide_transaction_field_desc(
                            sub_sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0xc5545f13bfaf6f69ae937bc64337405060dc56ce7649ea7051d2bbc3b4316b79
def test_gcs_nested_execTransaction_send(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    data = contract.encode_abi("execTransaction", [
        contract_addr,
        Web3.to_wei(0.0042, "ether"),
        bytes(),
        0,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(
            "a974345670d8e06c52eeb7bfe59b1ed0fc879223ff0938c859c3852110c8"
            "c58016ec4bf0c68e84d3a40e3ac519f0a0db6954e7c4107fc6985de7d"
            "c683603f62a1b"),
    ])
    tx_to = bytes.fromhex("C1897a9Acbdd54028dA5f7b76B5833A91553AaF6")
    tx = _store_contract_call(client, backend, tx_to, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             type_size=32,
                             data_path=DataPath(1, param_paths["value"])),
                spender=Value(1,
                              TypeFamily.ADDRESS,
                              container_path=ContainerPath.TO),
            ),
        ),
    ]

    client.provide_transaction_info(
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               tx_to,
               get_selector_from_data(data),
               compute_inst_hash(fields),
               "execute a Safe action",
               creator_name="Safe",
               creator_legal_name="Safe Ecosystem Foundation",
               creator_url="safe.global").serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0xbeafe22c9e3ddcf85b06f65a56cc3ea8f5b02c323cc433c93c103ad3526db88d
def test_gcs_nested_execTransaction_addOwnerWithThreshold(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    sub_data = contract.encode_abi("addOwnerWithThreshold", [
        bytes.fromhex("FD6765Ad4eE64668701356a16aB28B123B3A4170"),
        2,
    ])
    data = contract.encode_abi("execTransaction", [
        contract_addr,
        Web3.to_wei(0, "ether"),
        sub_data,
        1,  # operation
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(
            "c14660c23f715fc85c01326c7fa7f05ddeb71147fc7bad912eace6ee55"
            "c24a314f814262b3c8ca64fc77377ce6e65b20bdc902c34931888c433e"
            "23ab0069843d1bf3d2dfb18fd6bd807002bffec3326755c928e325981"
            "f30e1518e999b348a5f011446931b8bd9fbb152cdc00d945b7cd030c"
            "14e48c7826d31f9c09a1376f694de1b"),
    ])
    tx = _store_contract_call(client, backend, contract_addr, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "to",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "value",
            ParamAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["value"])),
            ),
        ),
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "Operation type",
            ParamEnum(
                1,
                0,
                Value(1,
                      TypeFamily.UINT,
                      type_size=1,
                      data_path=DataPath(1, param_paths["operation"])),
            ),
        ),
        Field(
            1,
            "safeTxGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["safeTxGas"])),
            ),
        ),
        Field(
            1,
            "dataGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["baseGas"])),
            ),
        ),
        Field(
            1,
            "gasPrice",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["gasPrice"])),
            ),
        ),
        Field(
            1,
            "gasToken",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["gasToken"])),
            ),
        ),
        Field(
            1,
            "refundReceiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["refundReceiver"])),
            ),
        ),
        Field(
            1,
            "signatures",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["signatures"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        contract_addr,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "execute a Safe action",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    client.provide_transaction_info(tx_info.serialize())

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "addOwnerWithThreshold")
    sub_fields = [
        Field(
            1,
            "owner",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["owner"])),
            ),
        ),
        Field(
            1,
            "_threshold",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["_threshold"])),
            ),
        ),
    ]
    sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, contract_addr,
                         get_selector_from_data(sub_data),
                         compute_inst_hash(sub_fields),
                         "add owner with threshold")

    enum_values = [
        (0, "Call"),
        (1, "Delegate Call"),
        (2, "Unknown"),
    ]
    for enum_val in enum_values:
        client.provide_enum_value(
            EnumValue(1, tx_info.chain_id, tx_info.contract_addr,
                      tx_info.selector, 0, enum_val[0],
                      enum_val[1]).serialize())

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# https://etherscan.io/tx/0x5047fedc98f46d2afd94d0a2813ddf0c8fe777ec0739ffd327586a91e1e5a89a
def test_gcs_nested_execTransaction_changeThreshold(
        scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    sub_data = contract.encode_abi("changeThreshold", [3])
    data = contract.encode_abi("execTransaction", [
        contract_addr,
        Web3.to_wei(0, "ether"),
        sub_data,
        0,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(
            "d3a6ddfb9dffe883d609129d9e87dda928a4a9b9d5d2f4a93879d03"
            "ccb0d32b12df7dcf9acd9c5f73443c82b0e01183794436a381148cf"
            "2fb928f7df776a01701b2fc9ebbc15bfdae0f5ef1b6f4ad1389d31"
            "f1dc137e51e7a184e255fd0ed065911ad684bd97ee43892013b4ee"
            "bdaec528020ed657b92b90562f4df5a18540e4b91b"),
    ])
    tx = _store_contract_call(client, backend, contract_addr, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "to",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                [TrustedNameType.ACCOUNT],
                [TrustedNameSource.MULTISIG_ADDRESS_BOOK],
            ),
        ),
        Field(
            1,
            "value",
            ParamAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["value"])),
            ),
        ),
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
        Field(
            1,
            "operation",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=1,
                      data_path=DataPath(1, param_paths["operation"])),
            ),
        ),
        Field(
            1,
            "safeTxGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["safeTxGas"])),
            ),
        ),
        Field(
            1,
            "dataGas",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["baseGas"])),
            ),
        ),
        Field(
            1,
            "gasPrice",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["gasPrice"])),
            ),
        ),
        Field(
            1,
            "gasToken",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["gasToken"])),
            ),
        ),
        Field(
            1,
            "refundReceiver",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["refundReceiver"])),
            ),
        ),
        Field(
            1,
            "signatures",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["signatures"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        contract_addr,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "execute a Safe action",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    client.provide_transaction_info(tx_info.serialize())

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "changeThreshold")
    sub_fields = [
        Field(
            1,
            "newThreshold",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["_threshold"])),
            ),
        ),
    ]
    sub_tx_info = TxInfo(1, TRON_MAINNET_CHAINID, contract_addr,
                         get_selector_from_data(sub_data),
                         compute_inst_hash(sub_fields), "change threshold")

    derivation_path = client.getAccount(0)["path"]
    wallet_addr = bytes.fromhex(client.getAccount(0)["addressHex"])[1:]
    client.provide_trusted_name(
        TrustedName(2,
                    contract_addr,
                    "My Safe",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=tx_info.chain_id,
                    challenge=_get_challenge(client),
                    owner=wallet_addr,
                    owner_deriv_path=derivation_path))

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_nested_no_param(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    sub_contract_addr = bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        sub_contract = Web3().eth.contract(abi=json.load(f),
                                           address=sub_contract_addr)
    sub_data = sub_contract.encode_abi("totalSupply", [])

    contract_addr = bytes.fromhex("23F8abfC2824C397cCB3DA89ae772984107dDB99")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    data = contract.encode_abi("execTransaction", [
        sub_contract_addr,
        Web3.to_wei(0, "ether"),
        sub_data,
        0,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes(),
    ])
    tx = _store_contract_call(client, backend, contract_addr, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    fields = [
        Field(
            1,
            "data",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        contract_addr,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "execute a Safe action",
        creator_name="Safe",
        creator_legal_name="Safe Ecosystem Foundation",
        creator_url="safe.global",
    )
    client.provide_transaction_info(tx_info.serialize())

    sub_tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        sub_contract_addr,
        get_selector_from_data(sub_data),
        hashlib.sha3_256().digest(),
        "get total supply",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        if field.param.type == ParamType.CALLDATA:
            client.provide_transaction_info(sub_tx_info.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_no_param(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    contract_addr = bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=contract_addr)
    data = contract.encode_abi("totalSupply", [])
    tx = _store_contract_call(client, backend, contract_addr, data)

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        contract_addr,
        get_selector_from_data(data),
        hashlib.sha3_256().digest(),
        "get total supply",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )
    client.provide_transaction_info(tx_info.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_trusted_name_token(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "name": "WETH",
            "address": bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
        },
        {
            "name": "USDC",
            "address": bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        },
    ]

    with Path(f"{ABIS_FOLDER}/1inch.abi.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    data = contract.encode_abi("swap", [
        bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
        [
            tokens[0]["address"],
            tokens[1]["address"],
            bytes.fromhex("F313B370D28760b98A2E935E56Be92Feb2c4EC04"),
            bytes.fromhex("Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
            Web3.to_wei(0.22, "ether"),
            682119805,
            0,
        ],
        bytes(),
    ])
    contract_addr20 = bytes.fromhex("111111125421cA6dc452d289314280a0f8842A65")
    tx = _store_contract_call(client, backend, contract_addr20, data)

    param_paths = get_all_tuple_paths(f"{ABIS_FOLDER}/1inch.abi.json", "swap",
                                      "desc")
    fields = [
        Field(
            1,
            "Send token",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["srcToken"])),
                [TrustedNameType.TOKEN],
                [TrustedNameSource.CAL],
            ),
        ),
        Field(
            1,
            "Receive token",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["dstToken"])),
                [TrustedNameType.TOKEN],
                [TrustedNameSource.CAL],
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        contract_addr20,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "swap",
        creator_name="1inch",
        creator_legal_name="1inch Network",
        creator_url="1inch.io",
        contract_name="Aggregation Router V6",
        deploy_date=1707724800,
    )
    client.provide_transaction_info(tx_info.serialize())

    for i, field in enumerate(fields):
        client.provide_trusted_name(
            TrustedName(2,
                        tokens[i]["address"],
                        tokens[i]["name"],
                        tn_type=TrustedNameType.TOKEN,
                        tn_source=TrustedNameSource.CAL,
                        chain_id=TRON_MAINNET_CHAINID,
                        challenge=_get_challenge(client)))
        client.provide_transaction_field_desc(field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "ticker": "USDT",
            "address": bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7"),
            "decimals": 6,
        },
        {
            "ticker": "WETH",
            "address": bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            "decimals": 18,
        },
    ]
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    data0 = contract.encode_abi("transfer", [
        bytes.fromhex("0000000000000000000000000000000000000000"),
        int(500 * pow(10, tokens[0]["decimals"])),
    ])
    data1 = contract.encode_abi("transfer", [
        bytes.fromhex("1111111111111111111111111111111111111111"),
        int(0.25 * pow(10, tokens[1]["decimals"])),
    ])

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f),
                                       address=tokens[1]["address"])
    data = contract.encode_abi("batchExecute", [[
        (tokens[0]["address"], Web3.to_wei(0, "ether"), data0),
        (tokens[1]["address"], Web3.to_wei(0, "ether"), data1),
    ]])
    tx = _store_contract_call(client, backend, tokens[1]["address"], data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    sub_fields = [
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_to"])),
            ),
        ),
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      32,
                      DataPath(1, param_paths["_value"])),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
    ]

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute", "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             data_path=DataPath(1, param_paths["value"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        tokens[1]["address"],
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "Batch transaction",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )
    client.provide_transaction_info(tx_info.serialize())

    sub_inst_hash = compute_inst_hash(sub_fields)
    sub_tx_info = [
        TxInfo(
            1,
            TRON_MAINNET_CHAINID,
            tokens[0]["address"],
            get_selector_from_data(data0),
            sub_inst_hash,
            "Transfer token",
        ),
        TxInfo(
            1,
            TRON_MAINNET_CHAINID,
            tokens[1]["address"],
            get_selector_from_data(data1),
            sub_inst_hash,
            "Transfer token",
        ),
    ]

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        for idx, sub_info in enumerate(sub_tx_info):
            client.provide_token_metadata(tokens[idx]["ticker"],
                                          tokens[idx]["address"],
                                          tokens[idx]["decimals"],
                                          TRON_MAINNET_CHAINID)
            client.provide_transaction_info(sub_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch_2(scenario_navigator: NavigateWithScenario):
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "ticker": "USDC",
            "address": bytes.fromhex("3c499c542cef5e3811e1192ce70d8cc03d5c3359"),
            "decimals": 6,
        },
        {
            "ticker": "USDC",
            "address": bytes.fromhex("3c499c542cef5e3811e1192ce70d8cc03d5c3359"),
            "decimals": 6,
        },
    ]
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    token_data0 = contract.encode_abi("transfer", [
        bytes.fromhex("B8C8EB8EFC68796E766F6AB320DB8C165C064949"),
        int(0.004 * pow(10, tokens[0]["decimals"])),
    ])
    token_data1 = contract.encode_abi("transfer", [
        bytes.fromhex("4DDA64E1EC1A2C00D0766F25877F6A3BC77F717E"),
        int(0.008 * pow(10, tokens[1]["decimals"])),
    ])

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        batch_contract = Web3().eth.contract(abi=json.load(f),
                                             address=tokens[1]["address"])
    batch_data = batch_contract.encode_abi("batchExecute", [[
        (tokens[0]["address"], Web3.to_wei(0, "ether"), token_data0),
        (tokens[1]["address"], Web3.to_wei(0, "ether"), token_data1),
    ]])

    safe_addr = bytes.fromhex("60aa01971a2adc1d6b2b59b972fb47b2fec095fc")
    with Path(f"{ABIS_FOLDER}/safe_1.4.1.abi.json").open(
            encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=safe_addr)
    exec_data_signature = (
        "93a3e6ff4d0798d51ba53f5d8287326adbe3e22dd0dc28bdbfab825be357"
        "ce8c76a13b8128f5d91530af675925220ede099e0f0a51af3a65760060"
        "d4b37db9281c")
    exec_tx_data = contract.encode_abi("execTransaction", [
        safe_addr,
        0,
        batch_data,
        1,
        0,
        0,
        0,
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000"),
        bytes.fromhex(exec_data_signature),
    ])

    tx_to = bytes.fromhex("19a4d6928cd3b32Fa4Eb3962bfF1Abca91EB7C52")
    tx = _store_contract_call(client, backend, tx_to, exec_tx_data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/safe_1.4.1.abi.json",
                                "execTransaction")
    l0_fields = [
        Field(
            1,
            "From Safe",
            ParamTrustedName(
                1,
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
                [TrustedNameType.CONTRACT],
                [TrustedNameSource.CAL],
            ),
        ),
        Field(
            1,
            "Execution signer",
            ParamTrustedName(
                1,
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.FROM),
                [TrustedNameType.ACCOUNT],
                [
                    TrustedNameSource.ENS,
                    TrustedNameSource.UD,
                    TrustedNameSource.FN,
                ],
            ),
        ),
        Field(
            1,
            "Transaction",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             type_size=32,
                             data_path=DataPath(1, param_paths["value"])),
                spender=Value(1,
                              TypeFamily.ADDRESS,
                              container_path=ContainerPath.TO),
            ),
        ),
        Field(
            1,
            "Gas amount",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["safeTxGas"])),
            ),
        ),
        Field(
            1,
            "Gas price",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      type_size=32,
                      data_path=DataPath(1, param_paths["baseGas"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["gasPrice"])),
                [bytes.fromhex("0000000000000000000000000000000000000000")],
            ),
        ),
        Field(
            1,
            "Gas receiver",
            ParamTrustedName(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["refundReceiver"])),
                [
                    TrustedNameType.ACCOUNT,
                    TrustedNameType.CONTRACT,
                    TrustedNameType.TOKEN,
                ],
                [
                    TrustedNameSource.CAL,
                    TrustedNameSource.ENS,
                    TrustedNameSource.UD,
                    TrustedNameSource.FN,
                ],
            ),
        ),
    ]
    l0_tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        bytes.fromhex("29fcb43b46531bca003ddc8fcb67ffe91900c762"),
        get_selector_from_data(exec_tx_data),
        compute_inst_hash(l0_fields),
        "sign multisig operation",
        creator_name="Safe",
        creator_legal_name="Safe{Wallet}",
        creator_url="https://app.safe.global/welcome",
        contract_name="SafeL2",
    )

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute", "calls")
    l1_fields = [
        Field(
            1,
            "Transaction",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             data_path=DataPath(1, param_paths["value"])),
            ),
        ),
    ]
    l1_hash = compute_inst_hash(l1_fields)
    l1_tx_info = [
        TxInfo(1,
               TRON_MAINNET_CHAINID,
               safe_addr,
               get_selector_from_data(batch_data),
               l1_hash,
               "Batch transactions",
               creator_name="Ledger",
               creator_legal_name="Ledger Multisig",
               creator_url="https://www.ledger.com",
               contract_name="BatchExecutor"),
    ]

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    l2_fields = [
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      data_path=DataPath(1, param_paths["_value"]),
                      type_size=32),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_to"])),
            ),
        ),
    ]
    l2_hash = compute_inst_hash(l2_fields)
    l2_tx_info = [
        TxInfo(1, TRON_MAINNET_CHAINID, tokens[0]["address"],
               get_selector_from_data(token_data0), l2_hash, "Send",
               contract_name="USD_Coin"),
        TxInfo(1, TRON_MAINNET_CHAINID, tokens[1]["address"],
               get_selector_from_data(token_data1), l2_hash, "Send",
               contract_name="USD_Coin"),
    ]

    client.provide_proxy_info(
        ProxyInfo(_get_challenge(client), tx_to, l0_tx_info.chain_id,
                  l0_tx_info.contract_addr).serialize())
    client.provide_transaction_info(l0_tx_info.serialize())

    for f0 in l0_fields:
        client.provide_transaction_field_desc(f0.serialize())
        if f0.param.type == ParamType.CALLDATA:
            for i1 in l1_tx_info:
                client.provide_transaction_info(i1.serialize())
                for f1 in l1_fields:
                    client.provide_transaction_field_desc(f1.serialize())

                for idx, i2 in enumerate(l2_tx_info):
                    client.provide_transaction_info(i2.serialize())
                    client.provide_token_metadata(tokens[idx]["ticker"],
                                                  tokens[idx]["address"],
                                                  tokens[idx]["decimals"],
                                                  TRON_MAINNET_CHAINID)
                    for f2 in l2_fields:
                        client.provide_transaction_field_desc(f2.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_batch_complex(scenario_navigator: NavigateWithScenario) -> None:
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)

    tokens = [
        {
            "ticker": "USDT",
            "address": bytes.fromhex("dac17f958d2ee523a2206206994597c13d831ec7"),
            "decimals": 6,
        },
        {
            "ticker": "WETH",
            "address": bytes.fromhex("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
            "decimals": 18,
        },
    ]
    with Path(f"{ABIS_FOLDER}/erc20.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f), address=None)
    data0 = contract.encode_abi("transfer", [
        bytes.fromhex("1111111111111111111111111111111111111111"),
        int(1.1 * pow(10, tokens[0]["decimals"])),
    ])
    data1 = contract.encode_abi("transfer", [
        bytes.fromhex("3333333333333333333333333333333333333333"),
        int(3.3 * pow(10, tokens[1]["decimals"])),
    ])

    with Path(f"{ABIS_FOLDER}/batch.json").open(encoding="utf-8") as f:
        contract = Web3().eth.contract(abi=json.load(f),
                                       address=BATCH_CONTRACT20)
    data = contract.encode_abi("batchExecute", [[
        (bytes.fromhex("0000000000000000000000000000000000000000"),
         Web3.to_wei(0.0, "ether"), b""),
        (tokens[0]["address"], Web3.to_wei(0, "ether"), data0),
        (bytes.fromhex("2222222222222222222222222222222222222222"),
         Web3.to_wei(2.2, "ether"), b""),
        (tokens[1]["address"], Web3.to_wei(0, "ether"), data1),
        (bytes.fromhex("4444444444444444444444444444444444444444"),
         Web3.to_wei(4.4, "ether"), b""),
    ]])
    tx = _store_contract_call(client, backend, BATCH_CONTRACT20, data)

    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    sub_fields = [
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["_to"])),
            ),
        ),
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(1,
                      TypeFamily.UINT,
                      32,
                      DataPath(1, param_paths["_value"])),
                Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO),
            ),
        ),
    ]

    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json",
                                            "batchExecute", "calls")
    fields = [
        Field(
            1,
            "Destination",
            ParamCalldata(
                1,
                Value(1,
                      TypeFamily.BYTES,
                      data_path=DataPath(1, param_paths["data"])),
                Value(1,
                      TypeFamily.ADDRESS,
                      data_path=DataPath(1, param_paths["to"])),
                amount=Value(1,
                             TypeFamily.UINT,
                             data_path=DataPath(1, param_paths["value"])),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        TRON_MAINNET_CHAINID,
        BATCH_CONTRACT20,
        get_selector_from_data(data),
        compute_inst_hash(fields),
        "Batch transaction",
        creator_name="Ledger Multisig",
        creator_legal_name="Ledger",
    )
    client.provide_transaction_info(tx_info.serialize())

    client.provide_trusted_name(
        TrustedName(2,
                    b"\x00" * 20,
                    "null.eth",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=_get_challenge(client)))

    derivation_path = client.getAccount(0)["path"]
    wallet_addr = bytes.fromhex(client.getAccount(0)["addressHex"])[1:]
    client.provide_trusted_name(
        TrustedName(2,
                    b"\x44" * 20,
                    "FOUR",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=TRON_MAINNET_CHAINID,
                    challenge=_get_challenge(client),
                    owner=wallet_addr,
                    owner_deriv_path=derivation_path))

    sub_inst_hash = compute_inst_hash(sub_fields)
    sub_tx_info = [
        TxInfo(1, TRON_MAINNET_CHAINID, tokens[0]["address"],
               get_selector_from_data(data0), sub_inst_hash, "Transfer token"),
        TxInfo(1, TRON_MAINNET_CHAINID, tokens[1]["address"],
               get_selector_from_data(data1), sub_inst_hash, "Transfer token"),
    ]

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())
        for idx, sub_info in enumerate(sub_tx_info):
            client.provide_token_metadata(tokens[idx]["ticker"],
                                          tokens[idx]["address"],
                                          tokens[idx]["decimals"],
                                          TRON_MAINNET_CHAINID)
            client.provide_transaction_info(sub_info.serialize())
            for sub_field in sub_fields:
                client.provide_transaction_field_desc(sub_field.serialize())

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


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

def test_gcs_amount_decimals(scenario_navigator: NavigateWithScenario):
    """AMOUNT field renders native TRX with 6 decimals (SUN_TO_TRX), not 18.

    Calldata _amount = 0xf4240 = 1_000_000; with TRON's 6 decimals this is
    "1 TRX". The old app-ethereum WEI_TO_ETHER (18) bug would render
    "0.000000000001 TRX", so the snapshot is the regression guard for the fix.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    amount_field = build_field_amount("Amount", 32,
                                      data_path=build_data_path_static(1))
    tx = _gcs_send_descriptor(client, backend, [amount_field])

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_datetime(scenario_navigator: NavigateWithScenario):
    """DATETIME (DT_UNIX) field renders the calldata word as a UTC timestamp.

    Calldata word = 0xf4240 = 1_000_000 seconds since the epoch, which
    time_format_to_utc() renders as "1970-01-12 ... UTC" in the snapshot.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    dt_field = build_field_datetime("Deadline", 32,
                                    data_path=build_data_path_static(1))
    tx = _gcs_send_descriptor(client, backend, [dt_field])

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


# `transfer(address _to, uint256 _amount)` arg0 (_to) doubles as a stand-in token
# address: we register it via INS_PROVIDE_TRC20_TOKEN_INFORMATION so the
# TOKEN_AMOUNT formatter resolves it to a ticker/decimals from the TRC20 registry.
TKN_ADDR20 = bytes.fromhex("364b03e0815687edaf90b81ff58e496dea7383d7")


def test_gcs_token_amount(scenario_navigator: NavigateWithScenario):
    """TOKEN_AMOUNT resolves the token via the TRC20 registry (trc_tokens).

    arg0 is registered as "TKN" with 6 decimals; the amount word arg1 =
    1_000_000 then renders as "1 TKN" in the snapshot using the registry's
    decimals/ticker.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    field = build_field_token_amount("Amount",
                                     value_path=build_data_path_static(1),
                                     token_path=build_data_path_static(0))

    def provision() -> None:
        client.provide_token_metadata("TKN", TKN_ADDR20, 6,
                                      TRON_MAINNET_CHAINID)

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_trusted_name(scenario_navigator: NavigateWithScenario):
    """TRUSTED_NAME resolves a calldata address via provideTrustedName (0x22).

    arg0 is registered as the account name "alice.eth"; the GCS TRUSTED_NAME
    field over arg0 then renders that name in the snapshot instead of the raw
    address -- the provideTrustedName path unblocked by get_public_key().
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
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

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)


def test_gcs_enum(scenario_navigator: NavigateWithScenario):
    """ENUM field resolves a calldata byte via provide_enum_value (INS 0x24).

    arg1's low byte is 0x40 (0xf4240 & 0xff); an enum descriptor maps
    (contract, selector, id=0, value=0x40) -> "Deposit", which the ENUM field
    then renders in the snapshot instead of the raw value.
    """
    backend = scenario_navigator.backend
    client = _client_from_scenario(scenario_navigator)
    contract_addr20 = bytes.fromhex(client.address_hex(TRC20_CONTRACT_B58))[1:]
    field = build_field_enum("Action", enum_id=0,
                             value_path=build_data_path_static(1))

    def provision() -> None:
        enum_desc = build_enum_value(contract_addr20, TRC20_TRANSFER_SELECTOR,
                                     enum_id=0, value=0x40, name="Deposit")
        client.provide_enum_value(enum_desc)

    tx = _gcs_send_descriptor(client, backend, [field], provision=provision)

    _start_gcs_flow_and_assert(scenario_navigator, client, tx)
