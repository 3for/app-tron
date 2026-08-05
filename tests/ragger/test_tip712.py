#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/ragger/test_tip712.py
'''
import pytest
import json
import fnmatch
import functools
import os
import web3
import hashlib

from contextlib import nullcontext
from ctypes import c_uint64

from typing import Optional, Callable

from ragger.error import ExceptionRAPDU
from pathlib import Path
from Crypto.Hash import keccak
from tron import TronClient
from utils import (check_hash_signature, get_challenge, get_selector_from_data,
                   recover_message, to_sun, to_units)

from ragger.backend import BackendInterface
from ragger.bip import pack_derivation_path
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import (NavigateWithScenario,
                                                   NavigationScenarioData,
                                                   UseCase)

from settings import settings_toggle, SettingID, get_device_settings
from client.command_builder import CommandBuilder, InsType, P1Type, P2Type
import response_parser as ResponseParser
from client.tip712 import InputData as InputData, EIP712CalldataParamPresence
from client.trusted_name import TrustedName, TrustedNameType, TrustedNameSource
from client.gating import Gating
from client.status_word import StatusWord
from client.proxy_info import ProxyInfo
from client.gcs import (Field, ParamRaw, Value, TypeFamily, DataPath, PathTuple,
                        ParamTokenAmount, ParamCalldata, ContainerPath, PathLeaf,
                        PathLeafType, TxInfo)
from gcs_utils import ABIS_FOLDER, compute_inst_hash
from fields_utils import get_all_paths, get_all_tuple_array_paths
from ledgered.devices import Device
from address import to_tvm_address

WALLET_ADDR: Optional[bytes] = None


def tip712_new_common(scenario_navigator: NavigateWithScenario,
                      client: TronClient,
                      json_data: dict,
                      filters: Optional[dict] = None,
                      snapshots_dirname: Optional[str] = None,
                      nb_warnings: int = 0,
                      gating_params: Optional[Gating] = None):
    # Mirrors app-ethereum's schema-hash selector for typed-data gating. The
    # gating prelude is shown on every device, so it adds one more warning page
    # on top of the blind-signing one.
    if gating_params is not None:
        InputData.init_signature_context(json_data["types"], json_data["domain"])
        gating_params.selector = bytes(InputData.sig_ctx["schema_hash"])
        nb_warnings += 1

    signing_path = client.getAccount(0)['path']
    assert InputData.process_data(client, json_data, filters, signing_path)

    if gating_params is not None:
        assert client.provide_gating(gating_params.serialize()).status == StatusWord.OK

    do_compare = snapshots_dirname is not None
    with client.tip712_sign_new(signing_path):
        if nb_warnings > 0:
            scenario_navigator.review_approve_with_warning(
                test_name=snapshots_dirname,
                do_comparison=do_compare,
                nb_warnings=nb_warnings)
        else:
            scenario_navigator.review_approve(test_name=snapshots_dirname,
                                              do_comparison=do_compare)

    return ResponseParser.signature(client.response().data)


def get_wallet_addr(client: TronClient) -> bytes:
    cmd_builder = CommandBuilder()
    global WALLET_ADDR
    if WALLET_ADDR is None:
        with client.exchange_async_raw(
                cmd_builder.get_public_addr(
                    display=False,
                    chaincode=False,
                    bip32_path=client.getAccount(0)['path'],
                    chain_id=None)):
            pass
        _, WALLET_ADDR, _ = ResponseParser.pk_addr(
            client.response().data)
    return WALLET_ADDR[1:]


def tip712_json_path() -> str:
    return f"{os.path.dirname(__file__)}/tip712_input_files"


def current_screen_texts(backend: BackendInterface) -> list[str]:
    content = backend.get_current_screen_content()
    if isinstance(content, dict):
        return [
            event.get("text", "").strip()
            for event in content.get("events", [])
            if event.get("text", "").strip()
        ]
    if isinstance(content, list):
        return [str(item).strip() for item in content if str(item).strip()]
    return []


def settings_toggle_from_settings_home(device: Device, navigator: Navigator,
                                       to_toggle: list[SettingID]):
    moves = [NavInsID.BOTH_CLICK]
    for setting in get_device_settings(device):
        if setting in to_toggle:
            moves += [NavInsID.BOTH_CLICK]
        moves += [NavInsID.RIGHT_CLICK]
    moves += [NavInsID.BOTH_CLICK]
    navigator.navigate(moves, screen_change_before_first_instruction=False)


def settings_toggle_from_current_nano_home(backend: BackendInterface,
                                           device: Device,
                                           navigator: Navigator,
                                           to_toggle: list[SettingID]):
    texts = current_screen_texts(backend)
    normalized_texts = [text.lower() for text in texts]

    if any("settings" in text for text in normalized_texts):
        settings_toggle_from_settings_home(device, navigator, to_toggle)
        return

    if any("quit" in text for text in normalized_texts):
        navigator.navigate([NavInsID.LEFT_CLICK],
                           screen_change_before_first_instruction=False)
        settings_toggle_from_settings_home(device, navigator, to_toggle)
        return

    settings_toggle(device, navigator, to_toggle)


def toggle_settings(backend: BackendInterface, device: Device,
                    navigator: Navigator, to_toggle: list[SettingID]):
    """Toggle device settings, picking the Nano-aware helper when needed.

    With the class-level `configuration` fixture removed (mirroring
    app-ethereum's test_eip712), each test must explicitly enable the
    settings it relies on; the device boots with everything disabled.
    """
    if not to_toggle:
        return
    if device.is_nano:
        settings_toggle_from_current_nano_home(backend, device, navigator,
                                               to_toggle)
    else:
        settings_toggle(device, navigator, to_toggle)


def input_files() -> list[str]:
    files = []
    for file in os.scandir(tip712_json_path()):
        if fnmatch.fnmatch(file, "*-data.json"):
            files.append(file.path)
    return sorted(files)


def tip712_new_cases():
    cases = []
    display_root = Path(tip712_json_path())
    for file in input_files():
        input_file = Path(file)
        test_path = Path(input_file.parent) / '-'.join(
            input_file.stem.split('-')[:-1])
        filterfile = Path(f"{test_path}-filter.json")
        case_id = f"{display_root / input_file.name}"

        cases.append(pytest.param((input_file, False), id=f"{case_id}-False"))
        if filterfile.exists():
            cases.append(pytest.param((input_file, True),
                                      id=f"{case_id}-True"))
        else:
            cases.append(
                pytest.param(
                    (input_file, True),
                    id=f"{case_id}-True",
                    marks=pytest.mark.skip(
                        reason=f"{filterfile.name}: No such file or directory")
                ))
    return cases


@pytest.fixture(name="tip712_case", params=tip712_new_cases())
def tip712_case_fixture(request) -> tuple[Path, bool]:
    return request.param


@pytest.fixture(name="verbose_raw", params=[True, False])
def verbose_raw_fixture(request) -> bool:
    return request.param


class DataSet():
    data: dict
    filters: dict
    suffix: str

    def __init__(self, data: dict, filters: dict, suffix: str = ""):
        self.data = data
        self.filters = filters
        self.suffix = suffix


ADVANCED_DATA_SETS = [
    DataSet(
        {
            "domain": {
                "chainId": 728126428,
                "name": "Advanced test",
                "verifyingContract": "TUe6BwpA7sVTDKaJQoia7FWZpC9sK8WM2t",
                "version": "1"
            },
            "message": {
                "with": "TVjpchRyV9wdpj6kmwqVsBDWY1J8PaFtnb",
                "value_recv": 10000000000000000,
                "token_send": "TKjTFaKheJ8BGrMSeY6FKcYdCoD2GMXFDW",
                "value_send": 24500000000000000000,
                "token_recv": "TTVHrJWLPEMpsRJLs14bAZTpfXB5HBmNRa",
                "expires": 1714559400,
            },
            "primaryType": "Transfer",
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Transfer": [
                    {"name": "with", "type": "address"},
                    {"name": "value_recv", "type": "uint256"},
                    {"name": "token_send", "type": "address"},
                    {"name": "value_send", "type": "uint256"},
                    {"name": "token_recv", "type": "address"},
                    {"name": "expires", "type": "uint64"},
                ]
            }
        },
        {
            "name": "Advanced Filtering",
            "tokens": [
                {
                    "addr": "TTVHrJWLPEMpsRJLs14bAZTpfXB5HBmNRa",
                    "ticker": "WETH",
                    "decimals": 18,
                    "chain_id": 728126428,
                },
                {
                    "addr": "TKjTFaKheJ8BGrMSeY6FKcYdCoD2GMXFDW",
                    "ticker": "DAI",
                    "decimals": 18,
                    "chain_id": 728126428,
                },
            ],
            "fields": {
                "value_send": {
                    "type": "amount_join_value",
                    "name": "Send",
                    "token": 1,
                },
                "token_send": {
                    "type": "amount_join_token",
                    "token": 1,
                },
                "value_recv": {
                    "type": "amount_join_value",
                    "name": "Receive",
                    "token": 0,
                },
                "token_recv": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "with": {
                    "type": "raw",
                    "name": "With",
                },
                "expires": {
                    "type": "datetime",
                    "name": "Will Expire"
                },
            }
        }
    ),
    DataSet(
        {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "ENS",
                "version": "1",
                "verifyingContract": "TTcQoDJ881H3Aq3N6qYoKGjZfLNoFw4Jrh",
                "chainId": 728126428,
            },
            "message": {
                "owner": "TVjpchRyV9wdpj6kmwqVsBDWY1J8PaFtnb",
                "spender": "TJHYbk7q2EuMJJZeEF6cxPBEDg9kG1sR1j",
                "value": 4200000000000000000,
                "nonce": 0,
                "deadline": 1719756000,
            }
        },
        {
            "name": "Permit filtering",
            "tokens": [
                {
                    "addr": "TTcQoDJ881H3Aq3N6qYoKGjZfLNoFw4Jrh",
                    "ticker": "ENS",
                    "decimals": 18,
                    "chain_id": 728126428,
                },
            ],
            "fields": {
                "value": {
                    "type": "amount_join_value",
                    "name": "Send",
                },
                "deadline": {
                    "type": "datetime",
                    "name": "Deadline",
                },
            }
        },
        "_permit"
    ),
    DataSet(
        {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Root": [
                    {"name": "token_big", "type": "address"},
                    {"name": "value_big", "type": "uint256"},
                    {"name": "token_biggest", "type": "address"},
                    {"name": "value_biggest", "type": "uint256"},
                ]
            },
            "primaryType": "Root",
            "domain": {
                "name": "test",
                "version": "1",
                "verifyingContract": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                "chainId": 728126428,
            },
            "message": {
                "token_big": "TKjTFaKheJ8BGrMSeY6FKcYdCoD2GMXFDW",
                "value_big": c_uint64(-1).value,
                "token_biggest": "TKjTFaKheJ8BGrMSeY6FKcYdCoD2GMXFDW",
                "value_biggest": int(web3.constants.MAX_INT, 0),
            }
        },
        {
            "name": "Unlimited test",
            "tokens": [
                {
                    "addr": "TKjTFaKheJ8BGrMSeY6FKcYdCoD2GMXFDW",
                    "ticker": "DAI",
                    "decimals": 18,
                    "chain_id": 728126428,
                },
            ],
            "fields": {
                "token_big": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "value_big": {
                    "type": "amount_join_value",
                    "name": "Big",
                    "token": 0,
                },
                "token_biggest": {
                    "type": "amount_join_token",
                    "token": 0,
                },
                "value_biggest": {
                    "type": "amount_join_value",
                    "name": "Biggest",
                    "token": 0,
                },
            }
        },
        "_unlimited"
    ),
]


@pytest.fixture(name="data_set", params=ADVANCED_DATA_SETS)
def data_set_fixture(request) -> DataSet:
    return request.param


TOKENS = [
    [
        {
            "addr": "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV",
            "ticker": "SRC",
            "decimals": 18,
            "chain_id": 728126428,
        },
        {},
    ],
    [
        {},
        {
            "addr": "TD5gsCwxykWsLN9aPrq2TAfNjByuZKYp4E",
            "ticker": "DST",
            "decimals": 18,
            "chain_id": 728126428,
        },
    ]
]


@pytest.fixture(name="tokens", params=TOKENS)
def tokens_fixture(request) -> list[dict]:
    return request.param


TRUSTED_NAMES = [
    (TrustedNameType.CONTRACT, TrustedNameSource.CAL, "Validator contract"),
    (TrustedNameType.ACCOUNT, TrustedNameSource.ENS, "validator.eth"),
]

FILT_TN_TYPES = [
    [TrustedNameType.CONTRACT],
    [TrustedNameType.ACCOUNT],
    [TrustedNameType.CONTRACT, TrustedNameType.ACCOUNT],
    [TrustedNameType.ACCOUNT, TrustedNameType.CONTRACT],
]


@pytest.fixture(name="trusted_name", params=TRUSTED_NAMES)
def trusted_name_fixture(request) -> tuple:
    return request.param


@pytest.fixture(name="filt_tn_types", params=FILT_TN_TYPES)
def filt_tn_types_fixture(request) -> list[TrustedNameType]:
    return request.param


# GCS (Generic Clear Signing) handlers for the nested-calldata TIP-712 tests. Each
# is bound -- via the filter's "handler" -- to (client, json_data) and invoked once a
# calldata's value field has been sent, streaming the GTP descriptor (TX_INFO +
# fields) that clear-signs the embedded transaction. Mirrors app-ethereum's
# gcs_handler* in test_eip712.py.


def gcs_handler(client: TronClient, json_data: dict) -> None:
    fields = [
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(
                    1,
                    TypeFamily.UINT,
                    type_size=32,
                    data_path=DataPath(
                        1,
                        [
                            PathTuple(1),
                            PathLeaf(PathLeafType.STATIC),
                        ]
                    ),
                ),
                token=Value(
                    1,
                    TypeFamily.ADDRESS,
                    container_path=ContainerPath.TO,
                ),
            )
        ),
    ]
    # compute instructions hash
    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1,
        json_data["domain"]["chainId"],
        to_tvm_address(json_data["message"]["to"]),
        get_selector_from_data(json_data["message"]["data"]),
        inst_hash,
        "Token transfer",
        contract_name="USDC",
    )
    client.provide_token_metadata(tx_info.contract_name, tx_info.contract_addr, 6, tx_info.chain_id)

    client.provide_transaction_info(tx_info.serialize())

    for field in fields:
        client.provide_transaction_field_desc(field.serialize())


def gcs_handler_trctoken(client: TronClient, json_data: dict) -> None:
    # For transferToken(address,uint256,trcToken), render the 3rd word (the trcToken
    # tokenId) via TypeFamily.TRC_TOKEN, exercising the TF_TRC_TOKEN family through the
    # TIP-712 nested-calldata field formatting.
    fields = [
        Field(
            1,
            "Token id",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.TRC_TOKEN,
                    type_size=32,
                    data_path=DataPath(
                        1,
                        [
                            PathTuple(2),  # transferToken word 2: the trcToken tokenId
                            PathLeaf(PathLeafType.STATIC),
                        ]
                    ),
                ),
            )
        ),
    ]
    inst_hash = compute_inst_hash(fields)
    tx_info = TxInfo(
        1,
        json_data["domain"]["chainId"],
        to_tvm_address(json_data["message"]["to"]),
        get_selector_from_data(json_data["message"]["data"]),
        inst_hash,
        "Token transfer",
        contract_name="USDC",
    )
    client.provide_transaction_info(tx_info.serialize())
    for field in fields:
        client.provide_transaction_field_desc(field.serialize())


def gcs_handler_batch(client: TronClient, json_data: dict) -> None:
    # Load TIP-712 JSON data
    with open(f"{tip712_json_path()}/safe_batch.json", encoding="utf-8") as file:
        data = json.load(file)

    # Define tokens
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
    # Encode token transfer data
    with open(f"{ABIS_FOLDER}/erc20.json", encoding="utf-8") as f:
        contract = web3.Web3().eth.contract(
            abi=json.load(f),
            address=None
        )
    tokenData0 = contract.encode_abi("transfer", [
        bytes.fromhex("B8C8EB8EFC68796E766F6AB320DB8C165C064949"),
        int(0.004 * pow(10, tokens[0]["decimals"])),
    ])
    tokenData1 = contract.encode_abi("transfer", [
        bytes.fromhex("4DDA64E1EC1A2C00D0766F25877F6A3BC77F717E"),
        int(0.008 * pow(10, tokens[1]["decimals"])),
    ])

    # Encode batchExecute data using token transfer data
    with open(f"{ABIS_FOLDER}/batch.json", encoding="utf-8") as f:
        contract = web3.Web3().eth.contract(
            abi=json.load(f),
            address=tokens[1]["address"]
        )
    batchData = contract.encode_abi("batchExecute", [[
        (
            tokens[0]["address"],
            to_sun(0),
            tokenData0
        ),
        (
            tokens[1]["address"],
            to_sun(0),
            tokenData1
        ),
    ]])

    # Top level transaction fields definition
    param_paths = get_all_tuple_array_paths(f"{ABIS_FOLDER}/batch.json", "batchExecute", "calls")
    L0_fields = [
        Field(
            1,
            "Transaction",
            ParamCalldata(
                1,
                Value(
                    1,
                    TypeFamily.BYTES,
                    data_path=DataPath(
                        1,
                        param_paths["data"]
                    ),
                ),
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(
                        1,
                        param_paths["to"]
                    ),
                ),
                amount=Value(
                    1,
                    TypeFamily.UINT,
                    data_path=DataPath(
                        1,
                        param_paths["value"]
                    ),
                ),
            )
        ),
    ]
    # compute instructions hash
    L0_hash = compute_inst_hash(L0_fields)

    # Define intermediate execTransaction transaction info
    L0_tx_info = TxInfo(
        1,
        data["domain"]["chainId"],
        to_tvm_address(json_data["domain"]["verifyingContract"]),
        get_selector_from_data(batchData),
        L0_hash,
        "Batch transactions",
        creator_name="Ledger",
        creator_legal_name="Ledger Multisig",
        creator_url="https://www.ledger.com",
        contract_name="BatchExecutor",
    )

    # Lower batchExecute transaction fields definition
    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    L1_fields = [
        Field(
            1,
            "Amount",
            ParamTokenAmount(
                1,
                Value(
                    1,
                    TypeFamily.UINT,
                    data_path=DataPath(
                        1,
                        param_paths["_value"]
                    ),
                    type_size=32,
                ),
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    container_path=ContainerPath.TO,
                ),
            )
        ),
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(
                        1,
                        param_paths["_to"]
                    ),
                )
            )
        ),
    ]
    # compute instructions hash
    L1_hash = compute_inst_hash(L1_fields)

    # Define lower batchExecute transaction info
    L1_tx_info = [
        TxInfo(
            1,
            data["domain"]["chainId"],
            tokens[0]["address"],
            get_selector_from_data(tokenData0),
            L1_hash,
            "Send",
            contract_name="USD_Coin",
        ),
        TxInfo(
            1,
            data["domain"]["chainId"],
            tokens[1]["address"],
            get_selector_from_data(tokenData1),
            L1_hash,
            "Send",
            contract_name="USD_Coin",
        )
    ]

    proxy_info = ProxyInfo(
        get_challenge(client),
        to_tvm_address(json_data["message"]["to"]),
        L0_tx_info.chain_id,
        L0_tx_info.contract_addr,
    )

    # Send Proxy information
    client.provide_proxy_info(proxy_info.serialize())

    # Send intermediate execTransaction info description
    client.provide_transaction_info(L0_tx_info.serialize())
    for f0 in L0_fields:
        # Send intermediate execTransaction fields description
        client.provide_transaction_field_desc(f0.serialize())

    # Lower batchExecute description
    for idx, i1 in enumerate(L1_tx_info):
        # Send lower batchExecute info description
        client.provide_transaction_info(i1.serialize())
        client.provide_token_metadata(tokens[idx]["ticker"],
                                      tokens[idx]["address"],
                                      tokens[idx]["decimals"],
                                      data["domain"]["chainId"])
        for f1 in L1_fields:
            # Send lower batchExecute fields description
            client.provide_transaction_field_desc(f1.serialize())


def gcs_handler_no_param(client: TronClient, json_data: dict) -> None:
    tx_info = TxInfo(
        1,
        json_data["domain"]["chainId"],
        to_tvm_address(json_data["message"]["to"]),
        get_selector_from_data(json_data["message"]["data"]),
        hashlib.sha3_256().digest(),
        "get total supply",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )

    client.provide_transaction_info(tx_info.serialize())


def _provide_no_param_tx_info(client: TronClient, json_data: dict,
                              callee_field: str, calldata_field: str) -> None:
    tx_info = TxInfo(
        1,
        json_data["domain"]["chainId"],
        to_tvm_address(json_data["message"][callee_field]),
        get_selector_from_data(json_data["message"][calldata_field]),
        hashlib.sha3_256().digest(),
        "zero-argument call",
    )
    client.provide_transaction_info(tx_info.serialize())


def gcs_handler_interleaved_first(client: TronClient, json_data: dict) -> None:
    _provide_no_param_tx_info(client, json_data, "toA", "dataA")
    # TX_INFO loads the calldata certificate. Restore the CAL certificate
    # before the next filtered TIP-712 field is sent.
    InputData.send_coin_meta_certificate(client)


def gcs_handler_interleaved_second(client: TronClient, json_data: dict) -> None:
    _provide_no_param_tx_info(client, json_data, "toB", "dataB")


def gcs_handler_separate_selector(client: TronClient, json_data: dict) -> None:
    _provide_no_param_tx_info(client, json_data, "to", "selector")


def test_sign_tip712(
                         scenario_navigator: NavigateWithScenario):
    """Legacy P2=0 remains signable without the full-mode INIT command."""
    backend = scenario_navigator.backend
    device = backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)
    # Legacy hash-based TIP-712 signing requires blind signing to be enabled.
    toggle_settings(backend, device, navigator, [SettingID.SIGN_BY_HASH])
    domainHash = bytes.fromhex(
        '6137beb405d9ff777172aa879e33edb34a1460e701802746c5ef96e741710e59')
    messageHash = bytes.fromhex(
        'eb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8')

    with client.tip712_sign_legacy(client.getAccount(0)['path'],
                                   domainHash,
                                   messageHash):
        scenario_navigator.review_approve(do_comparison=False)

    resp = scenario_navigator.backend.last_async_response

    sign_magic = b'\x19\x01'
    msg_to_sign = sign_magic + domainHash + messageHash
    digest = keccak.new(digest_bits=256, data=msg_to_sign).digest()

    assert check_hash_signature(digest, resp.data[0:65],
                                client.getAccount(0)['publicKey'][2:])


def test_tip712_legacy_host_apdu_remains_single_step():
    """Pin the wire format used by existing hash-only TIP-712 hosts."""
    signing_path = "m/44'/195'/0'/0/0"
    domain_hash = bytes(range(32))
    message_hash = bytes(range(32, 64))
    expected_payload = (pack_derivation_path(signing_path) + domain_hash +
                        message_hash)

    command = CommandBuilder().tip712_sign_legacy(signing_path,
                                                   domain_hash,
                                                   message_hash)

    # E0 0C 00 00 means one-step legacy TIP-712 signing. In particular, this
    # must not change to the P1=01 INIT command introduced for P2=01 full mode.
    assert command[:5] == bytes([0xE0, 0x0C, 0x00, 0x00,
                                 len(expected_payload)])
    assert command[5:] == expected_payload


def test_tip712_input_driver_isolates_filtered_unfiltered_sequence(monkeypatch):
    """Every process_data call owns fresh filters, handlers and signature state."""

    class FakeClient:
        def tip712_init_new(self, _path):
            return nullcontext()

        def tip712_filtering_activate(self):
            return nullcontext()

        def tip712_send_struct_impl_root_struct(self, _name):
            return nullcontext()

    def calldata_handler(_client, _data):
        pass

    data = {
        "primaryType": "Message",
        "types": {},
        "domain": {
            "name": "Isolation test",
            "chainId": 1,
            "verifyingContract": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
        },
        "message": {},
    }
    filters = {
        "name": "Isolation filter",
        "fields": {
            "message.data": {"type": "calldata_value", "index": 0},
        },
        "calldatas": [{"index": 0, "handler": calldata_handler}],
    }
    client = FakeClient()
    signing_path = "m/44'/195'/0'/0/0"

    monkeypatch.setattr(InputData, "send_coin_meta_certificate", lambda _client: None)
    monkeypatch.setattr(InputData, "send_struct_impl", lambda *_args: True)
    monkeypatch.setattr(InputData, "send_filtering_message_info", lambda *_args: None)

    assert InputData.process_data(client, data, filters, signing_path)
    first_handler = InputData.filtering_calldatas[0]["handler"]
    assert isinstance(first_handler, functools.partial)
    assert first_handler.func is calldata_handler
    assert filters["calldatas"][0] == {"index": 0, "handler": calldata_handler}

    assert InputData.process_data(client, data, None, signing_path)
    assert InputData.filtering_paths == {}
    assert InputData.filtering_tokens == []
    assert InputData.filtering_calldatas == []
    assert InputData.sig_ctx == {}

    assert InputData.process_data(client, data, filters, signing_path)
    second_handler = InputData.filtering_calldatas[0]["handler"]
    assert isinstance(second_handler, functools.partial)
    assert second_handler.func is calldata_handler
    assert second_handler is not first_handler
    assert filters["calldatas"][0] == {"index": 0, "handler": calldata_handler}


def test_tip712_new(
                        scenario_navigator: NavigateWithScenario,
                        tip712_case: tuple[Path, bool], verbose_raw: bool,
                        test_name: str):
    settings_to_toggle: list[SettingID] = []
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)
    input_file, filtering = tip712_case

    test_path = f"{input_file.parent}/{'-'.join(input_file.stem.split('-')[:-1])}"

    test_name += '-' + input_file.stem + '-' + f"{verbose_raw}" + '-' + f"{filtering}"

    filters = None
    if filtering:
        try:
            filterfile = Path(f"{test_path}-filter.json")
            with open(filterfile, encoding="utf-8") as f:
                filters = json.load(f)
        except FileNotFoundError as error:
            pytest.skip(f"{filterfile.name}: {error}")
        except json.decoder.JSONDecodeError as error:
            pytest.fail(f"{filterfile.name}: invalid JSON: {error}")
        except OSError as error:
            pytest.fail(f"{filterfile.name}: unable to read filter: {error}")
    else:
        # Unfiltered (blind) signing needs SIGN_BY_HASH enabled.
        settings_to_toggle.append(SettingID.SIGN_BY_HASH)

    if verbose_raw:
        settings_to_toggle.append(SettingID.VERBOSE_TIP712)

    nb_warnings = 1 if not filters or verbose_raw else 0
    toggle_settings(backend, device, navigator, settings_to_toggle)

    with open(input_file, encoding="utf-8") as file:
        data = json.load(file)
        vrs = tip712_new_common(scenario_navigator,
                                client,
                                data,
                                filters,
                                snapshots_dirname=test_name,
                                nb_warnings=nb_warnings)
        recovered_addr = recover_message(data, vrs)

    assert recovered_addr == get_wallet_addr(client)


def test_tip712_advanced_filtering(
        scenario_navigator: NavigateWithScenario,
        test_name: str, data_set: DataSet, verbose_raw: bool):
    if verbose_raw and data_set.suffix:
        pytest.skip("Skipping Verbose mode for this data sets")

    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    snapshots_dirname = test_name + data_set.suffix
    if verbose_raw:
        # Verbose mode additionally renders the message hash.
        toggle_settings(backend, device, navigator, [SettingID.DISPLAY_HASH])
        snapshots_dirname += "-verbose"

    vrs = tip712_new_common(scenario_navigator, client, data_set.data,
                            data_set.filters,
                            snapshots_dirname=snapshots_dirname)
    recovered_addr = recover_message(data_set.data, vrs)
    assert client.getAccount(
        0)['addressHex'][2:] == recovered_addr.hex().upper()

    assert recovered_addr == get_wallet_addr(client)


def test_tip712_filtering_empty_array(
        scenario_navigator: NavigateWithScenario, test_name: str):
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "addr", "type": "address"},
            ],
            "Message": [
                {"name": "title", "type": "string"},
                {"name": "to", "type": "Person[]"},
            ],
            "Root": [
                {"name": "text", "type": "string"},
                {"name": "subtext", "type": "string[]"},
                {"name": "msg_list1", "type": "Message[]"},
                {"name": "msg_list2", "type": "Message[]"},
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            "chainId": 728126428,
        },
        "message": {
            "text": "This is a test",
            "subtext": [],
            "msg_list1": [
                {
                    "title": "This is a test",
                    "to": [],
                }
            ],
            "msg_list2": [],
        }
    }
    filters = {
        "name": "Empty array filtering",
        "fields": {
            "text": {
                "type": "raw",
                "name": "Text",
            },
            "subtext.[]": {
                "type": "raw",
                "name": "Sub-Text",
            },
            "msg_list1.[].to.[].addr": {
                "type": "raw",
                "name": "(1) Recipient addr",
            },
            "msg_list2.[].to.[].addr": {
                "type": "raw",
                "name": "(2) Recipient addr",
            },
        }
    }

    vrs = tip712_new_common(scenario_navigator, client, data, filters,
                            snapshots_dirname=test_name)

    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


def test_tip712_advanced_missing_token(
        scenario_navigator: NavigateWithScenario,
        tokens: list[dict]):

    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Root": [
                {"name": "token_from", "type": "address"},
                {"name": "value_from", "type": "uint256"},
                {"name": "token_to", "type": "address"},
                {"name": "value_to", "type": "uint256"},
            ]
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            "chainId": 728126428,
        },
        "message": {
            "token_from": "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV",
            "value_from": to_units("3.65", 18),
            "token_to": "TD5gsCwxykWsLN9aPrq2TAfNjByuZKYp4E",
            "value_to": to_units("15.47", 18),
        }
    }
    filters = {
        "name": "Token not in CAL test",
        "tokens": tokens,
        "fields": {
            "token_from": {
                "type": "amount_join_token",
                "token": 0,
            },
            "value_from": {
                "type": "amount_join_value",
                "name": "From",
                "token": 0,
            },
            "token_to": {
                "type": "amount_join_token",
                "token": 1,
            },
            "value_to": {
                "type": "amount_join_value",
                "name": "To",
                "token": 1,
            },
        }
    }

    # Clear signing must never accept an amount-join address without the exact
    # token metadata that will be snapshotted for its amount display.
    with pytest.raises(ExceptionRAPDU) as error:
        InputData.process_data(client, data, filters,
                               client.getAccount(0)["path"])
    assert error.value.status == StatusWord.REFERENCED_DATA_NOT_FOUND


def test_tip712_amount_join_survives_asset_slot_wraparound(
        scenario_navigator: NavigateWithScenario,
        monkeypatch: pytest.MonkeyPatch):
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    token_address = "TKjTFaKheJ8BGrMSeY6FKcYdCoD2GMXFDW"
    data = {
        "types": {
            "EIP712Domain": [
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Root": [
                {"name": "token_first", "type": "address"},
                {"name": "token_second", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
        },
        "primaryType": "Root",
        "domain": {
            "chainId": 728126428,
            "verifyingContract": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
        },
        "message": {
            "token_first": token_address,
            "token_second": token_address,
            "amount": 1_000_000,
        },
    }
    filters = {
        "name": "Asset snapshot",
        "tokens": [{
            "addr": token_address,
            "ticker": "SNAP",
            "decimals": 6,
            "chain_id": 728126428,
        }],
        "fields": {
            "token_first": {"type": "amount_join_token", "token": 0},
            "token_second": {"type": "amount_join_token", "token": 0},
            "amount": {
                "type": "amount_join_value",
                "name": "Amount",
                "token": 0,
            },
        },
    }
    original_send_field = InputData.send_struct_impl_field

    def send_field_then_wrap_slots(value, field):
        result = original_send_field(value, field)
        if field["name"] == "token_first":
            for index in range(5):
                client.provide_token_metadata(
                    f"WRAP{index}",
                    bytes([index + 1]) * 20,
                    index,
                    728126428,
                )
        return result

    monkeypatch.setattr(InputData, "send_struct_impl_field",
                        send_field_then_wrap_slots)
    signing_path = client.getAccount(0)["path"]
    assert InputData.process_data(client, data, filters, signing_path)
    with client.tip712_sign_new(signing_path):
        scenario_navigator.review_approve(do_comparison=False)


def test_tip712_advanced_trusted_name(
        scenario_navigator: NavigateWithScenario,
        test_name: str, trusted_name: tuple,
        filt_tn_types: list[TrustedNameType]):
    test_name += f"_{trusted_name[0].name.lower()}_with"
    for trusted_name_type in filt_tn_types:
        test_name += f"_{trusted_name_type.name.lower()}"

    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Root": [
                {"name": "validator", "type": "address"},
                {"name": "enable", "type": "bool"},
            ]
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            "chainId": 728126428,
        },
        "message": {
            "validator": "TBXSw8fM4jpQkGc6zZjsVABFpVN7UvXPdV",
            "enable": True,
        }
    }
    filters = {
        "name": "Trusted name test",
        "fields": {
            "validator": {
                "type": "trusted_name",
                "name": "Validator",
                "tn_type": filt_tn_types,
                "tn_source": [TrustedNameSource.CAL, TrustedNameSource.ENS],
            },
            "enable": {
                "type": "raw",
                "name": "State",
            },
        }
    }

    if trusted_name[0] is TrustedNameType.ACCOUNT:
        challenge = get_challenge(client)
    else:
        challenge = None

    client.provide_trusted_name(
        TrustedName(
            2,
            to_tvm_address(data["message"]["validator"]),
            trusted_name[2],
            tn_type=trusted_name[0],
            tn_source=trusted_name[1],
            chain_id=data["domain"]["chainId"],
            challenge=challenge))

    vrs = tip712_new_common(scenario_navigator, client, data, filters,
                            snapshots_dirname=test_name)

    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


def _tip712_calldata_common(
                            scenario_navigator: NavigateWithScenario,
                            test_name: str,
                            filename: str,
                            handler: Optional[Callable] = None):
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    with open(f"{tip712_json_path()}/{filename}.json", encoding="utf-8") as file:
        data = json.load(file)

    filters = {
        "name": "Calldata test",
        "calldatas": [
            {
                "index": 0,
                "handler": handler,
                "value_flag": True,
                "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
                "chain_id_flag": False,
                "selector_flag": False,
                "amount_flag": True,
                "spender_flag": EIP712CalldataParamPresence.NONE,
            },
        ],
        "fields": {
            "to": {
                "type": "calldata_callee",
                "index": 0,
            },
            "value": {
                "type": "calldata_amount",
                "index": 0,
            },
            "data": {
                "type": "calldata_value",
                "index": 0,
            },
        }
    }

    vrs = tip712_new_common(scenario_navigator, client, data, filters,
                            snapshots_dirname=test_name)

    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


@pytest.mark.parametrize("fill", [0x00, 0xA5])
def test_tip712_rejects_nested_calldata_over_semantic_limit(
        backend: BackendInterface, fill: int):
    client = TronClient(backend)
    with open(f"{tip712_json_path()}/safe.json", encoding="utf-8") as file:
        data = json.load(file)

    # The selector is embedded in the bytes value, so 4097 bytes of normalized
    # argument data means a 4101-byte field on the wire.
    data["message"]["data"] = "0x" + (
        bytes.fromhex("a9059cbb") + bytes([fill]) * 4097
    ).hex()
    filters = {
        "name": "Oversized calldata",
        "calldatas": [{
            "index": 0,
            "handler": None,
            "value_flag": True,
            "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
            "chain_id_flag": False,
            "selector_flag": False,
            "amount_flag": True,
            "spender_flag": EIP712CalldataParamPresence.NONE,
        }],
        "fields": {
            "to": {"type": "calldata_callee", "index": 0},
            "value": {"type": "calldata_amount", "index": 0},
            "data": {"type": "calldata_value", "index": 0},
        },
    }

    with pytest.raises(ExceptionRAPDU) as error:
        InputData.process_data(client, data, filters,
                               client.getAccount(0)["path"])
    assert error.value.status == StatusWord.INVALID_DATA


def test_tip712_filtering_rejects_recursive_schema(backend: BackendInterface):
    client = TronClient(backend)
    data = {
        "types": {
            "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
            "Node": [{"name": "children", "type": "Node[]"}],
        },
        "primaryType": "Node",
        "domain": {"chainId": 728126428},
        "message": {"children": []},
    }
    filters = {"name": "Recursive schema", "fields": {}}

    with pytest.raises(ExceptionRAPDU) as error:
        InputData.process_data(client, data, filters,
                               client.getAccount(0)["path"])
    assert error.value.status == StatusWord.INVALID_DATA


def test_tip712_rejects_empty_dynamic_continuation(
        scenario_navigator: NavigateWithScenario,
        monkeypatch: pytest.MonkeyPatch):
    """A partial string/bytes APDU must consume at least one value byte."""
    backend = scenario_navigator.backend
    device = backend.device
    navigator = scenario_navigator.navigator
    toggle_settings(backend, device, navigator, [SettingID.SIGN_BY_HASH])
    client = TronClient(backend, device, navigator)
    signing_path = client.getAccount(0)["path"]
    with open(f"{tip712_json_path()}/03-long_string-data.json",
              encoding="utf-8") as data_file:
        data = json.load(data_file)
    data["message"]["contents"] = "A" * 300
    original_send = client.tip712_send_struct_impl_struct_field
    injected = False

    def send_with_empty_continuation(raw_value: bytes):
        nonlocal injected
        if (not injected) and (len(raw_value) == 300):
            injected = True
            chunks = CommandBuilder().tip712_send_struct_impl_struct_field(
                bytearray(raw_value))
            assert len(chunks) == 2
            client.exchange_raw(chunks[0])
            empty = CommandBuilder()._serialize(
                InsType.TIP712_SEND_STRUCT_IMPL,
                P1Type.PARTIAL_SEND,
                P2Type.STRUCT_FIELD,
                b"")
            return client.exchange_async_raw(empty)
        return original_send(raw_value)

    monkeypatch.setattr(client, "tip712_send_struct_impl_struct_field",
                        send_with_empty_continuation)
    with pytest.raises(ExceptionRAPDU) as error:
        InputData.process_data(client, data, None, signing_path)
    assert injected
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize(
    "field_type,value,expected_text",
    [
        pytest.param("uint", 255, "1970-01-01", id="bare-uint-compact-ff"),
        pytest.param("uint", (1 << 256) - 1, "Unlimited",
                     id="bare-uint-full-ff"),
        pytest.param("uint8", 255, "Unlimited", id="uint8-full-ff"),
    ])
def test_tip712_datetime_max_requires_full_type_width(
        scenario_navigator: NavigateWithScenario, field_type: str, value: int,
        expected_text: str):
    """Only a full-width all-ones uint is rendered as Unlimited."""
    backend = scenario_navigator.backend
    device = backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)
    signing_path = client.getAccount(0)["path"]
    data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [{"name": "expires", "type": field_type}],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Bare uint datetime",
            "version": "1",
            "chainId": 728126428,
            "verifyingContract": "TTcQoDJ881H3Aq3N6qYoKGjZfLNoFw4Jrh",
        },
        "message": {"expires": value},
    }
    filters = {
        "name": "Bare uint datetime",
        "fields": {
            "expires": {"type": "datetime", "name": "Expires"},
        },
    }

    assert InputData.process_data(client, data, filters, signing_path)
    with client.tip712_sign_new(signing_path):
        navigator.navigate_until_text(
            navigate_instruction=(NavInsID.RIGHT_CLICK if device.is_nano else
                                  NavInsID.SWIPE_CENTER_TO_LEFT),
            validation_instructions=[],
            text=expected_text,
            screen_change_after_last_instruction=False)
        if expected_text != "Unlimited":
            assert "Unlimited" not in current_screen_texts(backend)
        approve = NavigationScenarioData(device, backend, UseCase.TX_REVIEW,
                                         True)
        navigator.navigate_until_text(
            navigate_instruction=approve.navigation,
            validation_instructions=approve.validation,
            text=approve.pattern,
            screen_change_before_first_instruction=False)


def test_tip712_calldata(
        scenario_navigator: NavigateWithScenario, test_name: str):
    _tip712_calldata_common(scenario_navigator, test_name, "safe",
                                 gcs_handler)


def test_tip712_calldata_trctoken(
        scenario_navigator: NavigateWithScenario, test_name: str):
    # Nested-calldata TIP-712 whose embedded calldata is a real
    # transferToken(address,uint256,trcToken); the trcToken word is rendered via
    # TypeFamily.TRC_TOKEN, exercising the same TF_TRC_TOKEN path as test_gcs_trctoken.
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    with open(f"{tip712_json_path()}/safe.json", encoding="utf-8") as file:
        data = json.load(file)

    # Swap the embedded transfer() calldata for transferToken(address,uint256,trcToken).
    to20 = to_tvm_address(data["message"]["to"])
    selector = web3.Web3.keccak(text="transferToken(address,uint256,trcToken)")[:4]
    data["message"]["data"] = "0x" + (
        selector + bytes(12) + to20
        + (1000000).to_bytes(32, "big")   # word 1: uint256 tokenValue
        + (1002000).to_bytes(32, "big")   # word 2: trcToken tokenId
    ).hex()

    filters = {
        "name": "Calldata test",
        "calldatas": [
            {
                "index": 0,
                "handler": gcs_handler_trctoken,
                "value_flag": True,
                "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
                "chain_id_flag": False,
                "selector_flag": False,
                "amount_flag": True,
                "spender_flag": EIP712CalldataParamPresence.NONE,
            },
        ],
        "fields": {
            "to": {"type": "calldata_callee", "index": 0},
            "value": {"type": "calldata_amount", "index": 0},
            "data": {"type": "calldata_value", "index": 0},
        }
    }

    vrs = tip712_new_common(scenario_navigator, client, data, filters,
                            snapshots_dirname=test_name)
    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


def test_tip712_calldata_empty_send(
        scenario_navigator: NavigateWithScenario, test_name: str):
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)
    filename = "safe_empty"

    with open(f"{tip712_json_path()}/{filename}.json", encoding="utf-8") as file:
        json_data = json.load(file)

    client.provide_trusted_name(
        TrustedName(2,
                    to_tvm_address(json_data["message"]["to"]),
                    "MAB_addr",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=json_data["domain"]["chainId"],
                    challenge=get_challenge(client),
                    owner=bytes.fromhex(client.getAccount(0)["addressHex"])[1:],
                    owner_deriv_path=client.getAccount(0)["path"]))
    _tip712_calldata_common(scenario_navigator, test_name, filename)


@pytest.mark.parametrize(
    "missing_field", ["callee", "amount", "chain_id", "spender"])
def test_tip712_empty_calldata_requires_all_declared_fields(
        backend: BackendInterface, missing_field: str):
    """Empty calldata is complete only after every declared CAL field arrives."""
    client = TronClient(backend)
    with open(f"{tip712_json_path()}/safe_empty.json",
              encoding="utf-8") as data_file:
        data = json.load(data_file)

    data["types"]["SafeTx"].append({"name": "spender", "type": "address"})
    data["message"]["spender"] = "TTcQoDJ881H3Aq3N6qYoKGjZfLNoFw4Jrh"
    filters = {
        "name": "Incomplete empty calldata",
        "calldatas": [{
            "index": 0,
            "handler": None,
            "value_flag": True,
            "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
            "chain_id_flag": missing_field == "chain_id",
            "selector_flag": False,
            "amount_flag": True,
            "spender_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
        }],
        "fields": {
            "to": {"type": "calldata_callee", "index": 0},
            "value": {"type": "calldata_amount", "index": 0},
            "data": {"type": "calldata_value", "index": 0},
            "spender": {"type": "calldata_spender", "index": 0},
        },
    }
    if missing_field != "chain_id":
        del filters["fields"][{
            "callee": "to",
            "amount": "value",
            "spender": "spender",
        }[missing_field]]
    # For the chain_id case the domain value is still hashed, but it is
    # deliberately not routed through the calldata handler declared by CAL.

    signing_path = client.getAccount(0)["path"]
    assert InputData.process_data(client, data, filters, signing_path)
    with pytest.raises(ExceptionRAPDU) as error:
        with client.tip712_sign_new(signing_path):
            pass
    assert error.value.status == StatusWord.REFERENCED_DATA_NOT_FOUND


def test_tip712_calldata_no_param(
        scenario_navigator: NavigateWithScenario, test_name: str):
    _tip712_calldata_common(scenario_navigator, test_name,
                                 "safe_calldata_no_param",
                                 gcs_handler_no_param)


def test_tip712_calldata_infos_keep_independent_pending_values(
        scenario_navigator: NavigateWithScenario):
    """Interleaved calldata fields must not overwrite another info's value."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    data = {
        "domain": {
            "verifyingContract": "TTcY7HWMs6jqQr2BPRnEKZZDF8FVLHJoYx",
            "chainId": 728126428,
        },
        "message": {
            "dataA": "0x18160ddd",
            "dataB": "0x313ce567",
            "toA": "TTVHrJWLPEMpsRJLs14bAZTpfXB5HBmNRa",
            "toB": "TTcQoDJ881H3Aq3N6qYoKGjZfLNoFw4Jrh",
        },
        "primaryType": "InterleavedCalls",
        "types": {
            "EIP712Domain": [
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "InterleavedCalls": [
                {"name": "dataA", "type": "bytes"},
                {"name": "dataB", "type": "bytes"},
                {"name": "toA", "type": "address"},
                {"name": "toB", "type": "address"},
            ],
        },
    }
    filters = {
        "name": "Interleaved calls",
        "calldatas": [
            {
                "index": 0,
                "handler": gcs_handler_interleaved_first,
                "value_flag": True,
                "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
                "chain_id_flag": False,
                "selector_flag": False,
                "amount_flag": False,
                "spender_flag": EIP712CalldataParamPresence.NONE,
            },
            {
                "index": 1,
                "handler": gcs_handler_interleaved_second,
                "value_flag": True,
                "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
                "chain_id_flag": False,
                "selector_flag": False,
                "amount_flag": False,
                "spender_flag": EIP712CalldataParamPresence.NONE,
            },
        ],
        "fields": {
            "dataA": {"type": "calldata_value", "index": 0},
            "dataB": {"type": "calldata_value", "index": 1},
            "toA": {"type": "calldata_callee", "index": 0},
            "toB": {"type": "calldata_callee", "index": 1},
        },
    }

    signature = tip712_new_common(scenario_navigator, client, data, filters)
    assert recover_message(data, signature) == get_wallet_addr(client)


def test_tip712_zero_argument_call_with_separate_selector(
        scenario_navigator: NavigateWithScenario):
    """A separately filtered selector plus empty args remains a contract call."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    data = {
        "domain": {
            "verifyingContract": "TTcY7HWMs6jqQr2BPRnEKZZDF8FVLHJoYx",
            "chainId": 728126428,
        },
        "message": {
            "selector": "0x18160ddd",
            "data": "0x",
            "to": "TTVHrJWLPEMpsRJLs14bAZTpfXB5HBmNRa",
        },
        "primaryType": "SeparateSelectorCall",
        "types": {
            "EIP712Domain": [
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "SeparateSelectorCall": [
                {"name": "selector", "type": "bytes4"},
                {"name": "data", "type": "bytes"},
                {"name": "to", "type": "address"},
            ],
        },
    }
    filters = {
        "name": "Separate selector",
        "calldatas": [{
            "index": 0,
            "handler": gcs_handler_separate_selector,
            "value_flag": True,
            "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
            "chain_id_flag": False,
            "selector_flag": True,
            "amount_flag": False,
            "spender_flag": EIP712CalldataParamPresence.NONE,
        }],
        "fields": {
            "selector": {"type": "calldata_selector", "index": 0},
            "data": {"type": "calldata_value", "index": 0},
            "to": {"type": "calldata_callee", "index": 0},
        },
    }

    signature = tip712_new_common(scenario_navigator, client, data, filters)
    assert recover_message(data, signature) == get_wallet_addr(client)


def test_tip712_calldata_filtered_spender(
        scenario_navigator: NavigateWithScenario):
    """PRESENT_FILTERED spender descriptors accept their address field."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    with open(f"{tip712_json_path()}/safe_calldata_no_param.json",
              encoding="utf-8") as data_file:
        data = json.load(data_file)
    data["types"]["SafeTx"].append({"name": "spender", "type": "address"})
    data["message"]["spender"] = "TTcQoDJ881H3Aq3N6qYoKGjZfLNoFw4Jrh"
    filters = {
        "name": "Filtered spender",
        "calldatas": [{
            "index": 0,
            "handler": gcs_handler_no_param,
            "value_flag": True,
            "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
            "chain_id_flag": False,
            "selector_flag": False,
            "amount_flag": True,
            "spender_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
        }],
        "fields": {
            "to": {"type": "calldata_callee", "index": 0},
            "value": {"type": "calldata_amount", "index": 0},
            "data": {"type": "calldata_value", "index": 0},
            "spender": {"type": "calldata_spender", "index": 0},
        },
    }

    signature = tip712_new_common(scenario_navigator, client, data, filters)
    assert recover_message(data, signature) == get_wallet_addr(client)


def test_tip712_batch(
        scenario_navigator: NavigateWithScenario, test_name: str):
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    with open(f"{tip712_json_path()}/safe_batch.json", encoding="utf-8") as file:
        data = json.load(file)

    filters = {
        "name": "Calldata test",
        "calldatas": [
            {
                "index": 0,
                "handler": gcs_handler_batch,
                "value_flag": True,
                "callee_flag": EIP712CalldataParamPresence.PRESENT_FILTERED,
                "chain_id_flag": False,
                "selector_flag": False,
                "amount_flag": True,
                "spender_flag": EIP712CalldataParamPresence.NONE,
            },
        ],
        "fields": {
            "to": {
                "type": "calldata_callee",
                "index": 0,
            },
            "value": {
                "type": "calldata_amount",
                "index": 0,
            },
            "data": {
                "type": "calldata_value",
                "index": 0,
            },
            "operation": {
                "type": "raw",
                "name": "Operation type",
            },
            "baseGas": {
                "type": "raw",
                "name": "Gas amount",
            },
            "gasPrice": {
                "type": "raw",
                "name": "Gas price",
            },
            "gasToken": {
                "type": "raw",
                "name": "Gas token",
            },
            "refundReceiver": {
                "type": "trusted_name",
                "name": "Gas receiver",
                "tn_type": [TrustedNameType.ACCOUNT, TrustedNameType.CONTRACT,
                            TrustedNameType.TOKEN],
                "tn_source": [TrustedNameSource.CAL, TrustedNameSource.ENS,
                              TrustedNameSource.UD, TrustedNameSource.FN],
            },
        }
    }

    vrs = tip712_new_common(scenario_navigator, client, data, filters,
                            snapshots_dirname=test_name)

    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


def test_tip712_proxy(
        scenario_navigator: NavigateWithScenario, test_name: str):
    # Filtered TIP-712 where the descriptor targets a different address than the
    # domain's verifyingContract, resolved via provide_proxy_info. Mirrors
    # app-ethereum's test_eip712_proxy.
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    input_file = Path(input_files()[0])
    test_path = f"{input_file.parent}/{'-'.join(input_file.stem.split('-')[:-1])}"
    with open(input_file, encoding="utf-8") as file:
        data = json.load(file)
    with open(f"{test_path}-filter.json", encoding="utf-8") as file:
        filters = json.load(file)
    # Change its name & set a different address than the one in verifyingContract.
    filters["name"] = "Proxy test"
    filters["address"] = "TRXcKoEvHr6Y38VMcDYGBEYKznvH3XUX4g"

    proxy_info = ProxyInfo(
        get_challenge(client),
        to_tvm_address(data["domain"]["verifyingContract"]),
        int(data["domain"]["chainId"]),
        to_tvm_address(filters["address"]),
    )
    client.provide_proxy_info(proxy_info.serialize())

    vrs = tip712_new_common(scenario_navigator, client, data, filters,
                            snapshots_dirname=test_name)

    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


def test_tip712_rejects_message_info_before_domain_completion(
        backend: BackendInterface, monkeypatch: pytest.MonkeyPatch):
    client = TronClient(backend)
    with open(f"{tip712_json_path()}/00-simple_mail-data.json",
              encoding="utf-8") as file:
        data = json.load(file)
    with open(f"{tip712_json_path()}/00-simple_mail-filter.json",
              encoding="utf-8") as file:
        filters = json.load(file)
    original_send_struct_impl = InputData.send_struct_impl

    def send_premature_message_info(structs, values, structname):
        if structname == "EIP712Domain":
            first_field = structs[structname][0]
            assert InputData.evaluate_field(
                structs, values[first_field["name"]], first_field,
                len(first_field["array_lvls"]))
            InputData.send_filtering_message_info(
                filters["name"], len(InputData.filtering_paths))
            pytest.fail("incomplete domain unexpectedly accepted message-info")
        return original_send_struct_impl(structs, values, structname)

    monkeypatch.setattr(InputData, "send_struct_impl",
                        send_premature_message_info)
    with pytest.raises(ExceptionRAPDU) as error:
        InputData.process_data(client, data, filters,
                               client.getAccount(0)["path"])
    assert error.value.status == StatusWord.COMMAND_NOT_ALLOWED


def test_tip712_rejects_proxy_after_filter_context_lock(
        backend: BackendInterface, monkeypatch: pytest.MonkeyPatch):
    client = TronClient(backend)
    with open(f"{tip712_json_path()}/00-simple_mail-data.json",
              encoding="utf-8") as file:
        data = json.load(file)
    with open(f"{tip712_json_path()}/00-simple_mail-filter.json",
              encoding="utf-8") as file:
        filters = json.load(file)
    proxy = ProxyInfo(
        get_challenge(client),
        to_tvm_address(data["domain"]["verifyingContract"]),
        int(data["domain"]["chainId"]),
        to_tvm_address("TRXcKoEvHr6Y38VMcDYGBEYKznvH3XUX4g"),
    )
    original_message_info = InputData.send_filtering_message_info

    def send_message_info_then_proxy(display_name, filters_count):
        original_message_info(display_name, filters_count)
        client.provide_proxy_info(proxy.serialize())

    monkeypatch.setattr(InputData, "send_filtering_message_info",
                        send_message_info_then_proxy)
    with pytest.raises(ExceptionRAPDU) as error:
        InputData.process_data(client, data, filters,
                               client.getAccount(0)["path"])
    assert error.value.status == StatusWord.INVALID_DATA


def test_tip712_gondi(
        scenario_navigator: NavigateWithScenario, test_name: str):
    """Basic blind (unfiltered) TIP-712 signature over a nested struct/array
    payload. Mirrors app-ethereum's test_eip712_gondi."""
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    # Blind signing for the unfiltered payload.
    toggle_settings(backend, device, navigator, [SettingID.SIGN_BY_HASH])

    data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Root": [
                {"name": "child", "type": "Inner[]"},
            ],
            "Inner": [
                {"name": "child", "type": "Leaf"},
            ],
            "Leaf": [
                {"name": "value", "type": "uint256"},
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name": "DOMAIN",
            "version": "3.1",
            "chainId": 31337,
            "verifyingContract": "TPaNVXGh1G5uybcdsWDUqRJ1ped9VuYZRX",
        },
        "message": {
            "child": [
                {
                    "child": {
                        "value": 2,
                    },
                }
            ],
        }
    }

    vrs = tip712_new_common(scenario_navigator, client, data, None,
                            snapshots_dirname=test_name,
                            nb_warnings=1)

    addr = recover_message(data, vrs)
    assert addr == get_wallet_addr(client)


def test_tip712_bs_not_activated_error(
        scenario_navigator: NavigateWithScenario):
    # Blind signing is disabled by default, so an unfiltered payload must be
    # rejected. Mirrors app-ethereum's test_eip712_bs_not_activated_error.
    backend = scenario_navigator.backend
    device = scenario_navigator.backend.device
    navigator = scenario_navigator.navigator
    client = TronClient(backend, device, navigator)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        tip712_new_common(scenario_navigator, client,
                          ADVANCED_DATA_SETS[0].data, None,
                          nb_warnings=1)
    assert exc_info.value.status == InputData.StatusWord.INVALID_DATA


def test_tip712_filtering_freezes_schema(
        scenario_navigator: NavigateWithScenario):
    """Definitions accepted after activation would invalidate the cached schema hash."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    signing_path = client.getAccount(0)['path']

    with client.tip712_init_new(signing_path):
        pass
    with client.tip712_send_struct_def_struct_name("EIP712Domain"):
        pass
    with client.tip712_filtering_activate():
        pass

    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.tip712_send_struct_def_struct_name("Injected"):
            pass
    assert exc_info.value.status == StatusWord.COMMAND_NOT_ALLOWED


def test_tip712_full_requires_path_initialization(
        scenario_navigator: NavigateWithScenario):
    """Schema upload cannot begin before the signing path is locked."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)

    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.tip712_send_struct_def_struct_name("EIP712Domain"):
            pass
    assert exc_info.value.status == StatusWord.COMMAND_NOT_ALLOWED


def test_tip712_final_path_must_match_locked_path(
        scenario_navigator: NavigateWithScenario):
    """The final approval command cannot substitute another signing key."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    signing_path = client.getAccount(0)['path']
    different_path = "m/44'/195'/1'/0/0"

    assert InputData.process_data(client,
                                  ADVANCED_DATA_SETS[0].data,
                                  ADVANCED_DATA_SETS[0].filters,
                                  signing_path)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.tip712_sign_new(different_path):
            pass
    assert exc_info.value.status == StatusWord.INVALID_DATA


def test_tip712_filtering_rejects_chain_id_above_u64(
        scenario_navigator: NavigateWithScenario):
    """Filtering metadata must never bind a truncated uint256 domain chainId."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    input_dir = Path(tip712_json_path())

    with open(input_dir / "00-simple_mail-data.json", encoding="utf-8") as data_file:
        data = json.load(data_file)
    with open(input_dir / "00-simple_mail-filter.json", encoding="utf-8") as filter_file:
        filters = json.load(filter_file)

    data["domain"]["chainId"] = 1 << 64
    with pytest.raises(ExceptionRAPDU):
        InputData.process_data(client,
                               data,
                               filters,
                               client.getAccount(0)['path'])


def test_tip712_legacy_review_rejects_existing_full_context(
        scenario_navigator: NavigateWithScenario):
    """A hash-only review must never inherit a partially built full context."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    signing_path = client.getAccount(0)['path']

    with client.tip712_init_new(signing_path):
        pass
    with client.tip712_send_struct_def_struct_name("EIP712Domain"):
        pass
    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.tip712_sign_legacy(signing_path,
                                       bytes(32), bytes(32)):
            pass
    assert exc_info.value.status == StatusWord.COMMAND_NOT_ALLOWED

    # The rejected cross-mode command aborts the old session cleanly, so a new
    # full definition must be accepted without rebooting the app.
    with client.tip712_init_new(signing_path):
        pass
    with client.tip712_send_struct_def_struct_name("EIP712Domain"):
        pass


def test_tip712_definition_rejected_during_personal_message_reception(
        scenario_navigator: NavigateWithScenario):
    """TIP-712 cannot take ownership of tmpCtx during another chunked sign."""
    client = TronClient(scenario_navigator.backend,
                        scenario_navigator.backend.device,
                        scenario_navigator.navigator)
    path = pack_derivation_path(client.getAccount(0)['path'])
    first_chunk = (bytes([0xE0, 0x08, 0x00, 0x00, len(path) + 5]) +
                   path + (2).to_bytes(4, "big") + b"A")
    response = client.exchange_raw(first_chunk)
    assert response.status == StatusWord.OK

    signing_path = client.getAccount(0)['path']
    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.tip712_init_new(signing_path):
            pass
    assert exc_info.value.status == StatusWord.COMMAND_NOT_ALLOWED

    with client.tip712_init_new(signing_path):
        pass
    with client.tip712_send_struct_def_struct_name("EIP712Domain"):
        pass


def test_tip712_skip():
    pytest.skip("Skip action is not exposed by scenario_navigator")
