#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/ragger/test_tip712.py
'''
import pytest
import json
import fnmatch
import os
import web3
import hashlib

from ctypes import c_uint64
from functools import partial

from typing import Optional, Callable

from ragger.error import ExceptionRAPDU
from pathlib import Path
from Crypto.Hash import keccak
from inspect import currentframe
from client.command_builder import CLA, InsType
from tron import TronClient
from ragger.bip import pack_derivation_path
from utils import check_hash_signature

from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID, NavIns

from settings import settings_toggle, SettingID, get_device_settings
from client.command_builder import CommandBuilder
import response_parser as ResponseParser
from client.tip712 import InputData as InputData, EIP712CalldataParamPresence
from client.trusted_name import TrustedName, TrustedNameType, TrustedNameSource
from client.gating import Gating
from client.status_word import StatusWord
from client.proxy_info import ProxyInfo
from client.gcs import (Field, ParamRaw, Value, TypeFamily, DataPath, PathTuple,
                        ParamTokenAmount, ParamCalldata, ContainerPath, PathLeaf,
                        PathLeafType, TxInfo)
from utils import recover_message, get_selector_from_data
from test_gcs import compute_inst_hash, ABIS_FOLDER
from fields_utils import get_all_paths, get_all_tuple_array_paths
from ledgered.devices import Device, DeviceType
from ragger.firmware.touch.positions import POSITIONS

autonext_idx: int
snapshots_dirname: Optional[str] = None
WALLET_ADDR: Optional[bytes] = None
unfiltered_flow: bool = False
skip_flow: bool = False
autonext_running: bool = False


def autonext(device: Device, navigator: Navigator,
             default_screenshot_path: Path):
    global autonext_idx
    global autonext_running

    if autonext_running:
        return
    autonext_running = True

    try:
        moves = []
        if device.is_nano:
            if autonext_idx == 0 and unfiltered_flow:
                moves = [NavInsID.BOTH_CLICK]
            else:
                moves = [NavInsID.RIGHT_CLICK]
        else:
            if autonext_idx == 0 and unfiltered_flow:
                moves = [NavInsID.USE_CASE_CHOICE_REJECT]
            else:
                if autonext_idx == 2 and skip_flow:
                    InputData.disable_autonext()
                    moves = [
                        NavIns(NavInsID.TOUCH,
                               POSITIONS["RightHeader"][device.type]),
                        NavInsID.USE_CASE_CHOICE_CONFIRM,
                    ]
                else:
                    moves = [NavInsID.USE_CASE_REVIEW_TAP]
        if snapshots_dirname is not None:
            navigator.navigate_and_compare(
                default_screenshot_path,
                snapshots_dirname,
                moves,
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
                snap_start_idx=autonext_idx)
        else:
            navigator.navigate(moves,
                               screen_change_before_first_instruction=False,
                               screen_change_after_last_instruction=False)
        autonext_idx += len(moves)
    finally:
        autonext_running = False


def tip712_new_common(device: Device,
                      navigator,
                      default_screenshot_path: Path,
                      client: TronClient,
                      builder: CommandBuilder,
                      json_data: dict,
                      filters,
                      verbose_raw: bool,
                      golden_run: bool,
                      extra_left: bool = False,
                      gating_params: Optional[Gating] = None):
    global autonext_idx
    global unfiltered_flow
    global skip_flow
    global snapshots_dirname
    global autonext_running

    autonext_idx = 0
    autonext_running = False
    default_screenshot_path = Path(__file__).parent.resolve()
    try:
        # Mirrors app-ethereum's schema-hash selector for typed-data gating. The
        # gating prelude is shown on every device (nano included, like app-ethereum),
        # so it always adds one more warning page on top of the blind-signing one.
        nb_warnings = 1 if unfiltered_flow else 0
        if gating_params is not None:
            InputData.init_signature_context(json_data["types"], json_data["domain"])
            gating_params.selector = bytes(InputData.sig_ctx["schema_hash"])
            nb_warnings += 1

        assert InputData.process_data(
            client, json_data, filters,
            partial(autonext, device, navigator, default_screenshot_path),
            golden_run)

        if gating_params is not None:
            assert client.provide_gating(gating_params.serialize()).status == StatusWord.OK

        with client.exchange_async_raw(
                builder.tip712_sign_new(client.getAccount(0)['path'])):
            warning_approve = unfiltered_flow
            warning_ins = NavInsID.USE_CASE_CHOICE_CONFIRM
            if device.is_nano:
                nav_ins = NavInsID.RIGHT_CLICK
                val_ins = NavInsID.BOTH_CLICK
                text = "Accept risk and" if warning_approve else "Sign message"
            else:
                nav_ins = NavInsID.USE_CASE_REVIEW_TAP
                val_ins = NavInsID.USE_CASE_REVIEW_CONFIRM
                text = "Hold to sign"
                warning_ins = NavInsID.USE_CASE_CHOICE_REJECT
            if snapshots_dirname is not None:
                client.navigate(
                    snapshots_dirname,
                    text,
                    nb_warnings=nb_warnings,
                    warning_instruction=warning_ins)
            else:
                if nb_warnings > 0:
                    if device.is_nano:
                        warning_moves = [NavInsID.RIGHT_CLICK] * (nb_warnings - 1)
                        warning_moves += [NavInsID.BOTH_CLICK]
                    else:
                        warning_moves = [warning_ins] * nb_warnings
                    navigator.navigate(
                        warning_moves,
                        screen_change_before_first_instruction=False)
                navigator.navigate_until_text(
                    nav_ins,
                    [val_ins],
                    text,
                    screen_change_before_first_instruction=(nb_warnings == 0))
    finally:
        InputData.disable_autonext()
        unfiltered_flow = False
        skip_flow = False
        snapshots_dirname = None

    return ResponseParser.signature(client._client.last_async_response.data)


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
            client._client.last_async_response.data)
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
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
                "version": "1"
            },
            "message": {
                "with": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                "value_recv": 10000000000000000,
                "token_send": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                "value_send": 24500000000000000000,
                "token_recv": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
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
                    "addr": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    "ticker": "WETH",
                    "decimals": 18,
                    "chain_id": 728126428,
                },
                {
                    "addr": "0x6b175474e89094c44da98b954eedeac495271d0f",
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
                "verifyingContract": "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
                "chainId": 728126428,
            },
            "message": {
                "owner": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                "spender": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
                "value": 4200000000000000000,
                "nonce": 0,
                "deadline": 1719756000,
            }
        },
        {
            "name": "Permit filtering",
            "tokens": [
                {
                    "addr": "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
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
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "chainId": 728126428,
            },
            "message": {
                "token_big": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "value_big": c_uint64(-1).value,
                "token_biggest": "0x6b175474e89094c44da98b954eedeac495271d0f",
                "value_biggest": int(web3.constants.MAX_INT, 0),
            }
        },
        {
            "name": "Unlimited test",
            "tokens": [
                {
                    "addr": "0x6b175474e89094c44da98b954eedeac495271d0f",
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
            "addr": "0x1111111111111111111111111111111111111111",
            "ticker": "SRC",
            "decimals": 18,
            "chain_id": 728126428,
        },
        {},
    ],
    [
        {},
        {
            "addr": "0x2222222222222222222222222222222222222222",
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


def _get_challenge(client: TronClient) -> int:
    return ResponseParser.challenge(
        client.exchange_raw(CommandBuilder().get_challenge()).data)


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
        bytes.fromhex(json_data["message"]["to"][2:]),
        get_selector_from_data(json_data["message"]["data"]),
        inst_hash,
        "Token transfer",
        contract_name="USDC",
    )
    client.provide_token_metadata(tx_info.contract_name, tx_info.contract_addr, 6, tx_info.chain_id)

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
            web3.Web3.to_wei(0, "ether"),
            tokenData0
        ),
        (
            tokens[1]["address"],
            web3.Web3.to_wei(0, "ether"),
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
        bytes.fromhex(json_data["domain"]["verifyingContract"][2:]),
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
        _get_challenge(client),
        bytes.fromhex(json_data["message"]["to"][2:]),
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
        bytes.fromhex(json_data["message"]["to"][2:]),
        get_selector_from_data(json_data["message"]["data"]),
        hashlib.sha3_256().digest(),
        "get total supply",
        creator_name="WETH",
        creator_legal_name="Wrapped Ether",
        creator_url="weth.io",
    )

    client.provide_transaction_info(tx_info.serialize())


@pytest.mark.usefixtures('configuration')
class TestTRX():

    def test_trx_sign_tip712(self, backend, device, navigator):
        client = TronClient(backend, device, navigator)
        domainHash = bytes.fromhex(
            '6137beb405d9ff777172aa879e33edb34a1460e701802746c5ef96e741710e59')
        messageHash = bytes.fromhex(
            'eb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8')
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += domainHash
        data += messageHash

        with backend.exchange_async(CLA, InsType.SIGN_TIP_712_MESSAGE, 0x00,
                                    0x00, data):
            if device.is_nano:
                text = "Sign message"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        sign_magic = b'\x19\x01'
        msg_to_sign = sign_magic + domainHash + messageHash
        digest = keccak.new(digest_bits=256, data=msg_to_sign).digest()

        assert check_hash_signature(digest, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_tip712_new(self, device: Device,
                            backend: BackendInterface, navigator: Navigator,
                            default_screenshot_path: Path,
                            tip712_case: tuple[Path, bool], verbose_raw: bool,
                            golden_run: bool, test_name: str):
        global unfiltered_flow
        global snapshots_dirname

        settings_to_toggle: list[SettingID] = []
        client = TronClient(backend, device, navigator)
        input_file, filtering = tip712_case

        test_path = f"{input_file.parent}/{'-'.join(input_file.stem.split('-')[:-1])}"
        cmd_builder = CommandBuilder()

        test_name += '-' + input_file.stem + '-' + f"{verbose_raw}" + '-' + f"{filtering}"
        snapshots_dirname = test_name

        filters = None
        if filtering:
            try:
                filterfile = Path(f"{test_path}-filter.json")
                with open(filterfile, encoding="utf-8") as f:
                    filters = json.load(f)
            except (IOError, json.decoder.JSONDecodeError) as e:
                pytest.skip(f"{filterfile.name}: {e.strerror}")

        if verbose_raw:
            settings_to_toggle.append(SettingID.VERBOSE_TIP712)

        if not filters or verbose_raw:
            unfiltered_flow = True
        try:
            if len(settings_to_toggle) > 0:
                if device.is_nano:
                    settings_toggle_from_current_nano_home(
                        backend, device, navigator, settings_to_toggle)
                else:
                    settings_toggle(device, navigator, settings_to_toggle)

            with open(input_file, encoding="utf-8") as file:
                data = json.load(file)
                extra_left = test_path.endswith(
                    '01-addresses_array_mail'
                ) and verbose_raw and filters is None
                vrs = tip712_new_common(device,
                                        navigator,
                                        default_screenshot_path,
                                        client,
                                        cmd_builder,
                                        data,
                                        filters,
                                        verbose_raw,
                                        golden_run,
                                        extra_left=extra_left)
                recovered_addr = recover_message(data, vrs)

            assert recovered_addr == get_wallet_addr(client)
        finally:
            if len(settings_to_toggle) > 0:
                if device.is_nano:
                    settings_toggle_from_current_nano_home(
                        backend, device, navigator, settings_to_toggle)
                else:
                    settings_toggle(device, navigator, settings_to_toggle)

    def test_trx_tip712_advanced_filtering(self, device: Device,
                                           backend: BackendInterface,
                                           navigator: Navigator,
                                           default_screenshot_path: Path,
                                           test_name: str, data_set: DataSet,
                                           golden_run: bool):
        global snapshots_dirname

        client = TronClient(backend, device, navigator)
        cmd_builder = CommandBuilder()
        snapshots_dirname = test_name + data_set.suffix

        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data_set.data,
                                data_set.filters, False, golden_run)
        recovered_addr = recover_message(data_set.data, vrs)
        assert client.getAccount(
            0)['addressHex'][2:] == recovered_addr.hex().upper()

        assert recovered_addr == get_wallet_addr(client)

    def test_trx_tip712_filtering_empty_array(self, device: Device,
                                              backend: BackendInterface,
                                              navigator: Navigator,
                                              default_screenshot_path: Path,
                                              test_name: str,
                                              golden_run: bool):
        global snapshots_dirname

        client = TronClient(backend, device, navigator)

        snapshots_dirname = test_name

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
                "verifyingContract": "0x0000000000000000000000000000000000000000",
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

        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, filters,
                                False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_advanced_missing_token(
            self, device: Device, backend: BackendInterface,
            navigator: Navigator, default_screenshot_path: Path,
            test_name: str, tokens: list[dict], golden_run: bool):
        global snapshots_dirname

        test_name += "-%s-%s" % (len(tokens[0]) == 0, len(tokens[1]) == 0)
        snapshots_dirname = test_name

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
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "chainId": 728126428,
            },
            "message": {
                "token_from": "0x1111111111111111111111111111111111111111",
                "value_from": web3.Web3.to_wei(3.65, "ether"),
                "token_to": "0x2222222222222222222222222222222222222222",
                "value_to": web3.Web3.to_wei(15.47, "ether"),
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

        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, filters,
                                False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_advanced_trusted_name(
            self, device: Device, backend: BackendInterface,
            navigator: Navigator, default_screenshot_path: Path,
            test_name: str, trusted_name: tuple,
            filt_tn_types: list[TrustedNameType], golden_run: bool):
        global snapshots_dirname
        test_name += f"_{trusted_name[0].name.lower()}_with"
        for trusted_name_type in filt_tn_types:
            test_name += f"_{trusted_name_type.name.lower()}"
        snapshots_dirname = test_name

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
                "verifyingContract": "0x0000000000000000000000000000000000000000",
                "chainId": 728126428,
            },
            "message": {
                "validator": "0x1111111111111111111111111111111111111111",
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

        cmd_builder = CommandBuilder()
        if trusted_name[0] is TrustedNameType.ACCOUNT:
            challenge = ResponseParser.challenge(
                client.exchange_raw(cmd_builder.get_challenge()).data)
        else:
            challenge = None

        client.provide_trusted_name(
            TrustedName(
                2,
                bytes.fromhex(data["message"]["validator"][2:]),
                trusted_name[2],
                tn_type=trusted_name[0],
                tn_source=trusted_name[1],
                chain_id=data["domain"]["chainId"],
                challenge=challenge))

        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, filters,
                                False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def _tip712_calldata_common(self, device: Device,
                                backend: BackendInterface, navigator: Navigator,
                                default_screenshot_path: Path, test_name: str,
                                golden_run: bool, filename: str,
                                handler: Optional[Callable] = None):
        global snapshots_dirname

        client = TronClient(backend, device, navigator)
        snapshots_dirname = test_name

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

        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, filters,
                                False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_calldata(self, device: Device,
                                 backend: BackendInterface, navigator: Navigator,
                                 default_screenshot_path: Path, test_name: str,
                                 golden_run: bool):
        self._tip712_calldata_common(device, backend, navigator,
                                     default_screenshot_path, test_name,
                                     golden_run, "safe", gcs_handler)

    def test_trx_tip712_calldata_empty_send(self, device: Device,
                                            backend: BackendInterface,
                                            navigator: Navigator,
                                            default_screenshot_path: Path,
                                            test_name: str, golden_run: bool):
        client = TronClient(backend, device, navigator)
        filename = "safe_empty"

        with open(f"{tip712_json_path()}/{filename}.json", encoding="utf-8") as file:
            json_data = json.load(file)

        client.provide_trusted_name(
            TrustedName(2,
                        bytes.fromhex(json_data["message"]["to"][2:]),
                        "MAB_addr",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                        chain_id=json_data["domain"]["chainId"],
                        challenge=_get_challenge(client),
                        owner=bytes.fromhex(client.getAccount(0)["addressHex"])[1:],
                        owner_deriv_path=client.getAccount(0)["path"]))
        self._tip712_calldata_common(device, backend, navigator,
                                     default_screenshot_path, test_name,
                                     golden_run, filename)

    def test_trx_tip712_calldata_no_param(self, device: Device,
                                          backend: BackendInterface,
                                          navigator: Navigator,
                                          default_screenshot_path: Path,
                                          test_name: str, golden_run: bool):
        self._tip712_calldata_common(device, backend, navigator,
                                     default_screenshot_path, test_name,
                                     golden_run, "safe_calldata_no_param",
                                     gcs_handler_no_param)

    def test_trx_tip712_batch(self, device: Device,
                              backend: BackendInterface, navigator: Navigator,
                              default_screenshot_path: Path, test_name: str,
                              golden_run: bool):
        global snapshots_dirname

        client = TronClient(backend, device, navigator)
        snapshots_dirname = test_name

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

        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, filters,
                                False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_proxy(self, device: Device,
                              backend: BackendInterface, navigator: Navigator,
                              default_screenshot_path: Path, test_name: str,
                              golden_run: bool):
        # Filtered TIP-712 where the descriptor targets a different address than the
        # domain's verifyingContract, resolved via provide_proxy_info. Mirrors
        # app-ethereum's test_eip712_proxy.
        global snapshots_dirname

        client = TronClient(backend, device, navigator)
        snapshots_dirname = test_name

        input_file = Path(input_files()[0])
        test_path = f"{input_file.parent}/{'-'.join(input_file.stem.split('-')[:-1])}"
        with open(input_file, encoding="utf-8") as file:
            data = json.load(file)
        with open(f"{test_path}-filter.json", encoding="utf-8") as file:
            filters = json.load(file)
        # Change its name & set a different address than the one in verifyingContract.
        filters["name"] = "Proxy test"
        filters["address"] = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        cmd_builder = CommandBuilder()
        proxy_info = ProxyInfo(
            _get_challenge(client),
            bytes.fromhex(data["domain"]["verifyingContract"][2:]),
            int(data["domain"]["chainId"]),
            bytes.fromhex(filters["address"][2:]),
        )
        client.provide_proxy_info(proxy_info.serialize())

        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, filters,
                                False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_gondi(self, device: Device,
                              backend: BackendInterface, navigator: Navigator,
                              default_screenshot_path: Path, test_name: str,
                              golden_run: bool):
        """Basic blind (unfiltered) TIP-712 signature over a nested struct/array
        payload. Mirrors app-ethereum's test_eip712_gondi. Blind signing
        (SettingID.SIGN_BY_HASH) is already enabled by the `configuration` fixture."""
        global unfiltered_flow
        global snapshots_dirname

        client = TronClient(backend, device, navigator)
        snapshots_dirname = test_name

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
                "verifyingContract": "0x95401dc811bb5740090279ba06cfa8fcf6113778",
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

        unfiltered_flow = True
        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, None, False, golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_bs_not_activated_error(self, device: Device,
                                               backend: BackendInterface,
                                               navigator: Navigator,
                                               default_screenshot_path: Path):
        client = TronClient(backend, device, navigator)

        setting_id = SettingID.SIGN_BY_HASH
        if device.is_nano:
            settings_toggle_from_current_nano_home(backend, device, navigator,
                                                   [setting_id])
        else:
            settings_toggle(device, navigator, [setting_id])
        cmd_builder = CommandBuilder()
        with pytest.raises(ExceptionRAPDU) as exc_info:
            tip712_new_common(device, navigator, default_screenshot_path,
                              client, cmd_builder, ADVANCED_DATA_SETS[0].data,
                              None, False, False)
        InputData.disable_autonext()
        assert exc_info.value.status == InputData.StatusWord.INVALID_DATA

        if device.is_nano:
            navigator.navigate([NavInsID.BOTH_CLICK],
                               screen_change_before_first_instruction=True)
        elif device.type == DeviceType.STAX:
            navigator.navigate([NavIns(NavInsID.TOUCH, (100, 620))],
                               screen_change_before_first_instruction=True)
        elif device.type == DeviceType.FLEX:
            navigator.navigate([NavIns(NavInsID.TOUCH, (130, 550))],
                               screen_change_before_first_instruction=True)
        elif device.type == DeviceType.APEX_P:
            navigator.navigate([NavIns(NavInsID.TOUCH, (100, 350))],
                               screen_change_before_first_instruction=True)
        if device.is_nano:
            settings_toggle_from_current_nano_home(backend, device, navigator,
                                                   [setting_id])
        else:
            settings_toggle(device, navigator, [setting_id])

    def test_trx_tip712_skip(self, device: Device,
                             backend: BackendInterface, navigator: Navigator,
                             default_screenshot_path: Path, test_name: str,
                             golden_run: bool):
        global unfiltered_flow
        global skip_flow

        client = TronClient(backend, device, navigator)
        if device.is_nano:
            pytest.skip("Not supported on Nano devices")

        unfiltered_flow = True
        skip_flow = True

        with open(input_files()[0], encoding="utf-8") as file:
            data = json.load(file)

        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder, data, None, False,
                                golden_run)

        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)
