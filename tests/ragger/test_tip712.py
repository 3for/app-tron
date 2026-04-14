#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/ragger/test_tip712.py
'''
import pytest
import json
import fnmatch
import os

from functools import partial

from typing import Optional

from ragger.error import ExceptionRAPDU
from pathlib import Path
from Crypto.Hash import keccak
from inspect import currentframe
from tron import TronClient, CLA, InsType
from ragger.bip import pack_derivation_path
from utils import check_hash_signature

from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID, NavIns

from settings import settings_toggle, SettingID, get_device_settings
from client.command_builder import CommandBuilder
import response_parser as ResponseParser
from client.tip712 import InputData as InputData
from dataset import DataSet, ADVANCED_DATA_SETS, TOKENS, TRUSTED_NAMES, FILT_TN_TYPES
from utils import recover_message
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
                    moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
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
                      extra_left: bool = False):
    global autonext_idx
    global unfiltered_flow
    global skip_flow
    global snapshots_dirname
    global autonext_running

    autonext_idx = 0
    autonext_running = False
    default_screenshot_path = Path(__file__).parent.resolve()
    try:
        assert InputData.process_data(
            client, builder, json_data, filters,
            partial(autonext, device, navigator, default_screenshot_path),
            golden_run)

        with client.exchange_async_raw(
                builder.tip712_sign_new(client.getAccount(0)['path'])):
            warning_approve = unfiltered_flow
            if device.is_nano:
                nav_ins = NavInsID.RIGHT_CLICK
                val_ins = NavInsID.BOTH_CLICK
                text = "Accept risk and" if warning_approve else "Sign message"
            else:
                nav_ins = NavInsID.SWIPE_CENTER_TO_LEFT
                val_ins = NavInsID.USE_CASE_REVIEW_CONFIRM
                text = "Hold to sign"
            if snapshots_dirname is not None:
                client.navigate(
                    snapshots_dirname,
                    text,
                    warning_approve=warning_approve,
                    warning_instruction=NavInsID.USE_CASE_CHOICE_REJECT)
            else:
                if warning_approve:
                    if device.is_nano:
                        navigator.navigate(
                            [NavInsID.BOTH_CLICK],
                            screen_change_before_first_instruction=False)
                    else:
                        navigator.navigate(
                            [NavInsID.USE_CASE_CHOICE_REJECT],
                            screen_change_before_first_instruction=False)
                navigator.navigate_until_text(nav_ins, [val_ins], text)
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


@pytest.fixture(name="data_set", params=ADVANCED_DATA_SETS)
def data_set_fixture(request) -> DataSet:
    return request.param


@pytest.fixture(name="tokens", params=TOKENS)
def tokens_fixture(request) -> list[dict]:
    return request.param


@pytest.fixture(name="trusted_name", params=TRUSTED_NAMES)
def trusted_name_fixture(request) -> tuple:
    return request.param


@pytest.fixture(name="filt_tn_types", params=FILT_TN_TYPES)
def filt_tn_types_fixture(request) -> list[InputData.TrustedNameType]:
    return request.param


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
        from dataset import filtering_empty_array_test_data
        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder,
                                filtering_empty_array_test_data['data'],
                                filtering_empty_array_test_data['filters'],
                                False, golden_run)

        addr = recover_message(filtering_empty_array_test_data['data'], vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_advanced_missing_token(
            self, device: Device, backend: BackendInterface,
            navigator: Navigator, default_screenshot_path: Path,
            test_name: str, tokens: list[dict], golden_run: bool):
        global snapshots_dirname

        test_name += "-%s-%s" % (len(tokens[0]) == 0, len(tokens[1]) == 0)
        snapshots_dirname = test_name

        client = TronClient(backend, device, navigator)

        from dataset import advanced_missing_token_test_data
        advanced_missing_token_test_data['filters']['tokens'] = tokens
        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder,
                                advanced_missing_token_test_data['data'],
                                advanced_missing_token_test_data['filters'],
                                False, golden_run)

        addr = recover_message(advanced_missing_token_test_data['data'], vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_advanced_trusted_name(
            self, device: Device, backend: BackendInterface,
            navigator: Navigator, default_screenshot_path: Path,
            test_name: str, trusted_name: tuple,
            filt_tn_types: list[InputData.TrustedNameType], golden_run: bool):
        global snapshots_dirname
        test_name += f"_{trusted_name[0].name.lower()}_with"
        for trusted_name_type in filt_tn_types:
            test_name += f"_{trusted_name_type.name.lower()}"
        snapshots_dirname = test_name

        client = TronClient(backend, device, navigator)

        cmd_builder = CommandBuilder()
        if trusted_name[0] is InputData.TrustedNameType.ACCOUNT:
            challenge = ResponseParser.challenge(
                client.exchange_raw(cmd_builder.get_challenge()).data)
        else:
            challenge = None

        from dataset import advanced_trusted_name_test_data
        advanced_trusted_name_test_data['filters']['fields']['validator'][
            'tn_type'] = filt_tn_types

        InputData.provide_trusted_name_v2(
            client,
            cmd_builder,
            bytes.fromhex(advanced_trusted_name_test_data['data']["message"]
                          ["validator"][2:]),
            trusted_name[2],
            trusted_name[0],
            trusted_name[1],
            advanced_trusted_name_test_data['data']["domain"]["chainId"],
            challenge=challenge)

        vrs = tip712_new_common(device, navigator, default_screenshot_path,
                                client, cmd_builder,
                                advanced_trusted_name_test_data['data'],
                                advanced_trusted_name_test_data['filters'],
                                False, golden_run)

        addr = recover_message(advanced_trusted_name_test_data['data'], vrs)
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
