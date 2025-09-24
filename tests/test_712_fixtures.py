#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/test_trx.py
'''
from ledgered.devices import Device
from typing import Optional
from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns
import response_parser as ResponseParser
from pathlib import Path
from tron import TronClient, Errors, CLA, InsType, MAX_APDU_LEN
from client.command_builder import CommandBuilder
from settings import settings_toggle, SettingID
import fnmatch
import os
import json
from client.tip712 import InputData as InputData
import pytest
from utils import recover_message
from functools import partial
from ragger.firmware.touch.positions import POSITIONS


autonext_idx: int
snapshots_dirname: Optional[str] = None
WALLET_ADDR: Optional[bytes] = None
unfiltered_flow: bool = False
skip_flow: bool = False
def autonext(device: Device, navigator: Navigator,
             default_screenshot_path: Path):
    global autonext_idx

    moves = []
    if device.is_nano:
        moves = [NavInsID.RIGHT_CLICK]
    else:
        if autonext_idx == 0 and unfiltered_flow:
            moves = [NavInsID.USE_CASE_CHOICE_REJECT]
        else:
            if autonext_idx == 2 and skip_flow:
                InputData.disable_autonext()  # so the timer stops firing
                moves = [
                    # Ragger does not handle the skip button
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

def get_wallet_addr(client: TronClient) -> bytes:
    cmd_builder = CommandBuilder()
    global WALLET_ADDR
    # don't ask again if we already have it
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

def tip712_new_common_with_sort(device: Device,
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

    autonext_idx = 0
    default_screenshot_path = Path(__file__).parent.resolve()
    assert InputData.process_data(
        client, builder, json_data, filters,
        partial(autonext, device, navigator, default_screenshot_path),
        golden_run, sort = True)

    with client.exchange_async_raw(
            builder.tip712_sign_new(client.getAccount(0)['path'])):
        if device.is_nano:
            nav_ins = NavInsID.RIGHT_CLICK
            val_ins = NavInsID.BOTH_CLICK
            text = "and sign"  # need to match the text info of the last sign screen
        else:
            nav_ins = NavInsID.SWIPE_CENTER_TO_LEFT
            val_ins = NavInsID.USE_CASE_REVIEW_CONFIRM
            text = "Hold to sign"
        if snapshots_dirname is not None:
            navigator.navigate_until_text_and_compare(
                nav_ins, [val_ins],
                text,
                default_screenshot_path,
                snapshots_dirname,
                snap_start_idx=autonext_idx)
        else:
            navigator.navigate_until_text(nav_ins, [val_ins], text)
    # reset values
    unfiltered_flow = False
    skip_flow = False
    snapshots_dirname = None

    return ResponseParser.signature(client._client.last_async_response.data)

def tip712_json_path() -> str:
    return f"{os.path.dirname(__file__)}/fixtures/messages"

def input_files() -> list[str]:
    files = []
    for file in os.scandir(tip712_json_path()):
        if fnmatch.fnmatch(file, "*-data.json"):
            files.append(file.path)
    return sorted(files)
    # return ['/app/tests/tip712_input_files/01-addresses_array_mail-data.json']


@pytest.fixture(name="input_file", params=input_files())
def input_file_fixture(request) -> str:
    return Path(request.param)


@pytest.fixture(name="verbose_raw", params=[True, False])
def verbose_raw_fixture(request) -> bool:
    return request.param


@pytest.fixture(name="filtering", params=[False, True])
def filtering_fixture(request) -> bool:
    return request.param

def test_trx_712_legerlive_fixtures_with_sort(firmware: Firmware,
                            backend: BackendInterface, navigator: Navigator,
                            default_screenshot_path: Path, input_file: Path,
                            verbose_raw: bool, filtering: bool,
                            golden_run: bool, test_name: str):

        global unfiltered_flow
        global snapshots_dirname
        # snapshots_dirname = 'test_trx_tip712_new'
        settings_to_toggle: list[SettingID] = []
        client = TronClient(backend, firmware, navigator)
        device = backend.device

        test_path = f"{input_file.parent}/{'-'.join(input_file.stem.split('-')[:-1])}"
        cmd_builder = CommandBuilder()

        test_name += f"/" + input_file.stem + '-' + f"{verbose_raw}" + '-' + f"{filtering}"
        snapshots_dirname = test_name

        filters = None
        if filtering:
            try:
                filterfile = Path(f"{test_path}-filter.json")
                with open(filterfile, encoding="utf-8") as f:
                    filters = json.load(f)
            except (IOError, json.decoder.JSONDecodeError) as e:
                pytest.skip(f"{filterfile.name}: {e.strerror}")
        else:
            #pass
            settings_to_toggle.append(SettingID.SIGN_BY_HASH)

        if verbose_raw:
            setting_id = SettingID.VERBOSE_TIP712
            settings_to_toggle.append(setting_id)

        if not filters or verbose_raw:
            unfiltered_flow = True
        if len(settings_to_toggle) > 0:
            settings_toggle(device, navigator, settings_to_toggle)

        with open(input_file, encoding="utf-8") as file:
            data = json.load(file)
            extra_left = test_path.endswith(
                '01-addresses_array_mail') and verbose_raw and filters is None
            vrs = tip712_new_common_with_sort(
                device,
                navigator,
                default_screenshot_path,
                client,
                cmd_builder,
                data,
                filters,
                verbose_raw,
                golden_run,
                #False,
                extra_left=extra_left)
            recovered_addr = recover_message(data, vrs)

        assert recovered_addr == get_wallet_addr(client)
        if len(settings_to_toggle) > 0:
            settings_toggle(device, navigator, settings_to_toggle)
