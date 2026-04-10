from typing import Optional
import pytest
from web3 import Web3

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario

import response_parser as ResponseParser
from tron import TronClient
from client.tip712.InputData import StatusWord, TrustedNameType, TrustedNameSource
from settings import SettingID, settings_toggle
from client.command_builder import CommandBuilder
from client.tip712 import InputData as InputData

# Values used across all tests
CHAIN_ID = 1151668124
NAME = "ledger.eth"
ADDR = bytes.fromhex("0011223344556677889900112233445566778899")
KEY_ID = 1
ALGO_ID = 1
NONCE = 21
GAS_PRICE = 13
GAS_LIMIT = 21000
# TRX, decimal 10^6
AMOUNT = 1_220_000


def common(firmware: Firmware,
           app_client: TronClient,
           cmd_builder: CommandBuilder,
           get_challenge: bool = True) -> Optional[int]:
    if get_challenge:
        challenge = app_client.exchange_raw(cmd_builder.get_challenge())
        return ResponseParser.challenge(challenge.data)
    return None


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v1(firmware: Firmware, backend: BackendInterface,
                         navigator: Navigator,
                         scenario_navigator: NavigateWithScenario,
                         test_name: str):
    app_client = TronClient(backend, firmware, navigator)
    device = backend.device
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR, NAME,
                                      challenge)

    end_text = None
    if firmware.is_nano:
        end_text = "Sign"
    else:
        end_text = "Hold to sign"

    app_client.sign_for_trusted_name(
        app_client.getAccount(0)['path'], {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name, end_text)


def test_trusted_name_v1_wrong_challenge(firmware: Firmware,
                                         backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR, NAME,
                                          ~challenge & 0xffffffff)
    assert e.value.status == StatusWord.INVALID_DATA


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v1_wrong_addr(firmware: Firmware,
                                    backend: BackendInterface,
                                    navigator: Navigator,
                                    scenario_navigator: NavigateWithScenario,
                                    test_name: str):
    app_client = TronClient(backend, firmware, navigator)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR, NAME,
                                      challenge)

    addr = bytearray(ADDR)
    addr.reverse()

    end_text = None
    if firmware.is_nano:
        end_text = "Sign"
    else:
        end_text = "Hold to sign"

    app_client.sign_for_trusted_name(
        app_client.getAccount(0)['path'], {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": bytes(addr),
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name, end_text)


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v1_non_mainnet(firmware: Firmware,
                                     backend: BackendInterface,
                                     navigator: Navigator,
                                     scenario_navigator: NavigateWithScenario,
                                     test_name: str):
    app_client = TronClient(backend, firmware, navigator)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR, NAME,
                                      challenge)

    end_text = None
    if firmware.is_nano:
        end_text = "Sign"
    else:
        end_text = "Hold to sign"
    app_client.sign_for_trusted_name(
        app_client.getAccount(0)['path'], {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": 5
        }, test_name, end_text)


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v1_unknown_chain(
        firmware: Firmware, backend: BackendInterface, navigator: Navigator,
        scenario_navigator: NavigateWithScenario, test_name: str):
    app_client = TronClient(backend, firmware, navigator)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR, NAME,
                                      challenge)

    end_text = None
    if firmware.is_nano:
        end_text = "Sign"
    else:
        end_text = "Hold to sign"
    app_client.sign_for_trusted_name(
        app_client.getAccount(0)['path'], {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": 9
        }, test_name, end_text)


def test_trusted_name_v1_name_too_long(firmware: Firmware,
                                       backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR,
                                          "ledger" + "0" * 25 + ".eth",
                                          challenge)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_name_invalid_character(firmware: Firmware,
                                                backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR,
                                          "l\xe8dger.eth", challenge)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_uppercase(firmware: Firmware,
                                   backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR,
                                          NAME.upper(), challenge)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_name_non_ens(firmware: Firmware,
                                      backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v1(app_client, cmd_builder, ADDR,
                                          "ledger.hte", challenge)
    assert e.value.status == StatusWord.INVALID_DATA


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v2(firmware: Firmware, backend: BackendInterface,
                         navigator: Navigator,
                         scenario_navigator: NavigateWithScenario,
                         test_name: str):
    app_client = TronClient(backend, firmware, navigator)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    InputData.provide_trusted_name_v2(app_client,
                                      cmd_builder,
                                      ADDR,
                                      NAME,
                                      TrustedNameType.ACCOUNT,
                                      TrustedNameSource.ENS,
                                      CHAIN_ID,
                                      challenge=challenge)

    end_text = None
    if firmware.is_nano:
        end_text = "Sign"
    else:
        end_text = "Hold to sign"

    app_client.sign_for_trusted_name(
        app_client.getAccount(0)['path'], {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name, end_text)


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v2_wrong_chainid(
        firmware: Firmware, backend: BackendInterface, navigator: Navigator,
        scenario_navigator: NavigateWithScenario, test_name: str):
    app_client = TronClient(backend, firmware, navigator)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)
    InputData.provide_trusted_name_v2(app_client,
                                      cmd_builder,
                                      ADDR,
                                      NAME,
                                      TrustedNameType.ACCOUNT,
                                      TrustedNameSource.ENS,
                                      CHAIN_ID,
                                      challenge=challenge)
    end_text = None
    if firmware.is_nano:
        end_text = "Sign"
    else:
        end_text = "Hold to sign"
    app_client.sign_for_trusted_name(
        app_client.getAccount(0)['path'], {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID + 1,
        }, test_name, end_text)


def test_trusted_name_v2_missing_challenge(firmware: Firmware,
                                           backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    common(firmware, app_client, cmd_builder, False)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v2(app_client, cmd_builder, ADDR, NAME,
                                          TrustedNameType.ACCOUNT,
                                          TrustedNameSource.ENS, CHAIN_ID)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_expired(firmware: Firmware,
                                 backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v2(app_client,
                                          cmd_builder,
                                          ADDR,
                                          NAME,
                                          TrustedNameType.ACCOUNT,
                                          TrustedNameSource.ENS,
                                          CHAIN_ID,
                                          challenge=challenge,
                                          not_valid_after=(0, 1, 2))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_account_name(firmware: Firmware,
                                          backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)
    owner_path = app_client.getAccount(0)["path"]
    owner = bytes.fromhex(app_client.getAccount(0)["addressHex"][2:])

    rapdu = InputData.provide_trusted_name_v2(app_client,
                                              cmd_builder,
                                              ADDR,
                                              "MyLedger",
                                              TrustedNameType.ACCOUNT,
                                              TrustedNameSource.MAB,
                                              CHAIN_ID,
                                              challenge=challenge,
                                              owner=owner,
                                              owner_deriv_path=owner_path)
    assert rapdu.status == StatusWord.OK


def test_trusted_name_v2_mab_missing_owner_metadata(firmware: Firmware,
                                                    backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v2(app_client,
                                          cmd_builder,
                                          ADDR,
                                          "MyLedger",
                                          TrustedNameType.ACCOUNT,
                                          TrustedNameSource.MAB,
                                          CHAIN_ID,
                                          challenge=challenge)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_wrong_owner(firmware: Firmware,
                                         backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)
    owner_path = app_client.getAccount(0)["path"]
    wrong_owner = bytes.fromhex(app_client.getAccount(1)["addressHex"][2:])

    with pytest.raises(ExceptionRAPDU) as e:
        InputData.provide_trusted_name_v2(app_client,
                                          cmd_builder,
                                          ADDR,
                                          "MyLedger",
                                          TrustedNameType.ACCOUNT,
                                          TrustedNameSource.MAB,
                                          CHAIN_ID,
                                          challenge=challenge,
                                          owner=wrong_owner,
                                          owner_deriv_path=owner_path)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_token_cal(firmware: Firmware,
                                   backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()

    rapdu = InputData.provide_trusted_name_v2(app_client,
                                              cmd_builder,
                                              ADDR,
                                              "USDT",
                                              TrustedNameType.TOKEN,
                                              TrustedNameSource.CAL,
                                              CHAIN_ID)
    assert rapdu.status == StatusWord.OK


def test_trusted_name_v2_multiple_names_same_session(firmware: Firmware,
                                                     backend: BackendInterface):
    app_client = TronClient(backend, firmware, None)
    cmd_builder = CommandBuilder()
    challenge = common(firmware, app_client, cmd_builder)

    rapdu = InputData.provide_trusted_name_v2(app_client,
                                              cmd_builder,
                                              ADDR,
                                              NAME,
                                              TrustedNameType.ACCOUNT,
                                              TrustedNameSource.ENS,
                                              CHAIN_ID,
                                              challenge=challenge)
    assert rapdu.status == StatusWord.OK

    rapdu = InputData.provide_trusted_name_v2(app_client,
                                              cmd_builder,
                                              ADDR,
                                              "USDT",
                                              TrustedNameType.TOKEN,
                                              TrustedNameSource.CAL,
                                              CHAIN_ID)
    assert rapdu.status == StatusWord.OK
