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
AMOUNT = 1.22


def common(firmware: Firmware,
           app_client: TronClient,
           cmd_builder: CommandBuilder,
           get_challenge: bool = True) -> Optional[int]:
    if get_challenge:
        challenge = app_client.exchange_raw(cmd_builder.get_challenge())
        return ResponseParser.challenge(challenge.data)
    return None

def test_trusted_name_v1(firmware: Firmware, navigator: Navigator,
                         scenario_navigator: NavigateWithScenario,
                         test_name: str):
    backend = scenario_navigator.backend
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

    app_client.sign_for_trusted_name(app_client.getAccount(0)['path'], {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": ADDR,
        "value": Web3.to_wei(AMOUNT, "ether"),
        "chainId": CHAIN_ID
    },
                                     test_name,
                                     end_text,
                                     warning_approve=True)


