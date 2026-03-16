from typing import Optional
from Crypto.Hash import keccak
from pathlib import Path
from eth_keys import keys

from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.firmware import Firmware

from tron import TronClient, Errors, CLA, InsType, MAX_APDU_LEN
from client.tip712.InputData import StatusWord
import response_parser as ResponseParser

BIP32_PATH = "m/44'/195'/0'/0/0"


def common(scenario_navigator: NavigateWithScenario, test_name: str,
           firmware: Firmware, msg: str | bytes):

    backend = scenario_navigator.backend
    navigator = scenario_navigator.navigator
    app_client = TronClient(backend, firmware, navigator)

    with app_client.get_public_addr(display=False):
        pass
    _, DEVICE_ADDR, _ = ResponseParser.pk_addr(app_client.response().data)

    PUBLIC_ADDR = DEVICE_ADDR[1:]  # ETH format address
    if isinstance(msg, str):
        msg = msg.encode('ascii')

    try:
        with app_client.personal_sign_full_display(BIP32_PATH, msg):
            if firmware.is_nano:
                text = "message"
            else:
                text = "Hold to sign"
            app_client.navigate(test_name, text)

    except ExceptionRAPDU as err:
        assert False, f"Unexpected exception: {err}"

    # Magic define
    SIGN_MAGIC = b'\x19TRON Signed Message:\n'
    signedMessage = SIGN_MAGIC + str(len(msg)).encode() + msg
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(signedMessage)
    hash_to_sign = keccak_hash.digest()
    print(hash_to_sign.hex())

    # verify signature
    vrs = ResponseParser.signature(app_client.response().data)
    sig = keys.Signature(app_client.response().data)
    addr = sig.recover_public_key_from_msg_hash(hash_to_sign)

    assert addr.to_checksum_address().lower(
    ) == "0x" + PUBLIC_ADDR.hex().lower()


def test_personal_sign_metamask(scenario_navigator: NavigateWithScenario,
                                firmware: Firmware, test_name: str):

    msg = "Example `personal_sign` message"
    common(scenario_navigator, test_name, firmware, msg)


def test_personal_sign_non_ascii(scenario_navigator: NavigateWithScenario,
                                 firmware: Firmware, test_name: str):
    msg = bytes.fromhex(
        "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
    common(scenario_navigator, test_name, firmware, msg)


def test_personal_sign_opensea(scenario_navigator: NavigateWithScenario,
                               firmware: Firmware, test_name: str):

    msg = "Welcome to OpenSea!\n\n"
    msg += "Click to sign in and accept the OpenSea Terms of Service: https://opensea.io/tos\n\n"
    msg += "This request will not trigger a blockchain transaction or cost any gas fees.\n\n"
    msg += "Your authentication status will reset after 24 hours.\n\n"
    msg += "Wallet address:\n0x9858effd232b4033e47d90003d41ec34ecaeda94\n\nNonce:\n2b02c8a0-f74f-4554-9821-a28054dc9121"
    common(scenario_navigator, test_name, firmware, msg)


def test_personal_sign_reject(scenario_navigator: NavigateWithScenario,
                              firmware: Firmware, test_name: str):

    backend = scenario_navigator.backend
    navigator = scenario_navigator.navigator
    default_screenshot_path = Path(__file__).parent.resolve()
    app_client = TronClient(backend, firmware, navigator)

    msg = "This is an reject sign"
    try:
        with app_client.personal_sign_full_display(BIP32_PATH,
                                                   msg.encode('ascii')):
            scenario_navigator.review_reject(default_screenshot_path)

    except ExceptionRAPDU as e:
        assert e.status == StatusWord.CONDITION_NOT_SATISFIED
    else:
        assert False  # An exception should have been raised
