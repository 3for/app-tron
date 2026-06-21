from typing import Optional
from pathlib import Path
import pytest
from web3 import Web3
from ledgered.devices import DeviceType
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID, NavIns
from ragger.navigator.navigation_scenario import NavigateWithScenario

import response_parser as ResponseParser
from tron import TronClient
from client.status_word import StatusWord
from client.trusted_name import TrustedName, TrustedNameType, TrustedNameSource
from client.command_builder import CommandBuilder
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

# Values used across all tests
CHAIN_ID = 728126428
NAME = "ledger.eth"
ADDR = bytes.fromhex("0011223344556677889900112233445566778899")
KEY_ID = 1
ALGO_ID = 1
NONCE = 21
GAS_PRICE = 13
GAS_LIMIT = 21000
# TRX, decimal 10^6
AMOUNT = 1_220_000
# ETH in slip-44
COIN_TYPE_ETH = 0x3c


NANO_TRANSACTION_SIGN_PATTERN = r"(?is)^sign( transaction.*)?$"


def common(app_client: TronClient,
           cmd_builder: CommandBuilder,
           get_challenge: bool = True) -> Optional[int]:
    if get_challenge:
        challenge = app_client.exchange_raw(cmd_builder.get_challenge())
        return ResponseParser.challenge(challenge.data)
    return None


def trusted_name_tx(app_client: TronClient, tx_params: dict) -> bytes:
    return app_client.packContract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(app_client.getAccount(0)['addressHex']),
            to_address=bytes.fromhex("41" + tx_params["to"].hex()),
            amount=tx_params["value"]))


def sign_trusted_name(scenario_navigator: NavigateWithScenario,
                      app_client: TronClient,
                      tx_params: dict,
                      test_name: str):
    custom_screen_text = (
        NANO_TRANSACTION_SIGN_PATTERN
        if scenario_navigator.device.is_nano
        else None)
    with app_client.sign_async(app_client.getAccount(0)['path'],
                               trusted_name_tx(app_client, tx_params)):
        scenario_navigator.review_approve(
            test_name=test_name,
            custom_screen_text=custom_screen_text)


def test_trusted_name_v1(scenario_navigator: NavigateWithScenario,
                         test_name: str):
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(1, ADDR, NAME, challenge=challenge,
                    coin_type=COIN_TYPE_ETH))

    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name)


def test_trusted_name_v1_verbose(navigator: Navigator,
                                 scenario_navigator: NavigateWithScenario,
                                 default_screenshot_path: Path,
                                 test_name: str):
    """Reveal the address behind the recipient trusted name (ENS alias) during review.

    Mirrors app-ethereum's test_trusted_name_v1_verbose: provide a v1 trusted name,
    then on the transaction review open the "To" field's ENS alias to show the
    underlying address (part1 snapshots), and finally approve (part2). Relies on the
    ENS alias affordance added to the transfer review (ui_review_menu_nbgl.c).

    The navigation moves below are device/layout specific (TRON shows Amount / To /
    From); they mirror app-ethereum and are validated/refreshed by the golden run.
    """
    backend = scenario_navigator.backend
    device = backend.device
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(1, ADDR, NAME, challenge=challenge,
                    coin_type=COIN_TYPE_ETH))

    tx_params = {
        "nonce": NONCE,
        "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
        "gas": GAS_LIMIT,
        "to": ADDR,
        "value": AMOUNT,
        "chainId": CHAIN_ID,
    }

    moves = []
    if device.is_nano:
        # Walk to the "To" field (intro -> From -> Amount -> To), open its alias to
        # view the address, then step back. Matches app-ethereum's From/Amount/To
        # layout (RIGHT_CLICK * 3 to reach the aliased "To" field).
        moves += [NavInsID.RIGHT_CLICK] * 3
        moves += [NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    else:
        # Swipe to the fields page, tap the alias ">" on the "To" row, then close it.
        moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
        ENS_POSITIONS = {
            DeviceType.FLEX: (428, 350),
            DeviceType.STAX: (360, 324),
            DeviceType.APEX_P: (272, 230),
        }
        moves += [NavIns(NavInsID.TOUCH, ENS_POSITIONS[device.type])]
        moves += [NavInsID.LEFT_HEADER_TAP]

    with app_client.sign_async(app_client.getAccount(0)['path'],
                               trusted_name_tx(app_client, tx_params)):
        navigator.navigate_and_compare(default_screenshot_path,
                                       f"{test_name}/part1",
                                       moves,
                                       screen_change_after_last_instruction=False)
        custom_screen_text = (
            NANO_TRANSACTION_SIGN_PATTERN
            if scenario_navigator.device.is_nano
            else None)
        scenario_navigator.review_approve(
            test_name=f"{test_name}/part2",
            custom_screen_text=custom_screen_text)


def test_trusted_name_v1_wrong_challenge(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR, NAME, challenge=~challenge & 0xffffffff,
                        coin_type=COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_wrong_addr(
                                    scenario_navigator: NavigateWithScenario,
                                    test_name: str):
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(1, ADDR, NAME, challenge=challenge,
                    coin_type=COIN_TYPE_ETH))

    addr = bytearray(ADDR)
    addr.reverse()

    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": bytes(addr),
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name)


def test_trusted_name_v1_non_mainnet(
                                     scenario_navigator: NavigateWithScenario,
                                     test_name: str):
    """v1 (chain-agnostic) trusted name on a non-mainnet chainId.

    Mirrors app-ethereum's test_trusted_name_v1_non_mainnet, but TRON is a
    single-chain app: a TransferContract carries no per-tx chainId, so the firmware
    always resolves trusted names against TRON mainnet (network.c get_tx_chain_id).
    The `chainId` below is therefore informational only -- the v1 name still applies
    (review shows "ledger.eth"), and there is no per-network "Network" row like
    app-ethereum's "Goerli" one (TRON has no per-transfer network/gas display).
    """
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(1, ADDR, NAME, challenge=challenge,
                    coin_type=COIN_TYPE_ETH))

    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": 5
        }, test_name)


def test_trusted_name_v1_unknown_chain(
        scenario_navigator: NavigateWithScenario, test_name: str):
    """v1 (chain-agnostic) trusted name with an unknown chainId.

    Mirrors app-ethereum's test_trusted_name_v1_unknown_chain. There, the unknown
    chainId is not Ethereum-compatible so the v1 name is rejected and the raw address
    is shown. On TRON this cannot happen: the firmware always resolves trusted names
    against TRON mainnet (a single, Ethereum-compatible chain; see network.c
    get_tx_chain_id / chain_is_ethereum_compatible), so the `chainId` below is ignored
    and the v1 name still applies (review shows "ledger.eth"). Kept for parity with
    app-ethereum's test matrix.
    """
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(1, ADDR, NAME, challenge=challenge,
                    coin_type=COIN_TYPE_ETH))

    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": 9
        }, test_name)


def test_trusted_name_v1_name_too_long(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR, "ledger" + "0" * 25 + ".eth",
                        challenge=challenge, coin_type=COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_name_invalid_character(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR, "l\xe8dger.eth", challenge=challenge,
                        coin_type=COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_uppercase(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR, NAME.upper(), challenge=challenge,
                        coin_type=COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v1_name_non_ens(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR, "ledger.hte", challenge=challenge,
                        coin_type=COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2(scenario_navigator: NavigateWithScenario,
                         test_name: str):
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(2, ADDR, NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID,
                    challenge=challenge))

    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name)


def test_trusted_name_v2_wrong_chainid(
        scenario_navigator: NavigateWithScenario, test_name: str):
    """v2 (chain-bound) trusted name whose chain does not match the signing chain.

    Mirrors app-ethereum's test_trusted_name_v2_wrong_chainid: a v2 name is only
    applied when its chain_id matches the transaction's chain, otherwise the raw
    address is shown. TRON always signs on mainnet (CHAIN_ID), and the firmware
    matches the name's chain_id against it (trusted_name.c matching_trusted_name),
    so binding the name to a *different* chain (CHAIN_ID + 1) is the TRON-equivalent
    mismatch: the name is rejected and the review shows the raw recipient address.
    """
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)
    app_client.provide_trusted_name(
        TrustedName(2, ADDR, NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID + 1,
                    challenge=challenge))
    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": Web3.to_wei(GAS_PRICE, "gwei"),
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID,
        }, test_name)


def test_trusted_name_v2_missing_challenge(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    common(app_client, cmd_builder, False)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR, NAME,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_expired(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR, NAME,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID,
                        challenge=challenge,
                        not_valid_after=(0, 1, 2)))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_account_name(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)
    owner_path = app_client.getAccount(0)["path"]
    owner = bytes.fromhex(app_client.getAccount(0)["addressHex"][2:])

    rapdu = app_client.provide_trusted_name(
        TrustedName(2, ADDR, "MyLedger",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=CHAIN_ID,
                    challenge=challenge,
                    owner=owner,
                    owner_deriv_path=owner_path))
    assert rapdu.status == StatusWord.OK


def test_trusted_name_v2_mab_missing_owner_metadata(
        backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR, "MyLedger",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                        chain_id=CHAIN_ID,
                        challenge=challenge))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_wrong_owner(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)
    owner_path = app_client.getAccount(0)["path"]
    wrong_owner = bytes.fromhex(app_client.getAccount(1)["addressHex"][2:])

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR, "MyLedger",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                        chain_id=CHAIN_ID,
                        challenge=challenge,
                        owner=wrong_owner,
                        owner_deriv_path=owner_path))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_missing_owner_deriv_path(
        backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)
    owner = bytes.fromhex(app_client.getAccount(0)["addressHex"][2:])

    # The owner address is provided, but its derivation path is missing: the
    # firmware cannot prove ownership and must reject. Mirrors app-ethereum's
    # test_trusted_name_mab_missing_owner_deriv_path.
    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR, "MyLedger",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                        chain_id=CHAIN_ID,
                        challenge=challenge,
                        owner=owner))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_token_cal(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()

    rapdu = app_client.provide_trusted_name(
        TrustedName(2, ADDR, "USDT",
                    tn_type=TrustedNameType.TOKEN,
                    tn_source=TrustedNameSource.CAL,
                    chain_id=CHAIN_ID))
    assert rapdu.status == StatusWord.OK


def test_trusted_name_v2_multiple_names_same_session(
        backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    rapdu = app_client.provide_trusted_name(
        TrustedName(2, ADDR, NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID,
                    challenge=challenge))
    assert rapdu.status == StatusWord.OK

    rapdu = app_client.provide_trusted_name(
        TrustedName(2, ADDR, "USDT",
                    tn_type=TrustedNameType.TOKEN,
                    tn_source=TrustedNameSource.CAL,
                    chain_id=CHAIN_ID))
    assert rapdu.status == StatusWord.OK
