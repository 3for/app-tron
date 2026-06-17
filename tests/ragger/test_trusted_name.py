from typing import Optional
import pytest
from web3 import Web3
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
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


@pytest.mark.usefixtures('configuration')
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


def test_trusted_name_v1_wrong_challenge(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR, NAME, challenge=~challenge & 0xffffffff,
                        coin_type=COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


@pytest.mark.usefixtures('configuration')
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


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v1_non_mainnet(
                                     scenario_navigator: NavigateWithScenario,
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
            "chainId": 5
        }, test_name)


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v1_unknown_chain(
        scenario_navigator: NavigateWithScenario, test_name: str):
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


@pytest.mark.usefixtures('configuration')
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


@pytest.mark.usefixtures('configuration')
def test_trusted_name_v2_wrong_chainid(
        scenario_navigator: NavigateWithScenario, test_name: str):
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
            "chainId": CHAIN_ID + 1,
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
