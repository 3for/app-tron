from typing import Optional
from pathlib import Path
import pytest
from ledgered.devices import DeviceType
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID, NavIns
from ragger.navigator.navigation_scenario import NavigateWithScenario

import response_parser as ResponseParser
from tron import TronClient
from utils import to_sun
from client.status_word import StatusWord
from client.trusted_name import TrustedName, TrustedNameType, TrustedNameSource
from client.command_builder import CommandBuilder
from client.keychain import Key, sign_data
from client.ledger_pki import PKIPubKeyUsage
from client.tlv import eth_to_tron_base58
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

# Values used across all tests
CHAIN_ID = 728126428
NAME = "ledger.eth"
ADDR = bytes.fromhex("0011223344556677889900112233445566778899")
# CAL descriptors sign the address as a TRON Base58Check string. The transaction side
# keeps using the 20-byte ADDR; the firmware decodes ADDR_B58 back to ADDR to match.
ADDR_B58 = eth_to_tron_base58(ADDR)
NONCE = 21
GAS_PRICE = 13
GAS_LIMIT = 21000
# Legacy transaction metadata kept for parity with app-ethereum tests. When
# populated in TRON tests, express it in SUN rather than Ethereum gwei.
GAS_PRICE_SUN = to_sun(GAS_PRICE)
# TRX, decimal 10^6
AMOUNT = 1_220_000
# V1-only Ethereum coin type, retained solely to assert that legacy descriptors
# are rejected by the V2-only Tron implementation.
LEGACY_COIN_TYPE_ETH = 0x3c


NANO_TRANSACTION_SIGN_PATTERN = r"(?is)^sign( transaction.*)?$"


def common(app_client: TronClient,
           cmd_builder: CommandBuilder,
           get_challenge: bool = True) -> Optional[int]:
    if get_challenge:
        challenge = app_client.exchange_raw(cmd_builder.get_challenge())
        return ResponseParser.challenge(challenge.data)
    return None


def provide_trusted_name_with_key(app_client: TronClient,
                                  descriptor: TrustedName,
                                  signing_key: Key,
                                  certificate_from_cal: bool) -> None:
    """Send a descriptor whose source/key-id fields intentionally differ
    from its signer."""
    descriptor.signature = b""
    unsigned_payload = descriptor.serialize()
    assert unsigned_payload.endswith(b"\x15\x00")
    descriptor.signature = sign_data(signing_key, unsigned_payload[:-2])

    app_client.pki_client.send_certificate(
        PKIPubKeyUsage.PUBKEY_USAGE_TRUSTED_NAME,
        certificate_from_cal)
    for apdu in CommandBuilder().provide_trusted_name(descriptor.serialize()):
        app_client.exchange_raw(apdu)


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


def test_trusted_name_rejects_v1(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(1, ADDR_B58,NAME, challenge=challenge,
                        coin_type=LEGACY_COIN_TYPE_ETH))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2(scenario_navigator: NavigateWithScenario,
                         test_name: str):
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    app_client.provide_trusted_name(
        TrustedName(2, ADDR_B58,NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID,
                    challenge=challenge))

    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": GAS_PRICE_SUN,
            "gas": GAS_LIMIT,
            "to": ADDR,
            "value": AMOUNT,
            "chainId": CHAIN_ID
        }, test_name)


def test_trusted_name_v2_verbose(navigator: Navigator,
                                 scenario_navigator: NavigateWithScenario,
                                 default_screenshot_path: Path,
                                 test_name: str):
    """Reveal the address behind a V2 ENS alias during transaction review."""
    backend = scenario_navigator.backend
    device = backend.device
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())

    app_client.provide_trusted_name(
        TrustedName(2, ADDR_B58,NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID,
                    challenge=challenge))

    tx_params = {
        "nonce": NONCE,
        "gasPrice": GAS_PRICE_SUN,
        "gas": GAS_LIMIT,
        "to": ADDR,
        "value": AMOUNT,
        "chainId": CHAIN_ID,
    }

    moves = []
    if device.is_nano:
        moves += [NavInsID.RIGHT_CLICK] * 3
        moves += [NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    else:
        moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
        ens_positions = {
            DeviceType.FLEX: (428, 350),
            DeviceType.STAX: (360, 324),
            DeviceType.APEX_P: (272, 230),
        }
        moves += [NavIns(NavInsID.TOUCH, ens_positions[device.type])]
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


def test_trusted_name_v2_wrong_challenge(backend: BackendInterface):
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58,NAME,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID,
                        challenge=~challenge & 0xffffffff))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_rejects_legacy_coin_type(backend: BackendInterface):
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58,NAME,
                        coin_type=LEGACY_COIN_TYPE_ETH,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID,
                        challenge=challenge))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_wrong_addr(
        scenario_navigator: NavigateWithScenario, test_name: str):
    backend = scenario_navigator.backend
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())

    app_client.provide_trusted_name(
        TrustedName(2, ADDR_B58,NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID,
                    challenge=challenge))

    addr = bytearray(ADDR)
    addr.reverse()
    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": GAS_PRICE_SUN,
            "gas": GAS_LIMIT,
            "to": bytes(addr),
            "value": AMOUNT,
            "chainId": CHAIN_ID,
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
        TrustedName(2, ADDR_B58,NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID + 1,
                    challenge=challenge))
    sign_trusted_name(
        scenario_navigator, app_client, {
            "nonce": NONCE,
            "gasPrice": GAS_PRICE_SUN,
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
            TrustedName(2, ADDR_B58,NAME,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_rejects_cal_certificate_for_ens(backend: BackendInterface):
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())
    descriptor = TrustedName(2, ADDR_B58, NAME,
                             tn_type=TrustedNameType.ACCOUNT,
                             tn_source=TrustedNameSource.ENS,
                             chain_id=CHAIN_ID,
                             challenge=challenge)

    with pytest.raises(ExceptionRAPDU) as e:
        provide_trusted_name_with_key(app_client, descriptor, Key.CAL, True)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_rejects_domain_certificate_for_cal(backend: BackendInterface):
    app_client = TronClient(backend)
    descriptor = TrustedName(2, ADDR_B58, "Token",
                             tn_type=TrustedNameType.TOKEN,
                             tn_source=TrustedNameSource.CAL,
                             chain_id=CHAIN_ID)

    with pytest.raises(ExceptionRAPDU) as e:
        provide_trusted_name_with_key(app_client, descriptor, Key.TRUSTED_NAME, False)
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_expired(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58,NAME,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID,
                        challenge=challenge,
                        not_valid_after=(0, 1, 2)))
    assert e.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("name", [
    "ledger" + "0" * 25 + ".eth",
    "l\xe8dger.eth",
    NAME.upper(),
    "ledger.hte",
])
def test_trusted_name_v2_rejects_invalid_ens_name(
        backend: BackendInterface, name: str):
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58, name,
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.ENS,
                        chain_id=CHAIN_ID,
                        challenge=challenge))
    assert e.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("name", [
    "",
    "\0",
    "Safe name\0hidden suffix",
    " Leading",
    "Trailing ",
])
def test_trusted_name_v2_rejects_ambiguous_names(
        backend: BackendInterface, name: str):
    app_client = TronClient(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58, name,
                        tn_type=TrustedNameType.TOKEN,
                        tn_source=TrustedNameSource.CAL,
                        chain_id=CHAIN_ID))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_account_name(backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)
    owner_path = app_client.getAccount(0)["path"]
    owner = bytes.fromhex(app_client.getAccount(0)["addressHex"][2:])

    rapdu = app_client.provide_trusted_name(
        TrustedName(2, ADDR_B58,"MyLedger",
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                    chain_id=CHAIN_ID,
                    challenge=challenge,
                    owner=owner,
                    owner_deriv_path=owner_path))
    assert rapdu.status == StatusWord.OK


def test_trusted_name_v2_mab_rejects_short_owner(
        backend: BackendInterface):
    app_client = TronClient(backend)
    challenge = common(app_client, CommandBuilder())
    # This deterministic path derives 0x00149a...da46. Removing the leading
    # zero produces a 19-byte wire value that the old parser left-padded back
    # to the same owner, so the descriptor incorrectly passed ownership
    # verification. MAB owner encoding is canonical and must be exactly 20
    # bytes even when the address starts with zero.
    owner_path = "m/44'/195'/0'/0/430"
    owner_without_leading_zero = bytes.fromhex(
        "149a1b7dd4330a6e5893b266d00c0be443da46")

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58, "MyLedger",
                        tn_type=TrustedNameType.ACCOUNT,
                        tn_source=TrustedNameSource.MULTISIG_ADDRESS_BOOK,
                        chain_id=CHAIN_ID,
                        challenge=challenge,
                        owner=owner_without_leading_zero,
                        owner_deriv_path=owner_path))
    assert e.value.status == StatusWord.INVALID_DATA


def test_trusted_name_v2_mab_missing_owner_metadata(
        backend: BackendInterface):
    app_client = TronClient(backend)
    cmd_builder = CommandBuilder()
    challenge = common(app_client, cmd_builder)

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_trusted_name(
            TrustedName(2, ADDR_B58,"MyLedger",
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
            TrustedName(2, ADDR_B58,"MyLedger",
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
            TrustedName(2, ADDR_B58,"MyLedger",
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
        TrustedName(2, ADDR_B58,"USDT",
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
        TrustedName(2, ADDR_B58,NAME,
                    tn_type=TrustedNameType.ACCOUNT,
                    tn_source=TrustedNameSource.ENS,
                    chain_id=CHAIN_ID,
                    challenge=challenge))
    assert rapdu.status == StatusWord.OK

    rapdu = app_client.provide_trusted_name(
        TrustedName(2, ADDR_B58,"USDT",
                    tn_type=TrustedNameType.TOKEN,
                    tn_source=TrustedNameSource.CAL,
                    chain_id=CHAIN_ID))
    assert rapdu.status == StatusWord.OK
