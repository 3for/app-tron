import sys
from pathlib import Path
from typing import Optional

import base58
import pytest

from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from tron import TronClient
from client.gating import Gating
from client.proxy_info import ProxyInfo
from client.status_word import StatusWord
from settings import SettingID, settings_toggle
from utils import check_tx_signature
# Shared with the GCS tests: the proxy_info challenge helper and the TRON mainnet
# address prefix byte.
from test_gcs import _get_challenge, ADD_PRE_FIX_BYTE_MAINNET

# Tron Protobuf
PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract  # noqa: E402
from core import Tron_pb2 as tron  # noqa: E402


# TRON is single-chain: get_tx_chain_id() always returns TRON mainnet
# (src/chain_config.h TRON_MAINNET_CHAINID).
TRON_MAINNET_CHAINID = 728126428
SUN_PER_TRX = 1_000_000  # common_utils.h TRX_DECIMALS = 6

# An arbitrary TriggerSmartContract whose selector is neither TRC20 transfer
# (a9059cbb) nor approve (095ea7b3): the firmware sets TRC20Method == 0 and takes
# the legacy blind-signing (custom contract) review -- the analog of an Ethereum
# blind signing, and where TRON wires its transaction gating.
CUSTOM_CONTRACT_B58 = "TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M"
CUSTOM_CONTRACT_ADDR20 = base58.b58decode_check(CUSTOM_CONTRACT_B58)[1:]  # drop 0x41 prefix
CUSTOM_SELECTOR = bytes.fromhex("0a857040")
CUSTOM_CALLDATA = CUSTOM_SELECTOR + (10001).to_bytes(32, "big")


@pytest.fixture(name="reject", params=[False, True])
def reject_fixture(request) -> bool:
    return request.param


@pytest.fixture(name="amount", params=[0.0, 1.2])
def amount_fixture(request) -> float:
    return request.param


def build_blind_sign_tx(client: TronClient, amount: float = 0.0) -> bytes:
    """Build a custom-contract (blind-signing) TriggerSmartContract tx.

    `amount` (in TRX) is attached as the contract call value; the firmware shows it
    as the "Pay Token"/"Call Amount" pair when non-zero.
    """
    return client.packContract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(client.getAccount(0)["addressHex"]),
            contract_address=bytes([ADD_PRE_FIX_BYTE_MAINNET]) + CUSTOM_CONTRACT_ADDR20,
            call_value=int(amount * SUN_PER_TRX),
            data=CUSTOM_CALLDATA))


def common_blind_sign(scenario_navigator: NavigateWithScenario,
                      test_name: str,
                      client: TronClient,
                      tx: bytes,
                      reject: bool = False,
                      amount: float = 0.0,
                      nb_warnings: int = 1) -> None:
    """Sign a blind-sign tx, walk the warning + review pages, verify the result.

    Mirrors app-ethereum's common_blind_sign.
    """
    try:
        with client.sign_async(client.getAccount(0)["path"], tx):
            if reject:
                test_name += "_rejected"
            if amount > 0.0:
                test_name += "_nonzero"

            if reject:
                scenario_navigator.review_reject_with_warning(
                    test_name=test_name, nb_warnings=nb_warnings)
            else:
                scenario_navigator.review_approve_with_warning(
                    test_name=test_name, nb_warnings=nb_warnings)
    except ExceptionRAPDU as e:
        assert reject
        assert e.status == StatusWord.CONDITION_NOT_SATISFIED
    else:
        assert not reject
        resp = client.response()
        assert check_tx_signature(tx, resp.data[0:65],
                                  client.getAccount(0)["publicKey"][2:])


def test_blind_sign(scenario_navigator: NavigateWithScenario,
                    test_name: str,
                    reject: bool,
                    amount: float,
                    gating_params: Optional[Gating] = None,
                    with_proxy: bool = False) -> None:
    """Blind-sign a custom-contract transaction.

    Mirrors app-ethereum's test_blind_sign: parametrized by reject x amount, and
    reused by test_gating.py (which threads a gating descriptor + optional proxy).
    """
    # The rejection flow is independent of the call value, so skip the redundant
    # reject + non-zero combo (mirrors app-ethereum).
    if reject and amount > 0.0:
        pytest.skip()

    device = scenario_navigator.device
    navigator = scenario_navigator.navigator
    client = TronClient(scenario_navigator.backend, device, navigator)

    # Custom-contract blind signing requires the CUSTOM_CONTRACT setting, the TRON
    # analog of app-ethereum's BLIND_SIGNING toggle.
    settings_toggle(device, navigator, [SettingID.CUSTOM_CONTRACT])

    tx = build_blind_sign_tx(client, amount)

    nb_warnings = 1
    if gating_params is not None:
        if with_proxy:
            # Map the tx contract to the implementation the descriptor targets.
            # Mirrors app-ethereum: the proxy_info carries no selector, so the gating
            # descriptor needs none either (check_gating_address resolves the proxy).
            assert client.provide_proxy_info(
                ProxyInfo(_get_challenge(client),
                          CUSTOM_CONTRACT_ADDR20,
                          TRON_MAINNET_CHAINID,
                          gating_params.address).serialize()).status == StatusWord.OK
        assert client.provide_gating(gating_params.serialize()).status == StatusWord.OK
        nb_warnings += 1

    common_blind_sign(scenario_navigator, test_name, client, tx, reject, amount,
                      nb_warnings)


def test_blind_sign_reject_in_risk_review(scenario_navigator: NavigateWithScenario) -> None:
    """Reject a blind-signing transaction at the initial risk (warning) review.

    Mirrors app-ethereum's test_blind_sign_reject_in_risk_review: reject on the
    blind-signing warning page (before the field review) and expect the device to
    return CONDITION_NOT_SATISFIED. Same NBGL advanced-review flow as app-ethereum,
    so the navigation moves match.
    """
    device = scenario_navigator.device
    navigator = scenario_navigator.navigator
    client = TronClient(scenario_navigator.backend, device, navigator)

    settings_toggle(device, navigator, [SettingID.CUSTOM_CONTRACT])

    moves = []
    if device.is_nano:
        moves += [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    else:
        moves += [NavInsID.USE_CASE_CHOICE_CONFIRM]
    try:
        with client.sign_async(client.getAccount(0)["path"], build_blind_sign_tx(client)):
            navigator.navigate(moves)
    except ExceptionRAPDU as e:
        assert e.status == StatusWord.CONDITION_NOT_SATISFIED
    else:
        assert False  # Should have thrown


def test_blind_sign_not_enabled_error(scenario_navigator: NavigateWithScenario,
                                      test_name: str) -> None:
    """Signing a custom contract with the CUSTOM_CONTRACT setting disabled must error.

    TRON's analog of app-ethereum's test_blind_sign_not_enabled_error. The gate is the
    "Custom contracts" setting (distinct from the separate "Blind signing"
    setting), so the device shows the "Custom contracts must be enabled in
    settings" page, the user dismisses it, and the APDU returns the precise TRON-specific
    MISSING_SETTING_CUSTOM_CONTRACT (0x6a8d). No `configuration` fixture, so the setting
    stays at its disabled power-on default.
    """
    device = scenario_navigator.device
    navigator = scenario_navigator.navigator
    client = TronClient(scenario_navigator.backend, device, navigator)

    default_screenshot_path = Path(__file__).parent.resolve()
    moves = []
    if device.is_nano:
        moves += [NavInsID.BOTH_CLICK]
    else:
        moves += [NavInsID.USE_CASE_CHOICE_REJECT]
    try:
        with client.sign_async(client.getAccount(0)["path"], build_blind_sign_tx(client)):
            navigator.navigate_and_compare(default_screenshot_path, test_name, moves)
    except ExceptionRAPDU as e:
        assert e.status == StatusWord.MISSING_SETTING_CUSTOM_CONTRACT
    else:
        assert False  # Should have thrown
