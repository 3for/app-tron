import json
from pathlib import Path

from ragger.navigator.navigation_scenario import NavigateWithScenario

from tron import TronClient
from client.gating import Gating, TxType
from client.tlv import eth_to_tron_base58
from settings import SettingID, settings_toggle

# TRON wires its typed-data gating into the TIP-712 review and its transaction
# gating into the legacy blind-signing (custom contract) review -- the latter
# mirrors app-ethereum, which gates `ux_approve_tx` when the tx carries calldata.
# GCS (structured clear signing) is intentionally NOT gated. These tests therefore
# thread a gating descriptor through the blind-signing / TIP-712 signing helpers,
# mirroring app-ethereum's test_gating.py (which reuses test_blind_sign /
# test_eip712_new with `gating_params`).
from test_blind_sign import (test_blind_sign as blind_sign,
                             CUSTOM_CONTRACT_ADDR20, TRON_MAINNET_CHAINID)
from test_tip712 import tip712_new_common, tip712_json_path

INTRO_MSG = "To scan for threats and verify this transaction before signing, use Ledger Multisig."
TINY_URL = "ledger.com/ledger-multisig"

# Arbitrary implementation address sitting behind the proxy (mirrors app-ethereum's
# test_gating_blind_signing_with_proxy descriptor address). The proxy_info maps the
# tx contract (CUSTOM_CONTRACT_ADDR20) onto this implementation.
PROXY_IMPL_ADDR20 = bytes.fromhex("dad77910dbdfde764fc21fcd4e74d71bbaca6d8d")


def test_gating_blind_signing(scenario_navigator: NavigateWithScenario) -> None:
    """Test the Gating descriptor APDU with a blind signing transaction.

    Mirrors app-ethereum's test_gating_blind_signing: the descriptor targets the
    contract address + chain id of the custom-contract TriggerSmartContract.
    """
    descriptor = Gating(
        TxType.TRANSACTION,
        eth_to_tron_base58(CUSTOM_CONTRACT_ADDR20),
        INTRO_MSG,
        TINY_URL,
        TRON_MAINNET_CHAINID,
    )
    blind_sign(scenario_navigator,
               scenario_navigator.test_name,
               False,
               0.0,
               gating_params=descriptor)


def test_gating_blind_signing_with_proxy(scenario_navigator: NavigateWithScenario) -> None:
    """Test the Gating descriptor APDU with a blind signing transaction behind a proxy.

    Mirrors app-ethereum's test_gating_blind_signing_with_proxy: the tx calls the
    proxy address, a proxy_info maps it to the implementation, and the gating
    descriptor targets the implementation address.
    """
    descriptor = Gating(
        TxType.TRANSACTION,
        eth_to_tron_base58(PROXY_IMPL_ADDR20),
        INTRO_MSG,
        TINY_URL,
        TRON_MAINNET_CHAINID,
    )
    blind_sign(scenario_navigator,
               scenario_navigator.test_name,
               False,
               0.0,
               gating_params=descriptor,
               with_proxy=True)


def test_gating_tip712(scenario_navigator: NavigateWithScenario) -> None:
    """Test the Gating descriptor APDU on a TIP-712 typed-data signature.

    Mirrors app-ethereum's test_gating_eip712: the descriptor's selector is the schema
    hash (computed inside tip712_new_common, like the firmware's compute_schema_hash).
    """
    device = scenario_navigator.device
    navigator = scenario_navigator.navigator
    client = TronClient(scenario_navigator.backend, device, navigator)

    # Unfiltered (blind) typed-data signing needs SIGN_BY_HASH, mirroring
    # app-ethereum's test_gating_eip712 which signs an unfiltered EIP-712 (BLIND_SIGNING).
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])

    json_file = Path(tip712_json_path()) / "00-simple_mail-data.json"
    with open(json_file, encoding="utf-8") as file:
        data = json.load(file)

    verifying_contract = data["domain"]["verifyingContract"]
    if verifying_contract.startswith("0x"):
        verifying_contract = eth_to_tron_base58(bytes.fromhex(verifying_contract[2:]))
    else:
        verifying_contract = eth_to_tron_base58(verifying_contract)

    descriptor = Gating(
        TxType.TYPED_DATA,
        verifying_contract,
        INTRO_MSG,
        TINY_URL,
        chain_id=data["domain"].get("chainId", 0),
    )

    # Blind (unfiltered) typed-data flow; generate/compare snapshots under the
    # test name, mirroring app-ethereum's test_gating_eip712.
    tip712_new_common(scenario_navigator,
                      client,
                      data,
                      None,
                      snapshots_dirname=scenario_navigator.test_name,
                      nb_warnings=1,
                      gating_params=descriptor)
