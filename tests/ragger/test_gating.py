import json
from pathlib import Path

from ragger.navigator.navigation_scenario import NavigateWithScenario

from tron import TronClient
from client.command_builder import CommandBuilder
from client.gating import Gating, TxType

# TRON's transaction gating is wired into the Generic Clear Signing (GCS) review and
# its typed-data gating into the TIP-712 review, so these tests reuse the existing
# GCS / TIP-712 signing-flow helpers with a gating descriptor -- mirroring
# app-ethereum's test_gating.py (which threads `gating_params` through its
# test_blind_sign / test_eip712_new helpers).
import test_gcs
import test_tip712
from test_tip712 import tip712_new_common, tip712_json_path

INTRO_MSG = "To scan for threats and verify this transaction before signing, use Ledger Multisig."
TINY_URL = "ledger.com/ledger-multisig"

def test_gating_tip712(scenario_navigator: NavigateWithScenario, golden_run: bool,
                       configuration) -> None:
    """Test the Gating descriptor APDU on a TIP-712 typed-data signature.

    Mirrors app-ethereum's test_gating_eip712: the descriptor's selector is the schema
    hash (computed inside tip712_new_common, like the firmware's compute_schema_hash).
    """
    device = scenario_navigator.device
    navigator = scenario_navigator.navigator
    client = TronClient(scenario_navigator.backend, device, navigator)
    builder = CommandBuilder()

    json_file = Path(tip712_json_path()) / "00-simple_mail-data.json"
    with open(json_file, encoding="utf-8") as file:
        data = json.load(file)

    descriptor = Gating(
        TxType.TYPED_DATA,
        bytes.fromhex(data["domain"]["verifyingContract"][2:]),
        INTRO_MSG,
        TINY_URL,
        chain_id=data["domain"].get("chainId", 0),
    )

    # Blind (unfiltered) typed-data flow; generate/compare snapshots under the
    # test name, mirroring app-ethereum's test_gating_eip712.
    test_tip712.unfiltered_flow = True
    test_tip712.snapshots_dirname = scenario_navigator.test_name
    tip712_new_common(device, navigator, Path(__file__).parent.resolve(),
                      client, builder, data, None, False, golden_run,
                      gating_params=descriptor)
