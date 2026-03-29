# This final fixture will return the properly configured backend client, to be used in tests
import pytest
from ragger.conftest import configuration
from ragger.backend import SpeculosBackend, BackendInterface
from ragger.navigator import NavInsID, NavIns
from pathlib import Path
import re
from settings import SettingID, get_settings_moves

###########################
### CONFIGURATION START ###
###########################
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

configuration.OPTIONAL.BACKEND_SCOPE = "function"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC


@pytest.fixture(scope="function")
def configuration(backend: BackendInterface, navigator, firmware):
    if type(backend) is SpeculosBackend:
        instructions = get_settings_moves(backend.device, [
            SettingID.DATA_ALLOWED,
            SettingID.CUSTOM_CONTRACT,
            SettingID.SIGN_BY_HASH,
        ])

        navigator.navigate(instructions,
                           screen_change_before_first_instruction=False)


@pytest.fixture(name="app_version")
def app_version_fixture(request) -> tuple[int, int, int]:
    with open(Path(__file__).parent.parent.parent / "VERSION", encoding="utf-8") as f:
        parsed = {}
        first_line = f.readline().strip()
        parsed = [int(part) for part in first_line.split('.')]
    return (parsed[0], parsed[1], parsed[2])


#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )
