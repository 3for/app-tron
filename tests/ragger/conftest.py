# This final fixture will return the properly configured backend client, to be used in tests
import pytest
from ragger.conftest import configuration
from ragger.backend import SpeculosBackend, BackendInterface
from pathlib import Path
from settings import SettingID, get_device_settings, get_enabled_settings, get_settings_moves

###########################
### CONFIGURATION START ###
###########################
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

configuration.OPTIONAL.BACKEND_SCOPE = "function"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC


@pytest.fixture(scope="function")
def configuration(backend: BackendInterface, navigator, device):
    if type(backend) is SpeculosBackend:
        desired_enabled = {
            SettingID.DATA_ALLOWED,
            SettingID.CUSTOM_CONTRACT,
            SettingID.SIGN_BY_HASH,
        }
        current_enabled = get_enabled_settings(backend, backend.device)
        to_toggle = [
            setting for setting in get_device_settings(backend.device)
            if (setting in current_enabled) != (setting in desired_enabled)
        ]

        if to_toggle:
            navigator.navigate(get_settings_moves(backend.device, to_toggle),
                               screen_change_before_first_instruction=False)

        final_enabled = get_enabled_settings(backend, backend.device)
        assert final_enabled == desired_enabled, (
            f"Unexpected settings after configuration: {sorted(s.name for s in final_enabled)}"
        )


@pytest.fixture(name="app_version")
def app_version_fixture(request) -> tuple[int, int, int]:
    with open(Path(__file__).parent.parent.parent / "VERSION",
              encoding="utf-8") as f:
        parsed = {}
        first_line = f.readline().strip()
        parsed = [int(part) for part in first_line.split('.')]
    return (parsed[0], parsed[1], parsed[2])


#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )
