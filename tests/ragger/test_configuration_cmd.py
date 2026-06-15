from pathlib import Path
from typing import List
import pytest

from ledgered.devices import Device

from ragger.backend import BackendInterface
from ragger.navigator import Navigator
from ragger.utils.misc import get_current_app_name_and_version

from settings import SettingID, get_settings_moves


@pytest.mark.parametrize("name, setting", [
    ("data_allowed", [SettingID.DATA_ALLOWED]),
    ("custom_contract", [SettingID.CUSTOM_CONTRACT]),
    ("blind_sign", [SettingID.SIGN_BY_HASH]),
    ("tip712_token", [SettingID.VERBOSE_TIP712]),
    ("display_hash", [SettingID.DISPLAY_HASH]),
    ("multiple1", [SettingID.SIGN_BY_HASH, SettingID.VERBOSE_TIP712]),
    ("multiple2", [SettingID.SIGN_BY_HASH, SettingID.CUSTOM_CONTRACT]),
    ("multiple3", [SettingID.SIGN_BY_HASH, SettingID.DATA_ALLOWED]),
])
def test_settings(device: Device, navigator: Navigator, test_name: str,
                  default_screenshot_path: Path, name: str,
                  setting: List[SettingID]):
    """Check the settings"""

    moves = get_settings_moves(device, setting)
    default_screenshot_path = Path(__file__).parent.resolve()
    navigator.navigate_and_compare(
        default_screenshot_path,
        f"{test_name}/{name}",
        moves,
        screen_change_before_first_instruction=False)


def test_check_version(backend: BackendInterface, app_version: tuple[int, int,
                                                                     int]):
    """Check version and name"""

    # Send the APDU
    app_name, version = get_current_app_name_and_version(backend)
    print(f" Name: {app_name}")
    print(f" Version: {version}")
    print(f" app_version: {app_version}")
    vers_str = ".".join(map(str, app_version))
    assert version.split("-")[0] == vers_str
