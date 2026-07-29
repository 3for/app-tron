from pathlib import Path
from typing import List
import pytest
from ragger.error import ExceptionRAPDU

from ledgered.devices import Device

from ragger.backend import BackendInterface
from ragger.navigator import Navigator
from ragger.utils.misc import get_current_app_name_and_version

from client.status_word import StatusWord
from settings import (APP_CLA, GET_APP_CONFIGURATION_INS,
                      RESERVED_TRUNCATE_ADDRESS_MASK, SettingID,
                      get_settings_moves)


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


def test_truncate_address_flag_is_reserved(backend: BackendInterface):
    """The deprecated truncate-address wire bit must remain clear."""
    response = backend.exchange(APP_CLA, GET_APP_CONFIGURATION_INS, 0x00, 0x00)
    assert response.data[0] & RESERVED_TRUNCATE_ADDRESS_MASK == 0


@pytest.mark.parametrize(
    "p1,p2,data,expected",
    [
        (1, 0, b"", StatusWord.INVALID_P1_P2),
        (0, 1, b"", StatusWord.INVALID_P1_P2),
        (0, 0, b"\x00", StatusWord.WRONG_DATA_LENGTH),
    ],
)
def test_get_configuration_rejects_noncanonical_apdu(
        backend: BackendInterface, p1: int, p2: int, data: bytes,
        expected: StatusWord):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(APP_CLA, GET_APP_CONFIGURATION_INS, p1, p2, data)
    assert error.value.status == expected
