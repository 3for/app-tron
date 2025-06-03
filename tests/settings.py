from enum import Enum, auto
from typing import Union
from ledgered.devices import Device, DeviceType

from ragger.navigator import Navigator, NavInsID, NavIns

# The order must match that of BAGL and NBGL.
class SettingID(Enum):
    DATA_ALLOWED = auto()
    CUSTOM_CONTRACT = auto()
    SIGN_BY_HASH = auto()
    VERBOSE_TIP712 = auto()
    TRUSTED_NAME = auto()


# Settings Positions per device. Returns the tuple (page, x, y)
SETTINGS_POSITIONS = {
    DeviceType.STAX: {
        SettingID.DATA_ALLOWED: (0, 350, 130),
        SettingID.CUSTOM_CONTRACT: (0, 350, 270),
        SettingID.SIGN_BY_HASH: (0, 350, 430),
        SettingID.VERBOSE_TIP712: (1, 350, 130),
        SettingID.TRUSTED_NAME: (1, 350, 270),
    },
    DeviceType.FLEX: {
        SettingID.DATA_ALLOWED: (0, 420, 130),
        SettingID.CUSTOM_CONTRACT: (0, 420, 350),
        SettingID.SIGN_BY_HASH: (1, 420, 130),
        SettingID.VERBOSE_TIP712: (1, 420, 270),
        SettingID.TRUSTED_NAME: (2, 420, 140),
    },
}


# The order of the settings is important, as it is used to navigate
def get_device_settings(device: Device) -> list[SettingID]:
    """Get the list of settings available on the device"""
    if device.is_nano:
        return [
            SettingID.DATA_ALLOWED,
            SettingID.CUSTOM_CONTRACT,
            SettingID.SIGN_BY_HASH,
            SettingID.VERBOSE_TIP712,
            SettingID.TRUSTED_NAME,
        ]
    return [
        SettingID.DATA_ALLOWED,
        SettingID.CUSTOM_CONTRACT,
        SettingID.SIGN_BY_HASH,
        SettingID.VERBOSE_TIP712,
        SettingID.TRUSTED_NAME,
    ]


def get_settings_moves(device: Device,
                       to_toggle: list[SettingID]) -> list[Union[NavIns, NavInsID]]:
    """Get the navigation instructions to toggle the settings"""
    moves: list[Union[NavIns, NavInsID]] = []
    settings = get_device_settings(device)
    # Assume the app is on the 1st page of Settings
    if device.is_nano:
        moves += [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
        for setting in settings:
            if setting in to_toggle:
                moves += [NavInsID.BOTH_CLICK]
            moves += [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK]  # Back
    else:
        current_page = 0
        moves += [NavInsID.USE_CASE_HOME_SETTINGS]
        for setting in settings:
            if setting in to_toggle:
                page, x, y = SETTINGS_POSITIONS[device.type][setting]
                moves += [NavInsID.USE_CASE_SETTINGS_NEXT] * (page - current_page)
                moves += [NavIns(NavInsID.TOUCH, (x, y))]
                current_page = page
        moves += [NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    return moves


def settings_toggle(device: Device, navigator: Navigator, to_toggle: list[SettingID]):
    """Toggle the settings"""
    moves = get_settings_moves(device, to_toggle)
    navigator.navigate(moves, screen_change_before_first_instruction=False)
