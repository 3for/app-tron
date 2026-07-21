from enum import Enum, auto
from typing import Union
from ledgered.devices import Device, DeviceType

from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID, NavIns


# The order must match that of BAGL and NBGL.
class SettingID(Enum):
    DATA_ALLOWED = auto()
    CUSTOM_CONTRACT = auto()
    SIGN_BY_HASH = auto()
    VERBOSE_TIP712 = auto()
    DISPLAY_HASH = auto()


SETTING_BITS = {
    SettingID.DATA_ALLOWED: 0,
    SettingID.CUSTOM_CONTRACT: 1,
    # Bit 2 is reserved for the removed truncate-address setting.
    SettingID.SIGN_BY_HASH: 3,
    SettingID.VERBOSE_TIP712: 4,
    SettingID.DISPLAY_HASH: 5,
}

APP_CLA = 0xE0
GET_APP_CONFIGURATION_INS = 0x06
RESERVED_TRUNCATE_ADDRESS_MASK = 1 << 2

# Settings Positions per device. Returns the tuple (page, x, y)
SETTINGS_POSITIONS = {
    DeviceType.STAX: {
        SettingID.DATA_ALLOWED: (0, 350, 130),
        SettingID.CUSTOM_CONTRACT: (0, 350, 335),
        SettingID.SIGN_BY_HASH: (0, 350, 445),
        SettingID.VERBOSE_TIP712: (1, 350, 130),
        SettingID.DISPLAY_HASH: (1, 350, 335),
    },
    DeviceType.FLEX: {
        SettingID.DATA_ALLOWED: (0, 420, 130),
        SettingID.CUSTOM_CONTRACT: (0, 420, 350),
        SettingID.SIGN_BY_HASH: (1, 420, 130),
        SettingID.VERBOSE_TIP712: (1, 420, 270),
        SettingID.DISPLAY_HASH: (2, 420, 130),
    },
    DeviceType.APEX_P: {
        SettingID.DATA_ALLOWED: (0, 260, 90),
        SettingID.CUSTOM_CONTRACT: (0, 260, 235),
        SettingID.SIGN_BY_HASH: (1, 260, 90),
        SettingID.VERBOSE_TIP712: (1, 260, 190),
        SettingID.DISPLAY_HASH: (2, 260, 90),
    },
    DeviceType.APEX_M: {
        SettingID.DATA_ALLOWED: (0, 260, 90),
        SettingID.CUSTOM_CONTRACT: (0, 260, 235),
        SettingID.SIGN_BY_HASH: (1, 260, 90),
        SettingID.VERBOSE_TIP712: (1, 260, 190),
        SettingID.DISPLAY_HASH: (2, 260, 90),
    },
}


# The order of the settings is important, as it is used to navigate
def get_device_settings(device: Device) -> list[SettingID]:
    """Get the list of settings available on the device"""
    return [
        SettingID.DATA_ALLOWED,
        SettingID.CUSTOM_CONTRACT,
        SettingID.SIGN_BY_HASH,
        SettingID.VERBOSE_TIP712,
        SettingID.DISPLAY_HASH,
    ]


def get_enabled_settings(backend: BackendInterface,
                         device: Device) -> set[SettingID]:
    response = backend.exchange(APP_CLA, GET_APP_CONFIGURATION_INS, 0x00, 0x00)
    enabled_mask = response.data[0]
    return {
        setting
        for setting in get_device_settings(device)
        if enabled_mask & (1 << SETTING_BITS[setting])
    }


def get_settings_moves(
        device: Device,
        to_toggle: list[SettingID]) -> list[Union[NavIns, NavInsID]]:
    """Get the navigation instructions to toggle the settings"""
    moves: list[Union[NavIns, NavInsID]] = []
    settings = get_device_settings(device)
    # Assume the app is on the 1st page of Settings
    if device.is_nano:
        moves += [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK
                  ]  # On Nano NBGL, Settings is the 2nd home page.
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
                moves += [NavInsID.USE_CASE_SETTINGS_NEXT
                          ] * (page - current_page)
                moves += [NavIns(NavInsID.TOUCH, (x, y))]
                current_page = page
        moves += [NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    return moves


def settings_toggle(device: Device, navigator: Navigator,
                    to_toggle: list[SettingID]):
    """Toggle the settings"""
    moves = get_settings_moves(device, to_toggle)
    if device.is_nano:
        content = navigator._backend.get_current_screen_content()
        if isinstance(content, dict):
            texts = [
                event.get("text", "").strip().lower()
                for event in content.get("events", [])
                if event.get("text", "").strip()
            ]
        elif isinstance(content, list):
            texts = [str(item).strip().lower() for item in content if str(item).strip()]
        else:
            texts = []

        if any("app settings" in text for text in texts):
            moves = moves[1:]
        elif any("quit" in text for text in texts):
            moves = [NavInsID.LEFT_CLICK] + moves[1:]
    navigator.navigate(moves, screen_change_before_first_instruction=False)
