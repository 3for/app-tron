from enum import Enum, auto
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns
from typing import Union


class SettingID(Enum):
    pass


class NanoSettingID(SettingID):
    FLOW_1 = auto()
    FLOW_2 = auto()
    FLOW_3 = auto()
    FLOW_4 = auto()
    # BLIND_SIGNING = auto()
    VERBOSE_ENS = auto()
    VERBOSE_TIP712 = auto()


class NonNanoSettingID(SettingID):
    TX_DATA_ID = auto()
    CSTM_CONTRACTS_ID = auto()
    HASH_TX_ID = auto()
    # BLIND_SIGNING = auto()
    VERBOSE_ENS = auto()
    VERBOSE_TIP712 = auto()


def get_device_settings(firmware: Firmware) -> list:
    if firmware.is_nano:
        if firmware == Firmware.NANOS:
            return [
                NanoSettingID.NONCE,
                NanoSettingID.DEBUG_DATA,
            ]
        return [
            NanoSettingID.FLOW_1,
            NanoSettingID.FLOW_2,
            NanoSettingID.FLOW_3,
            NanoSettingID.FLOW_4,
            # NanoSettingID.BLIND_SIGNING,
            NanoSettingID.VERBOSE_ENS,
            NanoSettingID.VERBOSE_TIP712,
        ]
    else:
        return [
            NonNanoSettingID.TX_DATA_ID,
            NonNanoSettingID.CSTM_CONTRACTS_ID,
            NonNanoSettingID.HASH_TX_ID,
            # NonNanoSettingID.BLIND_SIGNING,
            NonNanoSettingID.VERBOSE_ENS,
            NonNanoSettingID.VERBOSE_TIP712,
        ]

# Maintain the status quo, no need to be consistent with Ethereum.
def get_setting_position(
        firmware: Firmware, setting: Union[NavInsID,
                                           SettingID]) -> tuple[int, int]:
    settings_per_page = 3 if firmware == Firmware.STAX else 2
    y_index = get_device_settings(firmware).index(
        NonNanoSettingID(setting)) % settings_per_page
    return 200, 150 * (y_index + 1)


def settings_toggle(firmware: Firmware, nav: Navigator,
                    to_toggle: list[SettingID]):
    moves: list[Union[NavIns, NavInsID]] = []
    settings = get_device_settings(firmware)
    # Assume the app is on the home page
    if firmware.is_nano:
        moves += [NavInsID.RIGHT_CLICK] * 2
        moves += [NavInsID.BOTH_CLICK]
        for setting in settings:
            if setting in to_toggle:
                moves += [NavInsID.BOTH_CLICK]
            moves += [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK]  # Back
    else:
        moves += [NavInsID.USE_CASE_HOME_SETTINGS]
        settings_per_page = 3 if firmware == Firmware.STAX else 2
        for setting in settings:
            setting_idx = settings.index(setting)
            if (setting_idx > 0) and (setting_idx % settings_per_page) == 0:
                moves += [NavInsID.USE_CASE_SETTINGS_NEXT]
            if setting in to_toggle:
                moves += [
                    NavIns(NavInsID.TOUCH,
                           get_setting_position(firmware, setting))
                ]
        moves += [NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    print(moves)
    nav.navigate(moves, screen_change_before_first_instruction=False)