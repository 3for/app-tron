from enum import IntEnum

from .struct import TIP712FieldType, TIP712TypeDescOffset, TIP712TypeDescMask  # noqa


# Presence of an address parameter (callee / spender) in an EIP-712 nested-calldata
# filter. Mirrors app-ethereum's EIP712CalldataParamPresence (client/client.py).
class EIP712CalldataParamPresence(IntEnum):
    NONE = 0x00
    PRESENT_FILTERED = 0x01
