from enum import IntEnum, auto


class TIP712TypeDescOffset(IntEnum):
    ARRAY = 7
    SIZE = 6
    TYPE = 0


class TIP712TypeDescMask(IntEnum):
    ARRAY = (0b1 << TIP712TypeDescOffset.ARRAY)
    SIZE = (0b1 << TIP712TypeDescOffset.SIZE)
    TYPE = (0b1111 << TIP712TypeDescOffset.TYPE)


class TIP712FieldType(IntEnum):
    CUSTOM = 0
    INT = auto()
    UINT = auto()
    ADDRESS = auto()
    BOOL = auto()
    STRING = auto()
    FIX_BYTES = auto()
    DYN_BYTES = auto()
    TRCTOKEN = auto()
