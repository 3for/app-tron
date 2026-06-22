from typing import Union
from enum import IntEnum

import base58

TRON_MAINNET_ADDRESS_PREFIX = 0x41


def eth_to_tron_base58(addr: Union[str, bytes]) -> str:
    """Return a TRON Base58Check address string ("T...") for use in CAL descriptors.

    CAL descriptors carry addresses in this form so the firmware verifies the signature
    over the Base58 bytes, then decodes back to 20 bytes. Accepts either an already
    Base58Check string (passed through after validation) or a 20-byte EVM / 21-byte
    0x41-prefixed binary address (encoded)."""
    if isinstance(addr, str):
        decoded = base58.b58decode_check(addr)
        if len(decoded) != 21 or decoded[0] != TRON_MAINNET_ADDRESS_PREFIX:
            raise ValueError(f"invalid TRON Base58 address: {addr}")
        return addr
    if len(addr) == 21 and addr[0] == TRON_MAINNET_ADDRESS_PREFIX:
        body = addr
    elif len(addr) == 20:
        body = bytes([TRON_MAINNET_ADDRESS_PREFIX]) + addr
    else:
        raise ValueError("address must be 20 or 21 (0x41-prefixed) bytes")
    return base58.b58encode_check(body).decode()


class FieldTag(IntEnum):
    STRUCT_TYPE = 0x01
    STRUCT_VERSION = 0x02
    CHALLENGE = 0x12
    DER_SIGNATURE = 0x15
    ADDRESS = 0x22
    CHAIN_ID = 0x23
    TICKER = 0x24
    TX_HASH = 0x27
    DOMAIN_HASH = 0x28
    SELECTOR = 0x40
    BLOCKCHAIN_FAMILY = 0x51
    NETWORK_NAME = 0x52
    NETWORK_ICON_HASH = 0x53
    TX_CHECKS_NORMALIZED_RISK = 0x80
    TX_CHECKS_NORMALIZED_CATEGORY = 0x81
    MESSAGE = 0x82
    TINY_URL = 0x83
    TX_TYPE = 0x84
    THRESHOLD = 0xa0,
    SIGNERS_COUNT = 0xa1,
    LESM_ROLE = 0xa2,


class TlvSerializable:
    def serialize(self) -> bytes:
        raise NotImplementedError

    @staticmethod
    def der_encode(value: int) -> bytes:
        # max() to have minimum length of 1
        value_bytes = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
        if value >= 0x80:
            value_bytes = (0x80 | len(value_bytes)).to_bytes(1, 'big') + value_bytes
        return value_bytes

    @staticmethod
    def serialize_field(tag: int, value: Union[int, str, bytes, bytearray]) -> bytes:
        if isinstance(value, int):
            # max() to have minimum length of 1
            value = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
        elif isinstance(value, str):
            value = value.encode()
        elif isinstance(value, bytearray):
            value = bytes(value)

        assert isinstance(value, bytes), f"Unhandled TLV formatting for type : {type(value)}"

        tlv = bytearray()
        tlv += TlvSerializable.der_encode(tag)
        tlv += TlvSerializable.der_encode(len(value))
        tlv += value
        return tlv

    @staticmethod
    def serialize_tron_address_field(tag: int, addr: bytes) -> bytes:
        # CAL descriptors carry the address as a 34-char TRON Base58Check string.
        return TlvSerializable.serialize_field(tag, eth_to_tron_base58(addr))
