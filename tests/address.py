import base58
from typing import Any, Union

class BadAddress(ValueError):
    pass

def to_base58check_address(raw_addr: Union[str, bytes]) -> str:
    """Convert hex address or base58check address to base58check address(and verify it)."""
    if isinstance(raw_addr, (str,)):
        if raw_addr[0] == "T" and len(raw_addr) == 34:
            try:
                # assert checked
                base58.b58decode_check(raw_addr)
            except ValueError as e:
                raise BadAddress("bad base58check format") from e
            return raw_addr
        if len(raw_addr) == 42:
            if raw_addr.startswith("0x"):  # eth address format
                return base58.b58encode_check(b"\x41" + bytes.fromhex(raw_addr[2:])).decode()
            return base58.b58encode_check(bytes.fromhex(raw_addr)).decode()
        if raw_addr.startswith("0x") and len(raw_addr) == 44:
            return base58.b58encode_check(bytes.fromhex(raw_addr[2:])).decode()
    elif isinstance(raw_addr, (bytes, bytearray)):
        if len(raw_addr) == 21 and int(raw_addr[0]) == 0x41:
            return base58.b58encode_check(raw_addr).decode()
        if len(raw_addr) == 20:  # eth address format
            return base58.b58encode_check(b"\x41" + raw_addr).decode()
        return to_base58check_address(raw_addr.decode())
    raise BadAddress(repr(raw_addr))

def to_raw_address(raw_addr: Union[str, bytes]) -> bytes:
    """
    Uniformly convert base58 / Tron hex / ETH hex into a Tron TVM raw address (21 bytes)
    """
    # Already bytes (must be 21 bytes)
    if isinstance(raw_addr, bytes):
        if len(raw_addr) == 21:
            return raw_addr
        if len(raw_addr) == 20:  # ETH style 20 bytes
            return b"\x41" + raw_addr
        raise ValueError("Invalid bytes address length")

    # Base58Check (Tron typical): decode_check result is 21 bytes
    if is_base58check_address(raw_addr):
        return base58.b58decode_check(raw_addr)

    # Tron hex starting with 41, must be 21 bytes
    if is_hex_address(raw_addr):
        return bytes.fromhex(raw_addr)

    # ETH hex starting with 0x, must be 20 bytes
    if is_eth_address(raw_addr):
        raw = bytes.fromhex(raw_addr[2:])
        return b"\x41" + raw  # convert ETH => Tron TVM

    raise ValueError(f"Unknown address format: {raw_addr}")


def to_tvm_address(raw_addr: Union[str, bytes]) -> bytes:
    """
    Return 20-byte address (drop first byte 0x41)
    """
    return to_raw_address(raw_addr)[1:]


def is_base58check_address(value: str) -> bool:
    try:
        return value.startswith("T") and len(base58.b58decode_check(value)) == 21
    except Exception:
        return False


def is_hex_address(value: str) -> bool:
    try:
        return value.startswith("41") and len(bytes.fromhex(value)) == 21
    except Exception:
        return False


def is_eth_address(value: str) -> bool:
    try:
        return value.startswith("0x") and len(bytes.fromhex(value[2:])) == 20
    except Exception:
        return False


def is_address(value: str) -> bool:
    return is_base58check_address(value) or is_hex_address(value) or is_eth_address(value)
