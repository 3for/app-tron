#!/usr/bin/env python3

from pathlib import Path


OUT_DIR = Path(__file__).resolve().parent / "corpus" / "fuzz_external_metadata"

INS_TRUSTED_NAME = 0x22
INS_ENUM_VALUE = 0x24
INS_PROXY_INFO = 0x2A
P1_FIRST_CHUNK = 0x01

TRON_ADDRESS = b"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
TRON_ADDRESS_2 = b"TFMA7iav1S9K46K2QaSKL5PV73qk4LcEcZ"
TRON_MAINNET_CHAIN_ID = 728126428
DUMMY_DER_SIGNATURE = b"\x30\x06\x02\x01\x01\x02\x01\x01"


def der_uint(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if value >= 0x80:
        return bytes([0x80 | len(encoded)]) + encoded
    return encoded


def tlv(tag: int, value: int | bytes | str) -> bytes:
    if isinstance(value, int):
        value = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    elif isinstance(value, str):
        value = value.encode()
    return der_uint(tag) + der_uint(len(value)) + value


def record(ins: int, p1: int, payload: bytes, p2: int = 0) -> bytes:
    if len(payload) > 0xFF:
        raise ValueError("fuzz APDU record payload exceeds one-byte length")
    return bytes([ins, p1, p2, len(payload)]) + payload


def single_chunk(ins: int, descriptor: bytes) -> bytes:
    return record(ins, P1_FIRST_CHUNK, len(descriptor).to_bytes(2, "big") + descriptor)


def fragmented(ins: int, descriptor: bytes, split: int) -> bytes:
    first = len(descriptor).to_bytes(2, "big") + descriptor[:split]
    return record(ins, P1_FIRST_CHUNK, first) + record(ins, 0, descriptor[split:])


def trusted_name_v1(challenge: int = 0) -> bytes:
    return b"".join(
        [
            tlv(0x01, 0x03),
            tlv(0x02, 0x01),
            tlv(0x21, 60),
            tlv(0x20, "ledger.eth"),
            tlv(0x22, TRON_ADDRESS),
            tlv(0x12, challenge),
            tlv(0x13, 7),
            tlv(0x14, 1),
            tlv(0x15, DUMMY_DER_SIGNATURE),
        ]
    )


def proxy_info(challenge: int = 0) -> bytes:
    return b"".join(
        [
            tlv(0x01, 0x26),
            tlv(0x02, 0x01),
            tlv(0x12, challenge),
            tlv(0x22, TRON_ADDRESS),
            tlv(0x23, TRON_MAINNET_CHAIN_ID),
            tlv(0x41, b"\xa9\x05\x9c\xbb"),
            tlv(0x42, TRON_ADDRESS_2),
            tlv(0x43, 0),
            tlv(0x15, DUMMY_DER_SIGNATURE),
        ]
    )


def enum_value() -> bytes:
    return b"".join(
        [
            tlv(0x00, 1),
            tlv(0x01, TRON_MAINNET_CHAIN_ID),
            tlv(0x02, TRON_ADDRESS),
            tlv(0x03, b"\xa9\x05\x9c\xbb"),
            tlv(0x04, 1),
            tlv(0x05, 2),
            tlv(0x06, "approved"),
            tlv(0xFF, DUMMY_DER_SIGNATURE),
        ]
    )


def write_seed(name: str, certificate_status: int, stream: bytes) -> None:
    (OUT_DIR / name).write_bytes(bytes([certificate_status]) + stream)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    trusted = trusted_name_v1()
    proxy = proxy_info()
    enum = enum_value()

    write_seed("00-trusted-name-v1.bin", 0, single_chunk(INS_TRUSTED_NAME, trusted))
    write_seed("01-proxy-info.bin", 0, single_chunk(INS_PROXY_INFO, proxy))
    write_seed("02-enum-value.bin", 0, single_chunk(INS_ENUM_VALUE, enum))
    write_seed("03-proxy-info-fragmented.bin", 0, fragmented(INS_PROXY_INFO, proxy, 37))

    for status, label in [
        (1, "missing-certificate"),
        (2, "wrong-usage"),
        (3, "wrong-curve"),
        (4, "wrong-signature"),
        (5, "unknown-pki-error"),
    ]:
        write_seed(
            f"{status + 3:02d}-proxy-{label}.bin",
            status,
            single_chunk(INS_PROXY_INFO, proxy),
        )


if __name__ == "__main__":
    main()
