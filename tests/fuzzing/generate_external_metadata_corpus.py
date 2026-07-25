#!/usr/bin/env python3

from pathlib import Path


OUT_DIR = Path(__file__).resolve().parent / "corpus" / "fuzz_external_metadata"

INS_TRUSTED_NAME = 0x22
INS_ENUM_VALUE = 0x24
INS_PROXY_INFO = 0x2A
INS_PROVIDE_NFT = 0x14
INS_PROVIDE_TRC20 = 0xCA
P1_FIRST_CHUNK = 0x01
P1_FOLLOWING_CHUNK = 0x00

TRON_ADDRESS = b"TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"
TRON_ADDRESS_2 = b"TFMA7iav1S9K46K2QaSKL5PV73qk4LcEcZ"
TRON_MAINNET_CHAIN_ID = 728126428
DUMMY_DER_SIGNATURE = b"\x30" + (b"\x00" * 66)


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
    return record(ins, P1_FIRST_CHUNK, first) + record(
        ins, P1_FOLLOWING_CHUNK, descriptor[split:]
    )


def trusted_name_v1(challenge: int = 0, key_id: int = 7) -> bytes:
    return b"".join(
        [
            tlv(0x01, 0x03),
            tlv(0x02, 0x01),
            tlv(0x21, 60),
            tlv(0x20, "ledger.eth"),
            tlv(0x22, TRON_ADDRESS),
            tlv(0x12, challenge),
            tlv(0x13, key_id),
            tlv(0x14, 1),
            tlv(0x15, DUMMY_DER_SIGNATURE),
        ]
    )


def trusted_name_v2_cal(
    chain_id: int = TRON_MAINNET_CHAIN_ID,
    key_id: int = 9,
    name: str = "Test Token",
) -> bytes:
    return b"".join(
        [
            tlv(0x01, 0x03),
            tlv(0x02, 0x02),
            tlv(0x70, 0x04),
            tlv(0x71, 0x01),
            tlv(0x20, name),
            tlv(0x22, TRON_ADDRESS),
            tlv(0x23, chain_id),
            tlv(0x13, key_id),
            tlv(0x14, 1),
            tlv(0x15, DUMMY_DER_SIGNATURE),
        ]
    )


def trusted_name_v2_mab(path: bytes) -> bytes:
    return b"".join(
        [
            tlv(0x01, 0x03),
            tlv(0x02, 0x02),
            tlv(0x70, 0x01),
            tlv(0x71, 0x07),
            tlv(0x20, "Address Book"),
            tlv(0x22, TRON_ADDRESS),
            tlv(0x23, TRON_MAINNET_CHAIN_ID),
            tlv(0x12, 0),
            tlv(0x74, b"\x00" * 20),
            tlv(0x75, path),
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


def enum_value(value: int = 2, name: str = "approved") -> bytes:
    return b"".join(
        [
            tlv(0x00, 1),
            tlv(0x01, TRON_MAINNET_CHAIN_ID),
            tlv(0x02, TRON_ADDRESS),
            tlv(0x03, b"\xa9\x05\x9c\xbb"),
            tlv(0x04, 1),
            tlv(0x05, value),
            tlv(0x06, name),
            tlv(0xFF, DUMMY_DER_SIGNATURE),
        ]
    )


def trc20_metadata(
    ticker: str = "TOK",
    decimals: int = 6,
    chain_id: int = TRON_MAINNET_CHAIN_ID,
) -> bytes:
    return b"".join(
        [
            bytes([len(ticker)]),
            ticker.encode(),
            TRON_ADDRESS,
            decimals.to_bytes(4, "big"),
            chain_id.to_bytes(4, "big"),
            DUMMY_DER_SIGNATURE,
        ]
    )


def nft_metadata(
    name: str = "Collection",
    chain_id: int = TRON_MAINNET_CHAIN_ID,
    key_id: int = 1,
    trailing: bytes = b"",
) -> bytes:
    signed_payload = b"".join(
        [
            b"\x01\x01",
            bytes([len(name)]),
            name.encode(),
            TRON_ADDRESS,
            chain_id.to_bytes(8, "big"),
            bytes([key_id, 1]),
        ]
    )
    return (
        signed_payload
        + bytes([len(DUMMY_DER_SIGNATURE)])
        + DUMMY_DER_SIGNATURE
        + trailing
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

    cal = trusted_name_v2_cal()
    write_seed("09-trusted-name-cal.bin", 0x80, single_chunk(INS_TRUSTED_NAME, cal))
    write_seed(
        "10-domain-certificate-for-cal.bin",
        0,
        single_chunk(INS_TRUSTED_NAME, cal),
    )
    write_seed(
        "11-cal-certificate-for-domain.bin",
        0x80,
        single_chunk(INS_TRUSTED_NAME, trusted),
    )
    write_seed(
        "12-cal-wrong-key-id.bin",
        0x80,
        single_chunk(INS_TRUSTED_NAME, trusted_name_v2_cal(key_id=7)),
    )
    write_seed(
        "13-trusted-name-oversized-declaration.bin",
        0,
        record(INS_TRUSTED_NAME, P1_FIRST_CHUNK, (513).to_bytes(2, "big")),
    )
    write_seed(
        "14-cross-ins-continuation.bin",
        0,
        record(
            INS_TRUSTED_NAME,
            P1_FIRST_CHUNK,
            (300).to_bytes(2, "big") + trusted[:20],
        )
        + record(INS_PROXY_INFO, P1_FOLLOWING_CHUNK, proxy[:20]),
    )
    write_seed(
        "15-zero-length-continuation.bin",
        0,
        record(
            INS_TRUSTED_NAME,
            P1_FIRST_CHUNK,
            len(trusted).to_bytes(2, "big") + trusted[:20],
        )
        + record(INS_TRUSTED_NAME, P1_FOLLOWING_CHUNK, b""),
    )
    write_seed(
        "16-invalid-trusted-name-p1-p2.bin",
        0,
        record(INS_TRUSTED_NAME, 0x7F, b"", p2=1),
    )
    write_seed(
        "17-replayed-cal-descriptor.bin",
        0x80,
        b"".join(single_chunk(INS_TRUSTED_NAME, cal) for _ in range(12)),
    )
    write_seed(
        "18-trusted-name-cache-cap.bin",
        0x80,
        b"".join(
            single_chunk(
                INS_TRUSTED_NAME,
                trusted_name_v2_cal(chain_id=TRON_MAINNET_CHAIN_ID + i),
            )
            for i in range(10)
        ),
    )
    write_seed(
        "19-mab-ten-component-path.bin",
        0,
        single_chunk(
            INS_TRUSTED_NAME,
            trusted_name_v2_mab(bytes([10]) + (b"\x80\x00\x00\x00" * 10)),
        ),
    )
    write_seed(
        "20-mab-path-trailing-byte.bin",
        0,
        single_chunk(
            INS_TRUSTED_NAME,
            trusted_name_v2_mab(bytes([1]) + b"\x80\x00\x00\x00\xff"),
        ),
    )
    write_seed(
        "21-cross-p2-continuation.bin",
        0,
        record(
            INS_ENUM_VALUE,
            P1_FIRST_CHUNK,
            len(enum).to_bytes(2, "big") + enum[:20],
        )
        + record(INS_ENUM_VALUE, P1_FOLLOWING_CHUNK, enum[20:], p2=1),
    )
    write_seed(
        "22-replayed-enum-value.bin",
        0,
        b"".join(single_chunk(INS_ENUM_VALUE, enum) for _ in range(20)),
    )
    write_seed(
        "23-enum-value-cache-cap.bin",
        0,
        b"".join(
            single_chunk(
                INS_ENUM_VALUE,
                enum_value(value=i, name=f"value-{i}"),
            )
            for i in range(18)
        ),
    )
    proxy_without_challenge = proxy.replace(tlv(0x12, 0), b"", 1)
    write_seed(
        "24-proxy-missing-challenge.bin",
        0,
        single_chunk(INS_PROXY_INFO, proxy_without_challenge),
    )
    write_seed(
        "25-trc20-valid.bin",
        0,
        record(INS_PROVIDE_TRC20, 0, trc20_metadata()),
    )
    write_seed(
        "26-trc20-ring-invalid-replacement.bin",
        0,
        b"".join(
            record(INS_PROVIDE_TRC20, 0, trc20_metadata(ticker=f"TOK{i}"))
            for i in range(5)
        )
        + record(
            INS_PROVIDE_TRC20,
            0,
            trc20_metadata(ticker="EVIL", chain_id=TRON_MAINNET_CHAIN_ID + 1),
        ),
    )
    write_seed(
        "27-trc20-decimals-overflow.bin",
        0,
        record(INS_PROVIDE_TRC20, 0, trc20_metadata(decimals=256)),
    )
    write_seed(
        "28-nft-valid.bin",
        0,
        record(INS_PROVIDE_NFT, 0, nft_metadata()),
    )
    write_seed(
        "29-nft-ring-invalid-replacement.bin",
        0,
        b"".join(
            record(INS_PROVIDE_NFT, 0, nft_metadata(name=f"NFT{i}"))
            for i in range(5)
        )
        + record(INS_PROVIDE_NFT, 0, nft_metadata(name="EVIL", key_id=2)),
    )
    write_seed(
        "30-nft-trailing-data.bin",
        0,
        record(INS_PROVIDE_NFT, 0, nft_metadata(trailing=b"\xff")),
    )
    write_seed(
        "31-trc20-invalid-p1-p2.bin",
        0,
        record(INS_PROVIDE_TRC20, 1, trc20_metadata(), p2=1),
    )
    write_seed(
        "32-nft-invalid-p1-p2.bin",
        0,
        record(INS_PROVIDE_NFT, 1, nft_metadata(), p2=1),
    )


if __name__ == "__main__":
    main()
