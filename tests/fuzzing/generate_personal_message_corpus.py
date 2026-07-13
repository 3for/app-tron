#!/usr/bin/env python3

from pathlib import Path


OUT_DIR = Path(__file__).resolve().parent / "corpus" / "fuzz_personal_message"

INS_PERSONAL_MESSAGE = 0x08
INS_PERSONAL_MESSAGE_FULL_DISPLAY = 0xC8
P1_FIRST = 0x00
P1_MORE = 0x80

BIP32_PATH = [0x8000002C, 0x800000C3, 0x80000000, 0, 0]


def derivation_path() -> bytes:
    return bytes([len(BIP32_PATH)]) + b"".join(
        component.to_bytes(4, "big") for component in BIP32_PATH
    )


def record(ins: int, p1: int, payload: bytes, p2: int = 0) -> bytes:
    if len(payload) > 0xFF:
        raise ValueError("personal-message fuzz APDU payload exceeds one-byte length")
    return bytes([ins, p1, p2, len(payload)]) + payload


def message_stream(ins: int, message: bytes, chunk_size: int = 0xFF) -> bytes:
    payload = derivation_path() + len(message).to_bytes(4, "big") + message
    chunks = []
    p1 = P1_FIRST
    while payload:
        chunks.append(record(ins, p1, payload[:chunk_size]))
        payload = payload[chunk_size:]
        p1 = P1_MORE
    return b"".join(chunks)


def write_seed(name: str, stream: bytes, public_key_status: int = 0) -> None:
    (OUT_DIR / name).write_bytes(bytes([public_key_status]) + stream)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    write_seed(
        "00-legacy-ascii.bin",
        message_stream(INS_PERSONAL_MESSAGE, b"Example personal message"),
    )
    write_seed(
        "01-legacy-fragmented.bin",
        message_stream(INS_PERSONAL_MESSAGE, b"legacy-fragment-" * 24, 73),
    )
    write_seed(
        "02-full-display-ascii.bin",
        message_stream(
            INS_PERSONAL_MESSAGE_FULL_DISPLAY,
            b"Welcome to TRON!\n\nReview this message before signing.",
        ),
    )
    write_seed(
        "03-full-display-binary.bin",
        message_stream(
            INS_PERSONAL_MESSAGE_FULL_DISPLAY,
            bytes.fromhex("9c22ff5f21f0b81b113e63f7db6da94f"),
        ),
    )
    write_seed(
        "04-full-display-fragmented.bin",
        message_stream(
            INS_PERSONAL_MESSAGE_FULL_DISPLAY,
            b"Sign in request\nWallet: TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH\n" * 8,
            61,
        ),
    )
    write_seed(
        "05-empty-message.bin",
        message_stream(INS_PERSONAL_MESSAGE_FULL_DISPLAY, b""),
    )

    interrupted = derivation_path() + (40).to_bytes(4, "big") + b"partial"
    write_seed(
        "06-interleaved-restart.bin",
        record(INS_PERSONAL_MESSAGE, P1_FIRST, interrupted)
        + message_stream(INS_PERSONAL_MESSAGE_FULL_DISPLAY, b"restart"),
    )
    write_seed(
        "07-invalid-continuation.bin",
        record(INS_PERSONAL_MESSAGE_FULL_DISPLAY, P1_MORE, b"orphan")
        + record(INS_PERSONAL_MESSAGE, P1_FIRST, b"\x00", p2=1),
    )
    write_seed(
        "08-public-key-failure.bin",
        message_stream(INS_PERSONAL_MESSAGE_FULL_DISPLAY, b"key failure"),
        public_key_status=1,
    )


if __name__ == "__main__":
    main()
