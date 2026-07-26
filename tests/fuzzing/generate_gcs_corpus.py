#!/usr/bin/env python3
"""Generate APDU-stream seeds for fuzz_gcs."""

from pathlib import Path

from generate_transaction_trigger_corpus import bytes_field, raw, trigger


OUT_DIR = Path(__file__).resolve().parent / "corpus" / "fuzz_gcs"

INS_SIGN_GCS = 0xD4
INS_GTP_TRANSACTION_INFO = 0x26
INS_GTP_FIELD = 0x28
P1_FIRST = 0x00
P1_MORE = 0x80
P1_LAST = 0x90
P1_SIGN = 0x10
P2_GCS_STORE = 0x10
P2_GCS_START_FLOW = 0x11

BIP32_PATH = [0x8000002C, 0x800000C3, 0x80000000, 0, 0]
OWNER = bytes.fromhex("41" + "11" * 20)
CALLEE = bytes.fromhex("41" + "22" * 20)
CALLDATA = bytes.fromhex("a9059cbb") + bytes(range(64))


def record(ins: int, p1: int, p2: int, payload: bytes = b"") -> bytes:
    assert len(payload) <= 0xFF
    return bytes((ins, p1, p2, len(payload))) + payload


def path() -> bytes:
    return bytes((len(BIP32_PATH),)) + b"".join(
        component.to_bytes(4, "big") for component in BIP32_PATH
    )


def store(raw_tx: bytes, chunk_size: int = 180) -> bytes:
    prefix = path() + len(raw_tx).to_bytes(4, "big")
    first_capacity = min(chunk_size, 0xFF - len(prefix))
    first = raw_tx[:first_capacity]
    offset = len(first)
    if offset == len(raw_tx):
        return record(INS_SIGN_GCS, P1_SIGN, P2_GCS_STORE, prefix + first)

    encoded = bytearray(record(INS_SIGN_GCS, P1_FIRST, P2_GCS_STORE,
                               prefix + first))
    while offset < len(raw_tx):
        chunk = raw_tx[offset:offset + chunk_size]
        offset += len(chunk)
        p1 = P1_LAST if offset == len(raw_tx) else P1_MORE
        encoded += record(INS_SIGN_GCS, p1, P2_GCS_STORE, chunk)
    return bytes(encoded)


def seed(settings: int, *records: bytes) -> bytes:
    return bytes((settings,)) + b"".join(records)


def write_seed(name: str, payload: bytes) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / name).write_bytes(payload)


def main() -> None:
    valid = raw(trigger(OWNER, CALLEE, CALLDATA, call_value=1_000_000),
                fee_limit=100_000_000, custom_data=b"ledger-fuzz")
    write_seed("00-valid-store.bin", seed(1, store(valid)))
    write_seed("01-byte-boundary-fragments.bin", seed(1, store(valid, chunk_size=1)))
    write_seed("02-memo-setting-disabled.bin", seed(0, store(valid)))

    trc10 = raw(trigger(OWNER, CALLEE, CALLDATA,
                        call_token_value=1, token_id=1_000_001),
                custom_data=b"")
    write_seed("03-trc10-values.bin", seed(1, store(trc10)))

    forbidden_raw = bytes_field(9, b"auth") + valid
    write_seed("04-forbidden-raw-field.bin", seed(1, store(forbidden_raw)))

    oversized_calldata = raw(trigger(OWNER, CALLEE, b"\x42" * 4097),
                             custom_data=b"")
    write_seed("05-calldata-4097.bin", seed(1, store(oversized_calldata)))

    declared = path() + (500 * 1024).to_bytes(4, "big") + valid[:32]
    write_seed("06-truncated-large-declaration.bin",
               seed(1, record(INS_SIGN_GCS, P1_FIRST, P2_GCS_STORE, declared)))

    write_seed("07-post-store-continuation.bin",
               seed(1, store(valid),
                    record(INS_SIGN_GCS, P1_MORE, P2_GCS_STORE, b"x")))
    write_seed("08-restart-during-store.bin",
               seed(1,
                    record(INS_SIGN_GCS, P1_FIRST, P2_GCS_STORE,
                           path() + len(valid).to_bytes(4, "big") + valid[:8]),
                    record(INS_SIGN_GCS, P1_FIRST, P2_GCS_STORE,
                           path() + len(valid).to_bytes(4, "big") + valid[:8])))
    write_seed("09-empty-continuation.bin",
               seed(1,
                    record(INS_SIGN_GCS, P1_FIRST, P2_GCS_STORE,
                           path() + len(valid).to_bytes(4, "big") + valid[:8]),
                    record(INS_SIGN_GCS, P1_MORE, P2_GCS_STORE)))

    write_seed("10-unauthenticated-descriptors.bin",
               seed(1, store(valid),
                    record(INS_GTP_TRANSACTION_INFO, 0, 0, b"\x01\x01\x01"),
                    record(INS_GTP_FIELD, 0, 0, b"\x01\x01\x01"),
                    record(INS_SIGN_GCS, P1_FIRST, P2_GCS_START_FLOW)))

    reserved_token_id = raw(trigger(OWNER, CALLEE, CALLDATA,
                                    token_id=1_000_000),
                            custom_data=b"")
    write_seed("11-trc10-reserved-token-id.bin",
               seed(1, store(reserved_token_id)))

    token_value_without_id = raw(trigger(OWNER, CALLEE, CALLDATA,
                                         call_token_value=1),
                                 custom_data=b"")
    write_seed("12-trc10-value-without-id.bin",
               seed(1, store(token_value_without_id)))

    incompressible = bytes.fromhex("a9059cbb") + (
        bytes(range(1, 256)) * 17
    )[:4092]
    maximum_root = raw(trigger(OWNER, CALLEE, incompressible), custom_data=b"")
    write_seed("13-maximum-root-clean-reentry.bin",
               seed(1,
                    store(maximum_root),
                    record(INS_SIGN_GCS, P1_FIRST, P2_GCS_START_FLOW),
                    store(valid)))


if __name__ == "__main__":
    main()
