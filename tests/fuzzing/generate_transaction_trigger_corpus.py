#!/usr/bin/env python3
"""Generate auditable protobuf seeds for transaction_trigger_decode_fuzzer.

Every output file is a raw protocol.Transaction.raw protobuf message.  The
fuzzer itself constructs the equivalent top-level Transaction wrapper so the
same seed drives both decoder entry modes.
"""

from pathlib import Path


OUT_DIR = Path(__file__).resolve().parent / "corpus" / "transaction_trigger_decode_fuzzer"
TYPE_URL = b"type.googleapis.com/protocol.TriggerSmartContract"


def varint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def key(tag: int, wire_type: int) -> bytes:
    return varint((tag << 3) | wire_type)


def uint_field(tag: int, value: int) -> bytes:
    return key(tag, 0) + varint(value)


def bytes_field(tag: int, value: bytes) -> bytes:
    return key(tag, 2) + varint(len(value)) + value


def fixed32_field(tag: int, value: bytes) -> bytes:
    assert len(value) == 4
    return key(tag, 5) + value


def fixed64_field(tag: int, value: bytes) -> bytes:
    assert len(value) == 8
    return key(tag, 1) + value


def trigger(owner: bytes = b"", contract_address: bytes = b"", data: bytes = b"",
            call_value: int = 0, call_token_value: int = 0, token_id: int = 0,
            include_addresses: bool = True, include_data: bool = True) -> bytes:
    message = bytearray()
    if include_addresses:
        message += bytes_field(1, owner)
        message += bytes_field(2, contract_address)
    if call_value:
        message += uint_field(3, call_value)
    if include_data:
        message += bytes_field(4, data)
    if call_token_value:
        message += uint_field(5, call_token_value)
    if token_id:
        message += uint_field(6, token_id)
    return bytes(message)


def contract(trigger_message: bytes, permission_id: int = 0) -> bytes:
    any_message = bytes_field(1, TYPE_URL) + bytes_field(2, trigger_message)
    message = uint_field(1, 31) + bytes_field(2, any_message)
    if permission_id:
        message += uint_field(5, permission_id)
    return message


def raw(trigger_message: bytes, fee_limit: int = 0, custom_data: bytes = b",") -> bytes:
    message = bytearray()
    if custom_data:
        message += bytes_field(10, custom_data)
    message += bytes_field(11, contract(trigger_message, permission_id=7))
    if fee_limit:
        message += uint_field(18, fee_limit)
    return bytes(message)


def write_seed(name: str, payload: bytes) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / name).write_bytes(payload)


def main() -> None:
    owner = bytes.fromhex("41" + "11" * 20)
    callee = bytes.fromhex("41" + "22" * 20)
    selector_and_args = bytes.fromhex("a9059cbb") + bytes(range(64))

    write_seed("00-minimal-empty-trigger.pb", raw(trigger(include_addresses=False,
                                                           include_data=False)))
    write_seed("01-transfer-call.pb", raw(trigger(owner, callee, selector_and_args,
                                                   call_value=1_000_000),
                                          fee_limit=100_000_000,
                                          custom_data=b"ledger-fuzz"))
    write_seed("02-token-values.pb", raw(trigger(owner, callee, selector_and_args,
                                                  call_token_value=2**40 + 7,
                                                  token_id=1_000_001),
                                         fee_limit=2**55 + 123))
    write_seed("03-zero-length-fields.pb", raw(trigger(b"", b"", b"")))
    write_seed("04-long-calldata.pb", raw(trigger(owner, callee,
                                                   bytes(range(256)) * 4),
                                          custom_data=bytes(range(64))))
    write_seed("05-oversized-addresses.pb", raw(trigger(owner + b"OWNER-TAIL",
                                                        callee + b"CALLEE-TAIL",
                                                        selector_and_args)))

    unknown_trigger = (fixed32_field(20, b"\x01\x02\x03\x04") +
                       trigger(owner, callee, selector_and_args) +
                       fixed64_field(21, bytes(range(8))))
    unknown_raw = (fixed32_field(12, b"\x44\x33\x22\x11") +
                   raw(unknown_trigger, fee_limit=999, custom_data=b"audit") +
                   bytes_field(19, b"unknown-field"))
    write_seed("06-unknown-fields.pb", unknown_raw)

    first = contract(trigger(owner, callee, selector_and_args), permission_id=1)
    second = contract(trigger(bytes.fromhex("41" + "33" * 20),
                              bytes.fromhex("41" + "44" * 20), b"second"),
                      permission_id=2)
    write_seed("07-multiple-contracts.pb",
               bytes_field(11, first) + bytes_field(11, second) + uint_field(18, 5000))


if __name__ == "__main__":
    main()
