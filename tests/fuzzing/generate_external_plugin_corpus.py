#!/usr/bin/env python3
import hashlib
from pathlib import Path


CONFIG_SIZE = 16
OP_RESET = 0x00
OP_SET_EXTERNAL_PLUGIN = 0x01
OP_SIGN_EXTERNAL_PLUGIN = 0x02

P1_SIGN = 0x10
P1_FIRST = 0x00
P1_MORE = 0x80
P1_LAST = 0x90

WIRE_VARINT = 0
WIRE_LEN = 2

TRC20_SELECTOR = bytes.fromhex("a9059cbb")
ALT_SELECTOR = bytes.fromhex("deadbeef")
PLUGIN_NAME = b"fuzzplug"
OWNER_ADDRESS = bytes.fromhex("41" + "12" * 20)
CONTRACT_ADDRESS = bytes.fromhex("41" + "34" * 20)
OTHER_CONTRACT_ADDRESS = bytes.fromhex("41" + "56" * 20)
TYPE_URL = b"type.googleapis.com/protocol.TriggerSmartContract"
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

REPO_ROOT = Path(__file__).resolve().parents[2]


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field_key(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def field_varint(field_number: int, value: int) -> bytes:
    return field_key(field_number, WIRE_VARINT) + encode_varint(value)


def field_bytes(field_number: int, value: bytes) -> bytes:
    return field_key(field_number, WIRE_LEN) + encode_varint(len(value)) + value


def encode_trigger_smart_contract(data: bytes, call_value: int = 0) -> bytes:
    payload = bytearray()
    payload += field_bytes(1, OWNER_ADDRESS)
    payload += field_bytes(2, CONTRACT_ADDRESS)
    if call_value != 0:
        payload += field_varint(3, call_value)
    payload += field_bytes(4, data)
    return bytes(payload)


def encode_any(trigger_payload: bytes) -> bytes:
    payload = bytearray()
    payload += field_bytes(1, TYPE_URL)
    payload += field_bytes(2, trigger_payload)
    return bytes(payload)


def encode_contract(trigger_payload: bytes, permission_id=None) -> bytes:
    payload = bytearray()
    payload += field_varint(1, 31)
    payload += field_bytes(2, encode_any(trigger_payload))
    if permission_id is not None:
        payload += field_varint(5, permission_id)
    return bytes(payload)


def encode_raw_transaction(data: bytes, call_value: int = 0, permission_id=None) -> bytes:
    contract_payload = encode_contract(
        encode_trigger_smart_contract(data, call_value=call_value),
        permission_id=permission_id,
    )
    payload = bytearray()
    payload += field_bytes(1, bytes.fromhex("3DCE"))
    payload += field_bytes(4, bytes.fromhex("95DA42177DB00507"))
    payload += field_varint(8, 1575712551000)
    payload += field_bytes(11, contract_payload)
    payload += field_varint(14, 1575712492061)
    return bytes(payload)


def base58check_encode(raw: bytes) -> bytes:
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    value = int.from_bytes(raw + checksum, "big")
    encoded = bytearray()

    while value > 0:
        value, digit = divmod(value, 58)
        encoded.append(BASE58_ALPHABET[digit])

    for byte in raw + checksum:
        if byte == 0:
            encoded.append(BASE58_ALPHABET[0])
        else:
            break

    encoded.reverse()
    return bytes(encoded)


def build_set_payload(contract_address: bytes, selector: bytes) -> bytes:
    return (bytes([len(PLUGIN_NAME)]) + PLUGIN_NAME +
            base58check_encode(contract_address) + selector + b"\x42")


def encode_config(
    *,
    signature_valid: bool = True,
    presence_mode: int = 0,
    init_mode: int = 0,
    parameter_mode: int = 0,
    parameter_fail_cfg: int = 0,
    finalize_mode: int = 0,
    ui_type_mode: int = 0,
    num_screens: int = 1,
    token_lookup_mode: int = 1,
    provide_info_mode: int = 0,
    additional_screens: int = 0,
    query_contract_id_mode: int = 0,
    empty_contract_name: bool = False,
    empty_contract_version: bool = False,
    query_contract_ui_mode: int = 0,
    query_contract_ui_fail_index: int = 0xFF,
) -> bytes:
    flags = 0
    if empty_contract_name:
        flags |= 0x01
    if empty_contract_version:
        flags |= 0x02

    return bytes([
        0x00,
        0x00 if signature_valid else 0x01,
        presence_mode & 0xFF,
        init_mode & 0xFF,
        parameter_mode & 0xFF,
        parameter_fail_cfg & 0xFF,
        finalize_mode & 0xFF,
        ui_type_mode & 0xFF,
        num_screens & 0xFF,
        token_lookup_mode & 0xFF,
        provide_info_mode & 0xFF,
        additional_screens & 0xFF,
        query_contract_id_mode & 0xFF,
        flags & 0xFF,
        query_contract_ui_mode & 0xFF,
        query_contract_ui_fail_index & 0xFF,
    ])


def op_reset() -> bytes:
    return bytes([OP_RESET])


def op_set(contract_address: bytes, selector: bytes) -> bytes:
    payload = build_set_payload(contract_address, selector)
    return bytes([OP_SET_EXTERNAL_PLUGIN, 0x00, 0x00, len(payload)]) + payload


def sign_payload(raw_tx: bytes) -> bytes:
    path = bytes.fromhex(
        "05"
        "8000002c"
        "800000c3"
        "80000000"
        "00000000"
        "00000000"
    )
    return path + len(raw_tx).to_bytes(4, "big") + raw_tx


def op_sign_single(raw_tx: bytes) -> bytes:
    payload = sign_payload(raw_tx)
    if len(payload) > 0xFF:
        raise ValueError("single sign payload exceeds one-byte op length")
    return bytes([OP_SIGN_EXTERNAL_PLUGIN, P1_SIGN, 0x00, len(payload)]) + payload


def op_sign_chunked(raw_tx: bytes, split1: int, split2: int) -> bytes:
    full = sign_payload(raw_tx)
    first = full[:split1]
    second = full[split1:split2]
    third = full[split2:]
    for chunk in (first, second, third):
        if len(chunk) > 0xFF:
            raise ValueError("chunked sign payload exceeds one-byte op length")
    return b"".join([
        bytes([OP_SIGN_EXTERNAL_PLUGIN, P1_FIRST, 0x00, len(first)]) + first,
        bytes([OP_SIGN_EXTERNAL_PLUGIN, P1_MORE, 0x00, len(second)]) + second,
        bytes([OP_SIGN_EXTERNAL_PLUGIN, P1_LAST, 0x00, len(third)]) + third,
    ])


def write_seed(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def main() -> None:
    corpus_dir = REPO_ROOT / "tests" / "fuzzing" / "corpus" / "fuzz_external_plugin"

    call_data_full = TRC20_SELECTOR + (b"\x00" * 64)
    call_data_tail = TRC20_SELECTOR + (b"\xAB" * 20)

    tx_full = encode_raw_transaction(call_data_full, call_value=1234567)
    tx_tail = encode_raw_transaction(call_data_tail, call_value=0, permission_id=2)

    seeds = {
        "00-positive.bin": (
            encode_config() +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "01-selector-mismatch.bin": (
            encode_config() +
            op_set(CONTRACT_ADDRESS, ALT_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "02-contract-mismatch.bin": (
            encode_config() +
            op_set(OTHER_CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "03-parameter-tail.bin": (
            encode_config(num_screens=1) +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_tail)
        ),
        "04-parameter-failure.bin": (
            encode_config(parameter_fail_cfg=0x80 | 0x01) +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "05-finalize-fallback.bin": (
            encode_config(finalize_mode=0x01) +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "06-ui-query-fail.bin": (
            encode_config(num_screens=2, query_contract_ui_fail_index=1) +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "07-ui-zero.bin": (
            encode_config(num_screens=0) +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "08-ui-oversized.bin": (
            encode_config(num_screens=32) +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_single(tx_full)
        ),
        "09-multi-chunk.bin": (
            encode_config() +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_chunked(tx_full, split1=48, split2=96)
        ),
        "10-reset-invalid-order.bin": (
            encode_config() +
            op_set(CONTRACT_ADDRESS, TRC20_SELECTOR) +
            op_sign_chunked(tx_full, split1=32, split2=64) +
            op_reset() +
            bytes([OP_SIGN_EXTERNAL_PLUGIN, P1_MORE, 0x00, 0x00])
        ),
    }

    for name, payload in seeds.items():
        write_seed(corpus_dir / name, payload)

    print(f"wrote {len(seeds)} seeds to {corpus_dir}")


if __name__ == "__main__":
    main()
