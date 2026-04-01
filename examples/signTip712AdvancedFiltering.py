#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Send the same TIP-712 advanced filtering payload as
tests/ragger/test_trx.py::TestTRX::test_trx_tip712_advanced_filtering[data_set0-...]
to a real Ledger device.

Prerequisites on device:
- `Data allowed` enabled
- `Sign by hash` enabled

Typical usage:
    python examples/signTip712AdvancedFiltering.py --device flex
    python examples/signTip712AdvancedFiltering.py --device nanosp --path "44'/195'/0'/0/0"
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import base58
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from eth_keys import KeyAPI
from eth_utils import keccak

from base import parse_bip32_path_to_bytes


REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_RAGGER_DIR = REPO_ROOT / "tests" / "ragger"
if str(TESTS_RAGGER_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_RAGGER_DIR))

import keychain  # noqa: E402
from tron_encode_typed_data.encoding_and_hashing import hash_eip712_message, hash_struct  # noqa: E402


CLA = 0xE0
PKI_CLA = 0xB0
PKI_INS = 0x06

INS_GET_PUBLIC_ADDR = 0x02
INS_TIP712_SIGN = 0x0C
INS_TIP712_STRUCT_DEF = 0x1A
INS_TIP712_STRUCT_IMPL = 0x1C
INS_TIP712_FILTERING = 0x1E
INS_PROVIDE_TRC20_TOKEN_INFORMATION = 0xCA

P1_COMPLETE = 0x00
P1_PARTIAL = 0xFF
P1_DISCARDED = 0x01

P2_STRUCT_NAME = 0x00
P2_STRUCT_FIELD = 0xFF
P2_ARRAY = 0x0F
P2_NEW_IMPLEM = 0x01
P2_FILTERING_ACTIVATE = 0x00
P2_FILTERING_DISCARDED_PATH = 0x01
P2_FILTERING_MESSAGE_INFO = 0x0F
P2_FILTERING_TRUSTED_NAME = 0xFB
P2_FILTERING_DATETIME = 0xFC
P2_FILTERING_TOKEN_ADDR_CHECK = 0xFD
P2_FILTERING_AMOUNT_FIELD = 0xFE
P2_FILTERING_RAW = 0xFF

TIP712_TYPE_CUSTOM = 0
TIP712_TYPE_INT = 1
TIP712_TYPE_UINT = 2
TIP712_TYPE_ADDRESS = 3
TIP712_TYPE_BOOL = 4
TIP712_TYPE_STRING = 5
TIP712_TYPE_FIX_BYTES = 6
TIP712_TYPE_DYN_BYTES = 7
TIP712_TYPE_TRCTOKEN = 8


ADVANCED_DATA = {
    "domain": {
        "chainId": 1151668124,
        "name": "Advanced test",
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        "version": "1",
    },
    "message": {
        "with": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "value_recv": 10000000000000000,
        "token_send": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "value_send": 24500000000000000000,
        "token_recv": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        "expires": 1714559400,
    },
    "primaryType": "Transfer",
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Transfer": [
            {"name": "with", "type": "address"},
            {"name": "value_recv", "type": "uint256"},
            {"name": "token_send", "type": "address"},
            {"name": "value_send", "type": "uint256"},
            {"name": "token_recv", "type": "address"},
            {"name": "expires", "type": "uint64"},
        ],
    },
}

ADVANCED_FILTERS = {
    "name": "Advanced Filtering",
    "tokens": [
        {
            "addr": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "ticker": "WETH",
            "decimals": 18,
            "chain_id": 1151668124,
        },
        {
            "addr": "0x6b175474e89094c44da98b954eedeac495271d0f",
            "ticker": "DAI",
            "decimals": 18,
            "chain_id": 1151668124,
        },
    ],
    "fields": {
        "value_send": {
            "type": "amount_join_value",
            "name": "Send",
            "token": 1,
        },
        "token_send": {
            "type": "amount_join_token",
            "token": 1,
        },
        "value_recv": {
            "type": "amount_join_value",
            "name": "Receive",
            "token": 0,
        },
        "token_recv": {
            "type": "amount_join_token",
            "token": 0,
        },
        "with": {
            "type": "raw",
            "name": "With",
        },
        "expires": {
            "type": "datetime",
            "name": "Will Expire",
        },
    },
}

COIN_META_CERTIFICATES = {
    "nanosp": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010310040102000015473045022100C15795C2AE41E6FAE6B1362EE1AE216428507D7C1D6939B928559CC7A1F6425C02206139CF2E133DD62F3E00F183E42109C9853AC62B6B70C5079B9A80DBB9D54AB5",
    "nanox": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010215473045022100E3B956F93FBFF0D41908483888F0F75D4714662A692F7A38DC6C41A13294F9370220471991BECB3CA4F43413CADC8FF738A8CC03568BFA832B4DCFE8C469080984E5",
    "stax": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501041546304402206731FCD3E2432C5CA162381392FD17AD3A41EEF852E1D706F21A656AB165263602204B89FAE8DBAF191E2D79FB00EBA80D613CB7EDF0BE960CB6F6B29D96E1437F5F",
    "flex": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010515473045022100B59EA8B958AA40578A6FBE9BBFB761020ACD5DBD8AA863C11DA17F42B2AFDE790220186316059EFA58811337D47C7F815F772EA42BBBCEA4AE123D1118C80588F5CB",
    "apex_p": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501061546304402207AB71BB46DD2361292195E95587D14FEDE2BA10FC23F0D6B20444B93A32258D302201362A6815779B2806005B0151BFADB811B78A76FDB90028FBE6C93EB7FB5EEA3",
}


def serialize_apdu(cla: int, ins: int, p1: int, p2: int, cdata: bytes = b"") -> bytes:
    return bytes([cla, ins, p1, p2, len(cdata)]) + cdata


def apdu_get_public_addr(path: str) -> bytes:
    path_bytes = parse_bip32_path_to_bytes(path)
    payload = bytes([len(path_bytes) // 4]) + path_bytes
    return serialize_apdu(CLA, INS_GET_PUBLIC_ADDR, 0x00, 0x00, payload)


def apdu_tip712_send_struct_def_name(name: str) -> bytes:
    return serialize_apdu(CLA, INS_TIP712_STRUCT_DEF, P1_COMPLETE, P2_STRUCT_NAME, name.encode())


def apdu_tip712_send_struct_def_field(field_type: int,
                                      type_name: str,
                                      type_size: Optional[int],
                                      array_levels: List[Optional[int]],
                                      key_name: str) -> bytes:
    payload = bytearray()
    typedesc = 0
    typedesc |= (1 if array_levels else 0) << 7
    typedesc |= (1 if type_size is not None else 0) << 6
    typedesc |= field_type
    payload.append(typedesc)

    if field_type == TIP712_TYPE_CUSTOM:
        payload.append(len(type_name))
        payload += type_name.encode()
    if type_size is not None:
        payload.append(type_size)
    if array_levels:
        payload.append(len(array_levels))
        for level in array_levels:
            payload.append(0 if level is None else 1)
            if level is not None:
                payload.append(level)
    payload.append(len(key_name))
    payload += key_name.encode()
    return serialize_apdu(CLA, INS_TIP712_STRUCT_DEF, P1_COMPLETE, P2_STRUCT_FIELD, payload)


def apdu_tip712_send_struct_impl_root(name: str) -> bytes:
    return serialize_apdu(CLA, INS_TIP712_STRUCT_IMPL, P1_COMPLETE, P2_STRUCT_NAME, name.encode())


def apdu_tip712_send_struct_impl_field(data: bytes) -> List[bytes]:
    payload = struct.pack(">H", len(data)) + data
    chunks = []
    while payload:
        chunk = payload[:0xFF]
        payload = payload[0xFF:]
        p1 = P1_PARTIAL if payload else P1_COMPLETE
        chunks.append(serialize_apdu(CLA, INS_TIP712_STRUCT_IMPL, p1, P2_STRUCT_FIELD, chunk))
    return chunks


def apdu_tip712_filtering_activate() -> bytes:
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_COMPLETE, P2_FILTERING_ACTIVATE, b"")


def apdu_tip712_filtering_discarded_path(path: str) -> bytes:
    payload = bytes([len(path)]) + path.encode()
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_COMPLETE, P2_FILTERING_DISCARDED_PATH,
                          payload)


def apdu_tip712_filtering_message_info(name: str, filters_count: int, sig: bytes) -> bytes:
    payload = bytes([len(name)]) + name.encode() + bytes([filters_count, len(sig)]) + sig
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_COMPLETE, P2_FILTERING_MESSAGE_INFO,
                          payload)


def apdu_tip712_filtering_amount_join_token(token_idx: int, sig: bytes, discarded: bool) -> bytes:
    payload = bytes([token_idx, len(sig)]) + sig
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_DISCARDED if discarded else P1_COMPLETE,
                          P2_FILTERING_TOKEN_ADDR_CHECK, payload)


def apdu_tip712_filtering_amount_join_value(token_idx: int,
                                            name: str,
                                            sig: bytes,
                                            discarded: bool) -> bytes:
    payload = bytes([len(name)]) + name.encode() + bytes([token_idx, len(sig)]) + sig
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_DISCARDED if discarded else P1_COMPLETE,
                          P2_FILTERING_AMOUNT_FIELD, payload)


def apdu_tip712_filtering_datetime(name: str, sig: bytes, discarded: bool) -> bytes:
    payload = bytes([len(name)]) + name.encode() + bytes([len(sig)]) + sig
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_DISCARDED if discarded else P1_COMPLETE,
                          P2_FILTERING_DATETIME, payload)


def apdu_tip712_filtering_raw(name: str, sig: bytes, discarded: bool) -> bytes:
    payload = bytes([len(name)]) + name.encode() + bytes([len(sig)]) + sig
    return serialize_apdu(CLA, INS_TIP712_FILTERING, P1_DISCARDED if discarded else P1_COMPLETE,
                          P2_FILTERING_RAW, payload)


def apdu_tip712_sign_new(path: str) -> bytes:
    path_bytes = parse_bip32_path_to_bytes(path)
    payload = bytes([len(path_bytes) // 4]) + path_bytes
    return serialize_apdu(CLA, INS_TIP712_SIGN, P1_COMPLETE, P2_NEW_IMPLEM, payload)


def apdu_provide_trc20_token_information(ticker: str,
                                         addr: bytes,
                                         decimals: int,
                                         chain_id: int,
                                         sig: bytes) -> bytes:
    payload = bytearray()
    payload.append(len(ticker))
    payload += ticker.encode()
    payload += addr
    payload += struct.pack(">I", decimals)
    payload += struct.pack(">I", chain_id)
    payload += sig
    return serialize_apdu(CLA, INS_PROVIDE_TRC20_TOKEN_INFORMATION, 0x00, 0x00, payload)


def apdu_send_coin_meta_certificate(device: str) -> Optional[bytes]:
    cert_hex = COIN_META_CERTIFICATES.get(device)
    if cert_hex is None:
        return None
    payload = bytes.fromhex(cert_hex)
    return serialize_apdu(PKI_CLA, PKI_INS, 0x08, 0x00, payload)


def exchange(dongle, apdu: bytes, label: str) -> bytes:
    print(f"{label} => {apdu.hex()}")
    response = dongle.exchange(apdu)
    if response:
        print(f"{label} <= {response.hex()}")
    else:
        print(f"{label} <= 9000")
    return response


def parse_pk_addr(response: bytes) -> Tuple[bytes, bytes]:
    idx = 0
    pk_len = response[idx]
    idx += 1
    pubkey = response[idx:idx + pk_len]
    idx += pk_len
    addr_len = response[idx]
    idx += 1
    raw_addr = base58.b58decode_check(response[idx:idx + addr_len])
    return pubkey, raw_addr


def to_raw_address(raw_addr: str) -> bytes:
    if raw_addr.startswith("0x"):
        return b"\x41" + bytes.fromhex(raw_addr[2:])
    if raw_addr.startswith("41"):
        return bytes.fromhex(raw_addr)
    if raw_addr.startswith("T"):
        return base58.b58decode_check(raw_addr)
    raise ValueError(f"Unsupported address format: {raw_addr}")


def to_tvm_address(raw_addr: str) -> bytes:
    return to_raw_address(raw_addr)[1:]


def to_base58check(raw_addr: bytes) -> str:
    return base58.b58encode_check(raw_addr).decode()


def encode_integer(value: int, type_size: int) -> bytes:
    if value == 0:
        return b"\x00"
    packed = struct.pack(">QQQQ",
                         (value >> 192) & 0xFFFFFFFFFFFFFFFF,
                         (value >> 128) & 0xFFFFFFFFFFFFFFFF,
                         (value >> 64) & 0xFFFFFFFFFFFFFFFF,
                         value & 0xFFFFFFFFFFFFFFFF)
    packed = packed[-type_size:]
    return packed.lstrip(b"\x00")


def encode_address(value: str) -> bytes:
    return to_tvm_address(value)


def encode_value(field_type: str, value) -> bytes:
    if field_type == "string":
        return value.encode()
    if field_type == "address":
        return encode_address(value)
    if field_type.startswith("uint"):
        bits = int(field_type[4:])
        return encode_integer(int(value), bits // 8)
    raise ValueError(f"Unsupported field type in example: {field_type}")


def get_array_levels(type_name: str) -> Tuple[str, List[Optional[int]]]:
    array_levels = []
    while type_name.endswith("]"):
        match = re.search(r"^(.*)\[(.*?)\]$", type_name)
        if match is None:
            raise ValueError(f"Unsupported array type: {type_name}")
        type_name = match.group(1)
        level_size = match.group(2)
        array_levels.insert(0, None if level_size == "" else int(level_size))
    return type_name, array_levels


def parse_field_type(type_name: str) -> Tuple[int, str, Optional[int], List[Optional[int]]]:
    base_type, array_levels = get_array_levels(type_name)
    match = re.match(r"^(\w+?)(\d*)$", base_type)
    if match is None:
        raise ValueError(f"Unsupported type: {type_name}")
    typename = match.group(1)
    type_size_bits = match.group(2)
    type_size = None if type_size_bits == "" else int(type_size_bits)

    if typename == "string":
        return TIP712_TYPE_STRING, typename, None, array_levels
    if typename == "address":
        return TIP712_TYPE_ADDRESS, typename, None, array_levels
    if typename == "uint":
        return TIP712_TYPE_UINT, typename, type_size // 8, array_levels
    if typename == "int":
        return TIP712_TYPE_INT, typename, type_size // 8, array_levels
    if typename == "bool":
        return TIP712_TYPE_BOOL, typename, None, array_levels
    if typename == "bytes":
        if type_size is None:
            return TIP712_TYPE_DYN_BYTES, typename, None, array_levels
        return TIP712_TYPE_FIX_BYTES, typename, type_size, array_levels
    if typename == "trcToken":
        return TIP712_TYPE_TRCTOKEN, typename, None, array_levels
    return TIP712_TYPE_CUSTOM, typename, None, array_levels


def compute_signature_context(data: dict) -> Dict[str, bytes]:
    types_json = json.dumps(data["types"]).replace(" ", "")
    contract = data["domain"]["verifyingContract"]
    if contract.startswith("0x"):
        contract = contract[2:]
    return {
        "chainid": int(data["domain"]["chainId"]).to_bytes(8, "big"),
        "caddr": bytes.fromhex(contract),
        "schema_hash": hashlib.sha224(types_json.encode()).digest(),
    }


def start_filter_signature_payload(sig_ctx: Dict[str, bytes], magic: int) -> bytearray:
    payload = bytearray()
    payload.append(magic)
    payload += sig_ctx["chainid"]
    payload += sig_ctx["caddr"]
    payload += sig_ctx["schema_hash"]
    return payload


def send_coin_meta_certificate(dongle, device: str) -> None:
    apdu = apdu_send_coin_meta_certificate(device)
    if apdu is None:
        print(f"[WARN] No coin-meta certificate configured for device '{device}', skipped.")
        return
    try:
        exchange(dongle, apdu, "coin_meta_cert")
    except CommException as exc:
        sw = getattr(exc, "sw", None)
        if sw is None and len(exc.args) >= 2:
            sw = exc.args[1]
        if isinstance(sw, int):
            print(f"[WARN] coin_meta_cert rejected by device: 0x{sw:04x}")
        else:
            print(f"[WARN] coin_meta_cert rejected by device: {exc}")
        print("[WARN] This certificate is the test certificate used by ragger/speculos.")
        print("[WARN] On real hardware, PKI validation may reject it.")
        print("[WARN] Continuing without coin-meta certificate.")


def provide_token_metadata(dongle, token: dict) -> None:
    unsigned_apdu = apdu_provide_trc20_token_information(
        token["ticker"],
        to_raw_address(token["addr"]),
        token["decimals"],
        token["chain_id"],
        b"",
    )
    sig = keychain.sign_data(keychain.Key.CAL, unsigned_apdu[6:])
    apdu = apdu_provide_trc20_token_information(token["ticker"],
                                                to_raw_address(token["addr"]),
                                                token["decimals"],
                                                token["chain_id"],
                                                sig)
    exchange(dongle, apdu, f"token_meta:{token['ticker']}")


def send_filtering_message_info(dongle, sig_ctx: Dict[str, bytes], display_name: str,
                                filters_count: int) -> None:
    payload = start_filter_signature_payload(sig_ctx, 183)
    payload.append(filters_count)
    payload += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, payload)
    exchange(dongle,
             apdu_tip712_filtering_message_info(display_name, filters_count, sig),
             "filtering:message_info")


def send_filter(dongle,
                sig_ctx: Dict[str, bytes],
                field_path: str,
                filter_rule: dict,
                sent_tokens: set,
                discarded: bool = False) -> None:
    filter_type = filter_rule["type"]

    if filter_type.startswith("amount_join_"):
        token_idx = filter_rule.get("token", 0)
        if token_idx not in sent_tokens:
            provide_token_metadata(dongle, ADVANCED_FILTERS["tokens"][token_idx])
            sent_tokens.add(token_idx)

        if filter_type.endswith("_token"):
            payload = start_filter_signature_payload(sig_ctx, 11)
            payload += field_path.encode()
            payload.append(token_idx)
            sig = keychain.sign_data(keychain.Key.CAL, payload)
            exchange(dongle,
                     apdu_tip712_filtering_amount_join_token(token_idx, sig, discarded),
                     f"filtering:{field_path}")
            return

        payload = start_filter_signature_payload(sig_ctx, 22)
        payload += field_path.encode()
        payload += filter_rule["name"].encode()
        payload.append(token_idx)
        sig = keychain.sign_data(keychain.Key.CAL, payload)
        exchange(dongle,
                 apdu_tip712_filtering_amount_join_value(token_idx,
                                                         filter_rule["name"],
                                                         sig,
                                                         discarded),
                 f"filtering:{field_path}")
        return

    if filter_type == "datetime":
        payload = start_filter_signature_payload(sig_ctx, 33)
        payload += field_path.encode()
        payload += filter_rule["name"].encode()
        sig = keychain.sign_data(keychain.Key.CAL, payload)
        exchange(dongle,
                 apdu_tip712_filtering_datetime(filter_rule["name"], sig, discarded),
                 f"filtering:{field_path}")
        return

    if filter_type == "raw":
        payload = start_filter_signature_payload(sig_ctx, 72)
        payload += field_path.encode()
        payload += filter_rule["name"].encode()
        sig = keychain.sign_data(keychain.Key.CAL, payload)
        exchange(dongle,
                 apdu_tip712_filtering_raw(filter_rule["name"], sig, discarded),
                 f"filtering:{field_path}")
        return

    raise ValueError(f"Unsupported filter type in example: {filter_type}")


def send_struct_definitions(dongle, data: dict) -> None:
    for struct_name, fields in data["types"].items():
        exchange(dongle,
                 apdu_tip712_send_struct_def_name(struct_name),
                 f"struct_def:{struct_name}")
        for field in fields:
            field_type, type_name, type_size, array_levels = parse_field_type(field["type"])
            exchange(dongle,
                     apdu_tip712_send_struct_def_field(field_type,
                                                       type_name,
                                                       type_size,
                                                       array_levels,
                                                       field["name"]),
                     f"struct_def:{struct_name}.{field['name']}")


def send_struct_impl(dongle,
                     data: dict,
                     struct_name: str,
                     values: dict,
                     sig_ctx: Dict[str, bytes],
                     sent_tokens: set) -> None:
    exchange(dongle,
             apdu_tip712_send_struct_impl_root(struct_name),
             f"struct_impl:{struct_name}")

    fields = data["types"][struct_name]
    for field in fields:
        field_name = field["name"]
        if struct_name == data["primaryType"] and field_name in ADVANCED_FILTERS["fields"]:
            send_filter(dongle,
                        sig_ctx,
                        field_name,
                        ADVANCED_FILTERS["fields"][field_name],
                        sent_tokens)

        encoded = encode_value(field["type"], values[field_name])
        for idx, apdu in enumerate(apdu_tip712_send_struct_impl_field(encoded)):
            exchange(dongle, apdu, f"struct_impl:{struct_name}.{field_name}:{idx}")


def try_recover_address(data: dict, signature: bytes) -> Optional[str]:
    try:
        domain_hash = hash_struct("EIP712Domain", data["types"], data["domain"])
        message_types = dict(data["types"])
        message_types.pop("EIP712Domain", None)
        message_hash = hash_eip712_message(message_types, data["message"])
        digest = keccak(b"\x19\x01" + domain_hash + message_hash)
        pubkey = KeyAPI.Signature(signature_bytes=signature).recover_public_key_from_msg_hash(digest)
        return to_base58check(b"\x41" + bytes.fromhex(pubkey.to_address()[2:]))
    except Exception as exc:
        print(f"[WARN] Skip local signature recovery: {exc}")
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device",
                        required=True,
                        choices=sorted(COIN_META_CERTIFICATES.keys()),
                        help="Target device family for PKI coin-meta certificate selection")
    parser.add_argument("--path",
                        default="44'/195'/0'/0/0",
                        help="BIP32 path used for signing")
    parser.add_argument("--skip-coin-meta-cert",
                        action="store_true",
                        help="Skip sending the Ledger-PKI coin metadata certificate")
    args = parser.parse_args()

    dongle = getDongle(True)
    sig_ctx = compute_signature_context(ADVANCED_DATA)
    sent_tokens = set()

    print("[INFO] Fetching public key/address")
    pk_resp = exchange(dongle, apdu_get_public_addr(args.path), "get_public_addr")
    pubkey, raw_addr = parse_pk_addr(pk_resp)
    wallet_addr = to_base58check(raw_addr)
    print(f"[INFO] Wallet address: {wallet_addr}")
    print(f"[INFO] Public key: {pubkey.hex()}")

    print("[INFO] Sending TIP-712 schema")
    send_struct_definitions(dongle, ADVANCED_DATA)

    print("[INFO] Activating advanced filtering")
    exchange(dongle, apdu_tip712_filtering_activate(), "filtering:activate")

    if not args.skip_coin_meta_cert:
        print("[INFO] Sending coin metadata certificate")
        send_coin_meta_certificate(dongle, args.device)

    print("[INFO] Sending domain implementation")
    send_struct_impl(dongle,
                     ADVANCED_DATA,
                     "EIP712Domain",
                     ADVANCED_DATA["domain"],
                     sig_ctx,
                     sent_tokens)

    print("[INFO] Sending filtering message info")
    send_filtering_message_info(dongle,
                                sig_ctx,
                                ADVANCED_FILTERS["name"],
                                len(ADVANCED_FILTERS["fields"]))

    print("[INFO] Sending message implementation")
    send_struct_impl(dongle,
                     ADVANCED_DATA,
                     ADVANCED_DATA["primaryType"],
                     ADVANCED_DATA["message"],
                     sig_ctx,
                     sent_tokens)

    print("[INFO] Review the message on device, then approve to receive the signature")
    signature = exchange(dongle, apdu_tip712_sign_new(args.path), "tip712:sign_new")
    print(f"[INFO] Signature: {signature.hex()}")

    recovered_addr = try_recover_address(ADVANCED_DATA, signature)
    if recovered_addr is not None:
        print(f"[INFO] Recovered address: {recovered_addr}")
        print(f"[INFO] Address match: {recovered_addr == wallet_addr}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
