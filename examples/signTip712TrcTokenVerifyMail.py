#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Send `tests/ragger/tip712_input_files/15-trctoken-data.json` to a real Ledger
device through the TIP-712 "new" flow, verify the signature locally, then call
the Nile `verifyMail` view on:

    TRHsc32MH4CLJf9VMhMjW6M9VgyvN85ku3

Prerequisites:
- Open the TRON app on the device
- Approve the TIP-712 review flow on-device
- Install the Python dependencies used by the examples and ragger helpers:
    pip install -r tests/ragger/requirements.txt

Typical usage:
    python examples/signTip712TrcTokenVerifyMail.py
    python examples/signTip712TrcTokenVerifyMail.py --path "44'/195'/0'/0/0"
"""

import argparse
import copy
import json
import re
import struct
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from Crypto.Hash import keccak
from eth_keys import KeyAPI
from ledgerblue.comm import getDongle

from base import parse_bip32_path_to_bytes


REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_RAGGER_DIR = REPO_ROOT / "tests" / "ragger"
if str(TESTS_RAGGER_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_RAGGER_DIR))

from address import to_base58check_address, to_tvm_address  # noqa: E402
from utils import encode_typed_data  # noqa: E402
from eth_abi import encode as _abi_encode, decode as _abi_decode  # noqa: E402


CLA = 0xE0
INS_GET_PUBLIC_ADDR = 0x02
INS_TIP712_SIGN = 0x0C
INS_TIP712_STRUCT_DEF = 0x1A
INS_TIP712_STRUCT_IMPL = 0x1C

P1_COMPLETE = 0x00
P1_PARTIAL = 0xFF

P2_STRUCT_NAME = 0x00
P2_STRUCT_FIELD = 0xFF
P2_ARRAY = 0x0F
P2_NEW_IMPLEM = 0x01

TIP712_TYPE_CUSTOM = 0
TIP712_TYPE_INT = 1
TIP712_TYPE_UINT = 2
TIP712_TYPE_ADDRESS = 3
TIP712_TYPE_BOOL = 4
TIP712_TYPE_STRING = 5
TIP712_TYPE_FIX_BYTES = 6
TIP712_TYPE_DYN_BYTES = 7
TIP712_TYPE_TRCTOKEN = 8

VERIFY_MAIL_CONTRACT = "TRHsc32MH4CLJf9VMhMjW6M9VgyvN85ku3"
VERIFY_MAIL_SELECTOR = bytes.fromhex("3dbfe627")
VERIFY_MAIL_ARG_TYPES = [
    "address",
    "((string,address,trcToken),(string,address,trcToken[]),string,address[],trcToken,trcToken[])",
    "uint8",
    "bytes32",
    "bytes32",
]
DEFAULT_INPUT = REPO_ROOT / "tests" / "ragger" / "tip712_input_files" / "15-trctoken-data.json"
DEFAULT_NILE_URL = "https://nile.trongrid.io"
DEFAULT_NILE_CHAIN_ID = 3448148188
ERROR_STRING_SELECTOR = bytes.fromhex("08c379a0")


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


def apdu_tip712_send_struct_impl_array(size: int) -> bytes:
    return serialize_apdu(CLA,
                          INS_TIP712_STRUCT_IMPL,
                          P1_COMPLETE,
                          P2_ARRAY,
                          bytes([size]))


def apdu_tip712_send_struct_impl_field(data: bytes) -> List[bytes]:
    payload = struct.pack(">H", len(data)) + data
    chunks = []
    while payload:
        chunk = payload[:0xFF]
        payload = payload[0xFF:]
        p1 = P1_PARTIAL if payload else P1_COMPLETE
        chunks.append(serialize_apdu(CLA, INS_TIP712_STRUCT_IMPL, p1, P2_STRUCT_FIELD, chunk))
    return chunks


def apdu_tip712_sign_new(path: str) -> bytes:
    path_bytes = parse_bip32_path_to_bytes(path)
    payload = bytes([len(path_bytes) // 4]) + path_bytes
    return serialize_apdu(CLA, INS_TIP712_SIGN, P1_COMPLETE, P2_NEW_IMPLEM, payload)


def exchange(dongle, apdu: bytes, label: str) -> bytes:
    print(f"{label} => {apdu.hex()}")
    response = dongle.exchange(apdu)
    print(f"{label} <= {response.hex() if response else '9000'}")
    return response


def parse_pk_addr(response: bytes) -> Tuple[bytes, str]:
    idx = 0
    pk_len = response[idx]
    idx += 1
    pubkey = response[idx:idx + pk_len]
    idx += pk_len
    addr_len = response[idx]
    idx += 1
    address = response[idx:idx + addr_len].decode()
    return pubkey, address


def get_array_levels(type_name: str) -> Tuple[str, List[Optional[int]]]:
    array_levels: List[Optional[int]] = []
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


def encode_integer(value: Any, type_size: int) -> bytes:
    if isinstance(value, str):
        value = int(value, 0)

    if value == 0:
        return b"\x00"

    if value < 0:
        value &= (1 << (type_size * 8)) - 1

    packed = value.to_bytes(type_size, "big", signed=False)
    return packed.lstrip(b"\x00") or b"\x00"


def encode_hex_string(value: str, size: int) -> bytes:
    if not value.startswith("0x"):
        raise ValueError(f"Expected 0x-prefixed hex string, got: {value}")
    hex_value = value[2:]
    if len(hex_value) < size * 2:
        hex_value = hex_value.rjust(size * 2, "0")
    if len(hex_value) != size * 2:
        raise ValueError(f"Unexpected fixed-bytes length for {value}")
    return bytes.fromhex(hex_value)


def encode_value(field_type: str, value: Any) -> bytes:
    base_type, _ = get_array_levels(field_type)
    match = re.match(r"^(\w+?)(\d*)$", base_type)
    if match is None:
        raise ValueError(f"Unsupported field type: {field_type}")
    typename = match.group(1)
    size_bits = match.group(2)
    type_size = None if size_bits == "" else int(size_bits) // 8

    if typename == "string":
        return value.encode()
    if typename == "address":
        return to_tvm_address(value)
    if typename == "uint":
        return encode_integer(value, type_size)
    if typename == "int":
        return encode_integer(value, type_size)
    if typename == "bool":
        return b"\x01" if value else b"\x00"
    if typename == "bytes":
        if type_size is None:
            return bytes.fromhex(value[2:]) if isinstance(value, str) else bytes(value)
        return encode_hex_string(value, type_size)
    if typename == "trcToken":
        return encode_integer(value, 32)
    raise ValueError(f"Unsupported scalar field type: {field_type}")


def prepare_struct_definitions(data: dict) -> Dict[str, List[dict]]:
    structs: Dict[str, List[dict]] = {}
    for struct_name, fields in data["types"].items():
        parsed_fields = []
        for field in fields:
            field_enum, type_name, type_size, array_levels = parse_field_type(field["type"])
            parsed_fields.append({
                "name": field["name"],
                "original_type": field["type"],
                "type": type_name,
                "enum": field_enum,
                "typesize": type_size,
                "array_lvls": array_levels,
            })
        structs[struct_name] = parsed_fields
    return structs


def send_struct_definitions(dongle, data: dict, structs: Dict[str, List[dict]]) -> None:
    for struct_name, fields in structs.items():
        exchange(dongle,
                 apdu_tip712_send_struct_def_name(struct_name),
                 f"struct_def:{struct_name}")
        for field in fields:
            exchange(dongle,
                     apdu_tip712_send_struct_def_field(field["enum"],
                                                       field["type"],
                                                       field["typesize"],
                                                       field["array_lvls"],
                                                       field["name"]),
                     f"struct_def:{struct_name}.{field['name']}")


def send_struct_impl_field(dongle, value: Any, field: dict, label: str) -> None:
    encoded = encode_value(field["original_type"], value)
    for idx, apdu in enumerate(apdu_tip712_send_struct_impl_field(encoded)):
        exchange(dongle, apdu, f"{label}:{idx}")


def evaluate_field(dongle,
                   structs: Dict[str, List[dict]],
                   value: Any,
                   field: dict,
                   lvls_left: int,
                   label: str) -> None:
    if field["array_lvls"] and lvls_left > 0:
        exchange(dongle,
                 apdu_tip712_send_struct_impl_array(len(value)),
                 f"{label}.array")
        expected_size = field["array_lvls"][lvls_left - 1]
        if expected_size is not None and expected_size != len(value):
            raise ValueError(f"{label}: expected array size {expected_size}, got {len(value)}")
        for idx, subvalue in enumerate(value):
            evaluate_field(dongle,
                           structs,
                           subvalue,
                           field,
                           lvls_left - 1,
                           f"{label}[{idx}]")
        return

    if field["enum"] == TIP712_TYPE_CUSTOM:
        send_struct_impl_values(dongle, structs, field["type"], value, label)
        return

    send_struct_impl_field(dongle, value, field, label)


def send_struct_impl_values(dongle,
                            structs: Dict[str, List[dict]],
                            struct_name: str,
                            values: dict,
                            label_prefix: Optional[str] = None) -> None:
    for field in structs[struct_name]:
        field_label = f"{label_prefix}.{field['name']}" if label_prefix else f"{struct_name}.{field['name']}"
        evaluate_field(dongle,
                       structs,
                       values[field["name"]],
                       field,
                       len(field["array_lvls"]),
                       field_label)


def send_root_struct_impl(dongle,
                          structs: Dict[str, List[dict]],
                          struct_name: str,
                          values: dict) -> None:
    exchange(dongle,
             apdu_tip712_send_struct_impl_root(struct_name),
             f"struct_impl:{struct_name}")
    send_struct_impl_values(dongle, structs, struct_name, values, struct_name)


def compute_digest(data: dict) -> bytes:
    smsg = encode_typed_data(full_message=data)
    return keccak.new(digest_bits=256,
                      data=b"\x19\x01" + bytes(smsg.header) + bytes(smsg.body)).digest()


def recover_signer_address(data: dict, signature: bytes) -> str:
    digest = compute_digest(data)
    pubkey = KeyAPI.Signature(signature_bytes=signature).recover_public_key_from_msg_hash(digest)
    return to_base58check_address(bytes.fromhex(pubkey.to_address()[2:]))


# --- TRON ABI codec on top of stock eth_abi -----------------------------------
# eth_abi has no TRON `address` (Base58) or `trcToken` support, so we adapt the
# inputs/outputs around it: Base58 "T..." <-> 0x-hex addresses, and trcToken treated
# as uint256. Recurses through arrays and tuples.
def _abi_split_components(tuple_type: str) -> list:
    inner = tuple_type[1:-1]  # strip the outer ( )
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def _abi_normalize_arg(type_str: str, value):
    type_str = type_str.strip()
    if type_str.endswith("]"):
        inner = type_str[:type_str.rfind("[")]
        return [_abi_normalize_arg(inner, elem) for elem in value]
    if type_str.startswith("("):
        comps = _abi_split_components(type_str)
        return tuple(_abi_normalize_arg(ct, cv) for ct, cv in zip(comps, value))
    if type_str == "address":
        return "0x" + to_tvm_address(value).hex()
    if type_str == "trcToken":
        return int(value, 0) if isinstance(value, str) else int(value)
    return value


def _abi_outputs_to_base58(type_str: str, value):
    type_str = type_str.strip()
    if type_str.endswith("]"):
        inner = type_str[:type_str.rfind("[")]
        return [_abi_outputs_to_base58(inner, elem) for elem in value]
    if type_str.startswith("("):
        comps = _abi_split_components(type_str)
        return tuple(_abi_outputs_to_base58(ct, cv) for ct, cv in zip(comps, value))
    if type_str == "address":
        return to_base58check_address(value)
    return value


def _rewrite_trctoken(type_str: str) -> str:
    return type_str.replace("trcToken", "uint256")


def encode_tron_abi(types: list, args) -> bytes:
    norm_types = [_rewrite_trctoken(t) for t in types]
    norm_args = [_abi_normalize_arg(t, a) for t, a in zip(types, args)]
    return _abi_encode(norm_types, norm_args)


def decode_tron_abi(types: list, data: bytes) -> tuple:
    decoded = _abi_decode([_rewrite_trctoken(t) for t in types], data)
    return tuple(_abi_outputs_to_base58(t, v) for t, v in zip(types, decoded))


def encode_verify_mail_call(sender: str, data: dict, signature: bytes, v: int) -> bytes:
    mail = build_verify_mail_mail_arg(data)
    args = (
        sender,
        mail,
        v,
        signature[:32],
        signature[32:64],
    )
    return VERIFY_MAIL_SELECTOR + encode_tron_abi(VERIFY_MAIL_ARG_TYPES, args)


def build_verify_mail_mail_arg(data: dict) -> tuple:
    return (
        (
            data["message"]["from"]["name"],
            data["message"]["from"]["wallet"],
            data["message"]["from"]["trcTokenId"],
        ),
        (
            data["message"]["to"]["name"],
            data["message"]["to"]["wallet"],
            data["message"]["to"]["trcTokenArr"],
        ),
        data["message"]["contents"],
        data["message"]["tAddr"],
        data["message"]["trcTokenId"],
        data["message"]["trcTokenArr"],
    )


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode())


def call_constant_contract(fullnode_url: str,
                           owner_address: str,
                           contract_address: str,
                           selector: str) -> dict:
    return post_json(
        f"{fullnode_url.rstrip('/')}/wallet/triggerconstantcontract",
        {
            "owner_address": owner_address,
            "contract_address": contract_address,
            "function_selector": selector,
            "visible": True,
        },
    )


def query_contract_chain_id(fullnode_url: str, owner_address: str) -> int:
    response = call_constant_contract(fullnode_url,
                                      owner_address,
                                      VERIFY_MAIL_CONTRACT,
                                      "_CACHED_CHAIN_ID()")
    constant_results = response.get("constant_result", [])
    if not response.get("result", {}).get("result") or not constant_results:
        print("[WARN] Failed to query _CACHED_CHAIN_ID(); falling back to default Nile chain ID")
        return DEFAULT_NILE_CHAIN_ID
    return int.from_bytes(bytes.fromhex(constant_results[0]), "big")


def query_contract_domain_verifier(fullnode_url: str, owner_address: str) -> str:
    response = call_constant_contract(fullnode_url,
                                      owner_address,
                                      VERIFY_MAIL_CONTRACT,
                                      "_CACHED_THIS()")
    constant_results = response.get("constant_result", [])
    if not response.get("result", {}).get("result") or not constant_results:
        print("[WARN] Failed to query _CACHED_THIS(); falling back to deployed contract address")
        return VERIFY_MAIL_CONTRACT
    return decode_tron_abi(["address"], bytes.fromhex(constant_results[0]))[0]


def align_domain_for_onchain_verification(data: dict, fullnode_url: str, owner_address: str) -> dict:
    aligned = copy.deepcopy(data)
    contract_chain_id = query_contract_chain_id(fullnode_url, owner_address)
    contract_domain_verifier = query_contract_domain_verifier(fullnode_url, owner_address)

    original_contract = aligned["domain"].get("verifyingContract")
    original_chain_id = aligned["domain"].get("chainId")

    aligned["domain"]["verifyingContract"] = contract_domain_verifier
    aligned["domain"]["chainId"] = contract_chain_id

    if original_contract != contract_domain_verifier:
        print("[INFO] Rewriting domain.verifyingContract for on-chain verification:")
        print(f"       {original_contract} -> {contract_domain_verifier}")
    if original_chain_id != contract_chain_id:
        print("[INFO] Rewriting domain.chainId for on-chain verification:")
        print(f"       {original_chain_id} -> {contract_chain_id} (0x{contract_chain_id:x})")

    return aligned


def call_verify_mail(fullnode_url: str,
                     owner_address: str,
                     sender_address: str,
                     data: dict,
                     signature: bytes,
                     v: int) -> bool:
    encoded_call = encode_verify_mail_call(sender_address, data, signature, v)
    response = post_json(
        f"{fullnode_url.rstrip('/')}/wallet/triggerconstantcontract",
        {
            "owner_address": owner_address,
            "contract_address": VERIFY_MAIL_CONTRACT,
            "data": encoded_call.hex(),
            "visible": True,
        },
    )

    if not response.get("result", {}).get("result"):
        raise RuntimeError(f"verifyMail RPC failed: {response}")
    constant_results = response.get("constant_result", [])
    if not constant_results:
        raise RuntimeError(f"verifyMail returned no constant_result: {response}")
    raw_result = bytes.fromhex(constant_results[0])
    if raw_result.startswith(ERROR_STRING_SELECTOR):
        revert_reason = decode_tron_abi(["string"], raw_result[4:])[0]
        raise RuntimeError(f"verifyMail reverted: {revert_reason}")
    return decode_tron_abi(["bool"], raw_result)[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path",
                        default="44'/195'/0'/0/0",
                        help="BIP32 path used for signing")
    parser.add_argument("--input",
                        default=str(DEFAULT_INPUT),
                        help="TIP-712 JSON file to send")
    parser.add_argument("--nile-url",
                        default=DEFAULT_NILE_URL,
                        help="Nile fullnode base URL used for triggerconstantcontract")
    parser.add_argument("--keep-input-domain",
                        action="store_true",
                        help="Sign the JSON exactly as provided, without aligning domain.chainId and domain.verifyingContract to the target Nile contract")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        input_data = json.load(handle)

    if args.keep_input_domain:
        data = input_data
    else:
        data = align_domain_for_onchain_verification(input_data,
                                                     args.nile_url,
                                                     VERIFY_MAIL_CONTRACT)

    structs = prepare_struct_definitions(data)
    dongle = getDongle(True)

    print("[INFO] Fetching public key/address")
    pk_resp = exchange(dongle, apdu_get_public_addr(args.path), "get_public_addr")
    pubkey, wallet_addr = parse_pk_addr(pk_resp)
    print(f"[INFO] Wallet address: {wallet_addr}")
    print(f"[INFO] Public key: {pubkey.hex()}")

    print("[INFO] Sending TIP-712 schema")
    send_struct_definitions(dongle, data, structs)

    print("[INFO] Sending domain implementation")
    send_root_struct_impl(dongle, structs, "EIP712Domain", data["domain"])

    print("[INFO] Sending message implementation")
    send_root_struct_impl(dongle, structs, data["primaryType"], data["message"])

    print("[INFO] Review the message on device, then approve to receive the signature")
    signature = exchange(dongle, apdu_tip712_sign_new(args.path), "tip712:sign_new")
    print(f"[INFO] Signature: {signature.hex()}")

    recovered_addr = recover_signer_address(data, signature)
    print(f"[INFO] Recovered address: {recovered_addr}")
    print(f"[INFO] Local verification ok: {recovered_addr == wallet_addr}")
    print(f"[INFO] sender_address: {wallet_addr}")
    print("[INFO] mail tuple for TronScan verifyMail:")
    print(json.dumps(build_verify_mail_mail_arg(data),
                     ensure_ascii=False,
                     separators=(",", ": ")))

    v_raw = signature[64]
    print(f"[INFO] Signature components: v={v_raw}, r=0x{signature[:32].hex()}, s=0x{signature[32:64].hex()}")

    candidate_vs = [v_raw]
    if v_raw < 27:
        candidate_vs.append(v_raw + 27)

    for candidate_v in candidate_vs:
        try:
            onchain_result = call_verify_mail(args.nile_url,
                                              wallet_addr,
                                              wallet_addr,
                                              data,
                                              signature,
                                              candidate_v)
            print(f"[INFO] verifyMail(wallet, mail, v={candidate_v}, r, s) => {onchain_result}")
        except RuntimeError as exc:
            print(f"[WARN] verifyMail(wallet, mail, v={candidate_v}, r, s) failed: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
