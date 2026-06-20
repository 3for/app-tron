#!/usr/bin/env python3
import copy
import json
from pathlib import Path

OP_STRUCT_DEF = 0
OP_FILTERING = 1
OP_STRUCT_IMPL = 2
OP_SIGN = 3
OP_RESET = 4
OP_SET_SETTINGS = 5

P1_COMPLETE = 0x00
P1_PARTIAL = 0x01
P1_DISCARDED = 0x01

P2_STRUCT_NAME = 0x00
P2_STRUCT_FIELD = 0xFF
P2_ARRAY = 0x0F

P2_FILT_ACTIVATE = 0x00
P2_FILT_DISCARDED_PATH = 0x01
P2_FILT_MESSAGE_INFO = 0x0F
P2_FILT_TRUSTED_NAME = 0xFB
P2_FILT_DATETIME = 0xFC
P2_FILT_AMOUNT_JOIN_TOKEN = 0xFD
P2_FILT_AMOUNT_JOIN_VALUE = 0xFE
P2_FILT_RAW_FIELD = 0xFF

TIP712_FIELD_CUSTOM = 0
TIP712_FIELD_INT = 1
TIP712_FIELD_UINT = 2
TIP712_FIELD_ADDRESS = 3
TIP712_FIELD_BOOL = 4
TIP712_FIELD_STRING = 5
TIP712_FIELD_FIX_BYTES = 6
TIP712_FIELD_DYN_BYTES = 7
TIP712_FIELD_TRCTOKEN = 8

S_SIGN_BY_HASH = 3
S_VERBOSE_TIP712 = 4

DEFAULT_BIP32_PATH = "44'/195'/0'/0/0"

ROOT = Path(__file__).resolve().parent
TIP712_INPUTS = ROOT.parent / "ragger" / "tip712_input_files"
OUT_DIR = ROOT / "corpus" / "fuzz_tip712"


def emit_command(op: int, p1: int, p2: int, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFF:
        raise ValueError(
            f"payload too large for single command: {len(payload)}")
    return bytes([op, p1, p2, len(payload)]) + payload


def emit_settings(settings: int) -> bytes:
    return bytes([OP_SET_SETTINGS, settings & 0xFF])


def emit_reset() -> bytes:
    return emit_command(OP_RESET, P1_COMPLETE, 0x00, b"")


def pack_derivation_path(path: str) -> bytes:
    packed = bytearray()
    elements = [part for part in path.split("/") if part not in ("", "m")]
    packed.append(len(elements))
    for element in elements:
        hardened = element.endswith("'")
        if hardened:
            element = element[:-1]
        value = int(element)
        if hardened:
            value |= 0x80000000
        packed += value.to_bytes(4, "big")
    return bytes(packed)


def get_array_levels(typename: str) -> tuple[str, list[int | None]]:
    levels: list[int | None] = []
    while typename.endswith("]"):
        start = typename.rfind("[")
        level = typename[start + 1:-1]
        levels.insert(0, None if level == "" else int(level))
        typename = typename[:start]
    return typename, levels


def get_typesize(typename: str) -> tuple[str, int | None]:
    base = typename.rstrip("0123456789")
    suffix = typename[len(base):]
    return base, None if suffix == "" else int(suffix)


def parse_field_type(
        typename: str) -> tuple[str, int, int | None, list[int | None]]:
    typename, array_levels = get_array_levels(typename)
    typename, typesize = get_typesize(typename)

    if typename == "int":
        return typename, TIP712_FIELD_INT, typesize // 8, array_levels
    if typename == "uint":
        return typename, TIP712_FIELD_UINT, typesize // 8, array_levels
    if typename == "address":
        return typename, TIP712_FIELD_ADDRESS, None, array_levels
    if typename == "bool":
        return typename, TIP712_FIELD_BOOL, None, array_levels
    if typename == "string":
        return typename, TIP712_FIELD_STRING, None, array_levels
    if typename == "bytes":
        if typesize is None:
            return typename, TIP712_FIELD_DYN_BYTES, None, array_levels
        return typename, TIP712_FIELD_FIX_BYTES, typesize, array_levels
    if typename == "trcToken":
        return typename, TIP712_FIELD_TRCTOKEN, None, array_levels

    return typename, TIP712_FIELD_CUSTOM, None, array_levels


def encode_struct_field(type_name: str, field_enum: int, type_size: int | None,
                        array_levels: list[int | None],
                        key_name: str) -> bytes:
    data = bytearray()
    typedesc = 0
    typedesc |= (1 if array_levels else 0) << 7
    typedesc |= (1 if type_size is not None else 0) << 6
    typedesc |= field_enum
    data.append(typedesc)
    if field_enum == TIP712_FIELD_CUSTOM:
        data.append(len(type_name))
        data += type_name.encode()
    if type_size is not None:
        data.append(type_size)
    if array_levels:
        data.append(len(array_levels))
        for level in array_levels:
            data.append(0 if level is None else 1)
            if level is not None:
                data.append(level)
    data.append(len(key_name))
    data += key_name.encode()
    return bytes(data)


def encode_integer(value, type_size: int) -> bytes:
    if isinstance(value, bool):
        value = 1 if value else 0
    elif isinstance(value, str):
        value = int(value, 0)
    else:
        value = int(value)

    if value == 0:
        return b"\x00"
    if value < 0:
        width = max(type_size, 1)
        value &= (1 << (width * 8)) - 1
        return value.to_bytes(width, "big")
    data = value.to_bytes(max(type_size, 1), "big", signed=False)
    return data.lstrip(b"\x00")


def encode_address(value: str) -> bytes:
    if value.startswith("0x"):
        return bytes.fromhex(value[2:])
    raise ValueError(f"unsupported address format: {value}")


def encode_value(field_enum: int, type_size: int | None, value):
    if field_enum in (TIP712_FIELD_INT, TIP712_FIELD_UINT,
                      TIP712_FIELD_TRCTOKEN):
        if field_enum == TIP712_FIELD_TRCTOKEN:
            return encode_integer(value, 32)
        return encode_integer(value, type_size or 32)
    if field_enum == TIP712_FIELD_ADDRESS:
        return encode_address(value)
    if field_enum == TIP712_FIELD_BOOL:
        return encode_integer(value, 1)
    if field_enum == TIP712_FIELD_STRING:
        return value.encode()
    if field_enum in (TIP712_FIELD_FIX_BYTES, TIP712_FIELD_DYN_BYTES):
        assert isinstance(value, str) and value.startswith("0x")
        return bytes.fromhex(value[2:])
    raise ValueError(f"unsupported field enum {field_enum}")


def normalize_types(data_json: dict) -> dict:
    normalized = copy.deepcopy(data_json)
    for fields in normalized["types"].values():
        for field in fields:
            field["type"], field["enum"], field["typesize"], field[
                "array_lvls"] = parse_field_type(field["type"])
    return normalized


def iter_filter_paths(filters: dict | None) -> list[str]:
    if not filters:
        return []
    return list(filters.get("fields", {}).keys())


def emit_filter(path: str, entry: dict, discarded: bool) -> bytes:
    discarded_flag = P1_DISCARDED if discarded else P1_COMPLETE
    if entry["type"] == "raw":
        payload = bytes([len(entry["name"])
                         ]) + entry["name"].encode() + b"\x00"
        return emit_command(OP_FILTERING, discarded_flag, P2_FILT_RAW_FIELD,
                            payload)
    if entry["type"] == "trusted_name":
        name_types = entry["tn_type"]
        if name_types is None:
            name_types = [2]
        name_sources = entry["tn_source"]
        payload = bytearray()
        payload.append(len(entry["name"]))
        payload += entry["name"].encode()
        payload.append(len(name_types))
        payload += bytes(name_types)
        payload.append(len(name_sources))
        payload += bytes(name_sources)
        payload.append(0)
        return emit_command(OP_FILTERING, discarded_flag, P2_FILT_TRUSTED_NAME,
                            bytes(payload))
    if entry["type"] == "amount_join_token":
        payload = bytes([entry.get("token", 0xFF), 0])
        return emit_command(OP_FILTERING, discarded_flag,
                            P2_FILT_AMOUNT_JOIN_TOKEN, payload)
    if entry["type"] == "amount_join_value":
        token_idx = entry.get("token", 0xFF)
        payload = bytearray()
        payload.append(len(entry["name"]))
        payload += entry["name"].encode()
        payload.append(token_idx)
        payload.append(0)
        return emit_command(OP_FILTERING, discarded_flag,
                            P2_FILT_AMOUNT_JOIN_VALUE, bytes(payload))
    if entry["type"] == "datetime":
        payload = bytes([len(entry["name"])
                         ]) + entry["name"].encode() + b"\x00"
        return emit_command(OP_FILTERING, discarded_flag, P2_FILT_DATETIME,
                            payload)
    raise ValueError(f"unsupported filter type {entry['type']}")


def emit_field_chunks(data: bytes) -> bytes:
    payload = len(data).to_bytes(2, "big") + data
    chunks = bytearray()
    while payload:
        chunk = payload[:0xFF]
        payload = payload[0xFF:]
        p1 = P1_PARTIAL if payload else P1_COMPLETE
        chunks += emit_command(OP_STRUCT_IMPL, p1, P2_STRUCT_FIELD, chunk)
    return bytes(chunks)


def emit_discarded_filters(current_path: list[str],
                           filters: dict | None) -> bytes:
    if not filters:
        return b""
    prefix = ".".join(current_path) + ".[]"
    stream = bytearray()
    for path, entry in filters.get("fields", {}).items():
        if path.startswith(prefix):
            stream += emit_command(OP_FILTERING, P1_COMPLETE,
                                   P2_FILT_DISCARDED_PATH,
                                   bytes([len(path)]) + path.encode())
            stream += emit_filter(path, entry, True)
    return bytes(stream)


def emit_struct_impl(types: dict, struct_name: str, data: dict,
                     filters: dict | None, current_path: list[str]) -> bytes:
    stream = bytearray()
    for field in types[struct_name]:
        stream += emit_field(types, field, data[field["name"]], filters,
                             current_path)
    return bytes(stream)


def emit_field(types: dict, field: dict, value, filters: dict | None,
               current_path: list[str]) -> bytes:
    stream = bytearray()
    current_path.append(field["name"])

    if field["array_lvls"]:
        assert isinstance(value, list)
        stream += emit_command(OP_STRUCT_IMPL, P1_COMPLETE, P2_ARRAY,
                               bytes([len(value)]))
        if len(value) == 0:
            stream += emit_discarded_filters(current_path, filters)
        for subvalue in value:
            current_path.append("[]")
            nested_field = dict(field)
            nested_field["array_lvls"] = field["array_lvls"][1:]
            if nested_field["array_lvls"]:
                stream += emit_field(types, nested_field, subvalue, filters,
                                     current_path[:-1])
            elif field["enum"] == TIP712_FIELD_CUSTOM:
                stream += emit_struct_impl(types, field["type"], subvalue,
                                           filters, current_path)
            else:
                path = ".".join(current_path)
                if filters and path in filters.get("fields", {}):
                    stream += emit_filter(path, filters["fields"][path], False)
                stream += emit_field_chunks(
                    encode_value(field["enum"], field["typesize"], subvalue))
            current_path.pop()
    elif field["enum"] == TIP712_FIELD_CUSTOM:
        stream += emit_struct_impl(types, field["type"], value, filters,
                                   current_path)
    else:
        path = ".".join(current_path)
        if filters and path in filters.get("fields", {}):
            stream += emit_filter(path, filters["fields"][path], False)
        stream += emit_field_chunks(
            encode_value(field["enum"], field["typesize"], value))

    current_path.pop()
    return bytes(stream)


def build_stream(data_json: dict,
                 filters: dict | None = None,
                 settings: int | None = None,
                 bip32_path: str = DEFAULT_BIP32_PATH) -> bytes:
    normalized = normalize_types(data_json)
    types = normalized["types"]
    domain = normalized["domain"]
    message = normalized["message"]
    stream = bytearray()

    if settings is not None:
        stream += emit_settings(settings)

    for struct_name, fields in types.items():
        stream += emit_command(OP_STRUCT_DEF, P1_COMPLETE, P2_STRUCT_NAME,
                               struct_name.encode())
        for field in fields:
            stream += emit_command(
                OP_STRUCT_DEF, P1_COMPLETE, P2_STRUCT_FIELD,
                encode_struct_field(field["type"], field["enum"],
                                    field["typesize"], field["array_lvls"],
                                    field["name"]))

    if filters:
        stream += emit_command(OP_FILTERING, P1_COMPLETE, P2_FILT_ACTIVATE,
                               b"")

    stream += emit_command(OP_STRUCT_IMPL, P1_COMPLETE, P2_STRUCT_NAME,
                           b"EIP712Domain")
    stream += emit_struct_impl(types, "EIP712Domain", domain, None, [])

    if filters:
        title = filters.get("name", domain["name"])
        payload = bytes([len(title)]) + title.encode() + bytes(
            [len(filters.get("fields", {})), 0])
        stream += emit_command(OP_FILTERING, P1_COMPLETE, P2_FILT_MESSAGE_INFO,
                               payload)

    stream += emit_command(OP_STRUCT_IMPL, P1_COMPLETE, P2_STRUCT_NAME,
                           normalized["primaryType"].encode())
    stream += emit_struct_impl(types, normalized["primaryType"], message,
                               filters, [])
    stream += emit_command(OP_SIGN, P1_COMPLETE, 0x01,
                           pack_derivation_path(bip32_path))
    return bytes(stream)


FILTERING_EMPTY_ARRAY = {
    "data": {
        "types": {
            "EIP712Domain": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "version",
                    "type": "string"
                },
                {
                    "name": "chainId",
                    "type": "uint256"
                },
                {
                    "name": "verifyingContract",
                    "type": "address"
                },
            ],
            "Person": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "addr",
                    "type": "address"
                },
            ],
            "Message": [
                {
                    "name": "title",
                    "type": "string"
                },
                {
                    "name": "to",
                    "type": "Person[]"
                },
            ],
            "Root": [
                {
                    "name": "text",
                    "type": "string"
                },
                {
                    "name": "subtext",
                    "type": "string[]"
                },
                {
                    "name": "msg_list1",
                    "type": "Message[]"
                },
                {
                    "name": "msg_list2",
                    "type": "Message[]"
                },
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "chainId": 728126428,
        },
        "message": {
            "text": "This is a test",
            "subtext": [],
            "msg_list1": [{
                "title": "This is a test",
                "to": []
            }],
            "msg_list2": [],
        },
    },
    "filters": {
        "name": "Empty array filtering",
        "fields": {
            "text": {
                "type": "raw",
                "name": "Text"
            },
            "subtext.[]": {
                "type": "raw",
                "name": "Sub-Text"
            },
            "msg_list1.[].to.[].addr": {
                "type": "raw",
                "name": "(1) Recipient addr"
            },
            "msg_list2.[].to.[].addr": {
                "type": "raw",
                "name": "(2) Recipient addr"
            },
        },
    },
}

AMOUNT_JOIN = {
    "data": {
        "types": {
            "EIP712Domain": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "version",
                    "type": "string"
                },
                {
                    "name": "chainId",
                    "type": "uint256"
                },
                {
                    "name": "verifyingContract",
                    "type": "address"
                },
            ],
            "Root": [
                {
                    "name": "token_from",
                    "type": "address"
                },
                {
                    "name": "value_from",
                    "type": "uint256"
                },
                {
                    "name": "token_to",
                    "type": "address"
                },
                {
                    "name": "value_to",
                    "type": "uint256"
                },
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "chainId": 728126428,
        },
        "message": {
            "token_from": "0x1111111111111111111111111111111111111111",
            "value_from": 3650000000000000000,
            "token_to": "0x2222222222222222222222222222222222222222",
            "value_to": 15470000000000000000,
        },
    },
    "filters": {
        "name": "Amount join test",
        "fields": {
            "token_from": {
                "type": "amount_join_token",
                "token": 0
            },
            "value_from": {
                "type": "amount_join_value",
                "name": "From",
                "token": 0
            },
            "token_to": {
                "type": "amount_join_token",
                "token": 1
            },
            "value_to": {
                "type": "amount_join_value",
                "name": "To",
                "token": 1
            },
        },
    },
}

TRUSTED_NAME = {
    "data": {
        "types": {
            "EIP712Domain": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "version",
                    "type": "string"
                },
                {
                    "name": "chainId",
                    "type": "uint256"
                },
                {
                    "name": "verifyingContract",
                    "type": "address"
                },
            ],
            "Root": [
                {
                    "name": "validator",
                    "type": "address"
                },
                {
                    "name": "enable",
                    "type": "bool"
                },
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "chainId": 728126428,
        },
        "message": {
            "validator": "0x1111111111111111111111111111111111111111",
            "enable": True,
        },
    },
    "filters": {
        "name": "Trusted name test",
        "fields": {
            "validator": {
                "type": "trusted_name",
                "name": "Validator",
                "tn_type": [2, 1],
                "tn_source": [1, 2],
            },
            "enable": {
                "type": "raw",
                "name": "State"
            },
        },
    },
}

DATETIME_FILTER = {
    "data": {
        "types": {
            "EIP712Domain": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "version",
                    "type": "string"
                },
                {
                    "name": "chainId",
                    "type": "uint256"
                },
                {
                    "name": "verifyingContract",
                    "type": "address"
                },
            ],
            "Transfer": [
                {
                    "name": "with",
                    "type": "address"
                },
                {
                    "name": "value_recv",
                    "type": "uint256"
                },
                {
                    "name": "token_send",
                    "type": "address"
                },
                {
                    "name": "value_send",
                    "type": "uint256"
                },
                {
                    "name": "token_recv",
                    "type": "address"
                },
                {
                    "name": "expires",
                    "type": "uint64"
                },
            ],
        },
        "primaryType": "Transfer",
        "domain": {
            "name": "Advanced test",
            "version": "1",
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            "chainId": 728126428,
        },
        "message": {
            "with": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "value_recv": 10000000000000000,
            "token_send": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            "value_send": 24500000000000000000,
            "token_recv": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "expires": 1714559400,
        },
    },
    "filters": {
        "name": "Advanced Filtering",
        "fields": {
            "value_send": {
                "type": "amount_join_value",
                "name": "Send",
                "token": 1
            },
            "token_send": {
                "type": "amount_join_token",
                "token": 1
            },
            "value_recv": {
                "type": "amount_join_value",
                "name": "Receive",
                "token": 0
            },
            "token_recv": {
                "type": "amount_join_token",
                "token": 0
            },
            "with": {
                "type": "raw",
                "name": "With"
            },
            "expires": {
                "type": "datetime",
                "name": "Will Expire"
            },
        },
    },
}

PERMIT_AMOUNT_JOIN = {
    "data": {
        "types": {
            "EIP712Domain": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "version",
                    "type": "string"
                },
                {
                    "name": "chainId",
                    "type": "uint256"
                },
                {
                    "name": "verifyingContract",
                    "type": "address"
                },
            ],
            "Permit": [
                {
                    "name": "owner",
                    "type": "address"
                },
                {
                    "name": "spender",
                    "type": "address"
                },
                {
                    "name": "value",
                    "type": "uint256"
                },
                {
                    "name": "nonce",
                    "type": "uint256"
                },
                {
                    "name": "deadline",
                    "type": "uint256"
                },
            ],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "ENS",
            "version": "1",
            "verifyingContract": "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72",
            "chainId": 728126428,
        },
        "message": {
            "owner": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "spender": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
            "value": 4200000000000000000,
            "nonce": 0,
            "deadline": 1719756000,
        },
    },
    "filters": {
        "name": "Permit filtering",
        "fields": {
            "value": {
                "type": "amount_join_value",
                "name": "Send"
            },
            "deadline": {
                "type": "datetime",
                "name": "Deadline"
            },
        },
    },
}

TRUSTED_NAME_FALLBACK = {
    "data": {
        "types": {
            "EIP712Domain": [
                {
                    "name": "name",
                    "type": "string"
                },
                {
                    "name": "version",
                    "type": "string"
                },
                {
                    "name": "chainId",
                    "type": "uint256"
                },
                {
                    "name": "verifyingContract",
                    "type": "address"
                },
            ],
            "Root": [
                {
                    "name": "validator",
                    "type": "address"
                },
                {
                    "name": "enable",
                    "type": "bool"
                },
            ],
        },
        "primaryType": "Root",
        "domain": {
            "name": "test",
            "version": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "chainId": 728126428,
        },
        "message": {
            "validator": "0x0000000000000000000000000000000000000000",
            "enable": True,
        },
    },
    "filters": {
        "name": "Trusted name fallback test",
        "fields": {
            "validator": {
                "type": "trusted_name",
                "name": "Validator",
                "tn_type": [2, 1],
                "tn_source": [1, 2],
            },
            "enable": {
                "type": "raw",
                "name": "State"
            },
        },
    },
}


def load_json(name: str) -> dict:
    with (TIP712_INPUTS / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_seed(name: str, payload: bytes) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / name).write_bytes(payload)


def main() -> None:
    write_seed(
        "00-simple-mail-sign-by-hash.bin",
        build_stream(load_json("00-simple_mail-data.json"),
                     settings=(1 << S_SIGN_BY_HASH)))
    write_seed(
        "01-simple-mail-verbose.bin",
        build_stream(load_json("00-simple_mail-data.json"),
                     settings=(1 << S_VERBOSE_TIP712)))
    write_seed("02-multidimensional-arrays.bin",
               build_stream(load_json("10-multidimensional_arrays-data.json")))
    write_seed(
        "03-filtering-empty-arrays.bin",
        build_stream(FILTERING_EMPTY_ARRAY["data"],
                     FILTERING_EMPTY_ARRAY["filters"]))
    write_seed("04-amount-join.bin",
               build_stream(AMOUNT_JOIN["data"], AMOUNT_JOIN["filters"]))
    write_seed("05-trusted-name.bin",
               build_stream(TRUSTED_NAME["data"], TRUSTED_NAME["filters"]))
    write_seed(
        "06-datetime-filter.bin",
        build_stream(DATETIME_FILTER["data"], DATETIME_FILTER["filters"]))
    write_seed(
        "07-permit-amount-join.bin",
        build_stream(PERMIT_AMOUNT_JOIN["data"],
                     PERMIT_AMOUNT_JOIN["filters"]))
    write_seed("08-long-string-partial.bin",
               build_stream(load_json("03-long_string-data.json")))
    write_seed("09-long-bytes-partial.bin",
               build_stream(load_json("04-long_bytes-data.json")))
    write_seed("10-signed-ints.bin",
               build_stream(load_json("05-signed_ints-data.json")))
    write_seed(
        "11-reset-replay.bin",
        build_stream(load_json("00-simple_mail-data.json"),
                     settings=(1 << S_SIGN_BY_HASH)) + emit_reset() +
        build_stream(TRUSTED_NAME_FALLBACK["data"],
                     TRUSTED_NAME_FALLBACK["filters"],
                     settings=(1 << S_VERBOSE_TIP712)))
    write_seed(
        "12-trusted-name-fallback.bin",
        build_stream(TRUSTED_NAME_FALLBACK["data"],
                     TRUSTED_NAME_FALLBACK["filters"]))


if __name__ == "__main__":
    main()
