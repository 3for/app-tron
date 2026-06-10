import hashlib
import json
import re
import signal
import sys
import copy
from typing import Any, Callable, Optional, Union
import struct
from enum import IntEnum

from client.command_builder import CommandBuilder
from client.ledger_pki import PKIPubKeyUsage
from client.status_word import StatusWord
from client.tip712 import TIP712FieldType
from client import keychain
from ragger.bip import pack_derivation_path
from ragger.utils import RAPDU
from client.keychain import sign_data, Key
import base58
from pathlib import Path
from ledgered.devices import DeviceType

sys.path.append(f"{Path(__file__).parent.parent.resolve()}")
from address import to_raw_address, to_tvm_address


class TrustedNameType(IntEnum):
    ACCOUNT = 0x01
    CONTRACT = 0x02
    NFT = 0x03
    TOKEN = 0x04


class TrustedNameSource(IntEnum):
    LAB = 0x00
    CAL = 0x01
    ENS = 0x02
    UD = 0x03
    FN = 0x04
    DNS = 0x05
    DYNAMIC_RESOLVER = 0x06
    MAB = 0x07


class TrustedNameTag(IntEnum):
    STRUCT_TYPE = 0x01
    STRUCT_VERSION = 0x02
    NOT_VALID_AFTER = 0x10
    CHALLENGE = 0x12
    SIGNER_KEY_ID = 0x13
    SIGNER_ALGO = 0x14
    SIGNATURE = 0x15
    NAME = 0x20
    COIN_TYPE = 0x21
    ADDRESS = 0x22
    CHAIN_ID = 0x23
    NAME_TYPE = 0x70
    NAME_SOURCE = 0x71
    NFT_ID = 0x72


class FieldTag(IntEnum):
    STRUCT_TYPE = 0x01
    STRUCT_VERSION = 0x02
    NOT_VALID_AFTER = 0x10
    CHALLENGE = 0x12
    SIGNER_KEY_ID = 0x13
    SIGNER_ALGO = 0x14
    DER_SIGNATURE = 0x15
    TRUSTED_NAME = 0x20
    COIN_TYPE = 0x21
    ADDRESS = 0x22
    CHAIN_ID = 0x23
    TICKER = 0x24
    BLOCKCHAIN_FAMILY = 0x51
    NETWORK_NAME = 0x52
    NETWORK_ICON_HASH = 0x53
    TRUSTED_NAME_TYPE = 0x70
    TRUSTED_NAME_SOURCE = 0x71
    TRUSTED_NAME_NFT_ID = 0x72
    TRUSTED_NAME_OWNER = 0x74
    TRUSTED_NAME_OWNER_DERIV_PATH = 0x75


# global variables
app_client = None
cmd_builder: CommandBuilder = None
filtering_paths: dict = {}
filtering_tokens: list[dict] = []
current_path: list[str] = []
sig_ctx: dict[str, Any] = {}


def der_encode(value: int) -> bytes:
    # max() to have minimum length of 1
    value_bytes = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    if value >= 0x80:
        value_bytes = (0x80 | len(value_bytes)).to_bytes(1,
                                                         'big') + value_bytes
    return value_bytes


def format_tlv(tag: int, value: Union[int, str, bytes]) -> bytes:
    if isinstance(value, int):
        # max() to have minimum length of 1
        value = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
    elif isinstance(value, str):
        value = value.encode()

    assert isinstance(
        value, bytes), f"Unhandled TLV formatting for type : {type(value)}"

    tlv = bytearray()
    tlv += der_encode(tag)
    tlv += der_encode(len(value))
    tlv += value
    return tlv


def default_handler():
    raise RuntimeError("Uninitialized handler")


autonext_handler: Callable = default_handler
is_golden_run: bool


# From a string typename, extract the type and all the array depth
# Input  = "uint8[2][][4]"          |   "bool"
# Output = ('uint8', [2, None, 4])  |   ('bool', [])
def get_array_levels(typename):
    array_lvls = list()
    regex = re.compile(r"(.*)\[([0-9]*)\]$")

    while True:
        result = regex.search(typename)
        if not result:
            break
        typename = result.group(1)

        level_size = result.group(2)
        if len(level_size) == 0:
            level_size = None
        else:
            level_size = int(level_size)
        array_lvls.insert(0, level_size)
    return (typename, array_lvls)


# From a string typename, extract the type and its size
# Input  = "uint64"         |   "string"
# Output = ('uint', 64)     |   ('string', None)
def get_typesize(typename):
    regex = re.compile(r"^(\w+?)(\d*)$")
    result = regex.search(typename)
    typename = result.group(1)
    typesize = result.group(2)
    if len(typesize) == 0:
        typesize = None
    else:
        typesize = int(typesize)
    return (typename, typesize)


def parse_int(typesize):
    return (TIP712FieldType.INT, int(typesize / 8))


def parse_uint(typesize):
    return (TIP712FieldType.UINT, int(typesize / 8))


def parse_address(typesize):
    return (TIP712FieldType.ADDRESS, None)


def parse_bool(typesize):
    return (TIP712FieldType.BOOL, None)


def parse_string(typesize):
    return (TIP712FieldType.STRING, None)


def parse_bytes(typesize):
    if typesize is not None:
        return (TIP712FieldType.FIX_BYTES, typesize)
    return (TIP712FieldType.DYN_BYTES, None)


def parse_trctoken(typesize):
    return (TIP712FieldType.TRCTOKEN, None)  # same as uint256


# set functions for each type
parsing_type_functions = {}
parsing_type_functions["int"] = parse_int
parsing_type_functions["uint"] = parse_uint
parsing_type_functions["address"] = parse_address
parsing_type_functions["bool"] = parse_bool
parsing_type_functions["string"] = parse_string
parsing_type_functions["bytes"] = parse_bytes
parsing_type_functions["trcToken"] = parse_trctoken


def send_struct_def_field(typename, keyname):
    type_enum = None

    (typename, array_lvls) = get_array_levels(typename)
    (typename, typesize) = get_typesize(typename)

    if typename in parsing_type_functions:
        (type_enum, typesize) = parsing_type_functions[typename](typesize)
    else:
        type_enum = TIP712FieldType.CUSTOM
        typesize = None
    with app_client.exchange_async_raw(
            cmd_builder.tip712_send_struct_def_struct_field(
                type_enum, typename, typesize, array_lvls, keyname)):
        pass
    return (typename, type_enum, typesize, array_lvls)


def encode_integer(value: Union[str, int], typesize: int) -> bytes:
    # Some are already represented as integers in the JSON, but most as strings
    if isinstance(value, str):
        value = int(value, 0)

    if value == 0:
        data = b'\x00'
    else:
        # biggest uint type accepted by struct.pack
        uint64_mask = 0xffffffffffffffff
        data = struct.pack(">QQQQ", (value >> 192) & uint64_mask,
                           (value >> 128) & uint64_mask,
                           (value >> 64) & uint64_mask, value & uint64_mask)
        data = data[len(data) - typesize:]
        data = data.lstrip(b'\x00')
    return data


def encode_int(value: str, typesize: int) -> bytes:
    return encode_integer(value, typesize)


def encode_uint(value: str, typesize: int) -> bytes:
    return encode_integer(value, typesize)


def encode_hex_string(value: str, size: int) -> bytes:
    assert value.startswith("0x")
    value = value[2:]
    if len(value) < (size * 2):
        value = value.rjust(size * 2, "0")
    assert len(value) == (size * 2)
    return bytes.fromhex(value)


def is_base58check_address(value: str) -> bool:
    return value[0] == "T" and len(base58.b58decode_check(value)) == 21


def is_eth_address(value: str) -> bool:
    return value.startswith("0x") and len(bytes.fromhex(value[2:])) == 20


def encode_address(value: str, typesize: int) -> bytes:
    eth_addr_hex = "0x" + to_tvm_address(value).hex()
    return encode_hex_string(eth_addr_hex, 20)


def encode_bool(value: str, typesize: int) -> bytes:
    return encode_integer(value, 1)


def encode_string(value: str, typesize: int) -> bytes:
    return value.encode()


def encode_bytes_fix(value: str, typesize: int) -> bytes:
    return encode_hex_string(value, typesize)


def encode_bytes_dyn(value: str, typesize: int) -> bytes:
    # length of the value string
    # - the length of 0x (2)
    # / by the length of one byte in a hex string (2)
    return encode_hex_string(value, int((len(value) - 2) / 2))


def encode_trctoken(value: str, typesize: int) -> bytes:
    # To support trcToken for TRON solidity,  `trcToken` type is equal to `uint256`
    return encode_integer(value, 256)


# set functions for each type
encoding_functions = {}
encoding_functions[TIP712FieldType.INT] = encode_int
encoding_functions[TIP712FieldType.UINT] = encode_uint
encoding_functions[TIP712FieldType.ADDRESS] = encode_address
encoding_functions[TIP712FieldType.BOOL] = encode_bool
encoding_functions[TIP712FieldType.STRING] = encode_string
encoding_functions[TIP712FieldType.FIX_BYTES] = encode_bytes_fix
encoding_functions[TIP712FieldType.DYN_BYTES] = encode_bytes_dyn
encoding_functions[TIP712FieldType.TRCTOKEN] = encode_trctoken


def send_filtering_token(token_idx: int):
    assert token_idx < len(filtering_tokens)
    if len(filtering_tokens[token_idx]) > 0:
        token = filtering_tokens[token_idx]
        if not token["sent"]:
            provide_token_metadata(token["ticker"],
                                   to_raw_address(token["addr"]),
                                   token["decimals"], token["chain_id"])
            token["sent"] = True


def send_filter(path: str, discarded: bool):
    assert path in filtering_paths.keys()

    if filtering_paths[path]["type"].startswith("amount_join_"):
        if "token" in filtering_paths[path].keys():
            token_idx = filtering_paths[path]["token"]
            send_filtering_token(token_idx)
        else:
            # Permit (ERC-2612)
            send_filtering_token(0)
            token_idx = 0xff
        if filtering_paths[path]["type"].endswith("_token"):
            send_filtering_amount_join_token(path, token_idx, discarded)
        elif filtering_paths[path]["type"].endswith("_value"):
            send_filtering_amount_join_value(path, token_idx,
                                             filtering_paths[path]["name"],
                                             discarded)

    elif filtering_paths[path]["type"] == "datetime":
        send_filtering_datetime(path, filtering_paths[path]["name"], discarded)
    elif filtering_paths[path]["type"] == "trusted_name":
        send_filtering_trusted_name(path, filtering_paths[path]["name"],
                                    filtering_paths[path]["tn_type"],
                                    filtering_paths[path]["tn_source"],
                                    discarded)
    elif filtering_paths[path]["type"] == "raw":
        print(path, filtering_paths[path]["name"], discarded)
        send_filtering_raw(path, filtering_paths[path]["name"], discarded)
    else:
        assert False


def send_struct_impl_field(value, field):
    assert not isinstance(value, list)
    assert field["enum"] != TIP712FieldType.CUSTOM

    data = encoding_functions[field["enum"]](value, field["typesize"])
    if filtering_paths:
        path = ".".join(current_path)
        if path in filtering_paths.keys():
            send_filter(path, False)
    with app_client.exchange_async_raw_chunks(
            cmd_builder.tip712_send_struct_impl_struct_field(bytearray(data))):
        enable_autonext()
    disable_autonext()


def evaluate_field(structs, data, field, lvls_left, new_level=True):
    array_lvls = field["array_lvls"]

    if new_level:
        current_path.append(field["name"])
    if len(array_lvls) > 0 and lvls_left > 0:
        with app_client.exchange_async_raw(
                cmd_builder.tip712_send_struct_impl_array(len(data))):
            pass
        if len(data) == 0:
            for path in filtering_paths.keys():
                dpath = ".".join(current_path) + ".[]"
                if path.startswith(dpath):
                    app_client.exchange_raw(
                        cmd_builder.tip712_filtering_discarded_path(path))
                    send_filter(path, True)
        idx = 0
        for subdata in data:
            current_path.append("[]")
            if not evaluate_field(structs, subdata, field, lvls_left - 1,
                                  False):
                return False
            current_path.pop()
            idx += 1
        if array_lvls[lvls_left - 1] is not None:
            if array_lvls[lvls_left - 1] != idx:
                print("Mismatch in array size! Got %d, expected %d\n" %
                      (idx, array_lvls[lvls_left - 1]),
                      file=sys.stderr)
                return False
    else:
        if field["enum"] == TIP712FieldType.CUSTOM:
            if not send_struct_impl(structs, data, field["type"]):
                return False
        else:
            send_struct_impl_field(data, field)
    if new_level:
        current_path.pop()
    return True


def send_struct_impl(structs, data, structname):
    # Check if it is a struct we don't known
    if structname not in structs.keys():
        return False

    struct = structs[structname]
    for f in struct:
        if not evaluate_field(structs, data[f["name"]], f, len(
                f["array_lvls"])):
            return False
    return True


def start_signature_payload(ctx: dict, magic: int) -> bytearray:
    to_sign = bytearray()
    # magic number so that signature for one type of filter can't possibly be
    # valid for another, defined in APDU specs
    to_sign.append(magic)
    to_sign += ctx["chainid"]
    to_sign += ctx["caddr"]
    to_sign += ctx["schema_hash"]
    return to_sign


# ledgerjs doesn't actually sign anything, and instead uses already pre-computed signatures
def send_filtering_message_info(display_name: str, filters_count: int):
    global sig_ctx

    to_sign = start_signature_payload(sig_ctx, 183)
    to_sign.append(filters_count)
    to_sign += display_name.encode()

    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(
            cmd_builder.tip712_filtering_message_info(display_name,
                                                      filters_count, sig)):
        enable_autonext()
    disable_autonext()


def send_filtering_amount_join_token(path: str, token_idx: int,
                                     discarded: bool):
    global sig_ctx

    to_sign = start_signature_payload(sig_ctx, 11)
    to_sign += path.encode()
    to_sign.append(token_idx)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(
            cmd_builder.tip712_filtering_amount_join_token(
                token_idx, sig, discarded)):
        pass


def send_filtering_amount_join_value(path: str, token_idx: int,
                                     display_name: str, discarded: bool):
    global sig_ctx

    to_sign = start_signature_payload(sig_ctx, 22)
    to_sign += path.encode()
    to_sign += display_name.encode()
    to_sign.append(token_idx)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(
            cmd_builder.tip712_filtering_amount_join_value(
                token_idx, display_name, sig, discarded)):
        pass


def send_filtering_datetime(path: str, display_name: str, discarded: bool):
    global sig_ctx

    to_sign = start_signature_payload(sig_ctx, 33)
    to_sign += path.encode()
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(
            cmd_builder.tip712_filtering_datetime(display_name, sig,
                                                  discarded)):
        pass


def send_filtering_trusted_name(path: str, display_name: str,
                                name_type: list[int], name_source: list[int],
                                discarded: bool):
    global sig_ctx

    to_sign = start_signature_payload(sig_ctx, 44)
    to_sign += path.encode()
    to_sign += display_name.encode()
    for t in name_type:
        to_sign.append(t)
    for s in name_source:
        to_sign.append(s)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(
            cmd_builder.tip712_filtering_trusted_name(display_name, name_type,
                                                      name_source, sig,
                                                      discarded)):
        pass


# ledgerjs doesn't actually sign anything, and instead uses already pre-computed signatures
def send_filtering_raw(path: str, display_name: str, discarded: bool):
    global sig_ctx

    to_sign = start_signature_payload(sig_ctx, 72)
    to_sign += path.encode()
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(
            cmd_builder.tip712_filtering_raw(display_name, sig, discarded)):
        pass


def send_coin_meta_certificate(app_client) -> None:
    if app_client._pki_client is None:
        print(f"Ledger-PKI Not supported on '{app_client._device.name}'")
        return

    app_client._pki_client.send_certificate(PKIPubKeyUsage.PUBKEY_USAGE_COIN_META)


def provide_token_metadata(ticker: str,
                           addr: bytes,
                           decimals: int,
                           chain_id: int,
                           sig: Optional[bytes] = None) -> RAPDU:
    send_coin_meta_certificate(app_client)

    if sig is None:
        # Temporarily get a command with an empty signature to extract the payload and
        # compute the signature on it
        tmp = cmd_builder.provide_trc20_token_information(
            ticker, addr, decimals, chain_id, bytes())
        # skip APDU header & empty sig
        sig = keychain.sign_data(keychain.Key.CAL, tmp[6:])
    return app_client.exchange_raw(
        cmd_builder.provide_trc20_token_information(ticker, addr, decimals,
                                                    chain_id, sig))


def prepare_filtering(filter_data, message):
    global filtering_paths
    global filtering_tokens

    if "fields" in filter_data:
        filtering_paths = filter_data["fields"]
    else:
        filtering_paths = {}
    if "tokens" in filter_data:
        filtering_tokens = filter_data["tokens"]
        for token in filtering_tokens:
            if len(token) > 0:
                token["sent"] = False
    else:
        filtering_tokens = []


def handle_optional_domain_values(domain):
    if "chainId" not in domain.keys():
        domain["chainId"] = 0
    if "verifyingContract" not in domain.keys():
        domain[
            "verifyingContract"] = "0x0000000000000000000000000000000000000000"


def init_signature_context(types, domain):
    global sig_ctx

    handle_optional_domain_values(domain)
    caddr = domain["verifyingContract"]
    if caddr.startswith("0x"):
        caddr = caddr[2:]
    sig_ctx["caddr"] = bytearray.fromhex(caddr)
    chainid = domain["chainId"]
    sig_ctx["chainid"] = bytearray()
    for i in range(8):
        sig_ctx["chainid"].append((chainid >> (i * 8)) & 0xff)
    sig_ctx["chainid"].reverse()
    schema_str = json.dumps(types).replace(" ", "")
    schema_hash = hashlib.sha224(schema_str.encode())
    sig_ctx["schema_hash"] = bytearray.fromhex(schema_hash.hexdigest())


def next_timeout(_signum: int, _frame):
    autonext_handler()


def enable_autonext():
    if app_client._device.type in (DeviceType.STAX, DeviceType.FLEX,
                                   DeviceType.APEX_P):
        delay = 1 * 3 / 2
    else:
        delay = 1 * 3 / 4

    # golden run has to be slower to make sure we take good snapshots
    # and not processing/loading screens
    if is_golden_run:
        delay *= 3

    signal.setitimer(signal.ITIMER_REAL, delay, delay)


def disable_autonext():
    signal.setitimer(signal.ITIMER_REAL, 0, 0)


def process_data(aclient,
                 cbuilder: CommandBuilder,
                 data_json: dict,
                 filters: Optional[dict] = None,
                 autonext: Optional[Callable] = None,
                 golden_run: bool = False) -> bool:
    global sig_ctx
    global app_client
    global cmd_builder
    global autonext_handler
    global is_golden_run
    global current_path

    current_path = []  # init to be empty
    # deepcopy because this function modifies the dict
    data_json = copy.deepcopy(data_json)
    app_client = aclient
    cmd_builder = cbuilder
    domain_typename = "EIP712Domain"
    message_typename = data_json["primaryType"]
    types = data_json["types"]
    domain = data_json["domain"]
    message = data_json["message"]
    if autonext:
        autonext_handler = autonext
        signal.signal(signal.SIGALRM, next_timeout)

    is_golden_run = golden_run

    if filters:
        init_signature_context(types, domain)

    # send types definition
    for key in types.keys():
        with app_client.exchange_async_raw(
                cmd_builder.tip712_send_struct_def_struct_name(key)):
            pass
        for f in types[key]:
            (f["type"], f["enum"], f["typesize"], f["array_lvls"]) = \
             send_struct_def_field(f["type"], f["name"])

    if filters:
        with app_client.exchange_async_raw(
                cmd_builder.tip712_filtering_activate()):
            pass
        prepare_filtering(filters, message)

    send_coin_meta_certificate(app_client)

    # send domain implementation
    with app_client.exchange_async_raw(
            cmd_builder.tip712_send_struct_impl_root_struct(domain_typename)):
        enable_autonext()
    disable_autonext()
    if not send_struct_impl(types, domain, domain_typename):
        return False

    if filters:
        if filters and "name" in filters:
            send_filtering_message_info(filters["name"], len(filtering_paths))
        else:
            send_filtering_message_info(domain["name"], len(filtering_paths))

    # send message implementation
    with app_client.exchange_async_raw(
            cmd_builder.tip712_send_struct_impl_root_struct(message_typename)):
        enable_autonext()
    disable_autonext()
    if not send_struct_impl(types, message, message_typename):
        print("Failed to send message implementation")
        return False

    return True


def provide_trusted_name_common(app_client, cmd_builder, payload: bytes,
                                name_source: TrustedNameSource) -> RAPDU:
    payload += format_tlv(FieldTag.STRUCT_TYPE, 3)  # TrustedName
    if name_source == TrustedNameSource.CAL:
        key_id = 9
        key = Key.CAL
        from_CAL = True
    else:
        key_id = 7
        key = Key.TRUSTED_NAME
        from_CAL = False

    if app_client._pki_client is not None:
        app_client._pki_client.send_certificate(
            PKIPubKeyUsage.PUBKEY_USAGE_TRUSTED_NAME, from_CAL=from_CAL)

    payload += format_tlv(FieldTag.SIGNER_KEY_ID, key_id)  # test key
    payload += format_tlv(FieldTag.SIGNER_ALGO, 1)  # secp256k1
    payload += format_tlv(FieldTag.DER_SIGNATURE, sign_data(key, payload))
    chunks = cmd_builder.provide_trusted_name(payload)
    for chunk in chunks[:-1]:
        app_client.exchange_raw(chunk)
    return app_client.exchange_raw(chunks[-1])


def provide_trusted_name_v1(app_client, cmd_builder, addr: bytes, name: str,
                            challenge: int) -> RAPDU:
    payload = format_tlv(FieldTag.STRUCT_VERSION, 1)
    payload += format_tlv(FieldTag.CHALLENGE, challenge)
    payload += format_tlv(FieldTag.COIN_TYPE, 0x3c)  # ETH in slip-44
    payload += format_tlv(FieldTag.TRUSTED_NAME, name)
    payload += format_tlv(FieldTag.ADDRESS, addr)
    return provide_trusted_name_common(app_client, cmd_builder, payload,
                                       TrustedNameSource.ENS)


def provide_trusted_name_v2(
        app_client,
        cmd_builder,
        addr: bytes,
        name: str,
        name_type: TrustedNameType,
        name_source: TrustedNameSource,
        chain_id: int,
        nft_id: Optional[int] = None,
        challenge: Optional[int] = None,
        not_valid_after: Optional[tuple[int]] = None,
        owner: Optional[bytes] = None,
        owner_deriv_path: Optional[str] = None) -> RAPDU:
    payload = format_tlv(FieldTag.STRUCT_VERSION, 2)
    payload += format_tlv(FieldTag.TRUSTED_NAME, name)
    payload += format_tlv(FieldTag.ADDRESS, addr)
    payload += format_tlv(FieldTag.TRUSTED_NAME_TYPE, name_type)
    payload += format_tlv(FieldTag.TRUSTED_NAME_SOURCE, name_source)
    payload += format_tlv(FieldTag.CHAIN_ID, chain_id)
    if nft_id is not None:
        payload += format_tlv(FieldTag.TRUSTED_NAME_NFT_ID, nft_id)
    if challenge is not None:
        payload += format_tlv(FieldTag.CHALLENGE, challenge)
    if not_valid_after is not None:
        assert len(not_valid_after) == 3
        payload += format_tlv(FieldTag.NOT_VALID_AFTER,
                              struct.pack("BBB", *not_valid_after))
    if owner is not None:
        payload += format_tlv(FieldTag.TRUSTED_NAME_OWNER, owner)
    if owner_deriv_path is not None:
        payload += format_tlv(FieldTag.TRUSTED_NAME_OWNER_DERIV_PATH,
                              pack_derivation_path(owner_deriv_path))
    return provide_trusted_name_common(app_client, cmd_builder, payload,
                                       name_source)
