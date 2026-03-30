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
from client.tip712 import TIP712FieldType
import keychain
from ragger.firmware import Firmware
from ragger.utils import RAPDU
from keychain import sign_data, Key
import base58
from pathlib import Path

sys.path.append(f"{Path(__file__).parent.parent.resolve()}")
from address import to_raw_address, to_tvm_address


class TrustedNameType(IntEnum):
    ACCOUNT = 0x01
    CONTRACT = 0x02
    NFT = 0x03


class TrustedNameSource(IntEnum):
    LAB = 0x00
    CAL = 0x01
    ENS = 0x02
    UD = 0x03
    FN = 0x04
    DNS = 0x05


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


class PKIPubKeyUsage(IntEnum):
    PUBKEY_USAGE_GENUINE_CHECK = 0x01
    PUBKEY_USAGE_EXCHANGE_PAYLOAD = 0x02
    PUBKEY_USAGE_NFT_METADATA = 0x03
    PUBKEY_USAGE_TRUSTED_NAME = 0x04
    PUBKEY_USAGE_BACKUP_PROVIDER = 0x05
    PUBKEY_USAGE_RECOVER_ORCHESTRATOR = 0x06
    PUBKEY_USAGE_PLUGIN_METADATA = 0x07
    PUBKEY_USAGE_COIN_META = 0x08
    PUBKEY_USAGE_SEED_ID_AUTH = 0x09


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


class StatusWord(IntEnum):
    OK = 0x9000
    ERROR_NO_INFO = 0x6a00
    INVALID_DATA = 0x6a80
    INSUFFICIENT_MEMORY = 0x6a84
    INVALID_INS = 0x6d00
    INVALID_P1_P2 = 0x6b00
    CONDITION_NOT_SATISFIED = 0x6985
    REF_DATA_NOT_FOUND = 0x6a88
    EXCEPTION_OVERFLOW = 0x6807
    NOT_IMPLEMENTED = 0x911c


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
        print(f"Ledger-PKI Not supported on '{app_client._firmware.name}'")
        return

    # pylint: disable=line-too-long
    if app_client._firmware == Firmware.NANOSP:
        cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010310040102000015473045022100C15795C2AE41E6FAE6B1362EE1AE216428507D7C1D6939B928559CC7A1F6425C02206139CF2E133DD62F3E00F183E42109C9853AC62B6B70C5079B9A80DBB9D54AB5"  # noqa: E501
    elif app_client._firmware == Firmware.NANOX:
        cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010215473045022100E3B956F93FBFF0D41908483888F0F75D4714662A692F7A38DC6C41A13294F9370220471991BECB3CA4F43413CADC8FF738A8CC03568BFA832B4DCFE8C469080984E5"  # noqa: E501
    elif app_client._firmware == Firmware.STAX:
        cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501041546304402206731FCD3E2432C5CA162381392FD17AD3A41EEF852E1D706F21A656AB165263602204B89FAE8DBAF191E2D79FB00EBA80D613CB7EDF0BE960CB6F6B29D96E1437F5F"  # noqa: E501
    elif app_client._firmware == Firmware.FLEX:
        cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010515473045022100B59EA8B958AA40578A6FBE9BBFB761020ACD5DBD8AA863C11DA17F42B2AFDE790220186316059EFA58811337D47C7F815F772EA42BBBCEA4AE123D1118C80588F5CB"  # noqa: E501
    elif app_client._firmware == Firmware.APEX_P:
        cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501061546304402207AB71BB46DD2361292195E95587D14FEDE2BA10FC23F0D6B20444B93A32258D302201362A6815779B2806005B0151BFADB811B78A76FDB90028FBE6C93EB7FB5EEA3"  # noqa: E501
    else:
        print(f"Invalid device '{app_client._firmware.name}'")
        cert_apdu = ""
    # pylint: enable=line-too-long

    if cert_apdu:
        app_client._pki_client.send_certificate(
            PKIPubKeyUsage.PUBKEY_USAGE_COIN_META, bytes.fromhex(cert_apdu))


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
    if app_client._client.firmware in (Firmware.STAX, Firmware.FLEX,
                                       Firmware.APEX_P):
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
    cert_apdu = ""
    if name_source == TrustedNameSource.CAL:
        if app_client._pki_client is not None:
            # pylint: disable=line-too-long
            if app_client._firmware == Firmware.NANOSP:
                cert_apdu = "010101020102110400000002120100130200021401011604000000002010547275737465645F4E616D655F43414C300200093101043201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501031546304402202397E6D4F5A9C13532810619EB766CB41919F7A814935CA207429966E41CE80202202E43159A04BB0596A6B1F0DDE1A12931EA56156751586BEE8FDCAB54EEE36883"  # noqa: E501
            elif app_client._firmware == Firmware.NANOX:
                cert_apdu = "010101020102110400000002120100130200021401011604000000002010547275737465645F4E616D655F43414C300200093101043201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010215473045022100BCAED6896A3413657F7F936F53FFF5BD7E30498B1109EAB878135F6DD4AAE555022056913EF42F166BEFEEDDB06C1F7AEEDE8712828F37B916E3E6DA7AE0809558E4"  # noqa: E501
            elif app_client._firmware == Firmware.STAX:
                cert_apdu = "010101020102110400000002120100130200021401011604000000002010547275737465645F4E616D655F43414C300200093101043201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010415473045022100ABA9D58446EE81EB073DA91941989DD7E133556D58DE2BCBA59E46253DB448B102201DF8AE930A9E318B50576D8922503A5D3EC84C00C332A7C8FF7CD48708751840"  # noqa: E501
            elif app_client._firmware == Firmware.FLEX:
                cert_apdu = "010101020102110400000002120100130200021401011604000000002010547275737465645F4E616D655F43414C300200093101043201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501051546304402206DC9F82C53F3B13400D3E343E3C8C81868E8C73B1EF2655D07891064B7AC3166022069A36E4059D75C93E488A5D58C02BCA9C80C081F77B31C5EDCF07F1A500C565A"  # noqa: E501
            elif app_client._firmware == Firmware.APEX_P:
                cert_apdu = "010101020102110400000002120100130200021401011604000000002010547275737465645F4E616D655F43414C300200093101043201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010615473045022100BF6920A641076921E6DCE96D77BC70581A28B73E932F8D2E117BFE8F48E9FC5F0220088FA292BB19B5F7594145F65614FDA65B899598FCA7A306E08926F67359EAA5"  # noqa: E501
            else:
                print(f"Invalid device '{app_client._firmware.name}'")
            # pylint: enable=line-too-long
        key_id = 9
        key = Key.CAL
    else:
        if app_client._pki_client is not None:
            # pylint: disable=line-too-long
            if app_client._firmware == Firmware.NANOSP:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010315473045022100F394484C045418507E0F76A3231F233B920C733D3E5BB68AFBAA80A55195F70D022012BC1FD796CD2081D8355DEEFA051FBB9329E34826FF3125098F4C6A0C29992A"  # noqa: E501
            elif app_client._firmware == Firmware.NANOX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350102154730450221009D97646C49EE771BE56C321AB59C732E10D5D363EBB9944BF284A3A04EC5A14102200633518E851984A7EA00C5F81EDA9DAA58B4A6C98E57DA1FBB9074AEFF0FE49F"  # noqa: E501
            elif app_client._firmware == Firmware.STAX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010415473045022100A57DC7AB3F0E38A8D10783C7449024D929C60843BB75E5FF7B8088CB71CB130C022045A03E6F501F3702871466473BA08CE1F111357ED9EF395959733477165924C4"  # noqa: E501
            elif app_client._firmware == Firmware.FLEX:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010515473045022100D5BB77756C3D7C1B4254EA8D5351B94A89B13BA69C3631A523F293A10B7144B302201519B29A882BB22DCDDF6BE79A9CBA76566717FA877B7CA4B9CC40361A2D579E"  # noqa: E501
            elif app_client._firmware == Firmware.APEX_P:
                cert_apdu = "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350106154630440220200261047BAF050570EA5105D1E05855131CB98A94C58B019732F849BD1CE5330220237D303A9606EA631DDD3E5E12D2A70878A0ED954D975BF55DD7A84BF08506AA"  # noqa: E501
            else:
                print(f"Invalid device '{app_client._firmware.name}'")
            # pylint: enable=line-too-long
        key_id = 7
        key = Key.TRUSTED_NAME

    if app_client._pki_client is not None and cert_apdu:
        app_client._pki_client.send_certificate(
            PKIPubKeyUsage.PUBKEY_USAGE_TRUSTED_NAME, bytes.fromhex(cert_apdu))

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
        not_valid_after: Optional[tuple[int]] = None) -> RAPDU:
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
    return provide_trusted_name_common(app_client, cmd_builder, payload,
                                       name_source)
