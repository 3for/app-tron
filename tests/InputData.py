import hashlib
import json
import re
import signal
import sys
import copy
from typing import Any, Callable, Optional, Union
import struct
from enum import IntEnum

from command_builder import CommandBuilder, TIP712FieldType
import keychain
from ragger.firmware import Firmware
from ragger.utils import RAPDU
# from tron import TronClient 

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

# global variables
app_client = None
cmd_builder: CommandBuilder = None
filtering_paths: dict = {}
current_path: list[str] = list()
sig_ctx: dict[str, Any] = {}


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


# set functions for each type
parsing_type_functions = {}
parsing_type_functions["int"] = parse_int
parsing_type_functions["uint"] = parse_uint
parsing_type_functions["address"] = parse_address
parsing_type_functions["bool"] = parse_bool
parsing_type_functions["string"] = parse_string
parsing_type_functions["bytes"] = parse_bytes


def send_struct_def_field(typename, keyname):
    type_enum = None

    (typename, array_lvls) = get_array_levels(typename)
    (typename, typesize) = get_typesize(typename)

    if typename in parsing_type_functions.keys():
        (type_enum, typesize) = parsing_type_functions[typename](typesize)
    else:
        type_enum = TIP712FieldType.CUSTOM
        typesize = None
    with app_client.exchange_async_raw(cmd_builder.tip712_send_struct_def_struct_field(
                                       type_enum,
                                       typename,
                                       typesize,
                                       array_lvls,
                                       keyname)):
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
        data = struct.pack(">QQQQ",
                           (value >> 192) & uint64_mask,
                           (value >> 128) & uint64_mask,
                           (value >> 64) & uint64_mask,
                           value & uint64_mask)
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


def encode_address(value: str, typesize: int) -> bytes:
    return encode_hex_string(value, 20)


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


# set functions for each type
encoding_functions = {}
encoding_functions[TIP712FieldType.INT] = encode_int
encoding_functions[TIP712FieldType.UINT] = encode_uint
encoding_functions[TIP712FieldType.ADDRESS] = encode_address
encoding_functions[TIP712FieldType.BOOL] = encode_bool
encoding_functions[TIP712FieldType.STRING] = encode_string
encoding_functions[TIP712FieldType.FIX_BYTES] = encode_bytes_fix
encoding_functions[TIP712FieldType.DYN_BYTES] = encode_bytes_dyn


def send_struct_impl_field(value, field):
    # Something wrong happened if this triggers
    if isinstance(value, list) or (field["enum"] == TIP712FieldType.CUSTOM):
        breakpoint()

    data = encoding_functions[field["enum"]](value, field["typesize"])

    if filtering_paths:
        path = ".".join(current_path)
        if path in filtering_paths.keys():
            if filtering_paths[path]["type"] == "amount_join_token":
                send_filtering_amount_join_token(filtering_paths[path]["token"])
            elif filtering_paths[path]["type"] == "amount_join_value":
                if "token" in filtering_paths[path].keys():
                    token = filtering_paths[path]["token"]
                else:
                    # Permit (ERC-2612)
                    token = 0xff
                send_filtering_amount_join_value(token,
                                                 filtering_paths[path]["name"])
            elif filtering_paths[path]["type"] == "datetime":
                send_filtering_datetime(filtering_paths[path]["name"])
            elif filtering_paths[path]["type"] == "raw":
                send_filtering_raw(filtering_paths[path]["name"])
            else:
                assert False

    with app_client.exchange_async_raw_chunks(cmd_builder.tip712_send_struct_impl_struct_field(bytearray(data))):
        enable_autonext()
    disable_autonext()


def evaluate_field(structs, data, field, lvls_left, new_level=True):
    array_lvls = field["array_lvls"]

    if new_level:
        current_path.append(field["name"])
    if len(array_lvls) > 0 and lvls_left > 0:
        with app_client.exchange_async_raw(cmd_builder.tip712_send_struct_impl_array(len(data))):
            pass
        idx = 0
        for subdata in data:
            current_path.append("[]")
            if not evaluate_field(structs, subdata, field, lvls_left - 1, False):
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
        if not evaluate_field(structs, data[f["name"]], f, len(f["array_lvls"])):
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
    with app_client.exchange_async_raw(cmd_builder.tip712_filtering_message_info(display_name, filters_count, sig)):
        enable_autonext()
    disable_autonext()


def send_filtering_amount_join_token(token_idx: int):
    global sig_ctx

    path_str = ".".join(current_path)

    to_sign = start_signature_payload(sig_ctx, 11)
    to_sign += path_str.encode()
    to_sign.append(token_idx)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(cmd_builder.tip712_filtering_amount_join_token(token_idx, sig)):
        pass


def send_filtering_amount_join_value(token_idx: int, display_name: str):
    global sig_ctx

    path_str = ".".join(current_path)

    to_sign = start_signature_payload(sig_ctx, 22)
    to_sign += path_str.encode()
    to_sign += display_name.encode()
    to_sign.append(token_idx)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(cmd_builder.tip712_filtering_amount_join_value(token_idx, display_name, sig)):
        pass


def send_filtering_datetime(display_name: str):
    global sig_ctx

    path_str = ".".join(current_path)

    to_sign = start_signature_payload(sig_ctx, 33)
    to_sign += path_str.encode()
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(cmd_builder.tip712_filtering_datetime(display_name, sig)):
        pass


# ledgerjs doesn't actually sign anything, and instead uses already pre-computed signatures
def send_filtering_raw(display_name):
    global sig_ctx

    path_str = ".".join(current_path)

    to_sign = start_signature_payload(sig_ctx, 72)
    to_sign += path_str.encode()
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    with app_client.exchange_async_raw(cmd_builder.tip712_filtering_raw(display_name, sig)):
        pass

def provide_token_metadata(ticker: str,
                           addr: bytes,
                           decimals: int,
                           chain_id: int,
                           sig: Optional[bytes] = None) -> RAPDU:

    if app_client._pki_client is None:
        print(f"Ledger-PKI Not supported on '{app_client._firmware.name}'")
    else:
        # pylint: disable=line-too-long
        print('app_client._firmware:', dir(app_client))
        print('app_client._firmware:', dir(app_client._firmware))
        print('app_client._firmware:', app_client._firmware.name)
        if app_client._firmware == Firmware.NANOSP:
            cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010310040102000015473045022100C15795C2AE41E6FAE6B1362EE1AE216428507D7C1D6939B928559CC7A1F6425C02206139CF2E133DD62F3E00F183E42109C9853AC62B6B70C5079B9A80DBB9D54AB5"  # noqa: E501
        elif app_client._firmware == Firmware.NANOX:
            cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010215473045022100E3B956F93FBFF0D41908483888F0F75D4714662A692F7A38DC6C41A13294F9370220471991BECB3CA4F43413CADC8FF738A8CC03568BFA832B4DCFE8C469080984E5"  # noqa: E501
        elif app_client._firmware == Firmware.STAX:
            cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501041546304402206731FCD3E2432C5CA162381392FD17AD3A41EEF852E1D706F21A656AB165263602204B89FAE8DBAF191E2D79FB00EBA80D613CB7EDF0BE960CB6F6B29D96E1437F5F"  # noqa: E501
        elif app_client._firmware == Firmware.FLEX:
            cert_apdu = "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010515473045022100B59EA8B958AA40578A6FBE9BBFB761020ACD5DBD8AA863C11DA17F42B2AFDE790220186316059EFA58811337D47C7F815F772EA42BBBCEA4AE123D1118C80588F5CB"  # noqa: E501
        # pylint: enable=line-too-long

        app_client._pki_client.send_certificate(PKIPubKeyUsage.PUBKEY_USAGE_COIN_META, bytes.fromhex(cert_apdu))

    if sig is None:
        # Temporarily get a command with an empty signature to extract the payload and
        # compute the signature on it
        tmp = cmd_builder.provide_erc20_token_information(ticker,
                                                          addr,
                                                          decimals,
                                                          chain_id,
                                                          bytes())
        # skip APDU header & empty sig
        sig = keychain.sign_data(keychain.Key.CAL, tmp[6:])
    return app_client.exchange_raw(cmd_builder.provide_erc20_token_information(ticker,
                                                                            addr,
                                                                            decimals,
                                                                            chain_id,
                                                                            sig))


def prepare_filtering(filtr_data, message):
    global filtering_paths

    if "fields" in filtr_data:
        filtering_paths = filtr_data["fields"]
    else:
        filtering_paths = {}
    if "tokens" in filtr_data:
        for token in filtr_data["tokens"]:
            provide_token_metadata(token["ticker"],
                                   bytes.fromhex(token["addr"][2:]),
                                   token["decimals"],
                                   token["chain_id"])


def handle_optional_domain_values(domain):
    if "chainId" not in domain.keys():
        domain["chainId"] = 0
    if "verifyingContract" not in domain.keys():
        domain["verifyingContract"] = "0x0000000000000000000000000000000000000000"


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
    if app_client._client.firmware in (Firmware.STAX, Firmware.FLEX):
        delay = 1/3
    else:
        delay = 1/4

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

    # deepcopy because this function modifies the dict
    data_json = copy.deepcopy(data_json)
    app_client = aclient
    cmd_builder = cbuilder
    domain_typename = "TIP712Domain"
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
        with app_client.exchange_async_raw(cmd_builder.tip712_send_struct_def_struct_name(key)):
            pass
        for f in types[key]:
            (f["type"], f["enum"], f["typesize"], f["array_lvls"]) = \
             send_struct_def_field(f["type"], f["name"])

    if filters:
        with app_client.exchange_async_raw(cmd_builder.tip712_filtering_activate()):
            pass
        prepare_filtering(filters, message)

    if app_client._pki_client is None:
        print(f"Ledger-PKI Not supported on '{app_client._firmware.name}'")
    else:
        # pylint: disable=line-too-long
        print('line513 app_client._firmware: ', app_client._firmware)
        if app_client._firmware == Firmware.NANOSP:
            cert_apdu = "0101010201021004010200001104000000021201001302000214010116040000000020104549503731325f46696c746572696e67300200053101083201213321024cca8fad496aa5040a00a7eb2f5cc3b85376d88ba147a7d7054a99c64056188734010135010315473045022100ef197e5b1cabb3de5dfc62f965db8536b0463d272c6fea38ebc73605715b1df9022017bef619d52a9728b37a9b5a33f0143bcdcc714694eed07c326796ffbb7c2958"  # noqa: E501
        elif app_client._firmware == Firmware.NANOX:
            cert_apdu = "0101010201021104000000021201001302000214010116040000000020104549503731325F46696C746572696E67300200053101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010215473045022100E07E129B0DC2A571D5205C3DB43BF4BB3463A2E9D2A4EEDBEC8FD3518CC5A95902205F80306EEF785C4D45BDCA1F25394A1341571BD1921C2740392DD22EB1ACDD8B"  # noqa: E501
        elif app_client._firmware == Firmware.STAX:
            cert_apdu = "0101010201021104000000021201001302000214010116040000000020104549503731325F46696C746572696E67300200053101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501041546304402204EA7B30F0EEFEF25FAB3ADDA6609E25296C41DD1C5969A92FAE6B600AAC2902E02206212054E123F5F965F787AE7EE565E243F21B11725626D3FF058522D6BDCD995"  # noqa: E501
        elif app_client._firmware == Firmware.FLEX:
            cert_apdu = "0101010201021104000000021201001302000214010116040000000020104549503731325F46696C746572696E67300200053101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501051546304402205FB5E970065A95C57F00FFA3964946251815527613724ED6745C37E303934BE702203CC9F4124B42806F0A7CA765CFAB5AADEB280C35AB8F809FC49ADC97D9B9CE15"  # noqa: E501
        # pylint: enable=line-too-long

        app_client._pki_client.send_certificate(PKIPubKeyUsage.PUBKEY_USAGE_COIN_META, bytes.fromhex(cert_apdu))

    # send domain implementation
    with app_client.exchange_async_raw(cmd_builder.tip712_send_struct_impl_root_struct(domain_typename)):
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
    with app_client.exchange_async_raw(cmd_builder.tip712_send_struct_impl_root_struct(message_typename)):
        enable_autonext()
    disable_autonext()
    if not send_struct_impl(types, message, message_typename):
        return False

    return True
