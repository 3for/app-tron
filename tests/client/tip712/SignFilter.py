from client.tip712 import InputData
from client.tip712 import EncodeTokenInfo
from client.tip712 import TIP712FieldType
import sys
import keychain
from typing import Optional
from client.command_builder import CommandBuilder
import copy
from typing import Any, Dict

# Define the top-level key as a variable
root_key = "tip712_signatures"

# global variable
out = {
    root_key: {
    }
}
schema: Dict[str, Dict[str, Any]] = {}
schema["fields"] = []
single_field = {}
token_entries = []
tip712_v2 = {}

def sign_filter_data(
                 #out: Dict[str, Dict[str, Any]],
                 data_json: dict,
                 filters: Optional[dict] = None) -> bool:

    print("ZYD 111 out:", out)
    InputData.current_path = []  # init to be empty
    # deepcopy because this function modifies the dict
    data_json = copy.deepcopy(data_json)
    domain_typename = "EIP712Domain"
    message_typename = data_json["primaryType"]
    types = data_json["types"]
    domain = data_json["domain"]
    message = data_json["message"]

    #if filters:
    InputData.init_signature_context(types, domain)

    caddr = "0x" + InputData.sig_ctx["caddr"].hex()
    out[root_key][caddr] = {}
    schema_hash = InputData.sig_ctx["schema_hash"].hex()
    out[root_key][caddr][schema_hash] = {}
    print("ZYD 222 out:", out)

    # get types definition
    for key in types.keys():
        for f in types[key]:
            (f["type"], f["enum"], f["typesize"], f["array_lvls"]) = \
             get_struct_def_field(f["type"], f["name"])

    if filters:
        InputData.prepare_filtering(filters)

    if not get_struct_impl(types, domain, domain_typename):
        return False

    sig = bytes()
    display_name = str()

    # in app-ethereum, the filters_count is fields count in filtering_paths
    # Will check if "712 filters are missing" when sign 712 messge
    if filters:
        if filters and "name" in filters:
            display_name = filters["name"]
        else:
            display_name = domain["name"]
        sig = sign_filtering_message_info(display_name, len(InputData.filtering_paths))
        out[root_key][caddr][schema_hash]["contractName"] = {}
        out[root_key][caddr][schema_hash]["contractName"]["label"] = display_name
        out[root_key][caddr][schema_hash]["contractName"]["signature"] = sig.hex()

    print("ZYD 333 out:", out)
    if not get_struct_impl(types, message, message_typename):
        print("Failed to get message implementation")
        return False

    out[root_key][caddr][schema_hash]["fields"] = schema["fields"]
    """ # in ledger-live hw-app-eth, the filters_count is fields count in epi712_signatures
    if filters:
        if filters and "name" in filters:
            display_name = filters["name"]
        else:
            display_name = domain["name"]
        print("ZYD filters_count:", len(schema["fields"]))
        sig = sign_filtering_message_info(display_name, len(schema["fields"]))
        out[root_key][caddr][schema_hash]["contractName"] = {}
        out[root_key][caddr][schema_hash]["contractName"]["label"] = display_name
        out[root_key][caddr][schema_hash]["contractName"]["signature"] = sig.hex() """
    
    print("ZYD AAA out:", out)

    trc20SignaturesBlob = EncodeTokenInfo.encode_token_info(token_entries)
    print("ZYD trc20SignaturesBlob:", trc20SignaturesBlob)

    new_key = build_entry(domain["chainId"], domain["verifyingContract"].lower(), schema_hash)
    tip712_v2[new_key] = out[root_key][caddr][schema_hash]
    print("ZYD tip712_v2:", tip712_v2)
    return True

def build_entry(chain_id: int, contract_address: str, schema_hash: str) -> str:
    return f"{chain_id}:{contract_address}:{schema_hash}"

def sign_filtering_token(token_idx: int) -> bytes:
    assert token_idx < len(InputData.filtering_tokens)
    sig = bytes()
    if len(InputData.filtering_tokens[token_idx]) > 0:
        token = InputData.filtering_tokens[token_idx]
        if not token["sent"]:
            sig = sign_token_metadata(token["ticker"],
                                   bytes.fromhex(token["addr"][2:]),
                                   token["decimals"], token["chain_id"])
            
            token_entry = {}
            token_entry["ticker"] = token["ticker"]
            token_entry["contractAddress"] = token["addr"]
            token_entry["decimals"] = token["decimals"]
            token_entry["chainId"] = token["chain_id"]
            token_entry["signature"] = sig.hex()
            token_entries.append(token_entry)

            token["sent"] = True

    return sig

def get_filter(path: str):
    assert path in InputData.filtering_paths.keys()
    sig = bytes()
    single_field = {}
    single_field["path"] = path
    single_field["format"] = InputData.filtering_paths[path]["type"]
    if InputData.filtering_paths[path]["type"].startswith("amount_join_"):
        if "token" in InputData.filtering_paths[path].keys():
            token_idx = InputData.filtering_paths[path]["token"]
            # For leger-live, ONLY add token_field if amount_join_token, not for amount_join_value
            if InputData.filtering_paths[path]["type"].endswith("_token"):
                sig = sign_filtering_token(token_idx)
        else:
            # Permit (ERC-2612)
            sig = sign_filtering_token(0)
            token_idx = 0xff
            
        single_field["coin_ref"] = token_idx
        print("ZYD 555 schema[\"fields\"]", schema["fields"])
        if InputData.filtering_paths[path]["type"].endswith("_token"):
            single_field["format"] = "token"
            # always set single_field["label"]
            if "name" in InputData.filtering_paths[path]:
                single_field["label"] = InputData.filtering_paths[path]["name"]
            else:
                single_field["label"] = single_field["path"]
            sig = sign_filtering_amount_join_token(path, token_idx)
            single_field["signature"] = sig.hex()
        elif InputData.filtering_paths[path]["type"].endswith("_value"):
            single_field["format"] = "amount"
            single_field["label"] = InputData.filtering_paths[path]["name"]
            sig = sign_filtering_amount_join_value(path, token_idx,
                                             InputData.filtering_paths[path]["name"])
            single_field["signature"] = sig.hex()

        schema["fields"].append(single_field)
    elif InputData.filtering_paths[path]["type"] == "datetime":
        single_field["label"] = InputData.filtering_paths[path]["name"]
        sig = sign_filtering_datetime(path, InputData.filtering_paths[path]["name"])
        single_field["signature"] = sig.hex()
        schema["fields"].append(single_field)
    elif InputData.filtering_paths[path]["type"] == "trusted_name":
        single_field["label"] = InputData.filtering_paths[path]["name"]
        sig = sign_filtering_trusted_name(path, InputData.filtering_paths[path]["name"],
                                    InputData.filtering_paths[path]["tn_type"],
                                    InputData.filtering_paths[path]["tn_source"])
        single_field["signature"] = sig.hex()
        schema["fields"].append(single_field)
    elif InputData.filtering_paths[path]["type"] == "raw":
        single_field["label"] = InputData.filtering_paths[path]["name"]
        sig = sign_filtering_raw(path, InputData.filtering_paths[path]["name"])
        single_field["signature"] = sig.hex()
        schema["fields"].append(single_field)
    else:
        assert False

def get_struct_impl_field(value, field):
    assert not isinstance(value, list)
    assert field["enum"] != TIP712FieldType.CUSTOM

    data = InputData.encoding_functions[field["enum"]](value, field["typesize"])
    print("ZYD get_struct_impl_field value:", value)
    print("ZYD get_struct_impl_field field:", field)
    if InputData.filtering_paths:
        path = ".".join(InputData.current_path)
        if path in InputData.filtering_paths.keys():
            print("ZYD get_struct_impl_field get_filter path:", path)
            print("ZYD get_struct_impl_field InputData.filtering_paths[path]:", InputData.filtering_paths[path])
            get_filter(path)

def get_evaluate_field(structs, data, field, lvls_left, new_level=True):
    array_lvls = field["array_lvls"]

    if new_level:
        InputData.current_path.append(field["name"])
    if len(array_lvls) > 0 and lvls_left > 0:
        if len(data) == 0:
            for path in InputData.filtering_paths.keys():
                dpath = ".".join(InputData.current_path) + ".[]"
                if path.startswith(dpath):
                    print("ZYD get_filter 111 path:", path)
                    get_filter(path)
        idx = 0
        for subdata in data:
            InputData.current_path.append("[]")
            if not get_evaluate_field(structs, subdata, field, lvls_left - 1,
                                  False):
                return False
            InputData.current_path.pop()
            idx += 1
        if array_lvls[lvls_left - 1] is not None:
            if array_lvls[lvls_left - 1] != idx:
                print("Mismatch in array size! Got %d, expected %d\n" %
                      (idx, array_lvls[lvls_left - 1]),
                      file=sys.stderr)
                return False
    else:
        if field["enum"] == TIP712FieldType.CUSTOM:
            if not get_struct_impl(structs, data, field["type"]):
                return False
        else:
            get_struct_impl_field(data, field)
    if new_level:
        InputData.current_path.pop()
    return True

def get_struct_impl(structs, data, structname):
    # Check if it is a struct we don't known
    if structname not in structs.keys():
        return False

    struct = structs[structname]
    for f in struct:
        if not get_evaluate_field(structs, data[f["name"]], f, len(
                f["array_lvls"])):
            return False
    return True

def get_struct_def_field(typename, keyname):
    type_enum = None

    (typename, array_lvls) = InputData.get_array_levels(typename)
    (typename, typesize) = InputData.get_typesize(typename)

    if typename in InputData.parsing_type_functions:
        (type_enum, typesize) = InputData.parsing_type_functions[typename](typesize)
    else:
        type_enum = TIP712FieldType.CUSTOM
        typesize = None
    
    return (typename, type_enum, typesize, array_lvls)

def sign_filtering_amount_join_token(path: str, token_idx: int) -> bytes:
    to_sign = InputData.start_signature_payload(InputData.sig_ctx, 11)
    to_sign += path.encode()
    to_sign.append(token_idx)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    print("ZYD sign_filtering_amount_join_token sig:", sig.hex())

    return sig

def sign_filtering_amount_join_value(path: str, token_idx: int,
                                     display_name: str) -> bytes:
    to_sign = InputData.start_signature_payload(InputData.sig_ctx, 22)
    to_sign += path.encode()
    to_sign += display_name.encode()
    to_sign.append(token_idx)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    print("ZYD sign_filtering_amount_join_value sig:", sig.hex())

    return sig

def sign_filtering_datetime(path: str, display_name: str) -> bytes:
    to_sign = InputData.start_signature_payload(InputData.sig_ctx, 33)
    to_sign += path.encode()
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    print("ZYD sign_filtering_datetime sig:", sig.hex())

    return sig

def sign_filtering_trusted_name(path: str, display_name: str,
                                name_type: list[int], name_source: list[int]) -> bytes:
    to_sign = InputData.start_signature_payload(InputData.sig_ctx, 44)
    to_sign += path.encode()
    to_sign += display_name.encode()
    for t in name_type:
        to_sign.append(t)
    for s in name_source:
        to_sign.append(s)
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    print("ZYD sign_filtering_trusted_name sig:", sig.hex())
    
    return sig


# ledgerjs doesn't actually sign anything, and instead uses already pre-computed signatures
def sign_filtering_raw(path: str, display_name: str) -> bytes:
    to_sign = InputData.start_signature_payload(InputData.sig_ctx, 72)
    to_sign += path.encode()
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    print("ZYD sign_filtering_raw sig:", sig.hex())

    return sig

def sign_token_metadata(ticker: str,
                           addr: bytes,
                           decimals: int,
                           chain_id: int,
                           sig: Optional[bytes] = None) -> bytes:
    cmd_builder = CommandBuilder()
    # Temporarily get a command with an empty signature to extract the payload and
    # compute the signature on it
    tmp = cmd_builder.provide_trc20_token_information(
        ticker, addr, decimals, chain_id, bytes())
    # skip APDU header & empty sig
    sig = keychain.sign_data(keychain.Key.CAL, tmp[6:])
    print("ZYD sign_token_metadata sig:", sig.hex())

    return sig

# ledgerjs doesn't actually sign anything, and instead uses already pre-computed signatures
def sign_filtering_message_info(display_name: str, filters_count: int) -> bytes:
    to_sign = InputData.start_signature_payload(InputData.sig_ctx, 183)
    to_sign.append(filters_count)
    to_sign += display_name.encode()
    sig = keychain.sign_data(keychain.Key.CAL, to_sign)
    print("ZYD sign_filtering_message_info sig:", sig.hex())

    return sig