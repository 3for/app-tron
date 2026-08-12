import copy
import hashlib
import re
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from Crypto.Hash import keccak
from eth_account import Account
from eth_account.messages import SignableMessage, encode_defunct
from eth_keys import KeyAPI
from eth_keys.datatypes import PublicKey
from eth_keys.datatypes import Signature

import response_parser as ResponseParser
from address import to_tvm_address
from client.command_builder import CommandBuilder

SUN_PER_TRX = 10**6


def to_units(amount, decimals: int) -> int:
    """Convert a human-readable amount to its integer on-chain unit."""
    return int(Decimal(str(amount)) * (10**decimals))


def to_sun(amount) -> int:
    """Convert TRX to SUN using TRON's six-decimal native precision."""
    return to_units(amount, 6)


def get_challenge(client) -> int:
    """Request and decode the current device challenge."""
    response = client.exchange_raw(CommandBuilder().get_challenge())
    return ResponseParser.challenge(response.data)


def normalize_vrs(vrs: tuple) -> tuple:
    vrs_l = list()
    for elem in vrs:
        vrs_l.append(elem.lstrip(b'\x00'))
    return tuple(vrs_l)


def check_hash_signature(txID, signature, public_key):
    s = Signature(signature_bytes=signature)
    keys = KeyAPI('eth_keys.backends.NativeECCBackend')
    publicKey = PublicKey(bytes.fromhex(public_key))
    return keys.ecdsa_verify(txID, s, publicKey)


def check_tx_signature(transaction, signature, public_key):
    txID = hashlib.sha256(transaction).digest()
    return check_hash_signature(txID, signature, public_key)


def get_selector_from_data(data: str) -> bytes:
    # `data` is the "0x"-prefixed ABI-encoded calldata returned by web3's
    # encode_abi; the 4-byte function selector is its first word.
    raw_data = bytes.fromhex(data[2:])
    return raw_data[:4]


def build_trc20_calldata(to_address_hex: str,
                         amount: Decimal,
                         selector: str = "a9059cbb"):
    # transfer(address,uint256) by default; callers can select another
    # compatible two-argument TRC20 method such as approve(address,uint256).
    selector_bytes = bytes.fromhex(selector)
    if len(selector_bytes) != 4:
        raise ValueError("TRC20 selector must be exactly 4 bytes")

    # Remove '41' prefix if present, then pad to 32 bytes
    clean_address = to_address_hex[2:] if to_address_hex.startswith(
        "41") else to_address_hex
    address_bytes = bytes.fromhex(clean_address).rjust(32, b'\x00')

    # Convert Decimal to integer, then to 32-byte big-endian
    amount_int = int(amount)
    amount_bytes = amount_int.to_bytes(32, 'big')

    return selector_bytes + address_bytes + amount_bytes


def recover_message(msg, vrs: tuple) -> bytes:
    if isinstance(msg, dict):  # TIP-712
        smsg = encode_typed_data(full_message=msg)
    else:  # TIP-191
        smsg = encode_defunct(primitive=msg)
    addr = Account.recover_message(smsg, normalize_vrs(vrs))
    return bytes.fromhex(addr[2:])


# EIP712Domain field -> ABI type, mirroring eth_account's hash_domain. Only
# verifyingContract is an address that needs TRON normalization.
_DOMAIN_FIELD_TYPES = {
    "name": "string",
    "version": "string",
    "chainId": "uint256",
    "verifyingContract": "address",
    "salt": "bytes32",
}


def _norm_addr(value: Any) -> str:
    # Accepts a TRON Base58 ("T...") or 0x-hex address and returns the 0x-hex,
    # 20-byte form eth_account/eth_abi expect.
    return "0x" + to_tvm_address(value).hex()


def _keccak(data: bytes = b"", text: Optional[str] = None) -> bytes:
    if text is not None:
        data = text.encode()
    return keccak.new(digest_bits=256, data=data).digest()


def _is_array_type(type_: str) -> bool:
    return type_.endswith("]")


def _parse_core_array_type(type_: str) -> str:
    if _is_array_type(type_):
        return type_[:type_.index("[")]
    return type_


def _parse_parent_array_type(type_: str) -> str:
    if _is_array_type(type_):
        return type_[:type_.rindex("[")]
    return type_


def _parse_integer_type(type_: str) -> Tuple[str, int]:
    if type_ == "trcToken":
        return ("uint", 256)
    match = re.fullmatch(r"(u?int)(\d*)", type_)
    if match is None:
        raise ValueError(f"not an integer type: {type_}")
    bits = int(match.group(2) or "256")
    return (match.group(1), bits)


def _to_int(value: Any) -> int:
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _is_0x_prefixed_hexstr(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("0x"):
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value[2:])


def _hexstr_to_bytes(value: str, size: Optional[int] = None) -> bytes:
    value = value[2:]
    if size is not None and len(value) < size * 2:
        value = value.rjust(size * 2, "0")
    elif len(value) % 2 != 0:
        value = "0" + value
    return bytes.fromhex(value)


def _encode_abi_word(type_: str, value: Union[bytes, int, bool, str]) -> bytes:
    if type_ == "bytes32":
        if not isinstance(value, bytes) or len(value) != 32:
            raise ValueError("bytes32 ABI value must be exactly 32 bytes")
        return value
    if type_ == "address":
        return bytes(12) + to_tvm_address(value)
    if type_ == "bool":
        return int(bool(value)).to_bytes(32, "big")
    if type_.startswith("bytes") and type_ != "bytes":
        size = int(type_[5:])
        if not isinstance(value, bytes):
            if _is_0x_prefixed_hexstr(value):
                value = _hexstr_to_bytes(value, size)
            elif isinstance(value, str):
                value = value.encode()
            else:
                value = int(value).to_bytes(max(1, (int(value).bit_length() + 7) // 8), "big")
        if len(value) > size:
            raise ValueError(f"{type_} ABI value must be at most {size} bytes")
        return value.ljust(32, b"\x00")
    if type_ == "trcToken" or type_.startswith(("int", "uint")):
        sign, bits = _parse_integer_type(type_)
        intval = _to_int(value)
        if sign == "uint":
            if intval < 0 or intval >= (1 << bits):
                raise ValueError(f"{type_} value out of bounds")
            return intval.to_bytes(32, "big")
        if intval < -(1 << (bits - 1)) or intval >= (1 << (bits - 1)):
            raise ValueError(f"{type_} value out of bounds")
        if intval < 0:
            intval = (1 << 256) + intval
        return intval.to_bytes(32, "big", signed=False)
    raise ValueError(f"unsupported ABI word type: {type_}")


def _derive_primary_type(message_types: Dict[str, List[Dict[str, str]]]) -> str:
    # The primary type is the only struct never referenced as a field of another
    # struct (EIP712Domain already excluded by the caller). Mirrors eth_account.
    custom = set(message_types.keys())
    referenced = set()
    for fields in message_types.values():
        for field in fields:
            base = _parse_core_array_type(field["type"])
            if base in custom:
                referenced.add(base)
    roots = custom - referenced
    if len(roots) != 1:
        raise ValueError(f"Unable to derive primaryType, candidates: {sorted(roots)}")
    return roots.pop()


_SOLIDITY_TYPES = {
    "bool",
    "address",
    "string",
    "bytes",
    "uint",
    "int",
    "trcToken",
    *{f"uint{(idx + 1) * 8}" for idx in range(32)},
    *{f"int{(idx + 1) * 8}" for idx in range(32)},
    *{f"bytes{idx + 1}" for idx in range(32)},
}


def _find_type_dependencies(type_: str,
                            types: Dict[str, List[Dict[str, str]]],
                            results: Optional[Set[str]] = None) -> Set[str]:
    if results is None:
        results = set()
    type_ = _parse_core_array_type(type_)
    if type_ in _SOLIDITY_TYPES or type_ in results:
        return results
    if type_ not in types:
        raise ValueError(f"No definition of type `{type_}`")
    results.add(type_)
    for field in types[type_]:
        _find_type_dependencies(field["type"], types, results)
    return results


def _encode_type(type_: str, types: Dict[str, List[Dict[str, str]]]) -> str:
    deps = _find_type_dependencies(type_, types)
    deps.discard(type_)
    ordered = [type_] + sorted(deps)
    result = ""
    for dep in ordered:
        fields = ",".join(f"{field['type']} {field['name']}" for field in types[dep])
        result += f"{dep}({fields})"
    return result


def _hash_type(type_: str, types: Dict[str, List[Dict[str, str]]]) -> bytes:
    return _keccak(text=_encode_type(type_, types))


def _encode_field(types: Dict[str, List[Dict[str, str]]],
                  name: str,
                  type_: str,
                  value: Any) -> Tuple[str, Union[bytes, int, bool, str]]:
    if type_ in types:
        return ("bytes32", bytes(32) if value is None else _hash_struct(type_, types, value))
    if type_ in ("string", "bytes") and value is None:
        return ("bytes32", b"")
    if value is None:
        raise ValueError(f"Missing value for field `{name}` of type `{type_}`")
    if _is_array_type(type_):
        if not isinstance(value, list):
            raise ValueError(f"Invalid value for field `{name}` of type `{type_}`")
        item_type = _parse_parent_array_type(type_)
        encoded_items = b"".join(
            _encode_abi_word(abi_type, abi_value)
            for abi_type, abi_value in (_encode_field(types, name, item_type, item)
                                        for item in value)
        )
        return ("bytes32", _keccak(encoded_items))
    if type_ == "bool":
        falsy_values = {"False", "false", "0"}
        return (type_, False if not value or value in falsy_values else True)
    if type_.startswith("bytes"):
        if not isinstance(value, bytes):
            if _is_0x_prefixed_hexstr(value):
                value = _hexstr_to_bytes(value, int(type_[5:]) if type_ != "bytes" else None)
            elif isinstance(value, str):
                value = value.encode()
            else:
                value = int(value).to_bytes(max(1, (int(value).bit_length() + 7) // 8), "big")
        return ("bytes32", _keccak(value)) if type_ == "bytes" else (type_, value)
    if type_ == "string":
        return ("bytes32", _keccak(str(value).encode()))
    if type_ == "address":
        return (type_, value)
    if type_ == "trcToken" or type_.startswith(("int", "uint")):
        return (type_, _to_int(value))
    return (type_, value)


def _encode_data(type_: str,
                 types: Dict[str, List[Dict[str, str]]],
                 data: Dict[str, Any]) -> bytes:
    encoded = [_hash_type(type_, types)]
    for field in types[type_]:
        abi_type, abi_value = _encode_field(types, field["name"], field["type"],
                                            data.get(field["name"]))
        encoded.append(_encode_abi_word(abi_type, abi_value))
    return b"".join(encoded)


def _hash_struct(type_: str,
                 types: Dict[str, List[Dict[str, str]]],
                 data: Dict[str, Any]) -> bytes:
    return _keccak(_encode_data(type_, types, data))


def _hash_domain(domain_data: Dict[str, Any]) -> bytes:
    domain_types = {
        "EIP712Domain": [
            {"name": key, "type": _DOMAIN_FIELD_TYPES[key]}
            for key in _DOMAIN_FIELD_TYPES
            if key in domain_data
        ]
    }
    return _hash_struct("EIP712Domain", domain_types, domain_data)


def encode_typed_data(
    domain_data: Dict[str, Any] = None,
    message_types: Dict[str, Any] = None,
    message_data: Dict[str, Any] = None,
    full_message: Dict[str, Any] = None,
) -> SignableMessage:
    if full_message is not None:
        fm = copy.deepcopy(full_message)
        domain_data = fm["domain"]
        message_types = {k: v for k, v in fm["types"].items() if k != "EIP712Domain"}
        message_data = fm["message"]
        primary_type = fm.get("primaryType") or _derive_primary_type(message_types)
    else:
        primary_type = _derive_primary_type(message_types)
    return SignableMessage(
        b"\x01",
        _hash_domain(domain_data),
        _hash_struct(primary_type, message_types, message_data),
    )


def recover_transaction(tx_params, vrs: tuple) -> bytes:
    raw_tx = Account.create().sign_transaction(tx_params).rawTransaction
    prefix = bytes()
    if raw_tx[0] in [0x01, 0x02]:
        prefix = raw_tx[:1]
        raw_tx = raw_tx[len(prefix):]
    else:
        if "chainId" in tx_params:
            # v is returned on one byte only so it might have overflowed
            # in that case, we will reconstruct it to its full value
            trunc_chain_id = tx_params["chainId"]
            while trunc_chain_id.bit_length() > 32:
                trunc_chain_id >>= 8

            trunc_target = trunc_chain_id * 2 + 35
            trunc_v = int.from_bytes(vrs[0], "big")

            if (trunc_target & 0xff) == trunc_v:
                parity = 0
            elif ((trunc_target + 1) & 0xff) == trunc_v:
                parity = 1
            else:
                # should have matched with a previous if
                assert False

            # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
            full_v = parity + tx_params["chainId"] * 2 + 35
            # 9 bytes would be big enough even for the biggest chain ID
            vrs = (int(full_v).to_bytes(9, "big"), vrs[1], vrs[2])
        else:
            # Pre EIP-155 TX
            assert False
    decoded = rlp.decode(raw_tx)
    reencoded = rlp.encode(decoded[:-3] + list(normalize_vrs(vrs)))
    addr = Account.recover_transaction(prefix + reencoded)
    return bytes.fromhex(addr[2:])
