from eth_keys import KeyAPI
from eth_keys.datatypes import Signature
from eth_keys.datatypes import PublicKey

from eth_account import Account 
from eth_account.messages import encode_defunct, SignableMessage
from eth_account._utils.encode_typed_data.encoding_and_hashing import get_primary_type, encode_data, hash_struct

from typing import Any, Dict, List
from hexbytes import HexBytes
from eth_utils import keccak

import hashlib

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

def recover_message(msg, vrs: tuple) -> bytes:
    if isinstance(msg, dict):  # TIP-712
        smsg = encode_typed_data(full_message=msg)
    else:  # EIP-191
        smsg = encode_defunct(primitive=msg)
    addr = Account.recover_message(smsg, normalize_vrs(vrs))
    return bytes.fromhex(addr[2:])

def encode_typed_data(
    domain_data: Dict[str, Any] = None,
    message_types: Dict[str, Any] = None,
    message_data: Dict[str, Any] = None,
    full_message: Dict[str, Any] = None,
) -> SignableMessage:
    if full_message is not None:
        if (
            domain_data is not None
            or message_types is not None
            or message_data is not None
        ):
            raise ValueError(
                "You may supply either `full_message` as a single argument or "
                "`domain_data`, `message_types`, and `message_data` as three arguments,"
                " but not both."
            )

        full_message_types = full_message["types"].copy()
        full_message_domain = full_message["domain"].copy()

        # If TIP712Domain types were provided, check that they match the domain data
        if "TIP712Domain" in full_message_types:
            domain_data_keys = list(full_message_domain.keys())
            domain_types_keys = [
                field["name"] for field in full_message_types["TIP712Domain"]
            ]

            if set(domain_data_keys) != (set(domain_types_keys)):
                raise ValidationError(
                    "The fields provided in `domain` do not match the fields provided"
                    " in `types.TIP712Domain`. The fields provided in `domain` were"
                    f" `{domain_data_keys}`, but the fields provided in "
                    f"`types.TIP712Domain` were `{domain_types_keys}`."
                )

        full_message_types.pop("TIP712Domain", None)

        # If primaryType was provided, check that it matches the derived primaryType
        if "primaryType" in full_message:
            derived_primary_type = get_primary_type(full_message_types)
            provided_primary_type = full_message["primaryType"]
            if derived_primary_type != provided_primary_type:
                raise ValidationError(
                    "The provided `primaryType` does not match the derived "
                    "`primaryType`. The provided `primaryType` was "
                    f"`{provided_primary_type}`, but the derived `primaryType` was "
                    f"`{derived_primary_type}`."
                )

        parsed_domain_data = full_message_domain
        parsed_message_types = full_message_types
        parsed_message_data = full_message["message"]

    else:
        parsed_domain_data = domain_data
        parsed_message_types = message_types
        parsed_message_data = message_data

    return SignableMessage(
        HexBytes(b"\x01"),
        hash_domain(parsed_domain_data),
        hash_tip712_message(parsed_message_types, parsed_message_data),
    )

def hash_tip712_message(
    # returns the same hash as `hash_struct`, but automatically determines primary type
    message_types: Dict[str, List[Dict[str, str]]],
    message_data: Dict[str, Any],
) -> bytes:
    primary_type = get_primary_type(message_types)
    return bytes(keccak(encode_data(primary_type, message_types, message_data)))

def hash_domain(domain_data: Dict[str, Any]) -> bytes:
    tip712_domain_map = {
        "name": {"name": "name", "type": "string"},
        "version": {"name": "version", "type": "string"},
        "chainId": {"name": "chainId", "type": "uint256"},
        "verifyingContract": {"name": "verifyingContract", "type": "address"},
        "salt": {"name": "salt", "type": "bytes32"},
    }

    for k in domain_data.keys():
        if k not in tip712_domain_map.keys():
            raise ValueError(f"Invalid domain key: `{k}`")

    domain_types = {
        "TIP712Domain": [
            tip712_domain_map[k] for k in tip712_domain_map.keys() if k in domain_data
        ]
    }

    return hash_struct("TIP712Domain", domain_types, domain_data)