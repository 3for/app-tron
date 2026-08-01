import hashlib
from decimal import Decimal

from eth_keys import KeyAPI
from eth_keys.datatypes import PublicKey
from eth_keys.datatypes import Signature


def check_hash_signature(txID, signature, public_key):
    s = Signature(signature_bytes=signature)
    keys = KeyAPI('eth_keys.backends.NativeECCBackend')
    publicKey = PublicKey(bytes.fromhex(public_key))
    return keys.ecdsa_verify(txID, s, publicKey)


def check_tx_signature(transaction, signature, public_key):
    txID = hashlib.sha256(transaction).digest()
    return check_hash_signature(txID, signature, public_key)


def build_trc20_method_calldata(selector_hex: str,
                                address_hex: str,
                                amount: Decimal):
    """Build calldata for a two-argument TRC20 address/uint256 method."""
    selector = bytes.fromhex(selector_hex)
    if len(selector) != 4:
        raise ValueError("TRC20 selector must be exactly 4 bytes")

    # Remove '41' prefix if present, then pad to 32 bytes
    clean_address = address_hex[2:] if address_hex.startswith(
        "41") else address_hex
    if len(clean_address) != 40:
        raise ValueError("TRC20 address must be exactly 20 bytes")
    address_bytes = bytes.fromhex(clean_address).rjust(32, b'\x00')

    # Convert Decimal to integer, then to 32-byte big-endian
    amount_int = int(amount)
    if amount_int < 0 or amount_int >= 2**256:
        raise ValueError("TRC20 amount must fit in uint256")
    amount_bytes = amount_int.to_bytes(32, 'big')

    return selector + address_bytes + amount_bytes


def build_trc20_calldata(to_address_hex: str, amount: Decimal):
    # Function selector for transfer(address,uint256)
    return build_trc20_method_calldata("a9059cbb", to_address_hex, amount)
