import functools

from eth_abi.base import parse_type_str
from eth_abi.codec import ABICodec as ETHABICodec
from eth_abi.decoding import Fixed32ByteSizeDecoder
from eth_abi.encoding import (Fixed32ByteSizeEncoder, NumberEncoder)
from eth_abi.registry import BaseEquals
from eth_abi.registry import registry as default_registry
from eth_utils import (
    int_to_big_endian,
    is_integer,
    big_endian_to_int,
)
from eth_abi.utils.numeric import (
    compute_unsigned_integer_bounds,
)
from eth_abi.exceptions import NonEmptyPaddingBytes
import sys
from pathlib import Path
sys.path.append(f"{Path(__file__).parent.resolve()}")
from address import (
    to_tvm_address,
    is_address,
    to_base58check_address,
)

class TronAddressEncoder(Fixed32ByteSizeEncoder):
    value_bit_size = 20 * 8
    encode_fn = staticmethod(to_tvm_address)
    is_big_endian = True

    @classmethod
    def validate_value(cls, value):
        if not is_address(value):
            cls.invalidate_value(value)

    def validate(self):
        super().validate()
        if self.value_bit_size != 20 * 8:
            raise ValueError("Addresses must be 160 bits in length")

    @parse_type_str("address")
    def from_type_str(cls, abi_type, registry):
        return cls()

class TronAddressDecoder(Fixed32ByteSizeDecoder):
    value_bit_size = 20 * 8
    is_big_endian = True
    decoder_fn = staticmethod(to_base58check_address)

    @parse_type_str("address")
    def from_type_str(cls, abi_type, registry):
        return cls()

    def validate_padding_bytes(self, value, padding_bytes):
        value_byte_size = self._get_value_byte_size()
        padding_size = self.data_byte_size - value_byte_size

        if (
            padding_bytes != b"\x00" * padding_size
            and padding_bytes != b"\x00" * (padding_size - 2) + b"\x00A"
            and self.strict
        ):
            raise NonEmptyPaddingBytes(f"Padding bytes were not empty: {repr(padding_bytes)}")

#
# trcToken Encoder
#
class TrcTokenEncoder(NumberEncoder):
    encode_fn = staticmethod(int_to_big_endian)
    bounds_fn = staticmethod(compute_unsigned_integer_bounds)
    type_check_fn = staticmethod(is_integer)

    @parse_type_str("trcToken")
    def from_type_str(cls, abi_type, registry):
        return cls(value_bit_size=256)
    
    def encode(self, value):
        # Convert numeric strings (e.g., "1002000") to int
        # Because eth-abi requires integers for uint256 encoding
        if isinstance(value, str):
            if not value.isdigit():
                raise ValueError(f"Invalid trcToken string: {value}")
            value = int(value)

        # Delegate to the parent class to perform standard uint256 encoding
        return super().encode(value)
    
    def validate_value(self, value):
        if isinstance(value, str) and value.isdigit():
            value = int(value)
        return super().validate_value(value)

#
# trcToken Decoder
#
class TrcTokenDecoder(Fixed32ByteSizeDecoder):
    decoder_fn = staticmethod(big_endian_to_int)
    is_big_endian = True

    @parse_type_str("trcToken")
    def from_type_str(cls, abi_type, registry):
        return cls(value_bit_size=256)

def do_patching(registry):
    registry.unregister("address")

    registry.register(
        BaseEquals("address"),
        TronAddressEncoder,
        TronAddressDecoder,
        label="address",
    )

    registry.register(
        BaseEquals("trcToken"),
        TrcTokenEncoder,
        TrcTokenDecoder,
        label="trcToken",
    )

    def _get_decoder_uncached_new(self, type_str, strict=True):  # https://github.com/ethereum/eth-abi/pull/240
        decoder = self._get_registration(self._decoders, type_str)
        decoder.strict = strict
        return decoder

    registry._get_decoder_uncached = _get_decoder_uncached_new.__get__(registry, registry.__class__)
    registry.get_decoder = functools.lru_cache(maxsize=None)(registry._get_decoder_uncached)


class ABICodec(ETHABICodec):
    def encode_single(self, typ, arg):
        encoder = self._registry.get_encoder(typ)
        return encoder(arg)

    def decode_single(self, typ, data):
        decoder = self._registry.get_decoder(typ)
        stream = self.stream_class(data)
        return decoder(stream)

    def encode_abi(self, types, args):
        return super().encode(types, args)

    def decode_abi(self, types, data, strict=True):
        return super().decode(types, data, strict)


registry = default_registry.copy()
do_patching(registry)
tron_abi = ABICodec(registry)

""" # Assuming you have a TRC10 token ID
token_id = 1000001 # Example TRC10 token ID
encoded_test = tron_abi.encode_abi(['trcToken'], [token_id])
print("encoded_test:", encoded_test.hex())
(decoded_token_id, ) = tron_abi.decode_abi(['trcToken'], encoded_test)
print("decoded_token_id:", decoded_token_id)
assert token_id == decoded_token_id """