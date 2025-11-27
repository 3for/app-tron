import functools

from eth_abi.base import parse_type_str
from eth_abi.codec import ABICodec as ETHABICodec
from eth_abi.decoding import Fixed32ByteSizeDecoder
from eth_abi.encoding import NumberEncoder
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