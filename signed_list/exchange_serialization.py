MAX_UINT64 = (1 << 64) - 1
MAX_TOKEN_PRECISION = 6
SIGNATURE_FORMAT_V1 = 1
SIGNATURE_DOMAIN = b"TRON-EXCHANGE-DETAILS"


def _validate_token_id(token_id):
    if token_id == b"_":
        return
    if len(token_id) != 7 or any(value < ord("0") or value > ord("9")
                                 for value in token_id):
        raise ValueError("token ID must be '_' or exactly seven ASCII digits")


def _validate_token_name(token_name, require_leading_letter=False):
    if not token_name or len(token_name) > 31:
        raise ValueError("token name must contain between 1 and 31 bytes")
    if require_leading_letter and not (ord("A") <= token_name[0] <= ord("Z") or
                                       ord("a") <= token_name[0] <= ord("z")):
        raise ValueError("legacy token name must begin with an ASCII letter")
    if any(value < 0x20 or value > 0x7e for value in token_name):
        raise ValueError("token name must contain only printable ASCII bytes")


def _validate_exchange_details(exchange_id,
                               token1_id,
                               token1_name,
                               token1_precision,
                               token2_id,
                               token2_name,
                               token2_precision,
                               require_leading_letter=False):
    if not isinstance(exchange_id, int) or not 0 <= exchange_id <= MAX_UINT64:
        raise ValueError("exchange ID must be a uint64")

    _validate_token_id(token1_id)
    _validate_token_name(token1_name, require_leading_letter)
    _validate_token_id(token2_id)
    _validate_token_name(token2_name, require_leading_letter)

    for precision in (token1_precision, token2_precision):
        if not isinstance(precision,
                          int) or not 0 <= precision <= MAX_TOKEN_PRECISION:
            raise ValueError("token precision must be between 0 and 6")


def serialize_legacy_exchange_signature_payload(exchange_id, token1_id,
                                                token1_name, token1_precision,
                                                token2_id, token2_name,
                                                token2_precision):
    _validate_exchange_details(exchange_id, token1_id, token1_name,
                               token1_precision, token2_id, token2_name,
                               token2_precision, True)
    return (str(exchange_id).encode("ascii") + token1_id + token1_name +
            bytes([token1_precision]) + token2_id + token2_name +
            bytes([token2_precision]))


def serialize_exchange_signature_payload(exchange_id, token1_id, token1_name,
                                         token1_precision, token2_id,
                                         token2_name, token2_precision):
    _validate_exchange_details(exchange_id, token1_id, token1_name,
                               token1_precision, token2_id, token2_name,
                               token2_precision)
    return (SIGNATURE_DOMAIN + bytes([SIGNATURE_FORMAT_V1]) +
            exchange_id.to_bytes(8, "big") + bytes([len(token1_id)]) +
            token1_id + bytes([len(token1_name)]) + token1_name +
            bytes([token1_precision, len(token2_id)]) + token2_id +
            bytes([len(token2_name)]) + token2_name +
            bytes([token2_precision]))
