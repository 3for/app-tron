import re
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).parent.parent / "signed_list"))
from exchange_serialization import SIGNATURE_DOMAIN
from exchange_serialization import SIGNATURE_FORMAT_V1
from exchange_serialization import TOKEN_SIGNATURE_DOMAIN
from exchange_serialization import TOKEN_SIGNATURE_FORMAT_V1
from exchange_serialization import serialize_exchange_signature_payload
from exchange_serialization import serialize_legacy_exchange_signature_payload
from exchange_serialization import serialize_legacy_token_signature_payload
from exchange_serialization import serialize_token_signature_payload


def _read_varint(data, offset):
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def _decode_exchange_details(data):
    fields = {}
    offset = 0
    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        field_number = tag >> 3
        wire_type = tag & 7
        if wire_type == 0:
            fields[field_number], offset = _read_varint(data, offset)
        elif wire_type == 2:
            length, offset = _read_varint(data, offset)
            fields[field_number] = data[offset:offset + length]
            offset += length
        else:
            raise AssertionError(f"unsupported wire type {wire_type}")
    return fields


def details(exchange_id=166, **overrides):
    values = {
        "exchange_id": exchange_id,
        "token1_id": b"1002000",
        "token1_name": b"BitTorrent",
        "token1_precision": 6,
        "token2_id": b"_",
        "token2_name": b"TRX",
        "token2_precision": 6,
    }
    values.update(overrides)
    return values


def test_existing_legacy_exchange_signature_payload_is_unchanged():
    payload = serialize_legacy_exchange_signature_payload(**details())
    assert payload == b"1661002000BitTorrent\x06_TRX\x06"


def test_existing_legacy_token_signature_payload_is_unchanged():
    assert serialize_legacy_token_signature_payload(
        b"1002000", b"BitTorrent", 6) == b"1002000BitTorrent\x06"
    assert serialize_legacy_token_signature_payload(b"TRX", b"TRX",
                                                    6) == b"TRXTRX\x06"


def test_token_v1_payload_is_domain_separated_and_length_delimited():
    assert serialize_token_signature_payload(
        b"1002000", b"BitTorrent", 6) == (
            TOKEN_SIGNATURE_DOMAIN + bytes([TOKEN_SIGNATURE_FORMAT_V1, 7]) +
            b"1002000\x0aBitTorrent\x06")


def test_legacy_exchange_payload_cannot_be_replayed_as_token_metadata():
    payload = serialize_legacy_exchange_signature_payload(**details())
    assert payload == b"1661002000BitTorrent\x06_TRX\x06"
    with pytest.raises(ValueError):
        serialize_legacy_token_signature_payload(payload[:7], payload[7:-1],
                                                 payload[-1])


@pytest.mark.parametrize(("token_id", "token_name", "precision"), [
    (b"1661002", b"000BitTorrent\x06_TRX", 6),
    (b"10020A0", b"BitTorrent", 6),
    (b"1002000", b"Bit\tTorrent", 6),
    (b"1002000", b"", 6),
    (b"1002000", b"BitTorrent", 7),
    (b"_", b"TRX", 6),
])
def test_token_payload_rejects_invalid_or_cross_domain_fields(
        token_id, token_name, precision):
    with pytest.raises(ValueError):
        serialize_token_signature_payload(token_id, token_name, precision)


def test_token_v1_accepts_future_id_lengths_but_legacy_does_not():
    canonical = serialize_token_signature_payload(b"10000000", b"Future", 6)
    assert canonical.startswith(TOKEN_SIGNATURE_DOMAIN)
    with pytest.raises(ValueError):
        serialize_legacy_token_signature_payload(b"10000000", b"Future", 6)


@pytest.mark.parametrize("token_id", [b"01", b"1" * 20])
def test_token_v1_rejects_noncanonical_or_oversized_ids(token_id):
    with pytest.raises(ValueError):
        serialize_token_signature_payload(token_id, b"Token", 6)


def test_every_decodable_published_token_record_remains_accepted():
    token_list = (Path(__file__).parent.parent / "signed_list" / "tokens10.js")
    records_rejected_by_existing_protobuf_limit = []
    for line in token_list.read_text().splitlines():
        match = re.search(r"id:\s*(\d+)\s*,\s*message:\s*'([0-9a-f]+)'", line)
        if match is None:
            continue
        listed_id, encoded_hex = match.groups()
        fields = _decode_exchange_details(bytes.fromhex(encoded_hex))
        if len(fields[1]) > 31:
            records_rejected_by_existing_protobuf_limit.append(int(listed_id))
            continue
        signing_id = b"TRX" if listed_id == "0" else listed_id.encode("ascii")
        assert serialize_legacy_token_signature_payload(signing_id, fields[1],
                                                        fields.get(2, 0))
    assert records_rejected_by_existing_protobuf_limit == [
        1001788,
        1000825,
        1000748,
    ]


def test_every_decodable_published_legacy_record_remains_accepted():
    signed_list = (Path(__file__).parent.parent / "signed_list" /
                   "signedList_Exchanges.txt")
    records_rejected_by_existing_protobuf_limit = []
    for line in signed_list.read_text().splitlines()[1:]:
        listed_exchange_id, _, encoded_hex = line.split(",")
        fields = _decode_exchange_details(bytes.fromhex(encoded_hex))
        if len(fields[3]) > 31 or len(fields[6]) > 31:
            records_rejected_by_existing_protobuf_limit.append(
                int(listed_exchange_id))
            continue
        record = details(exchange_id=fields[1],
                         token1_id=fields[2],
                         token1_name=fields[3],
                         token1_precision=fields.get(4, 0),
                         token2_id=fields[5],
                         token2_name=fields[6],
                         token2_precision=fields.get(7, 0))
        assert fields[1] == int(listed_exchange_id)
        assert serialize_legacy_exchange_signature_payload(**record)
    assert records_rejected_by_existing_protobuf_limit == [103]


def test_v1_payload_is_domain_separated_and_length_delimited():
    payload = serialize_exchange_signature_payload(**details())
    assert payload == (SIGNATURE_DOMAIN + bytes([SIGNATURE_FORMAT_V1]) +
                       bytes.fromhex("00000000000000a6") + b"\x07" +
                       b"1002000" + b"\x0a" + b"BitTorrent" + b"\x06" +
                       b"\x01" + b"_" + b"\x03" + b"TRX" + b"\x06")


def test_exchange_v1_accepts_future_id_lengths_but_legacy_does_not():
    record = details(token1_id=b"10000000")
    canonical = serialize_exchange_signature_payload(**record)
    assert canonical.startswith(SIGNATURE_DOMAIN)
    with pytest.raises(ValueError):
        serialize_legacy_exchange_signature_payload(**record)


@pytest.mark.parametrize("exchange_id", [
    (1 << 31) - 1,
    1 << 31,
    (1 << 32) - 1,
    1 << 32,
    (1 << 63) - 1,
    (1 << 64) - 1,
])
def test_v1_payload_preserves_full_width_id(exchange_id):
    payload = serialize_exchange_signature_payload(**details(exchange_id))
    offset = len(SIGNATURE_DOMAIN) + 1
    assert payload[offset:offset + 8] == exchange_id.to_bytes(8, "big")


def test_v1_payload_rejects_modulo_replay():
    low = serialize_exchange_signature_payload(**details())
    for offset in (1 << 32, 1 << 33):
        high = serialize_exchange_signature_payload(**details(166 + offset))
        assert low != high


def test_legacy_payload_uses_the_full_width_exchange_id():
    low = serialize_legacy_exchange_signature_payload(**details())
    for offset in (1 << 32, 1 << 33):
        record = details(166 + offset)
        high = serialize_legacy_exchange_signature_payload(**record)
        assert low != high


def test_v1_field_boundaries_cannot_be_repartitioned():
    original = serialize_exchange_signature_payload(**details())
    reframed = details(token1_name=b"BitTorrent\x06",
                       token1_precision=95,
                       token2_id=b"T",
                       token2_name=b"RX")
    with pytest.raises(ValueError):
        serialize_exchange_signature_payload(**reframed)
    assert original.startswith(SIGNATURE_DOMAIN)


def test_v1_distinct_semantics_have_distinct_payloads():
    records = [
        details(),
        details(167),
        details(token1_id=b"1002001"),
        details(token1_name=b"BitTorrent2"),
        details(token1_precision=5),
        details(token2_id=b"1000166"),
        details(token2_name=b"TRX2"),
        details(token2_precision=5),
    ]
    payloads = {
        serialize_exchange_signature_payload(**record)
        for record in records
    }
    assert len(payloads) == len(records)


@pytest.mark.parametrize(("field", "value"), [
    ("token1_id", b"T"),
    ("token1_id", b"10020A0"),
    ("token1_id", b"01002000"),
    ("token1_id", b"1" * 20),
    ("token1_name", b"BitTorrent\x06"),
    ("token1_name", b"Bit\tTorrent"),
    ("token1_precision", 7),
])
def test_v1_payload_rejects_invalid_fields(field, value):
    with pytest.raises(ValueError):
        serialize_exchange_signature_payload(**details(**{field: value}))


def test_v1_framing_allows_printable_names_without_legacy_prefix_rule():
    record = details(token1_name=b"1BitTorrent")
    canonical = serialize_exchange_signature_payload(**record)
    assert canonical.startswith(SIGNATURE_DOMAIN)
    with pytest.raises(ValueError):
        serialize_legacy_exchange_signature_payload(**record)
