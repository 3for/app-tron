#!/usr/bin/env python3
"""Generate transaction-signing seeds for fuzz_handle_sign."""

from pathlib import Path


OUT_DIR = Path(__file__).resolve().parent / "corpus" / "fuzz_handle_sign"
TRANSFER_TYPE_URL = b"type.googleapis.com/protocol.TransferContract"
TYPE_URL = b"type.googleapis.com/protocol.DelegateResourceContract"
VOTE_TYPE_URL = b"type.googleapis.com/protocol.VoteWitnessContract"
ASSET_ISSUE_TYPE_URL = b"type.googleapis.com/protocol.AssetIssueContract"
PARTICIPATE_ASSET_ISSUE_TYPE_URL = (
    b"type.googleapis.com/protocol.ParticipateAssetIssueContract"
)
UNFREEZE_ASSET_TYPE_URL = b"type.googleapis.com/protocol.UnfreezeAssetContract"
UPDATE_ASSET_TYPE_URL = b"type.googleapis.com/protocol.UpdateAssetContract"
CREATE_SMART_CONTRACT_TYPE_URL = (
    b"type.googleapis.com/protocol.CreateSmartContract"
)
EXCHANGE_CREATE_TYPE_URL = (
    b"type.googleapis.com/protocol.ExchangeCreateContract"
)
EXCHANGE_TRANSACTION_TYPE_URL = (
    b"type.googleapis.com/protocol.ExchangeTransactionContract"
)
BIP32_PATH = [0x8000002C, 0x800000C3, 0x80000000, 0, 0]


def varint(value: int) -> bytes:
    if value < 0:
        # Protobuf int64 uses the ten-byte two's-complement varint form.
        value &= (1 << 64) - 1
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def uint_field(tag: int, value: int) -> bytes:
    return varint(tag << 3) + varint(value)


def bytes_field(tag: int, value: bytes) -> bytes:
    return varint((tag << 3) | 2) + varint(len(value)) + value


def delegate_resource(lock_period) -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    receiver = bytes.fromhex("41" + "22" * 20)
    message = (bytes_field(1, owner)
               + uint_field(2, 1)
               + uint_field(3, 100_000_000)
               + bytes_field(4, receiver)
               + uint_field(5, 1))
    if lock_period is not None:
        message += uint_field(6, lock_period)
    return message


def transfer(amount: int) -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    receiver = bytes.fromhex("41" + "22" * 20)
    return (bytes_field(1, owner)
            + bytes_field(2, receiver)
            + uint_field(3, amount))


def vote_witness(votes_count: int) -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    message = bytes_field(1, owner)
    for index in range(1, votes_count + 1):
        address = b"\x41" + index.to_bytes(20, "big")
        vote = bytes_field(1, address) + uint_field(2, 100)
        message += bytes_field(2, vote)
    return message


def asset_issue() -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    frozen_supply = uint_field(1, 100_000) + uint_field(2, 30)
    return (bytes_field(1, owner)
            + bytes_field(2, b"LedgerAsset")
            + bytes_field(3, b"LAS")
            + uint_field(4, 1_000_000)
            + bytes_field(5, frozen_supply)
            + uint_field(6, 1)
            + uint_field(7, 6)
            + uint_field(8, 100)
            + uint_field(9, 2_000_000_000_000)
            + uint_field(10, 2_000_086_400_000)
            + uint_field(16, 1)
            + bytes_field(20, b"Ledger TRC10 asset")
            + bytes_field(21, b"https://ledger.com/trc10")
            + uint_field(22, 1_000)
            + uint_field(23, 10_000))


def participate_asset_issue() -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    issuer = bytes.fromhex("41" + "22" * 20)
    return (bytes_field(1, owner)
            + bytes_field(2, issuer)
            + bytes_field(3, b"1000001")
            + uint_field(4, 1_000_000))


def unfreeze_asset() -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    return bytes_field(1, owner)


def update_asset() -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    return (bytes_field(1, owner)
            + bytes_field(2, b"Updated TRC10 asset")
            + bytes_field(3, b"https://ledger.com/updated-trc10")
            + uint_field(4, 1_000)
            + uint_field(5, 10_000))


def create_smart_contract() -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    smart_contract = (bytes_field(1, owner)
                      + bytes_field(4, bytes.fromhex(
                          "608060405260008055600160005260206000f3"))
                      + uint_field(5, 1_000_000)
                      + uint_field(6, 30)
                      + bytes_field(7, b"LedgerContract")
                      + uint_field(8, 10_000_000))
    return (bytes_field(1, owner)
            + bytes_field(2, smart_contract)
            + uint_field(3, 123)
            + uint_field(4, 1_000_001))


def exchange_create(first_token_id: bytes, second_token_id: bytes) -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    return (bytes_field(1, owner)
            + bytes_field(2, first_token_id)
            + uint_field(3, 1_000_000)
            + bytes_field(4, second_token_id)
            + uint_field(5, 2_000_000))


def exchange_transaction(token_id: bytes) -> bytes:
    owner = bytes.fromhex("41" + "11" * 20)
    return (bytes_field(1, owner)
            + uint_field(2, 6)
            + bytes_field(3, token_id)
            + uint_field(4, 1_000_000)
            + uint_field(5, 2_000_000))


def token_details(name: bytes, precision: int) -> bytes:
    # Signature verification is intentionally accepted by the fuzz cx mock.
    return bytes_field(1, name) + uint_field(2, precision)


def exchange_details(first_token_id: bytes,
                     first_name: bytes,
                     second_token_id: bytes,
                     second_name: bytes) -> bytes:
    # Signature verification is intentionally accepted by the fuzz cx mock.
    return (uint_field(1, 6)
            + bytes_field(2, first_token_id)
            + bytes_field(3, first_name)
            + uint_field(4, 6)
            + bytes_field(5, second_token_id)
            + bytes_field(6, second_name)
            + uint_field(7, 6))


def raw_transaction(lock_period) -> bytes:
    value = delegate_resource(lock_period)
    any_message = bytes_field(1, TYPE_URL) + bytes_field(2, value)
    contract = uint_field(1, 57) + bytes_field(2, any_message)
    return (bytes_field(1, bytes.fromhex("3dce"))
            + bytes_field(4, bytes.fromhex("95da42177db00507"))
            + uint_field(8, 1_575_712_551_000)
            + bytes_field(11, contract)
            + uint_field(14, 1_575_712_492_061))


def raw_vote_transaction(votes_count: int) -> bytes:
    value = vote_witness(votes_count)
    any_message = bytes_field(1, VOTE_TYPE_URL) + bytes_field(2, value)
    contract = uint_field(1, 4) + bytes_field(2, any_message)
    return (bytes_field(1, bytes.fromhex("3dce"))
            + bytes_field(4, bytes.fromhex("95da42177db00507"))
            + uint_field(8, 1_575_712_551_000)
            + bytes_field(11, contract)
            + uint_field(14, 1_575_712_492_061))


def raw_asset_issue_transaction() -> bytes:
    any_message = (bytes_field(1, ASSET_ISSUE_TYPE_URL)
                   + bytes_field(2, asset_issue()))
    contract = uint_field(1, 6) + bytes_field(2, any_message)
    return (bytes_field(1, bytes.fromhex("3dce"))
            + bytes_field(4, bytes.fromhex("95da42177db00507"))
            + uint_field(8, 1_575_712_551_000)
            + bytes_field(11, contract)
            + uint_field(14, 1_575_712_492_061))


def raw_asset_contract_transaction(contract_type: int,
                                   type_url: bytes,
                                   value: bytes,
                                   fee_limit: int = 0) -> bytes:
    any_message = bytes_field(1, type_url) + bytes_field(2, value)
    contract = uint_field(1, contract_type) + bytes_field(2, any_message)
    transaction = (bytes_field(1, bytes.fromhex("3dce"))
                   + bytes_field(4, bytes.fromhex("95da42177db00507"))
                   + uint_field(8, 1_575_712_551_000)
                   + bytes_field(11, contract)
                   + uint_field(14, 1_575_712_492_061))
    if fee_limit:
        transaction += uint_field(18, fee_limit)
    return transaction


def derivation_path() -> bytes:
    return bytes([len(BIP32_PATH)]) + b"".join(
        component.to_bytes(4, "big") for component in BIP32_PATH
    )


def signing_seed(lock_period) -> bytes:
    payload = derivation_path() + raw_transaction(lock_period)
    record = bytes([0x10, 0x00]) + len(payload).to_bytes(2, "little") + payload
    return b"\x00" + record


def chunked_large_memo_seed() -> bytes:
    raw = raw_transaction(None) + bytes_field(10, b"A" * 4097)
    splits = (1, 2, 3, 127, 128, 251, 509, 1021)
    records = bytearray()
    offset = 0
    chunk_index = 0

    while offset < len(raw):
        take = min(splits[chunk_index % len(splits)], len(raw) - offset)
        chunk = raw[offset:offset + take]
        if offset == 0:
            records += apdu_record(0x00, derivation_path() + chunk)
        elif offset + take == len(raw):
            records += apdu_record(0x90, chunk)
        else:
            records += apdu_record(0x80, chunk)
        offset += take
        chunk_index += 1

    return b"\x01" + bytes(records)


def vote_signing_seed(votes_count: int) -> bytes:
    payload = derivation_path() + raw_vote_transaction(votes_count)
    record = bytes([0x10, 0x00]) + len(payload).to_bytes(2, "little") + payload
    return b"\x00" + record


def asset_issue_signing_seed() -> bytes:
    payload = derivation_path() + raw_asset_issue_transaction()
    record = bytes([0x10, 0x00]) + len(payload).to_bytes(2, "little") + payload
    return b"\x00" + record


def asset_contract_signing_seed(contract_type: int,
                                type_url: bytes,
                                value: bytes,
                                fee_limit: int = 0) -> bytes:
    payload = derivation_path() + raw_asset_contract_transaction(
        contract_type, type_url, value, fee_limit
    )
    record = bytes([0x10, 0x00]) + len(payload).to_bytes(2, "little") + payload
    return b"\x00" + record


def apdu_record(p1: int, payload: bytes) -> bytes:
    return bytes([p1, 0x00]) + len(payload).to_bytes(2, "little") + payload


def exchange_create_max_metadata_seed() -> bytes:
    first_id = b"9223372036854775806"
    second_id = b"9223372036854775807"
    raw = raw_asset_contract_transaction(
        41,
        EXCHANGE_CREATE_TYPE_URL,
        exchange_create(first_id, second_id),
    )
    return (b"\x00"
            + apdu_record(0x00, derivation_path() + raw)
            + apdu_record(0xA0, token_details(b"A" * 32, 6))
            + apdu_record(0xA9, token_details(b"B" * 32, 6)))


def exchange_transaction_max_metadata_seed() -> bytes:
    first_id = b"9223372036854775806"
    second_id = b"9223372036854775807"
    raw = raw_asset_contract_transaction(
        44,
        EXCHANGE_TRANSACTION_TYPE_URL,
        exchange_transaction(first_id),
    )
    metadata = exchange_details(
        first_id,
        b"A" * 32,
        second_id,
        b"B" * 32,
    )
    return (b"\x00"
            + apdu_record(0x00, derivation_path() + raw)
            + apdu_record(0xA8, metadata))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "00-delegate-lock-without-period.bin").write_bytes(signing_seed(None))
    (OUT_DIR / "01-delegate-lock-with-period.bin").write_bytes(signing_seed(86400))
    (OUT_DIR / "02-vote-witness-30.bin").write_bytes(vote_signing_seed(30))
    (OUT_DIR / "03-vote-witness-31.bin").write_bytes(vote_signing_seed(31))
    (OUT_DIR / "04-asset-issue.bin").write_bytes(asset_issue_signing_seed())
    (OUT_DIR / "05-participate-asset-issue.bin").write_bytes(
        asset_contract_signing_seed(
            9, PARTICIPATE_ASSET_ISSUE_TYPE_URL, participate_asset_issue()
        )
    )
    (OUT_DIR / "06-unfreeze-asset.bin").write_bytes(
        asset_contract_signing_seed(14, UNFREEZE_ASSET_TYPE_URL, unfreeze_asset())
    )
    (OUT_DIR / "07-update-asset.bin").write_bytes(
        asset_contract_signing_seed(15, UPDATE_ASSET_TYPE_URL, update_asset())
    )
    (OUT_DIR / "08-create-smart-contract.bin").write_bytes(
        asset_contract_signing_seed(
            30,
            CREATE_SMART_CONTRACT_TYPE_URL,
            create_smart_contract(),
            fee_limit=100_000_000,
        )
    )
    (OUT_DIR / "09-exchange-create-max-metadata.bin").write_bytes(
        exchange_create_max_metadata_seed()
    )
    (OUT_DIR / "10-exchange-transaction-max-metadata.bin").write_bytes(
        exchange_transaction_max_metadata_seed()
    )
    (OUT_DIR / "11-chunked-large-memo.bin").write_bytes(
        chunked_large_memo_seed()
    )
    (OUT_DIR / "12-transfer-int64-max.bin").write_bytes(
        asset_contract_signing_seed(
            1, TRANSFER_TYPE_URL, transfer((1 << 63) - 1)
        )
    )
    (OUT_DIR / "13-transfer-zero.bin").write_bytes(
        asset_contract_signing_seed(1, TRANSFER_TYPE_URL, transfer(0))
    )
    (OUT_DIR / "14-transfer-negative.bin").write_bytes(
        asset_contract_signing_seed(1, TRANSFER_TYPE_URL, transfer(-1))
    )


if __name__ == "__main__":
    main()
