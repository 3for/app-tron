import pytest

from ledgered.devices import Device

from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU

from tron import TronClient
from client.status_word import StatusWord
from client.gating import Gating, TxType

# Values used across all tests
CHAIN_ID = 728126428
# 20-byte TVM contract address (no 0x41 prefix, as used internally / by the proxy module)
ADDR = bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f")
SELECTOR = bytes.fromhex("a9059cbb")  # transfer(address,uint256)
# 28-byte schema hash (CX_SHA224_SIZE) for the typed-data path
SCHEMA_HASH = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabb")
INTRO_MSG = "To verify this transaction before signing, use Ledger Multisig."
TINY_URL = "ledger.com/ledger-multisig"


# The gating descriptor (INS_PROVIDE_GATING) is verified (TLV + signature) at provide
# time; whether it matches the current signing context is only checked later, during
# the review. These tests therefore exercise the parse/verify contract of the new APDU.
def test_gating_provide_transaction(device: Device, backend: BackendInterface):
    app_client = TronClient(backend, device, None)
    rapdu = app_client.provide_gating(
        Gating(TxType.TRANSACTION, ADDR, INTRO_MSG, TINY_URL,
               chain_id=CHAIN_ID, selector=SELECTOR).serialize())
    assert rapdu.status == StatusWord.OK


def test_gating_provide_typed_data(device: Device, backend: BackendInterface):
    app_client = TronClient(backend, device, None)
    rapdu = app_client.provide_gating(
        Gating(TxType.TYPED_DATA, ADDR, INTRO_MSG, TINY_URL,
               selector=SCHEMA_HASH).serialize())
    assert rapdu.status == StatusWord.OK


def test_gating_wrong_signature(device: Device, backend: BackendInterface):
    app_client = TronClient(backend, device, None)
    payload = bytearray(
        Gating(TxType.TRANSACTION, ADDR, INTRO_MSG, TINY_URL,
               chain_id=CHAIN_ID, selector=SELECTOR).serialize())
    # Corrupt the last byte (inside the DER signature's S value): the DER framing
    # stays valid but the signature no longer matches the payload hash.
    payload[-1] ^= 0xFF

    with pytest.raises(ExceptionRAPDU) as e:
        app_client.provide_gating(bytes(payload))
    assert e.value.status == StatusWord.INVALID_DATA
