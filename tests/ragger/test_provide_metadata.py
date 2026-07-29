import pytest
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU

import response_parser as ResponseParser
from tron import TronClient
from client.command_builder import CommandBuilder
from client.enum_value import EnumValue
from client.gating import Gating, TxType
from client.keychain import Key, sign_data
from client.ledger_pki import PKIPubKeyUsage
from client.proxy_info import ProxyInfo
from client.status_word import StatusWord


CHAIN_ID = 728126428
CONTRACT = bytes.fromhex("1111111111111111111111111111111111111111")
IMPLEMENTATION = bytes.fromhex("2222222222222222222222222222222222222222")
SELECTOR = bytes.fromhex("a9059cbb")


def get_challenge(client: TronClient) -> int:
    response = client.exchange_raw(CommandBuilder().get_challenge())
    return ResponseParser.challenge(response.data)


@pytest.mark.parametrize(
    ("apdu", "status"),
    [
        (bytes.fromhex("e020010000"), StatusWord.INVALID_P1_P2),
        (bytes.fromhex("e020000100"), StatusWord.INVALID_P1_P2),
        (bytes.fromhex("e02000000100"), StatusWord.WRONG_DATA_LENGTH),
    ],
)
def test_get_challenge_rejects_noncanonical_apdu(
        backend: BackendInterface, apdu: bytes, status: StatusWord):
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange_raw(apdu)
    assert error.value.status == status


def send_tlv_chunks(client: TronClient, chunks: list[bytes]) -> None:
    for chunk in chunks:
        client.exchange_raw(chunk)


def test_proxy_rejects_cal_trusted_name_certificate(backend: BackendInterface):
    client = TronClient(backend)
    descriptor = ProxyInfo(get_challenge(client), CONTRACT, CHAIN_ID, IMPLEMENTATION)

    descriptor.signature = b""
    unsigned = descriptor.serialize()
    assert unsigned.endswith(b"\x15\x00")
    descriptor.signature = sign_data(Key.CAL, unsigned[:-2])

    client.pki_client.send_certificate(
        PKIPubKeyUsage.PUBKEY_USAGE_TRUSTED_NAME, from_CAL=True)
    with pytest.raises(ExceptionRAPDU) as error:
        send_tlv_chunks(
            client,
            CommandBuilder().provide_proxy_info(descriptor.serialize()),
        )
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("selector", [b"\x01\x02\x03", b"\x01\x02\x03\x04\x05"])
def test_proxy_rejects_noncanonical_selector(
        backend: BackendInterface, selector: bytes):
    client = TronClient(backend)
    descriptor = ProxyInfo(
        get_challenge(client), CONTRACT, CHAIN_ID, IMPLEMENTATION, selector=selector)

    with pytest.raises(ExceptionRAPDU) as error:
        client.provide_proxy_info(descriptor.serialize())
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("selector", [b"\x01\x02\x03", b"\x01\x02\x03\x04\x05"])
def test_enum_rejects_noncanonical_selector(
        backend: BackendInterface, selector: bytes):
    client = TronClient(backend)
    descriptor = EnumValue(1, CHAIN_ID, CONTRACT, selector, 0, 1, "Enabled")

    with pytest.raises(ExceptionRAPDU) as error:
        client.provide_enum_value(descriptor.serialize())
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("name", ["", "Safe\0hidden", "line\nbreak", "\x80", "\xff"])
def test_enum_rejects_ambiguous_name(backend: BackendInterface, name: str):
    client = TronClient(backend)
    descriptor = EnumValue(1, CHAIN_ID, CONTRACT, SELECTOR, 0, 1, name)

    with pytest.raises(ExceptionRAPDU) as error:
        client.provide_enum_value(descriptor.serialize())
    assert error.value.status == StatusWord.INVALID_DATA


def test_enum_accepts_full_name_capacity(backend: BackendInterface):
    client = TronClient(backend)
    descriptor = EnumValue(1, CHAIN_ID, CONTRACT, SELECTOR, 0, 1, "A" * 20)

    assert client.provide_enum_value(descriptor.serialize()).status == StatusWord.OK


@pytest.mark.parametrize(
    ("intro", "url"),
    [
        ("", "ledger.com"),
        ("Review", ""),
        ("Safe\0hidden", "ledger.com"),
        ("Review", "ledger.com\nspoof"),
        ("\x80", "ledger.com"),
        ("Review", "\xff"),
    ],
)
def test_gating_rejects_ambiguous_text(
        backend: BackendInterface, intro: str, url: str):
    client = TronClient(backend)
    descriptor = Gating(
        TxType.TRANSACTION,
        CONTRACT,
        intro,
        url,
        chain_id=CHAIN_ID,
    )

    with pytest.raises(ExceptionRAPDU) as error:
        client.provide_gating(descriptor.serialize())
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("ticker", ["", "USD\0T", "USD\nT", "\x80", "\xff"])
def test_trc20_rejects_ambiguous_ticker(
        backend: BackendInterface, ticker: str):
    client = TronClient(backend)

    with pytest.raises(ExceptionRAPDU) as error:
        client.provide_token_metadata(ticker, CONTRACT, 6, CHAIN_ID)
    assert error.value.status == StatusWord.INVALID_DATA


@pytest.mark.parametrize("collection", ["", "Safe\0hidden", "line\nbreak", "\x80", "\xff"])
def test_nft_rejects_ambiguous_collection(
        backend: BackendInterface, collection: str):
    client = TronClient(backend)

    with pytest.raises(ExceptionRAPDU) as error:
        client.provide_nft_metadata(collection, CONTRACT, CHAIN_ID)
    assert error.value.status == StatusWord.INVALID_DATA
