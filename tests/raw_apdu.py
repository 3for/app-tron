#!/usr/bin/env python3
"""
Raw APDU channel to Speculos + APDU builders.

Why this exists
---------------
Ragger's ``SpeculosBackend`` drives the emulator through its REST API. The
``/apdu`` endpoint of that API serialises exchanges behind
``APDUBridge.endpoint_lock`` (see ``speculos/api/apdu.py``): a second APDU
cannot be POSTed while a previous one is still waiting for its response.

That is exactly the situation the TOCTOU tests need to create: the host pushes
a *new* APDU while the device is still displaying the review of a *previous*
one, which the baseline ``apdu_dispatcher()`` happily accepts.

Speculos also exposes a raw APDU TCP server (``--apdu-port``, which Ragger
always passes and remembers in ``SpeculosBackend._apdu_port``). That server
has no such serialisation: it simply forwards every packet it receives to the
application and forwards back every response the SE transmits. Framing is:

    host   -> device : uint32be(len(apdu))       || apdu
    device -> host   : uint32be(len(rapdu) - 2)  || rapdu  (rapdu ends w/ SW)

Note that responses are broadcast to *both* the raw socket client and the REST
bridge, so a test must not mix the two transports while an exchange is in
flight. Tests using :func:`raw_channel` should therefore run their whole
interleaved sequence on the raw socket.
"""
import socket
from contextlib import contextmanager
from typing import Generator, List, Optional

import pytest
from ragger.backend import SpeculosBackend
from ragger.bip import pack_derivation_path
from ragger.utils import RAPDU

from tron import CLA, InsType, P1, P2, MAX_APDU_LEN

DEFAULT_TIMEOUT = 30.0


class RawApduChannel:
    """Minimal TCP client for the Speculos raw APDU server.

    Unlike ``BackendInterface.exchange()``, :meth:`send` and :meth:`receive`
    are fully decoupled, so several APDUs can be in flight at once.
    """

    def __init__(self, port: int, timeout: float = DEFAULT_TIMEOUT):
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None

    def __enter__(self) -> "RawApduChannel":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def connect(self) -> None:
        self._sock = socket.create_connection(("127.0.0.1", self._port),
                                              timeout=self._timeout)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    @property
    def socket(self) -> socket.socket:
        assert self._sock is not None, "raw APDU channel is not connected"
        return self._sock

    def send(self, apdu: bytes) -> None:
        """Push an APDU without waiting for its response."""
        self.socket.sendall(len(apdu).to_bytes(4, "big") + apdu)

    def _recvall(self, size: int) -> Optional[bytes]:
        data = b""
        while len(data) < size:
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def try_receive(self, timeout: Optional[float] = None) -> Optional[RAPDU]:
        """Read one response, or return ``None`` if none arrives in time.

        Used to assert that the device *never* answers a given request.
        """
        self.socket.settimeout(self._timeout if timeout is None else timeout)
        try:
            header = self._recvall(4)
            if header is None:
                return None
            payload = self._recvall(int.from_bytes(header, "big") + 2)
        except socket.timeout:
            return None
        finally:
            self.socket.settimeout(self._timeout)
        if payload is None:
            return None
        return RAPDU(int.from_bytes(payload[-2:], "big"), payload[:-2])

    def receive(self, timeout: Optional[float] = None) -> RAPDU:
        rapdu = self.try_receive(timeout)
        if rapdu is None:
            raise TimeoutError("no APDU response received from the device")
        return rapdu

    def exchange(self, apdu: bytes,
                 timeout: Optional[float] = None) -> RAPDU:
        self.send(apdu)
        return self.receive(timeout)


@contextmanager
def raw_channel(backend) -> Generator[RawApduChannel, None, None]:
    """Open a raw APDU channel towards the Speculos instance of `backend`."""
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("TOCTOU tests require the Speculos raw APDU socket")

    port = getattr(backend, "_apdu_port", None)
    if not port:
        pytest.skip("Speculos raw APDU port could not be determined")

    channel = RawApduChannel(port)
    try:
        channel.connect()
    except OSError as exc:
        pytest.skip(f"cannot reach the Speculos APDU socket on {port}: {exc}")

    try:
        yield channel
    finally:
        channel.close()


###############################################################################
# APDU builders
###############################################################################
def apdu(ins: int, p1: int, p2: int, data: bytes = b"") -> bytes:
    assert len(data) <= 255, "APDU payload does not fit in a single command"
    return bytes([CLA, ins, p1, p2, len(data)]) + bytes(data)


def get_public_key_apdu(path: str,
                        confirm: bool,
                        chaincode: bool = False) -> bytes:
    return apdu(InsType.GET_PUBLIC_KEY,
                P1.CONFIRM if confirm else P1.NON_CONFIRM,
                P2.CHAINCODE if chaincode else P2.NO_CHAINCODE,
                pack_derivation_path(path))


def get_app_configuration_apdu() -> bytes:
    return apdu(InsType.GET_APP_CONFIGURATION, 0x00, 0x00)


def sign_txn_hash_apdu(path: str, tx_hash: bytes) -> bytes:
    assert len(tx_hash) == 32, "TRON transaction hashes are 32 bytes long"
    return apdu(InsType.SIGN_TXN_HASH, 0x00, 0x00,
                pack_derivation_path(path) + tx_hash)


def personal_message_first_apdu(path: str, declared_length: int,
                                chunk: bytes) -> bytes:
    """First (and deliberately non-final) chunk of a personal message.

    Announcing more bytes than are actually sent makes the handler store the
    BIP32 path in the shared ``transactionContext`` and reply ``0x9000``
    immediately, without ever displaying anything.
    """
    assert len(chunk) < declared_length, \
        "the message must stay incomplete so the handler replies immediately"
    payload = (pack_derivation_path(path) +
               declared_length.to_bytes(4, "big") + chunk)
    return apdu(InsType.SIGN_PERSONAL_MESSAGE, P1.FIRST, 0x00, payload)


def build_sign_apdus(client, path: str, tx: bytes) -> List[bytes]:
    """Split `tx` into INS_SIGN APDUs, mirroring ``TronClient.sign()``."""
    messages: List[bytes] = []
    data = bytearray(pack_derivation_path(path))
    tx = bytes(tx)
    while len(tx) > 0:
        newpos = client.get_next_length(tx)
        assert newpos < MAX_APDU_LEN
        if (len(data) + newpos) < MAX_APDU_LEN:
            data += tx[:newpos]
            tx = tx[newpos:]
        else:
            messages.append(bytes(data))
            data = bytearray()
    messages.append(bytes(data))

    apdus: List[bytes] = []
    last = len(messages) - 1
    for i, message in enumerate(messages):
        if last == 0:
            p1 = P1.SIGN
        elif i == 0:
            p1 = P1.FIRST
        elif i == last:
            p1 = P1.LAST
        else:
            p1 = P1.MORE
        apdus.append(apdu(InsType.SIGN, p1, 0x00, message))
    return apdus
