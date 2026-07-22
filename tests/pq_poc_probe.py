#!/usr/bin/env python3
"""Drive the opt-in ML-DSA PoC against an already running Speculos instance.

This probe intentionally uses only Python's standard library. It validates the
APDU state machine, a recoverable parser error, Nano review approval, and the
chunked public-key/signature outputs. With --output-dir it also emits the three
artifacts needed for an independent java-tron verification.
"""

import argparse
import hashlib
import json
import socket
import struct
import threading
import time
import urllib.request
from pathlib import Path


CLA = 0xE0
INS_CAPABILITIES = 0x30
INS_GENERATE_KEY = 0x32
INS_SIGN = 0x34
INS_GET_RESULT = 0x36
INS_ABORT = 0x3A
INS_CLOSE_RESULT = 0x3E
SCHEME_ML_DSA_44 = 2
RESULT_PUBLIC_KEY = 1
RESULT_SIGNATURE = 2
PUBLIC_KEY_SIZE = 1312
SIGNATURE_SIZE = 2420
STATUS_OK = 0x9000


def varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if value == 0:
            return bytes(result)


def uint_field(tag: int, value: int) -> bytes:
    return varint(tag << 3) + varint(value)


def bytes_field(tag: int, value: bytes) -> bytes:
    return varint((tag << 3) | 2) + varint(len(value)) + value


def transfer_raw_data(owner: bytes) -> bytes:
    destination = bytes.fromhex("411111111111111111111111111111111111111111")
    transfer = (bytes_field(1, owner) + bytes_field(2, destination) +
                uint_field(3, 100_000_000))
    any_message = (bytes_field(
        1, b"type.googleapis.com/protocol.TransferContract") +
                   bytes_field(2, transfer))
    contract = uint_field(1, 1) + bytes_field(2, any_message)
    return (bytes_field(1, bytes.fromhex("3dce")) +
            bytes_field(4, bytes.fromhex("95da42177db00507")) +
            uint_field(8, 1_575_712_551_000) + bytes_field(11, contract) +
            uint_field(14, 1_575_712_492_061))


def recv_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("Speculos closed the APDU connection")
        result.extend(chunk)
    return bytes(result)


class Probe:

    def __init__(self, host: str, apdu_port: int, api_port: int):
        self.host = host
        self.apdu_port = apdu_port
        self.api_url = f"http://{host}:{api_port}"

    def exchange(self, ins: int, p1: int = 0, p2: int = 0,
                 data: bytes = b"") -> tuple[bytes, int]:
        if len(data) > 255:
            raise ValueError("short APDU payload exceeds 255 bytes")
        command = bytes([CLA, ins, p1, p2, len(data)]) + data
        with socket.create_connection((self.host, self.apdu_port), timeout=10) as sock:
            sock.sendall(struct.pack(">I", len(command)) + command)
            response_size = struct.unpack(">I", recv_exact(sock, 4))[0]
            # Speculos' TCP length covers response data only; the two-byte SW
            # follows the advertised payload.
            response = recv_exact(sock, response_size + 2)
        if len(response) < 2:
            raise RuntimeError("truncated APDU response")
        return response[:-2], struct.unpack(">H", response[-2:])[0]

    def screen_text(self) -> str:
        with urllib.request.urlopen(
                f"{self.api_url}/events?currentscreenonly=true", timeout=2) as response:
            events = json.load(response)["events"]
        return "\n".join(event.get("text", "") for event in events)

    def button(self, name: str) -> None:
        request = urllib.request.Request(
            f"{self.api_url}/button/{name}",
            data=b'{"action":"press-and-release"}',
            headers={"Content-Type": "application/json"},
            method="POST")
        with urllib.request.urlopen(request, timeout=2):
            pass

    def approve_review(self, timeout: float = 30) -> list[str]:
        deadline = time.monotonic() + timeout
        screens = []
        previous = ""
        while time.monotonic() < deadline:
            text = self.screen_text()
            if text and text != previous:
                screens.append(text)
                previous = text
                lowered = text.lower()
                if "sign with" in lowered and "ml-dsa-44" in lowered:
                    self.button("both")
                    return screens
                self.button("right")
            time.sleep(0.2)
        raise TimeoutError(f"review approval timed out; last screen: {previous!r}")

    def get_result(self, session: bytes, obj: int, total: int) -> bytes:
        result = bytearray()
        while len(result) < total:
            request = (session + bytes([obj]) + struct.pack(">H", len(result)) +
                       bytes([220]))
            data, status = self.exchange(INS_GET_RESULT, data=request)
            if status != STATUS_OK or len(data) < 13:
                raise RuntimeError(f"result APDU failed: {status:04x}")
            offset = struct.unpack(">H", data[7:9])[0]
            advertised_total = struct.unpack(">H", data[9:11])[0]
            chunk_size = data[12]
            if offset != len(result) or advertised_total != total:
                raise RuntimeError("inconsistent result chunk header")
            if chunk_size != len(data[13:]):
                raise RuntimeError("inconsistent result chunk length")
            result.extend(data[13:])
        return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--apdu-port", type=int, default=9999)
    parser.add_argument("--api-port", type=int, default=5000)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--keep-session", action="store_true")
    args = parser.parse_args()
    probe = Probe(args.host, args.apdu_port, args.api_port)

    startup_deadline = time.monotonic() + 15
    while True:
        try:
            capabilities, status = probe.exchange(INS_CAPABILITIES)
            break
        except OSError:
            if time.monotonic() >= startup_deadline:
                raise
            time.sleep(0.2)
    if status != STATUS_OK or capabilities != bytes.fromhex("01020520097407"):
        raise RuntimeError("ML-DSA PoC capability is unavailable")

    metadata, status = probe.exchange(INS_GENERATE_KEY, p2=SCHEME_ML_DSA_44)
    if status != STATUS_OK or len(metadata) != 63:
        raise RuntimeError(f"key generation failed: {status:04x}")
    session = metadata[2:6]
    address = metadata[6:27]
    fingerprint = metadata[31:63]

    # A malformed final transaction must clear only transaction state. The
    # random session key remains usable and byte-for-byte unchanged.
    _, malformed_status = probe.exchange(INS_SIGN,
                                         p1=0x10,
                                         data=session + b"\x00")
    if malformed_status == STATUS_OK:
        raise RuntimeError("malformed transaction unexpectedly accepted")
    public_key = probe.get_result(session, RESULT_PUBLIC_KEY, PUBLIC_KEY_SIZE)
    if hashlib.sha256(public_key).digest() != fingerprint:
        raise RuntimeError("recoverable error rotated or corrupted the PQ key")

    raw_data = transfer_raw_data(address)
    signed_response = {}

    def sign_request() -> None:
        signed_response["value"] = probe.exchange(INS_SIGN,
                                                   p1=0x10,
                                                   data=session + raw_data)

    thread = threading.Thread(target=sign_request, daemon=True)
    thread.start()
    screens = probe.approve_review()
    thread.join(timeout=30)
    if thread.is_alive():
        raise TimeoutError("ML-DSA signing APDU did not complete")
    sign_metadata, sign_status = signed_response["value"]
    if sign_status != STATUS_OK or len(sign_metadata) != 63:
        raise RuntimeError(f"ML-DSA signing failed: {sign_status:04x}")

    signature = probe.get_result(session, RESULT_SIGNATURE, SIGNATURE_SIZE)
    if len(signature) != SIGNATURE_SIZE:
        raise RuntimeError("truncated ML-DSA signature")

    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "raw_data.bin").write_bytes(raw_data)
        (args.output_dir / "message_hash.bin").write_bytes(
            hashlib.sha256(raw_data).digest())
        (args.output_dir / "public_key.bin").write_bytes(public_key)
        (args.output_dir / "signature.bin").write_bytes(signature)

    if not args.keep_session:
        _, close_status = probe.exchange(INS_CLOSE_RESULT, data=session)
        if close_status != STATUS_OK:
            raise RuntimeError(f"result cleanup failed: {close_status:04x}")
        public_key_after_close = probe.get_result(session, RESULT_PUBLIC_KEY,
                                                  PUBLIC_KEY_SIZE)
        if public_key_after_close != public_key:
            raise RuntimeError("closing a result changed the session key")
        signature_request = (session + bytes([RESULT_SIGNATURE]) + b"\x00\x00" +
                             bytes([220]))
        _, closed_signature_status = probe.exchange(INS_GET_RESULT,
                                                    data=signature_request)
        if closed_signature_status == STATUS_OK:
            raise RuntimeError("closed signature remained readable")
        _, abort_status = probe.exchange(INS_ABORT, data=session)
        if abort_status != STATUS_OK:
            raise RuntimeError(f"session cleanup failed: {abort_status:04x}")

    print(
        json.dumps({
            "session_id": session.hex(),
            "address": address.hex(),
            "raw_data_sha256": hashlib.sha256(raw_data).hexdigest(),
            "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
            "signature_size": len(signature),
            "recoverable_error_status": f"{malformed_status:04x}",
            "closed_signature_status":
            f"{closed_signature_status:04x}" if not args.keep_session else None,
            "review_screens": screens,
        },
                   indent=2))


if __name__ == "__main__":
    main()
