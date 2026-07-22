#!/usr/bin/env python3
"""Sign a TRON transfer with the random-key ML-DSA-44 PoC on a real Ledger.

The default node is Nile, but broadcasting is guarded by the node's
getAllowMlDsa44 chain parameter. A missing protobuf-default `value` is treated
as zero. The same script can therefore run the complete flow against a private
chain configured with allowMlDsa44=1 without weakening the public-Nile gate.
"""

import argparse
import hashlib
import json
import os
import shlex
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any


CLA = 0xE0
INS_CAPABILITIES = 0x30
INS_GENERATE_KEY = 0x32
INS_SIGN = 0x34
INS_GET_RESULT = 0x36
INS_ABORT = 0x3A
INS_CLOSE_RESULT = 0x3E

P1_CONFIRM = 0x01
P1_SINGLE = 0x10
P1_FIRST = 0x00
P1_MORE = 0x80
P1_LAST = 0x90
SCHEME_ML_DSA_44 = 2
RESULT_PUBLIC_KEY = 1
RESULT_SIGNATURE = 2
PUBLIC_KEY_SIZE = 1312
SIGNATURE_SIZE = 2420
RESULT_CHUNK_SIZE = 220
METADATA_SIZE = 63
CAPABILITIES = bytes.fromhex("01020520097407")

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode a negative integer")
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


def base58_encode(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeroes + (encoded or ("1" if not leading_zeroes else ""))


def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


def base58check_decode(value: str) -> bytes:
    number = 0
    for char in value:
        try:
            digit = BASE58_ALPHABET.index(char)
        except ValueError as exc:
            raise ValueError(f"invalid Base58 character: {char!r}") from exc
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    decoded = b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded
    if len(decoded) < 5:
        raise ValueError("truncated Base58Check value")
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("invalid Base58Check checksum")
    return payload


def parse_key_metadata(data: bytes,
                       expected_signature_size: int | None = None) -> tuple[bytes, bytes, bytes]:
    if len(data) != METADATA_SIZE:
        raise RuntimeError(f"unexpected session metadata length: {len(data)}")
    if data[:2] != bytes([1, SCHEME_ML_DSA_44]):
        raise RuntimeError("unexpected PQ protocol version or scheme")
    if struct.unpack(">H", data[27:29])[0] != PUBLIC_KEY_SIZE:
        raise RuntimeError("unexpected ML-DSA-44 public-key size")
    signature_size = struct.unpack(">H", data[29:31])[0]
    if (expected_signature_size is not None and
            signature_size != expected_signature_size):
        raise RuntimeError(f"unexpected ML-DSA-44 signature size: {signature_size}")
    return data[2:6], data[6:27], data[31:63]


def chain_parameter_value(parameters: dict[str, Any], key: str) -> int:
    for item in parameters.get("chainParameter", []):
        if item.get("key", "").lower() == key.lower():
            # java-tron omits a protobuf scalar at its default value. Missing
            # `value` therefore means zero, never "unknown" or enabled.
            return int(item.get("value", 0))
    return 0


def assemble_pq_transaction(raw_data: bytes, public_key: bytes,
                            signature: bytes) -> bytes:
    pq_auth_sig = (uint_field(1, SCHEME_ML_DSA_44) +
                   bytes_field(2, public_key) + bytes_field(3, signature))
    return bytes_field(1, raw_data) + bytes_field(6, pq_auth_sig)


class TronNode:
    def __init__(self, base_url: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def post(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["TRON-PRO-API-KEY"] = self.api_key
        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=json.dumps(body).encode(),
            headers=headers,
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"{endpoint} returned HTTP {exc.code}: {detail}") from exc
        if not isinstance(result, dict):
            raise RuntimeError(f"{endpoint} returned a non-object response")
        return result

    def allow_mldsa44(self) -> int:
        return chain_parameter_value(
            self.post("/wallet/getchainparameters", {}), "getAllowMlDsa44")

    def account(self, address: bytes) -> dict[str, Any]:
        return self.post("/wallet/getaccount", {
            "address": address.hex(),
            "visible": False,
        })

    def create_transfer(self, owner: bytes, destination: bytes,
                        amount_sun: int) -> dict[str, Any]:
        result = self.post("/wallet/createtransaction", {
            "owner_address": owner.hex(),
            "to_address": destination.hex(),
            "amount": amount_sun,
            "visible": False,
        })
        if "raw_data_hex" not in result:
            raise RuntimeError(f"node did not create a transaction: {result}")
        raw_data = bytes.fromhex(result["raw_data_hex"])
        expected_txid = hashlib.sha256(raw_data).hexdigest()
        if result.get("txID", "").lower() != expected_txid:
            raise RuntimeError("node txID does not equal SHA256(raw_data_hex)")
        return result

    def broadcast(self, transaction: bytes) -> dict[str, Any]:
        return self.post("/wallet/broadcasthex", {"transaction": transaction.hex()})


class LedgerPqClient:
    def __init__(self, debug: bool = False, timeout_seconds: int = 180,
                 apdu_tcp: str | None = None):
        try:
            if apdu_tcp:
                from ledgerblue.commTCP import DongleServer
            else:
                from ledgerblue.comm import getDongle
        except ImportError as exc:
            raise RuntimeError(
                "ledgerblue is required for hardware access; install tests/ragger/requirements.txt"
            ) from exc
        if apdu_tcp:
            host, separator, port = apdu_tcp.rpartition(":")
            if not separator or not host:
                raise ValueError("--apdu-tcp must use HOST:PORT format")
            self.dongle = DongleServer(host, int(port), debug=debug)
        else:
            self.dongle = getDongle(debug)
        self.timeout_seconds = timeout_seconds
        maximum = getattr(self.dongle, "apduMaxDataSize", lambda: 240)()
        self.max_apdu_data = min(int(maximum), 250)

    def close(self) -> None:
        self.dongle.close()

    def exchange(self, ins: int, p1: int = 0, p2: int = 0,
                 data: bytes = b"") -> bytes:
        if len(data) > self.max_apdu_data:
            raise ValueError(f"APDU data exceeds transport maximum {self.max_apdu_data}")
        apdu = bytes([CLA, ins, p1, p2, len(data)]) + data
        try:
            return bytes(self.dongle.exchange(apdu, timeout=self.timeout_seconds))
        except Exception as exc:
            status = getattr(exc, "sw", None)
            suffix = f" (SW={status:04x})" if isinstance(status, int) else ""
            raise RuntimeError(f"Ledger APDU INS {ins:#04x} failed{suffix}: {exc}") from exc

    def capabilities(self) -> None:
        if self.exchange(INS_CAPABILITIES) != CAPABILITIES:
            raise RuntimeError("connected Tron app does not expose the ML-DSA PoC capability")

    def generate_key_confirmed(self) -> tuple[bytes, bytes, bytes]:
        print("Confirm the temporary ML-DSA-44 address on the Ledger device...")
        return parse_key_metadata(
            self.exchange(INS_GENERATE_KEY, P1_CONFIRM, SCHEME_ML_DSA_44), 0)

    def get_result(self, session: bytes, obj: int, total: int) -> bytes:
        result = bytearray()
        while len(result) < total:
            request = (session + bytes([obj]) + struct.pack(">H", len(result)) +
                       bytes([RESULT_CHUNK_SIZE]))
            response = self.exchange(INS_GET_RESULT, data=request)
            if len(response) < 13 or response[:6] != bytes(
                    [1, SCHEME_ML_DSA_44]) + session:
                raise RuntimeError("invalid result chunk header")
            offset = struct.unpack(">H", response[7:9])[0]
            advertised_total = struct.unpack(">H", response[9:11])[0]
            chunk_length = response[12]
            if (response[6] != obj or offset != len(result) or
                    advertised_total != total or chunk_length != len(response[13:])):
                raise RuntimeError("inconsistent result chunk")
            result.extend(response[13:])
        return bytes(result)

    def sign_raw_data(self, session: bytes, raw_data: bytes) -> bytes:
        first_capacity = self.max_apdu_data - len(session)
        if len(raw_data) <= first_capacity:
            print("Review and approve the transfer on the Ledger device...")
            return self.exchange(INS_SIGN, P1_SINGLE, data=session + raw_data)

        offset = first_capacity
        self.exchange(INS_SIGN, P1_FIRST, data=session + raw_data[:offset])
        while len(raw_data) - offset > self.max_apdu_data:
            self.exchange(INS_SIGN,
                          P1_MORE,
                          data=raw_data[offset:offset + self.max_apdu_data])
            offset += self.max_apdu_data
        print("Review and approve the transfer on the Ledger device...")
        return self.exchange(INS_SIGN, P1_LAST, data=raw_data[offset:])

    def close_result(self, session: bytes) -> None:
        self.exchange(INS_CLOSE_RESULT, data=session)

    def abort(self, session: bytes) -> None:
        self.exchange(INS_ABORT, data=session)


def verify_address(public_key: bytes, address: bytes) -> None:
    try:
        from Crypto.Hash import keccak
    except ImportError as exc:
        raise RuntimeError("pycryptodome is required to verify the TRON PQ address") from exc
    expected = b"\x41" + keccak.new(digest_bits=256, data=public_key).digest()[-20:]
    if address != expected:
        raise RuntimeError("Ledger PQ address does not match Keccak256(public_key)")


def ecdsa_address_and_signer(private_key_hex: str):
    try:
        from Crypto.Hash import keccak
        from ecdsa import SECP256k1, SigningKey
    except ImportError as exc:
        raise RuntimeError("ecdsa and pycryptodome are required for private-chain funding") from exc
    private_key = bytes.fromhex(private_key_hex)
    if len(private_key) != 32:
        raise ValueError("private-chain funding key must be exactly 32 bytes")
    signer = SigningKey.from_string(private_key, curve=SECP256k1)
    public_key = b"\x04" + signer.verifying_key.to_string()
    digest = keccak.new(digest_bits=256, data=public_key[1:]).digest()
    return b"\x41" + digest[-20:], signer


def sign_ecdsa_transaction(raw_data: bytes, signer) -> bytes:
    from ecdsa import SECP256k1, VerifyingKey
    from ecdsa.util import sigdecode_string, sigencode_string_canonize

    digest = hashlib.sha256(raw_data).digest()
    signature = signer.sign_digest_deterministic(
        digest, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)
    expected_key = signer.verifying_key.to_string()
    recovered = VerifyingKey.from_public_key_recovery_with_digest(
        signature, digest, curve=SECP256k1, sigdecode=sigdecode_string)
    recovery_id = next((index for index, key in enumerate(recovered)
                        if key.to_string() == expected_key), None)
    if recovery_id is None:
        raise RuntimeError("could not construct a recoverable ECDSA signature")
    return bytes_field(1, raw_data) + bytes_field(2, signature + bytes([recovery_id]))


def fund_private_chain_account(node: TronNode, private_key_hex: str,
                               destination: bytes, amount_sun: int) -> str:
    owner, signer = ecdsa_address_and_signer(private_key_hex)
    unsigned = node.create_transfer(owner, destination, amount_sun)
    raw_data = bytes.fromhex(unsigned["raw_data_hex"])
    transaction = sign_ecdsa_transaction(raw_data, signer)
    result = node.broadcast(transaction)
    if not result.get("result", False):
        raise RuntimeError(f"private-chain funding transaction failed: {result}")
    return hashlib.sha256(raw_data).hexdigest()


class SpeculosApprover:
    """Minimal opt-in UI driver used only for the local private-chain test."""

    def __init__(self, api_url: str, approvals: int = 2):
        self.api_url = api_url.rstrip("/")
        self.approvals = approvals
        self.error: Exception | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def finish(self) -> None:
        if self.thread is None:
            return
        self.thread.join(timeout=20)
        if self.thread.is_alive():
            raise TimeoutError("Speculos UI auto-approval did not finish")
        if self.error is not None:
            raise RuntimeError(f"Speculos UI auto-approval failed: {self.error}")

    def _screen_text(self) -> str:
        with urllib.request.urlopen(
                f"{self.api_url}/events?currentscreenonly=true", timeout=2) as response:
            events = json.load(response).get("events", [])
        return "\n".join(event.get("text", "") for event in events)

    def _button(self, name: str) -> None:
        request = urllib.request.Request(
            f"{self.api_url}/button/{name}",
            data=b'{"action":"press-and-release"}',
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=2):
            pass

    def _run(self) -> None:
        try:
            deadline = time.monotonic() + 180
            previous = ""
            approved = 0
            in_review = False
            while approved < self.approvals and time.monotonic() < deadline:
                text = self._screen_text()
                lowered = text.lower()
                if text and text != previous:
                    previous = text
                    if "ml-dsa" in lowered or "review transaction" in lowered:
                        in_review = True
                    normalized = " ".join(lowered.split())
                    final_address = normalized in {
                        "accept risk", "accept", "approve", "confirm"
                    }
                    final_sign = (("sign with" in lowered and "ml-dsa-44" in lowered) or
                                  normalized in {"sign", "sign transaction"})
                    if final_address or final_sign:
                        self._button("both")
                        approved += 1
                        in_review = False
                    elif in_review:
                        self._button("right")
                time.sleep(0.2)
            if approved != self.approvals:
                raise TimeoutError(
                    f"approved {approved}/{self.approvals}; last screen was {previous!r}")
        except Exception as exc:  # surfaced by finish() on the main thread
            self.error = exc


def run_java_tron_verify(project_dir: Path, java_tron_dir: Path,
                         output_dir: Path) -> None:
    crypto_classes = java_tron_dir / "crypto/build/classes/java/main"
    if not crypto_classes.is_dir():
        raise RuntimeError(
            f"missing {crypto_classes}; first run {java_tron_dir / 'gradlew'} :crypto:classes")
    gradlew = java_tron_dir / "gradlew"
    args = " ".join(shlex.quote(str(output_dir / name)) for name in (
        "public_key.bin", "message_hash.bin", "signature.bin"))
    command = [
        str(gradlew), "--no-daemon", "-p", str(project_dir),
        f"-PjavaTronDir={java_tron_dir}", "run", f"--args={args}"
    ]
    try:
        completed = subprocess.run(command, check=True, text=True,
                                   capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"java-tron verifier failed:\n{exc.stdout or ''}{exc.stderr or ''}") from exc
    output = completed.stdout + completed.stderr
    if "valid=true" not in output:
        raise RuntimeError(f"java-tron did not accept the signature:\n{output}")
    print("java-tron MLDSA44.verify: valid=true")


def wait_for_funding(node: TronNode, address: bytes, minimum: int,
                     timeout: int, interval: float) -> int:
    deadline = time.monotonic() + timeout
    while True:
        account = node.account(address)
        balance = int(account.get("balance", 0))
        activated = account.get("address", "").lower() == address.hex()
        print(f"Account activated={activated}, balance={balance} SUN")
        if activated and balance >= minimum:
            return balance
        if time.monotonic() >= deadline:
            raise TimeoutError("PQ account was not funded before the timeout")
        time.sleep(interval)


def write_artifacts(output_dir: Path, raw_data: bytes, public_key: bytes,
                    signature: bytes, transaction: bytes,
                    summary: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "raw_data.bin").write_bytes(raw_data)
    (output_dir / "message_hash.bin").write_bytes(hashlib.sha256(raw_data).digest())
    (output_dir / "public_key.bin").write_bytes(public_key)
    (output_dir / "signature.bin").write_bytes(signature)
    (output_dir / "signed_transaction.bin").write_bytes(transaction)
    (output_dir / "signed_transaction.hex").write_text(transaction.hex() + "\n")
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-url", default="https://nile.trongrid.io")
    parser.add_argument("--api-key", default=os.getenv("TRON_PRO_API_KEY"))
    parser.add_argument("--to", help="destination TRON Base58Check address")
    parser.add_argument("--check-chain", action="store_true",
                        help="print getAllowMlDsa44 and exit without opening a device")
    parser.add_argument("--amount-sun", type=int, default=1_000_000)
    parser.add_argument("--minimum-balance-sun", type=int, default=10_000_000)
    parser.add_argument("--wait-for-funds", action="store_true")
    parser.add_argument(
        "--private-chain-funding-key",
        default=os.getenv("TRON_PRIVATE_FUNDING_KEY"),
        help="local-test key used to fund the confirmed PQ address; never sent to the node")
    parser.add_argument("--funding-timeout", type=int, default=600)
    parser.add_argument("--poll-interval", type=float, default=3.0)
    parser.add_argument("--broadcast", action="store_true")
    parser.add_argument("--abort-after-success", action="store_true")
    parser.add_argument("--output-dir", type=Path,
                        default=Path("/tmp/tron-mldsa-hardware"))
    parser.add_argument("--java-tron-dir", type=Path,
                        default=Path(os.environ["JAVA_TRON_DIR"])
                        if "JAVA_TRON_DIR" in os.environ else None)
    parser.add_argument("--skip-java-verify", action="store_true")
    parser.add_argument("--debug-apdu", action="store_true")
    parser.add_argument("--apdu-tcp", help="Speculos APDU endpoint HOST:PORT")
    parser.add_argument("--speculos-api-url",
                        help="opt-in Speculos UI auto-approval endpoint")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.amount_sun <= 0 or args.minimum_balance_sun < args.amount_sun:
        raise ValueError("amount must be positive and no greater than minimum balance")

    node = TronNode(args.node_url, args.api_key)
    allow_mldsa44 = node.allow_mldsa44()
    print(f"Node: {args.node_url}")
    print(f"getAllowMlDsa44={allow_mldsa44}")
    if args.check_chain:
        return 0
    if not args.to:
        raise ValueError("--to is required unless --check-chain is used")
    destination = base58check_decode(args.to)
    if len(destination) != 21 or destination[0] != 0x41:
        raise ValueError("destination must be a TRON main/test-network address")
    if args.broadcast and allow_mldsa44 != 1:
        raise RuntimeError(
            "broadcast refused before key generation: getAllowMlDsa44 is not 1")
    if args.wait_for_funds and allow_mldsa44 != 1:
        raise RuntimeError(
            "funding wait refused: this network cannot spend from an ML-DSA-44 account")

    if args.private_chain_funding_key and allow_mldsa44 != 1:
        raise RuntimeError("private-chain funding refused: getAllowMlDsa44 is not 1")
    if args.private_chain_funding_key:
        hostname = urllib.parse.urlparse(args.node_url).hostname
        if hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise RuntimeError(
                "--private-chain-funding-key is restricted to a loopback node")
    if bool(args.apdu_tcp) != bool(args.speculos_api_url):
        raise ValueError("--apdu-tcp and --speculos-api-url must be supplied together")

    approver = SpeculosApprover(args.speculos_api_url) if args.speculos_api_url else None
    if approver:
        approver.start()
    ledger = LedgerPqClient(debug=args.debug_apdu, apdu_tcp=args.apdu_tcp)
    session = None
    try:
        ledger.capabilities()
        session, address, fingerprint = ledger.generate_key_confirmed()
        address58 = base58check_encode(address)
        print(f"Temporary PQ address: {address58}")
        print(f"Session: {session.hex()}")
        print("Keep the Tron app open: this key is random, RAM-only, and unrecoverable.")

        public_key = ledger.get_result(session, RESULT_PUBLIC_KEY, PUBLIC_KEY_SIZE)
        if hashlib.sha256(public_key).digest() != fingerprint:
            raise RuntimeError("public-key fingerprint does not match session metadata")
        verify_address(public_key, address)

        if args.private_chain_funding_key:
            funding_txid = fund_private_chain_account(
                node, args.private_chain_funding_key, address,
                args.minimum_balance_sun)
            print(f"Private-chain funding accepted: {funding_txid}")
            wait_for_funding(node, address, args.minimum_balance_sun,
                             args.funding_timeout, args.poll_interval)

        elif args.wait_for_funds:
            print(f"Fund {address58} with at least {args.minimum_balance_sun} SUN.")
            wait_for_funding(node, address, args.minimum_balance_sun,
                             args.funding_timeout, args.poll_interval)

        unsigned = node.create_transfer(address, destination, args.amount_sun)
        raw_data = bytes.fromhex(unsigned["raw_data_hex"])
        sign_metadata = ledger.sign_raw_data(session, raw_data)
        signed_session, signed_address, signed_fingerprint = parse_key_metadata(
            sign_metadata, SIGNATURE_SIZE)
        if (signed_session != session or signed_address != address or
                signed_fingerprint != fingerprint):
            raise RuntimeError("signing response does not match the confirmed PQ session")

        signature = ledger.get_result(session, RESULT_SIGNATURE, SIGNATURE_SIZE)
        transaction = assemble_pq_transaction(raw_data, public_key, signature)
        summary = {
            "node_url": args.node_url,
            "allow_mldsa44": allow_mldsa44,
            "session_id": session.hex(),
            "address": address58,
            "address_hex": address.hex(),
            "destination": args.to,
            "amount_sun": args.amount_sun,
            "txid": hashlib.sha256(raw_data).hexdigest(),
            "public_key_sha256": fingerprint.hex(),
            "public_key_size": len(public_key),
            "signature_size": len(signature),
            "broadcast": None,
        }
        write_artifacts(args.output_dir, raw_data, public_key, signature,
                        transaction, summary)

        if not args.skip_java_verify:
            if args.java_tron_dir is None:
                raise RuntimeError(
                    "set --java-tron-dir/JAVA_TRON_DIR for independent verification, "
                    "or explicitly pass --skip-java-verify")
            run_java_tron_verify(Path(__file__).resolve().parents[1] / "tron-pq-verify",
                                 args.java_tron_dir.resolve(), args.output_dir.resolve())

        # Free the large signature buffer while retaining the session key for
        # another transfer or manual recovery if broadcasting fails.
        ledger.close_result(session)

        if args.broadcast:
            # Re-check immediately before the irreversible network action. This
            # is intentionally redundant with the early check above.
            if node.allow_mldsa44() != 1:
                raise RuntimeError(
                    "broadcast refused: getAllowMlDsa44 changed or is not 1")
            result = node.broadcast(transaction)
            summary["broadcast"] = result
            (args.output_dir / "summary.json").write_text(
                json.dumps(summary, indent=2) + "\n")
            if not result.get("result", False):
                raise RuntimeError(f"node rejected the PQ transaction: {result}")
            print(f"Broadcast accepted: {summary['txid']}")
            if args.abort_after_success:
                print("Erasing the temporary PQ key at explicit user request.")
                ledger.abort(session)
                session = None
        else:
            print("Dry run complete; signed transaction was NOT broadcast.")
            print(f"Artifacts: {args.output_dir}")
        if approver:
            approver.finish()
        return 0
    finally:
        ledger.close()
        if session is not None:
            print("PQ key remains only while the Tron app stays open; it was not aborted.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
