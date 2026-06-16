#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Drive the Generic Clear Signing (GCS) flow for an over-long shielded-`mint`
calldata against a real Ledger device, mirroring
tests/ragger/test_gcs.py::test_gcs_mint_long_calldata.

Target network: TRON Nile testnet.
  NOTE on chain id: the GCS "store" path pins the parked transaction's chain id to
  TRON mainnet (`gcs_bridge_finalize(..., TRON_MAINNET_CHAINID)` in
  src/handlers/sign_external_plugin.c), and `app_compatible_with_chain_id()` accepts
  both Tron and Tron Nile. So the GCS descriptor + token metadata MUST use the mainnet
  chain id (728126428) even when the app/device is connected to Nile; "Nile" here refers
  to the network the `mint` contract lives on, not the value carried in the descriptor.

Flow (each step is one or more APDUs):
  1. 0x02            get the device address (becomes the tx owner / GCS "From")
  2. 0xC4 P2=0x10    STORE: stream the TriggerSmartContract protobuf (parks the calldata,
                     chunked because the ~1 KB calldata overflows a single APDU)
  3. 0xB0 PKI        coin-metadata certificate, then 0xCA token metadata (CAL-signed)
  4. 0xB0 PKI        calldata certificate, then 0x26 TX_INFO (CALLDATA-signed) + 0x28 FIELDs
  5. 0xC4 P2=0x11    START_FLOW: render the review, user approves, device returns the sig

Prerequisites:
  - app-tron installed on the device (mainnet or Nile build both work, see note above)
  - this host has tests/ragger importable (keychain PEMs under tests/ragger/keychain/)
    and the compiled protobuf under <repo>/proto
  - the CALLDATA Ledger-PKI test certificate is accepted by the target app. This is
    normally true on Speculos/test-key builds, not on production-keyed hardware.

Typical usage:
    python examples/signGCSMintLongCalldata.py --device flex
    python examples/signGCSMintLongCalldata.py --device nanosp --path "44'/195'/0'/0/0"
    # sign AND broadcast to the Nile testnet, printing the txID:
    python examples/signGCSMintLongCalldata.py --device nanosp --broadcast
    # (optional) custom node / fee limit:
    python examples/signGCSMintLongCalldata.py --device flex --broadcast \
        --node https://api.nileex.io --fee-limit 1500000000
"""

import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import base58
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException

from base import parse_bip32_path_to_bytes

REPO_ROOT = Path(__file__).resolve().parents[1]
for extra in (REPO_ROOT / "tests" / "ragger", REPO_ROOT / "proto"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from client import keychain  # noqa: E402
from client.gcs import (  # noqa: E402
    ContainerPath, DataPath, Field, ParamRaw, ParamTokenAmount, PathLeaf,
    PathLeafType, PathTuple, TxInfo, TypeFamily, Value)
from utils import check_tx_signature  # noqa: E402
from google.protobuf.any_pb2 import Any  # noqa: E402
from core import Contract_pb2 as contract  # noqa: E402
from core import Tron_pb2 as tron  # noqa: E402

# --- Protocol constants (mirror src/apdu_constants.h) ------------------------
CLA = 0xE0
PKI_CLA = 0xB0
PKI_INS = 0x06

INS_GET_PUBLIC_ADDR = 0x02
INS_SIGN_EXTERNAL_PLUGIN = 0xC4
INS_PROVIDE_TRC20_TOKEN_INFORMATION = 0xCA
INS_GTP_TRANSACTION_INFO = 0x26
INS_GTP_FIELD = 0x28

# 0xC4 streaming P1s / GCS P2s
P1_FIRST = 0x00
P1_MORE = 0x80
P1_LAST = 0x90
P1_SIGN = 0x10
P2_GCS_STORE = 0x10
P2_GCS_START_FLOW = 0x11

# Chunked-TLV framing for 0x26 / 0x28 (first chunk carries a 2-byte BE total length).
P1_TLV_FIRST = 0x01
P1_TLV_FOLLOWING = 0x00

# Ledger-PKI public key usages
PKI_USAGE_COIN_META = 0x08
PKI_USAGE_CALLDATA = 0x0B

MAX_APDU_LEN = 255
ADDRESS_PREFIX = 0x41  # TRON mainnet address prefix (parse.h ADD_PRE_FIX_BYTE_MAINNET)

# The GCS path uses the TRON mainnet chain id internally (see module docstring).
CHAIN_ID = 728126428

# Shielded `mint(uint256 rawValue, bytes32[9] output, bytes32[2] bindingSignature,
# bytes32[21] c)` on Nile -- same vectors as tests/ragger/test_gcs.py.
MINT_CONTRACT_B58 = "TNnFMMykZzwhPZkurKtNMyVGvgeSkCrnPi"
MINT_CALLDATA = bytes.fromhex(
    "855d175e"
    "00000000000000000000000000000000000000000000000053444835ec580000"
    "8a84b240830d86393b3fed2e3883ef7a1d47159a9d85ded1827a65a84314904c"
    "77d345ba2d03ccf28c5d3533655b1250ac40ddf33f454f6ccd05c53002532ca7"
    "44d34a033ef3aed90f6e1146cad2ea868cd0cbbde4c91db7168f7df0a1255a45"
    "817f67bfad8beacd2d9a02e0309333d28c5c8e95baaaa9c97563a9f49a91f40c"
    "db6a52090313df7083ac80665541969f964652d87a5bc756f6d4395eb2f42f37"
    "e753bf38fdb292faf806ee444b114e9426ab5a6f6bf9807e8924b2b5aa9e3b7a"
    "16ac3588fa32c24d4307e0768df78f31e94b46c95f19492ccf1074b524b907cf"
    "c6508ecfbf17503b3c2d0a18452d2a3295199a3f3cc27598c3507c47dd400c2e"
    "c720844ad330d659ce34c3e5c2f7eb75d6a345b4274faf9e5439256b50ec96a4"
    "8fc7bcb17fd49e9d0535802a4078d55abd5e9273c78af2e95403de738e6d9f4a"
    "966a4b4a8dddef198f58e7d9cb6a6d9b997415b4444fc63238285ff4930fea02"
    "a61bea2bbb35416ecb7556dc6a5e8f2e8cc75ce91a628d8ad4755ecb279f1181"
    "82160284c8740187ccb70ccadc61e793e6287dfcd53cd8a632b3ae6bf5d6551c"
    "8ff30abedba0ccc9f6ef69b5fef451650c7e7f16fac22dfa5033f4c66512e5cb"
    "71b99fa7832aebc50c1906722b8dd9bf5fe0fba3b4f427cc841030ef6a761059"
    "521d85699de248797e35354d433c27bf6cac27f580a4eca5ea26d63b3b3395be"
    "9a82cb1bd2463e7e1c936410ba9c4e103ef389f5c51974dc9fe0a3b8623370ed"
    "8b3243786ccaa3a98b55ff1fdda001384f015ec3e6bbd05b600817c502e6185c"
    "8fe885bad8b7674a1425ccffd7eba7e14bd5d2a323316ed14862e29f9c25e3bb"
    "b4a5f8cc4eaed65a2ca1bd5276f5790c0fb2365530687ceaf97c3d998efb7eec"
    "2d47064e68fcbf586e946fe335fc209b10ffa84c8d71d87b4f6d7cca21160cfe"
    "45a45092db86694dfd7cb3d7beb9b867910d5cc3367d5c1c54b34ca2e28acc7c"
    "a3f6b6170b79177f2ebfe39f72a0d04741892c863cad68010ce7b2118b6300cf"
    "46f6fd67fcec51312189989f6fc497371a2d15c199f5cdb6c7a7a3d30835b705"
    "36f3ac5b41b273a7132d85aacc3a30e8d4a8dcff90465a72f3e9fe2763a77450"
    "1d7129e36f86b20432dbf894b66c4f2063be9ca30bc1d76715c9c32ec0e2d376"
    "73e3531f79391d804a821e484a37fbeed28546e042ab75d4cc439c8fe3dacb1b"
    "7f19bae6370fdce4cbe22c2d319a1e8d4c1082d78d89c62a8f267bafeb37c3e1"
    "78f047c4d6b5284b277fed2237a8782e06548cc30ed46fe85e0f87824f9d2bb1"
    "1b0c5d4742e1a3fc38379f63d2c0e405d173481aa61ae7974cb1bc541b9348c8"
    "1790ad8ad80ed11c5ef3b7c83cd1dc8e13abb872570db6c249ad039c00240f7f"
    "c3ca8ee4e47ae81da4bffb81243c48e8e8d93fec000000000000000000000000")
MINT_SELECTOR = MINT_CALLDATA[:4]

# Ledger-PKI test certificates (same ones ragger/speculos use). On production-keyed
# hardware these may be rejected -- pass --skip-certs to omit them.
COIN_META_CERTIFICATES = {
    "nanosp": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010310040102000015473045022100C15795C2AE41E6FAE6B1362EE1AE216428507D7C1D6939B928559CC7A1F6425C02206139CF2E133DD62F3E00F183E42109C9853AC62B6B70C5079B9A80DBB9D54AB5",
    "nanox": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010215473045022100E3B956F93FBFF0D41908483888F0F75D4714662A692F7A38DC6C41A13294F9370220471991BECB3CA4F43413CADC8FF738A8CC03568BFA832B4DCFE8C469080984E5",
    "stax": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501041546304402206731FCD3E2432C5CA162381392FD17AD3A41EEF852E1D706F21A656AB165263602204B89FAE8DBAF191E2D79FB00EBA80D613CB7EDF0BE960CB6F6B29D96E1437F5F",
    "flex": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C64056188734010135010515473045022100B59EA8B958AA40578A6FBE9BBFB761020ACD5DBD8AA863C11DA17F42B2AFDE790220186316059EFA58811337D47C7F815F772EA42BBBCEA4AE123D1118C80588F5CB",
    "apex_p": "01010102010211040000000212010013020002140101160400000000200B45524332305F546F6B656E300200063101083201213321024CCA8FAD496AA5040A00A7EB2F5CC3B85376D88BA147A7D7054A99C6405618873401013501061546304402207AB71BB46DD2361292195E95587D14FEDE2BA10FC23F0D6B20444B93A32258D302201362A6815779B2806005B0151BFADB811B78A76FDB90028FBE6C93EB7FB5EEA3",
}
CALLDATA_CERTIFICATES = {
    "nanosp": "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B434010135010315463044022076DD2EAB72E69D440D6ED8290C8C37E39F54294C23FF0F8520F836E7BE07455C02201D9A8A75223C1ADA1D9D00966A12EBB919D0BBF2E66F144C83FADCAA23672566",
    "nanox": "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B434010135010215463044022077FF9625006CB8A4AD41A4B04FF2112E92A732BD263CCE9B97D8E7D2536D04300220445B8EE3616FB907AA5E68359275E94D0A099C3E32A4FC8B3669C34083671F2F",
    "stax": "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B434010135010415473045022100A88646AD72CA012D5FDAF8F6AE0B7EBEF079212768D57323CB5B57CADD9EB20D022005872F8EA06092C9783F01AF02C5510588FB60CBF4BA51FB382B39C1E060BB6B",
    "flex": "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B43401013501051546304402205305BDDDAD0284A2EAC2A9BE4CEF6604AE9415C5F46883448F5F6325026234A3022001ED743BCF33CCEB070FDD73C3D3FCC2CEE5AB30A5C3EB7D2A8D21C6F58D493F",
    "apex_p": "01010102010211040000000212010013020002140101160400000000200863616C6C646174613002000831010B32012133210381C0821E2A14AC2546FB0B9852F37CA2789D7D76483D79217FB36F51DCE1E7B4340101350106154730450221009F5EDA5B6ED34FA9F1C44B1CC234BE5FE6C0DD4655F42EE50CA6201F59491E5A02206E055F490F56F42B625F2B5772AE860CAC6848B6C5AC8E44BC529A959249FC37",
}


def serialize_apdu(cla: int, ins: int, p1: int, p2: int, cdata: bytes = b"") -> bytes:
    return bytes([cla, ins, p1, p2, len(cdata)]) + cdata


def pack_derivation_path(path: str) -> bytes:
    path_bytes = parse_bip32_path_to_bytes(path)
    return bytes([len(path_bytes) // 4]) + path_bytes


def exchange(dongle, apdu: bytes, label: str) -> bytes:
    print(f"{label} => {apdu.hex()}")
    response = dongle.exchange(apdu)
    print(f"{label} <= {(response.hex() if response else '') }9000")
    return response


def parse_pk_addr(response: bytes) -> Tuple[bytes, bytes]:
    """Return (public_key, raw_21byte_address) from a GET_PUBLIC_ADDR response."""
    idx = 0
    pk_len = response[idx]
    idx += 1
    pubkey = response[idx:idx + pk_len]
    idx += pk_len
    addr_len = response[idx]
    idx += 1
    raw_addr = base58.b58decode_check(response[idx:idx + addr_len])
    return pubkey, raw_addr


def to_base58check(raw_addr: bytes) -> str:
    return base58.b58encode_check(raw_addr).decode()


def apdu_get_public_addr(path: str) -> bytes:
    return serialize_apdu(CLA, INS_GET_PUBLIC_ADDR, 0x00, 0x00, pack_derivation_path(path))


def apdu_pki_certificate(usage: int, cert_hex: str) -> bytes:
    return serialize_apdu(PKI_CLA, PKI_INS, usage, 0x00, bytes.fromhex(cert_hex))


def send_certificate(dongle,
                     usage: int,
                     cert_hex: Optional[str],
                     label: str,
                     *,
                     required: bool) -> None:
    if cert_hex is None:
        msg = f"No {label} certificate for this device."
        if required:
            raise RuntimeError(msg)
        print(f"[WARN] {msg} Skipping.")
        return
    try:
        exchange(dongle, apdu_pki_certificate(usage, cert_hex), f"pki:{label}")
    except CommException as exc:
        msg = (f"{label} certificate rejected ({exc}). The bundled certificates are "
               "test PKI certificates and are normally accepted only by Speculos or "
               "test-key/debug builds.")
        if required:
            raise RuntimeError(
                f"{msg} Cannot continue because GCS TX_INFO descriptors are signed "
                "with tests/ragger/keychain/calldata.pem and the firmware verifies "
                "them against the loaded CALLDATA certificate.") from exc
        print(f"[WARN] {msg} Continuing.")


def build_trigger_tx(owner_addr21: bytes, contract_addr21: bytes, calldata: bytes, *,
                     ref_block_bytes: bytes, ref_block_hash: bytes, timestamp: int,
                     expiration: int, fee_limit: Optional[int] = None):
    """Build a TriggerSmartContract Transaction, mirroring TronClient.packContract but
    with caller-supplied block reference / timing (a stale ref is rejected by the
    network). Returns the Transaction object; sign over `tx.raw_data.SerializeToString()`."""
    tx = tron.Transaction()
    tx.raw_data.timestamp = timestamp
    tx.raw_data.expiration = expiration
    tx.raw_data.ref_block_hash = ref_block_hash
    tx.raw_data.ref_block_bytes = ref_block_bytes
    if fee_limit is not None:
        tx.raw_data.fee_limit = fee_limit
    c = tx.raw_data.contract.add()
    c.type = tron.Transaction.Contract.TriggerSmartContract
    param = Any()
    param.Pack(contract.TriggerSmartContract(owner_address=owner_addr21,
                                             contract_address=contract_addr21,
                                             data=calldata),
               deterministic=True)
    c.parameter.CopyFrom(param)
    return tx


def http_post_json(url: str, payload: dict) -> dict:
    import urllib.request
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def fetch_block_ref(node: str) -> Tuple[bytes, bytes]:
    """Fetch the latest block from a TRON node and derive the TaPoS reference
    (ref_block_bytes = low 2 bytes of the block number, ref_block_hash = blockID[8:16])."""
    blk = http_post_json(f"{node.rstrip('/')}/wallet/getnowblock", {})
    block_id = bytes.fromhex(blk["blockID"])
    number = int(blk["block_header"]["raw_data"]["number"])
    ref_block_bytes = number.to_bytes(8, "big")[-2:]
    ref_block_hash = block_id[8:16]
    return ref_block_bytes, ref_block_hash


def broadcast_tx(node: str, tx, signature: bytes) -> Tuple[str, dict]:
    """Attach the signature, POST the full signed transaction, return (txID, result)."""
    tx.signature.append(bytes(signature))  # protobuf bytes field rejects bytearray
    txid = hashlib.sha256(tx.raw_data.SerializeToString()).hexdigest()
    result = http_post_json(f"{node.rstrip('/')}/wallet/broadcasthex",
                            {"transaction": tx.SerializeToString().hex()})
    return txid, result


def gcs_store_apdus(path: str, tx: bytes) -> List[bytes]:
    """0xC4 P2=STORE stream: derivation path + 4-byte tx length + tx, chunked."""
    head = bytearray(pack_derivation_path(path))
    head += struct.pack(">I", len(tx))
    first_room = MAX_APDU_LEN - len(head)
    head += tx[:first_room]
    rest = tx[first_room:]

    chunks = [bytes(head)]
    while rest:
        chunks.append(rest[:MAX_APDU_LEN])
        rest = rest[MAX_APDU_LEN:]

    apdus = []
    for i, chunk in enumerate(chunks):
        if len(chunks) == 1:
            p1 = P1_SIGN          # single chunk: init + finalize in one APDU
        elif i == 0:
            p1 = P1_FIRST
        elif i == len(chunks) - 1:
            p1 = P1_LAST
        else:
            p1 = P1_MORE
        apdus.append(serialize_apdu(CLA, INS_SIGN_EXTERNAL_PLUGIN, p1, P2_GCS_STORE, chunk))
    return apdus


def tlv_chunk_apdus(ins: int, tlv_payload: bytes) -> List[bytes]:
    """Chunked-TLV framing (0x26 / 0x28): first chunk prefixes the 2-byte BE length."""
    payload = struct.pack(">H", len(tlv_payload)) + tlv_payload
    apdus = []
    first = True
    while payload:
        p1 = P1_TLV_FIRST if first else P1_TLV_FOLLOWING
        apdus.append(serialize_apdu(CLA, ins, p1, 0x00, payload[:MAX_APDU_LEN]))
        payload = payload[MAX_APDU_LEN:]
        first = False
    return apdus


def apdu_token_metadata(ticker: str, addr21: bytes, decimals: int, chain_id: int) -> bytes:
    cdata = bytearray()
    cdata.append(len(ticker))
    cdata += ticker.encode()
    cdata += addr21
    cdata += struct.pack(">I", decimals)
    cdata += struct.pack(">I", chain_id)
    # The CAL signature covers the cdata without its leading APDU header *and* without
    # the leading ticker-length byte (sign over apdu[6:]), matching the firmware.
    unsigned = serialize_apdu(CLA, INS_PROVIDE_TRC20_TOKEN_INFORMATION, 0x00, 0x00, bytes(cdata))
    sig = keychain.sign_data(keychain.Key.CAL, unsigned[6:])
    cdata += sig
    return serialize_apdu(CLA, INS_PROVIDE_TRC20_TOKEN_INFORMATION, 0x00, 0x00, bytes(cdata))


def compute_inst_hash(fields: List[Field]) -> bytes:
    digest = hashlib.sha3_256()
    for field in fields:
        digest.update(field.serialize())
    return digest.digest()


def build_descriptor(contract_addr20: bytes) -> Tuple[bytes, List[bytes]]:
    """Build the GCS TX_INFO + FIELD descriptors for the shielded mint, mirroring
    test_gcs_mint_long_calldata: a "Value" token-amount (rawValue, arg 0; token = the
    contract via ContainerPath.TO) and the trigger tx owner via ContainerPath.FROM."""
    value = Value(1, TypeFamily.UINT, type_size=32,
                  data_path=DataPath(1, [PathTuple(0), PathLeaf(PathLeafType.STATIC)]))
    token = Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.TO)
    fields = [
        Field(1, "Value", ParamTokenAmount(1, value=value, token=token)),
        Field(1, "From",
              ParamRaw(1, Value(1, TypeFamily.ADDRESS, container_path=ContainerPath.FROM))),
    ]
    tx_info = TxInfo(1, CHAIN_ID, contract_addr20, MINT_SELECTOR,
                     compute_inst_hash(fields), "Shielded Mint",
                     creator_name="ShieldedJST", contract_name="Shielded")
    return tx_info.serialize(), [field.serialize() for field in fields]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", required=True,
                        choices=sorted(COIN_META_CERTIFICATES.keys()),
                        help="Target device family (selects the PKI test certificates)")
    parser.add_argument("--path", default="44'/195'/0'/0/0", help="BIP32 signing path")
    parser.add_argument("--skip-certs", action="store_true",
                        help="Do not send the Ledger-PKI certificates. This only works on "
                        "debug builds that bypass descriptor signature checks.")
    parser.add_argument("--broadcast", action="store_true",
                        help="After signing, broadcast the transaction to the Nile testnet and "
                        "print its txID. Fetches a fresh block reference so the tx is valid.")
    parser.add_argument("--node", default="https://nile.trongrid.io",
                        help="TRON Nile full-node HTTP endpoint (used with --broadcast)")
    parser.add_argument("--fee-limit", type=int, default=1_000_000_000,
                        help="fee_limit in SUN for the contract call (default 1000 TRX)")
    args = parser.parse_args()

    dongle = getDongle(True)
    contract_addr20 = base58.b58decode_check(MINT_CONTRACT_B58)[1:]
    contract_addr21 = bytes([ADDRESS_PREFIX]) + contract_addr20

    assert len(MINT_CALLDATA) > MAX_APDU_LEN, "calldata must overflow one APDU"

    print("[INFO] Fetching device address (tx owner / GCS From)")
    pk_resp = exchange(dongle, apdu_get_public_addr(args.path), "get_public_addr")
    pubkey, owner_addr21 = parse_pk_addr(pk_resp)
    print(f"[INFO] Owner address: {to_base58check(owner_addr21)}")

    if args.broadcast:
        # A real broadcast needs a current TaPoS reference + future expiration + fee_limit.
        ref_block_bytes, ref_block_hash = fetch_block_ref(args.node)
        now = int(time.time() * 1000)
        ts, exp, fee = now, now + 60_000, args.fee_limit
        print(f"[INFO] Nile block ref: bytes={ref_block_bytes.hex()} hash={ref_block_hash.hex()}")
    else:
        # Static demo values (mirror TronClient.packContract); not broadcastable.
        ref_block_bytes, ref_block_hash = bytes.fromhex("3DCE"), bytes.fromhex("95DA42177DB00507")
        ts, exp, fee = 1575712492061, 1575712551000, None

    tx_obj = build_trigger_tx(owner_addr21, contract_addr21, MINT_CALLDATA,
                              ref_block_bytes=ref_block_bytes, ref_block_hash=ref_block_hash,
                              timestamp=ts, expiration=exp, fee_limit=fee)
    tx = tx_obj.raw_data.SerializeToString()

    print(f"[INFO] STORE: streaming {len(tx)}-byte tx ({len(MINT_CALLDATA)}-byte calldata)")
    for i, apdu in enumerate(gcs_store_apdus(args.path, tx)):
        exchange(dongle, apdu, f"gcs_store[{i}]")

    if not args.skip_certs:
        send_certificate(dongle, PKI_USAGE_COIN_META,
                         COIN_META_CERTIFICATES.get(args.device), "coin_meta", required=False)
    print("[INFO] Providing token metadata (JST, 18 decimals)")
    exchange(dongle,
             apdu_token_metadata("JST", contract_addr21, 18, CHAIN_ID),
             "token_meta")

    if not args.skip_certs:
        # Non-fatal: the bundled test certificates are rejected by non-test-key builds,
        # but such builds also verify the descriptors against embedded test keys (the
        # token metadata above succeeds the same way), so the cert is best-effort. If a
        # build genuinely enforces it, the 0x26 TX_INFO step below fails with its own SW.
        send_certificate(dongle, PKI_USAGE_CALLDATA,
                         CALLDATA_CERTIFICATES.get(args.device), "calldata", required=False)
    else:
        print("[WARN] Skipping CALLDATA certificate. TX_INFO will be accepted only if this "
              "app build bypasses descriptor signature checks.")
    tx_info_payload, field_payloads = build_descriptor(contract_addr20)
    print("[INFO] Providing TX_INFO descriptor")
    try:
        for i, apdu in enumerate(tlv_chunk_apdus(INS_GTP_TRANSACTION_INFO, tx_info_payload)):
            exchange(dongle, apdu, f"tx_info[{i}]")
    except CommException as exc:
        sw = getattr(exc, "sw", 0)
        if sw == 0x6A80:
            print("\n[ERROR] TX_INFO rejected (0x6A80). GCS descriptors are verified against the "
                  "CALLDATA PKI certificate, and gtp_tx_info.c passes NULL as the fallback key "
                  "(check_signature_with_pubkey) -- so, unlike token metadata, there is NO "
                  "embedded-key legacy path: a loaded CALLDATA certificate is mandatory.\n"
                  "[ERROR] The PKI certificate is validated by the OS, not the app, against the "
                  "OS PKI root. Only Speculos's OS trusts the bundled test certificates; a real "
                  "device rejects them (the 4231/5720 above) regardless of dbg_use_test_keys "
                  "(that flag only swaps the app's embedded keys, which the token-metadata legacy "
                  "path uses -- GCS does not).\n"
                  "[ERROR] To run GCS end to end: use Speculos (ragger env), OR rebuild/flash with "
                  "`make ... BYPASS_SIGNATURES=1` (HAVE_BYPASS_SIGNATURES) to skip descriptor "
                  "signature checks. The store + token-metadata steps already passed, so the APDU "
                  "flow and descriptor bytes are correct.")
        raise
    for fi, field_payload in enumerate(field_payloads):
        print(f"[INFO] Providing FIELD descriptor #{fi}")
        for i, apdu in enumerate(tlv_chunk_apdus(INS_GTP_FIELD, field_payload)):
            exchange(dongle, apdu, f"field{fi}[{i}]")

    print("[INFO] START_FLOW: review the transaction on device, then approve to sign")
    signature = exchange(dongle,
                         serialize_apdu(CLA, INS_SIGN_EXTERNAL_PLUGIN, P1_FIRST,
                                        P2_GCS_START_FLOW, b""),
                         "gcs_start_flow")
    print(f"[INFO] Signature: {signature[:65].hex()}")

    # check_tx_signature wants the 64-byte uncompressed key as a hex string (no 0x04).
    pubkey_hex = pubkey.hex()
    if len(pubkey) == 65 and pubkey_hex[:2] == "04":
        pubkey_hex = pubkey_hex[2:]
    ok = check_tx_signature(tx, signature[0:65], pubkey_hex)
    print(f"[INFO] Signature valid over sha256(tx): {ok}")
    if not ok:
        print("[ERROR] Local signature check failed; not broadcasting.")
        return 1

    if args.broadcast:
        print(f"[INFO] Broadcasting to Nile via {args.node}")
        txid, result = broadcast_tx(args.node, tx_obj, signature[0:65])
        print(f"[INFO] Transaction ID: {txid}")
        print(f"[INFO] Broadcast result: {json.dumps(result)}")
        if not result.get("result", False):
            # e.g. CONTRACT_VALIDATE_ERROR / SIGERROR / TAPOS / BANDWITH_ERROR
            print("[WARN] Broadcast not accepted. The txID is still computed above; check the "
                  "node message (the mint calldata is a fixed test vector and the contract may "
                  "revert/validate-fail, and the owner needs TRX/energy on Nile).")
            return 1
        print(f"[INFO] Track it: https://nile.tronscan.org/#/transaction/{txid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
