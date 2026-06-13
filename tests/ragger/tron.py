#!/usr/bin/env python3
import sys
import base58
import rlp
import pickle

from typing import Optional
from contextlib import contextmanager
from enum import IntEnum
from pathlib import Path
from typing import Tuple, Generator
from struct import unpack, pack
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from bip_utils.addr import TrxAddrEncoder
from eth_keys import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.navigator import NavInsID, NavIns
from ragger.bip import pack_derivation_path
from conftest import MNEMONIC
from web3 import Web3
from client.command_builder import (CLA, MAX_APDU_LEN, CommandBuilder, InsType,
                                    P1Type as P1, P2Type as P2)
from client.keychain import Key, sign_data
from client.ledger_pki import PKIClient, PKIPubKeyUsage
from client.status_word import StatusWord
from client.trusted_name import TrustedName, TrustedNameSource
from ledgered.devices import Device
'''
Tron Protobuf
'''
PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Tron_pb2 as tron
from core import Contract_pb2 as contract

from google.protobuf.any_pb2 import Any
from google.protobuf.internal.decoder import _DecodeVarint32

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

PUBLIC_KEY_LENGTH = 65
BASE58_ADDRESS_SIZE = 34
GET_ADDRESS_RESP_LEN = 101
GET_VERSION_RESP_LEN = 4
TRON_MAINNET_ADDRESS_PREFIX = 0x41

Errors = StatusWord


class APDUOffsets(IntEnum):
    CLA = 0
    INS = 1
    P1 = 2
    P2 = 3
    LC = 4
    CDATA = 5


class TronClient:
    # default APDU TCP server
    HOST, PORT = ('127.0.0.1', 9999)
    CLA = 0xE0

    def __init__(self, client: BackendInterface, device: Device, navigator):
        if not isinstance(client, BackendInterface):
            raise TypeError('client must be an instance of BackendInterface')
        self._client = client
        self._device = device
        self._navigator = navigator
        self.accounts = [None, None]
        self.hardware = True
        self._pki_client: Optional[PKIClient] = None
        self._pki_client = PKIClient(self._client)
        # app-ethereum parity: the shared EIP-712 InputData driver references
        # app_client.pki_client (see EthAppClient).
        self.pki_client = self._pki_client

        # Init account with default address to compare with ledger
        for i in range(2):
            HD = self.getPrivateKey(MNEMONIC, i, 0, 0)
            key = keys.PrivateKey(HD)
            diffieHellman = ec.derive_private_key(int.from_bytes(HD, "big"),
                                                  ec.SECP256K1(),
                                                  default_backend())
            self.accounts[i] = {
                "path": ("m/44'/195'/{}'/0/0".format(i)),
                "privateKeyHex":
                HD.hex(),
                "key":
                key,
                "addressHex":
                "41" + key.public_key.to_checksum_address()[2:].upper(),
                "publicKey":
                key.public_key.to_hex().upper(),
                "dh":
                diffieHellman,
            }

    def exchange_async_raw(self, payload: bytes):
        return self._client.exchange_async_raw(payload)

    def exchange_raw(self, payload: bytes):
        return self._client.exchange_raw(payload)

    def exchange_async_raw_chunks(self, chunks):
        for chunk in chunks[:-1]:
            self.exchange_raw(chunk)
        return self.exchange_async_raw(chunks[-1])

    # ------------------------------------------------------------------ #
    # app-ethereum EIP-712 client parity.
    #
    # These mirror EthAppClient.tip712_* (app-ethereum client.py) so the
    # shared EIP-712 InputData driver and test bodies are byte-for-byte
    # comparable with app-ethereum. They wrap the TIP712 CommandBuilder
    # serializers; exchange_raw/exchange_async_raw map 1:1 to app-ethereum's
    # _exchange/_exchange_async, and response() == last_async_response.
    # ------------------------------------------------------------------ #
    def response(self) -> RAPDU:
        return self._client.last_async_response

    def tip712_send_struct_def_struct_name(self, name: str):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_send_struct_def_struct_name(name))

    def tip712_send_struct_def_struct_field(self, field_type, type_name,
                                            type_size, array_levels, key_name):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_send_struct_def_struct_field(
                field_type, type_name, type_size, array_levels, key_name))

    def tip712_send_struct_impl_root_struct(self, name: str):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_send_struct_impl_root_struct(name))

    def tip712_send_struct_impl_array(self, size: int):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_send_struct_impl_array(size))

    def tip712_send_struct_impl_struct_field(self, raw_value: bytes):
        chunks = CommandBuilder().tip712_send_struct_impl_struct_field(
            bytearray(raw_value))
        for chunk in chunks[:-1]:
            self._client.exchange_raw(chunk)
        return self._client.exchange_async_raw(chunks[-1])

    def tip712_sign_new(self, bip32_path: str):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_sign_new(bip32_path))

    def tip712_sign_legacy(self, bip32_path: str, domain_hash: bytes,
                           message_hash: bytes):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_sign_legacy(bip32_path, domain_hash,
                                                message_hash))

    def tip712_filtering_activate(self):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_activate())

    def tip712_filtering_discarded_path(self, path: str):
        return self._client.exchange_raw(
            CommandBuilder().tip712_filtering_discarded_path(path))

    def tip712_filtering_message_info(self, name: str, filters_count: int,
                                      sig: bytes):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_message_info(name, filters_count,
                                                           sig))

    def tip712_filtering_amount_join_token(self, token_idx: int, sig: bytes,
                                           discarded: bool):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_amount_join_token(token_idx, sig,
                                                               discarded))

    def tip712_filtering_amount_join_value(self, token_idx: int, name: str,
                                           sig: bytes, discarded: bool):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_amount_join_value(token_idx, name,
                                                               sig, discarded))

    def tip712_filtering_datetime(self, name: str, sig: bytes, discarded: bool):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_datetime(name, sig, discarded))

    def tip712_filtering_trusted_name(self, name: str, name_type: list,
                                      name_source: list, sig: bytes,
                                      discarded: bool):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_trusted_name(name, name_type,
                                                           name_source, sig,
                                                           discarded))

    def tip712_filtering_raw(self, name: str, sig: bytes, discarded: bool):
        return self._client.exchange_async_raw(
            CommandBuilder().tip712_filtering_raw(name, sig, discarded))

    def address_hex(self, address):
        return base58.b58decode_check(address).hex().upper()

    def getPrivateKey(self, seed, account, change, address_index):
        seed_bytes = Bip39SeedGenerator(seed).Generate()
        bip32_ctx = Bip32Slip10Secp256k1.FromSeedAndPath(
            seed_bytes, f"m/44'/195'/{account}'/{change}/{address_index}")
        return bytes(bip32_ctx.PrivateKey().Raw())

    def getAccount(self, number):
        return self.accounts[number]

    def packContract(self,
                     contractType,
                     newContract,
                     data=None,
                     permission_id=None):
        tx = tron.Transaction()
        tx.raw_data.timestamp = 1575712492061
        tx.raw_data.expiration = 1575712551000
        tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
        tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")
        if data:
            if data.__class__ is dict:
                tx.raw_data.custom_data = pickle.dumps(data)
            else:
                tx.raw_data.custom_data = data

        c = tx.raw_data.contract.add()
        c.type = contractType
        param = Any()
        param.Pack(newContract, deterministic=True)

        c.parameter.CopyFrom(param)

        if permission_id:
            c.Permission_id = permission_id
        return tx.raw_data.SerializeToString()

    def get_next_length(self, tx):
        field, pos = _DecodeVarint32(tx, 0)
        size, newpos = _DecodeVarint32(tx, pos)
        if (field & 0x07 == 0):
            return newpos
        return size + newpos

    def navigate(
            self,
            snappath: Path = None,
            text: str = "",
            warning_approve: bool = False,
            warning_instruction: NavInsID = NavInsID.USE_CASE_CHOICE_CONFIRM):
        if self._device.is_nano:
            path_name = ""
            screen_change_before_first_instruction = True
            if warning_approve:
                self._navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                                     str(snappath) + "/part1",
                                                     [NavInsID.BOTH_CLICK])
                path_name = "/part2"
                screen_change_before_first_instruction = False
            self._navigator.navigate_until_text_and_compare(
                NavIns(NavInsID.RIGHT_CLICK), [NavIns(NavInsID.BOTH_CLICK)],
                text,
                ROOT_SCREENSHOT_PATH,
                str(snappath) + path_name,
                screen_change_before_first_instruction=
                screen_change_before_first_instruction)
        else:
            path_name = ""
            screen_change_before_first_instruction = True
            if warning_approve:
                self._navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                                     str(snappath) + "/part1",
                                                     [warning_instruction])
                path_name = "/part2"
                screen_change_before_first_instruction = False
            self._navigator.navigate_until_text_and_compare(
                NavInsID.USE_CASE_REVIEW_TAP, [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                text,
                ROOT_SCREENSHOT_PATH,
                str(snappath) + path_name,
                screen_change_before_first_instruction=
                screen_change_before_first_instruction)

    def getVersion(self):
        return self._client.exchange(CLA, InsType.GET_APP_CONFIGURATION, 0x00,
                                     0x00)

    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response

    def compute_address_from_public_key(self, public_key: bytes) -> str:
        return TrxAddrEncoder.EncodeKey(public_key)

    def parse_get_public_key_response(
            self, response: bytes,
            request_chaincode: bool) -> (bytes, str, bytes):
        # response = public_key_len (1) ||
        #            public_key (var) ||
        #            address_len (1) ||
        #            address (var) ||
        #            chain_code (32)
        offset: int = 0

        public_key_len: int = response[offset]
        offset += 1
        public_key: bytes = response[offset:offset + public_key_len]
        offset += public_key_len
        address_len: int = response[offset]
        offset += 1
        address: str = response[offset:offset + address_len].decode("ascii")
        offset += address_len
        if request_chaincode:
            chaincode: bytes = response[offset:offset + 32]
            offset += 32
        else:
            chaincode = None

        assert len(response) == offset
        assert len(public_key) == 65
        assert self.compute_address_from_public_key(public_key) == address

        return public_key, address, chaincode

    def send_get_public_key_non_confirm(self, derivation_path: str,
                                        request_chaincode: bool) -> RAPDU:
        p1 = P1.NON_CONFIRM
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        payload = pack_derivation_path(derivation_path)
        return self._client.exchange(CLA, InsType.GET_PUBLIC_KEY, p1, p2,
                                     payload)

    @contextmanager
    def send_async_get_public_key_confirm(
            self, derivation_path: str,
            request_chaincode: bool) -> Generator[None, None, None]:
        p1 = P1.CONFIRM
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        payload = pack_derivation_path(derivation_path)
        with self._client.exchange_async(CLA, InsType.GET_PUBLIC_KEY, p1, p2,
                                         payload):
            yield

    def unpackGetVersionResponse(self,
                                 response: bytes) -> Tuple[int, int, int]:
        assert (len(response) == GET_VERSION_RESP_LEN)
        major, minor, patch = unpack("BBB", response[1:])
        return major, minor, patch

    def sign(self,
             path: str,
             tx,
             signatures=[],
             snappath: Path = None,
             text: str = "",
             navigate: bool = True,
             warning_approve: bool = False,
             ins: InsType = InsType.SIGN,
             include_tx_len: bool = False):
        messages = []

        # Split transaction in multiples APDU
        tx_len = len(tx)
        data = pack_derivation_path(path)
        if ins == InsType.SIGN_EXTERNAL_PLUGIN:
            if include_tx_len:
                data += pack(">I", tx_len)
            max_first = MAX_APDU_LEN - len(data)
            assert (max_first >= 0)
            data += tx[:max_first]
            tx = tx[max_first:]
            messages.append(data)
            while len(tx) > 0:
                messages.append(tx[:MAX_APDU_LEN])
                tx = tx[MAX_APDU_LEN:]
            token_pos = len(messages)
        else:
            if include_tx_len:
                data += pack(">I", tx_len)
            while len(tx) > 0:
                # get next message field
                newpos = self.get_next_length(tx)
                assert (newpos < MAX_APDU_LEN)
                if (len(data) + newpos) < MAX_APDU_LEN:
                    # append to data
                    data += tx[:newpos]
                    tx = tx[newpos:]
                else:
                    # add chunk
                    messages.append(data)
                    data = bytearray()
                    continue
            # append last
            messages.append(data)
            token_pos = len(messages)

        for signature in signatures:
            messages.append(bytearray.fromhex(signature))

        # Send all the messages except the last
        for i, data in enumerate(messages[:-1]):
            if i == 0:
                p1 = P1.FIRST
            else:
                if i < token_pos:
                    p1 = P1.MORE
                else:
                    p1 = P1.TRC10_NAME | P1.FIRST | i - token_pos

            self._client.exchange(CLA, ins, p1, 0x00, data)

        # Send last message
        if len(messages) == 1:
            p1 = P1.SIGN
        elif signatures:
            p1 = P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE | len(
                signatures) - 1
        else:
            p1 = P1.LAST

        if navigate:
            with self._client.exchange_async(CLA, ins, p1, 0x00, messages[-1]):
                self.navigate(snappath, text, warning_approve)
            return self._client.last_async_response
        else:
            return self._client.exchange(CLA, ins, p1, 0x00, messages[-1])

    def sign_for_trusted_name(self,
                              bip32_path: str,
                              tx_params: dict,
                              snap_path: str,
                              text: str,
                              warning_approve: bool = False):
        tx = self.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(owner_address=bytes.fromhex(
                self.getAccount(0)['addressHex']),
                                      to_address=bytes.fromhex(
                                          ("41" + tx_params["to"].hex())),
                                      amount=tx_params["value"]))

        return self.sign(bip32_path,
                         tx,
                         text=text,
                         snappath=snap_path,
                         warning_approve=warning_approve)

    def response(self) -> Optional[RAPDU]:
        return self._client.last_async_response

    def get_public_addr(self,
                        display: bool = True,
                        chaincode: bool = False,
                        bip32_path: str = "m/44'/195'/0'/0/0",
                        chain_id: Optional[int] = None):
        cmd_builder = CommandBuilder()
        return self._client.exchange_async_raw(
            cmd_builder.get_public_addr(display, chaincode, bip32_path,
                                        chain_id))

    def personal_sign_full_display(self, path: str, msg: bytes):
        cmd_builder = CommandBuilder()
        chunks = cmd_builder.personal_sign_full_display(path, msg)
        for chunk in chunks[:-1]:
            self._client.exchange_raw(chunk)
        return self._client.exchange_async_raw(chunks[-1])

    def _provide_tlv(self, chunks: list) -> RAPDU:
        # Generic clear-signing descriptors (0x24/0x26/0x28) are streamed as a
        # chunked TLV payload; every chunk must return 0x9000.
        for chunk in chunks[:-1]:
            response = self._client.exchange_raw(chunk)
            assert response.status == StatusWord.OK
        response = self._client.exchange_raw(chunks[-1])
        assert response.status == StatusWord.OK
        return response

    def provide_enum_value(self, payload: bytes) -> RAPDU:
        self._pki_client.send_certificate(PKIPubKeyUsage.PUBKEY_USAGE_CALLDATA)
        return self._provide_tlv(CommandBuilder().provide_enum_value(payload))

    def provide_transaction_info(self, payload: bytes) -> RAPDU:
        self._pki_client.send_certificate(PKIPubKeyUsage.PUBKEY_USAGE_CALLDATA)
        return self._provide_tlv(
            CommandBuilder().provide_transaction_info(payload))

    def provide_transaction_field_desc(self, payload: bytes) -> RAPDU:
        return self._provide_tlv(
            CommandBuilder().provide_transaction_field_desc(payload))

    def provide_proxy_info(self, payload: bytes) -> RAPDU:
        # Send ledgerPKI certificate
        self._pki_client.send_certificate(
            PKIPubKeyUsage.PUBKEY_USAGE_TRUSTED_NAME)
        return self._provide_tlv(CommandBuilder().provide_proxy_info(payload))

    def provide_trusted_name(self, trusted_name: TrustedName) -> RAPDU:
        self._pki_client.send_certificate(
            PKIPubKeyUsage.PUBKEY_USAGE_TRUSTED_NAME,
            trusted_name.tn_source == TrustedNameSource.CAL)
        return self._provide_tlv(
            CommandBuilder().provide_trusted_name(trusted_name.serialize()))

    def provide_token_metadata(self,
                               ticker: str,
                               addr: bytes,
                               decimals: int,
                               chain_id: int,
                               sig: Optional[bytes] = None) -> RAPDU:
        cmd_builder = CommandBuilder()
        if len(addr) == 20:
            addr = bytes([TRON_MAINNET_ADDRESS_PREFIX]) + addr
        elif len(addr) != 21:
            raise ValueError("Token metadata address must be 20 or 21 bytes")

        if sig is None:
            # Send ledgerPKI certificate
            self._pki_client.send_certificate(
                PKIPubKeyUsage.PUBKEY_USAGE_COIN_META)
            # Temporarily get a command with an empty signature to extract the payload and
            # compute the signature on it
            tmp = cmd_builder.provide_trc20_token_information(ticker,
                                                              addr,
                                                              decimals,
                                                              chain_id,
                                                              bytes())
            # skip APDU header & empty sig
            sig = sign_data(Key.CAL, tmp[6:])

        response = self._client.exchange_raw(
            cmd_builder.provide_trc20_token_information(ticker,
                                                        addr,
                                                        decimals,
                                                        chain_id,
                                                        sig))
        assert response.status == StatusWord.OK
        return response

    def provide_nft_metadata(self,
                             collection: str,
                             addr: bytes,
                             chain_id: int,
                             type_: int = 1,
                             version: int = 1,
                             key_id: int = 1,
                             algo_id: int = 1,
                             sig: Optional[bytes] = None) -> RAPDU:
        cmd_builder = CommandBuilder()
        if len(addr) == 20:
            addr = bytes([TRON_MAINNET_ADDRESS_PREFIX]) + addr
        elif len(addr) != 21:
            raise ValueError("NFT metadata address must be 20 or 21 bytes")

        if sig is None:
            # Send ledgerPKI certificate
            self._pki_client.send_certificate(
                PKIPubKeyUsage.PUBKEY_USAGE_NFT_METADATA)

            # Temporarily get a command with an empty signature to extract the payload and
            # compute the signature on it
            tmp = cmd_builder.provide_nft_information(type_,
                                                      version,
                                                      collection,
                                                      addr,
                                                      chain_id,
                                                      key_id,
                                                      algo_id,
                                                      bytes())
            # skip APDU header & empty sig
            sig = sign_data(Key.NFT, tmp[5:-1])

        response = self._client.exchange_raw(
            cmd_builder.provide_nft_information(type_,
                                                version,
                                                collection,
                                                addr,
                                                chain_id,
                                                key_id,
                                                algo_id,
                                                sig))
        assert response.status == StatusWord.OK
        return response
