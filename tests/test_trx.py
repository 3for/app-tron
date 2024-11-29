#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/test_trx.py
'''
import pytest
import sys
import struct
import re
import json
import fnmatch
import os

from functools import partial

from typing import Optional

from ragger.error import ExceptionRAPDU
from contextlib import contextmanager
from pathlib import Path
from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric import ec
from inspect import currentframe
from tron import TronClient, Errors, CLA, InsType, MAX_APDU_LEN
from ragger.bip import pack_derivation_path
from utils import check_tx_signature, check_hash_signature
from eth_keys import KeyAPI

from ragger.backend import BackendInterface
from ragger.firmware import Firmware
from ragger.navigator import Navigator, NavInsID, NavIns

from settings import NanoSettingID, NonNanoSettingID, settings_toggle, SettingID
from command_builder import CommandBuilder
import response_parser as ResponseParser
import InputData as InputData
from dataset import DataSet, ADVANCED_DATA_SETS, TOKENS, TRUSTED_NAMES, FILT_TN_TYPES
from utils import recover_message
from web3 import Web3
'''
Tron Protobuf
'''
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/proto")
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron

autonext_idx: int
snapshots_dirname: Optional[str] = None
WALLET_ADDR: Optional[bytes] = None
unfiltered_flow: bool = False
skip_flow: bool = False

def autonext(firmware, navigator, default_screenshot_path: Path):
    global autonext_idx
    moves = []
    if firmware.is_nano:
        moves = [NavInsID.RIGHT_CLICK]
    else:
        if autonext_idx == 0 and unfiltered_flow:
            moves = [NavInsID.USE_CASE_CHOICE_REJECT]
        else:
            if autonext_idx == 2 and skip_flow:
                InputData.disable_autonext()  # so the timer stops firing
                if firmware == Firmware.STAX:
                    skip_btn_pos = (355, 44)
                else:  # FLEX
                    skip_btn_pos = (420, 49)
                moves = [
                    # Ragger does not handle the skip button
                    NavIns(NavInsID.TOUCH, skip_btn_pos),
                    NavInsID.USE_CASE_CHOICE_CONFIRM,
                ]
            else:
                moves = [NavInsID.SWIPE_CENTER_TO_LEFT]
    if snapshots_dirname is not None:
        navigator.navigate_and_compare(
            default_screenshot_path,
            snapshots_dirname,
            moves,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=False,
            snap_start_idx=autonext_idx)
    else:
        navigator.navigate(moves,
                           screen_change_before_first_instruction=False,
                           screen_change_after_last_instruction=False)
    autonext_idx += len(moves)

def tip712_new_common(firmware, navigator, default_screenshot_path: Path,
                      client: TronClient, builder: CommandBuilder,
                      json_data: dict, filters, verbose: bool,
                      golden_run: bool,
                      extra_left: bool = False):
    global autonext_idx
    global unfiltered_flow
    global skip_flow
    global snapshots_dirname

    autonext_idx = 0
    default_screenshot_path = Path(__file__).parent.resolve()
    assert InputData.process_data(
        client, builder, json_data, filters,
        partial(autonext, firmware, navigator, default_screenshot_path),
        golden_run)

    with client.exchange_async_raw(
            builder.tip712_sign_new(client.getAccount(0)['path'])):
        moves = []
        if firmware.is_nano:
            # need to skip the message hash
            if not verbose and filters is None:
                moves += [NavInsID.RIGHT_CLICK] * 2
            moves += [NavInsID.BOTH_CLICK]
        else:
            if not skip_flow:
                # this move is necessary most of the times, but can't be 100% sure with the fields grouping
                moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
                # need to skip the message hash
                if not verbose and filters is None:
                    moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
            if extra_left:
                moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
            moves += [NavInsID.USE_CASE_REVIEW_CONFIRM]
        if snapshots_dirname is not None:
            # Could break (time-out) if given a JSON that requires less moves
            # TODO: Maybe take list of moves as input instead of trying to guess them ?
            navigator.navigate_and_compare(default_screenshot_path,
                                           snapshots_dirname,
                                           moves,
                                           snap_start_idx=autonext_idx)
        else:
            # Do them one-by-one to prevent an unnecessary move from timing-out and failing the test
            for move in moves:
                navigator.navigate(
                    [move],
                    screen_change_before_first_instruction=False,
                    screen_change_after_last_instruction=False)
    # reset values
    unfiltered_flow = False
    skip_flow = False
    snapshots_dirname = None

    return ResponseParser.signature(client._client.last_async_response.data)

def get_wallet_addr(client: TronClient) -> bytes:
    cmd_builder = CommandBuilder()
    global WALLET_ADDR
    # don't ask again if we already have it
    if WALLET_ADDR is None:
        with client.exchange_async_raw(
                cmd_builder.get_public_addr(
                    display=False,
                    chaincode=False,
                    bip32_path=client.getAccount(0)['path'],
                    chain_id=None)):
            pass
        _, WALLET_ADDR, _ = ResponseParser.pk_addr(
            client._client.last_async_response.data)
    return WALLET_ADDR[1:]

def tip712_json_path() -> str:
    return f"{os.path.dirname(__file__)}/tip712_input_files"


def input_files() -> list[str]:
    files = []
    for file in os.scandir(tip712_json_path()):
        if fnmatch.fnmatch(file, "*-data.json"):
            files.append(file.path)
    return sorted(files)
    # return ['/app/tests/tip712_input_files/01-addresses_array_mail-data.json']


@pytest.fixture(name="input_file", params=input_files())
def input_file_fixture(request) -> str:
    return Path(request.param)


@pytest.fixture(name="verbose", params=[True, False])
def verbose_fixture(request) -> bool:
    return request.param


@pytest.fixture(name="filtering", params=[False, True])
def filtering_fixture(request) -> bool:
    return request.param


@pytest.fixture(name="data_set", params=ADVANCED_DATA_SETS)
def data_set_fixture(request) -> DataSet:
    return request.param


@pytest.fixture(name="tokens", params=TOKENS)
def tokens_fixture(request) -> list[dict]:
    return request.param


@pytest.fixture(name="trusted_name", params=TRUSTED_NAMES)
def trusted_name_fixture(request) -> tuple:
    return request.param


@pytest.fixture(name="filt_tn_types", params=FILT_TN_TYPES)
def filt_tn_types_fixture(request) -> list[InputData.TrustedNameType]:
    return request.param

@pytest.mark.usefixtures('configuration')
class TestTRX():
    '''Test TRX client.'''

    def sign_and_validate(self,
                          client,
                          firmware,
                          text_index,
                          tx,
                          signatures=[],
                          warning_approve=False):
        path = Path(currentframe().f_back.f_code.co_name)
        text = None
        if firmware.is_nano:
            if text_index == 0:
                text = "Sign"
            elif text_index == 1:
                text = "Accept"
        else:
            if text_index == 0 or text_index == 1:
                text = "Hold to sign"
        assert text
        resp = client.sign(client.getAccount(0)['path'],
                           tx,
                           signatures=signatures,
                           snappath=path,
                           text=text,
                           warning_approve=warning_approve)
        assert check_tx_signature(tx, resp.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    def test_trx_get_version(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        resp = client.getVersion()
        major, minor, patch = client.unpackGetVersionResponse(resp.data)
        path = str(Path(__file__).parent.parent.resolve()) + "/VERSION"
        version_file = open(path, "r").read()
        version = re.findall(r"(\d)\.(\d)\.(\d)", version_file)
        assert (major == int(version[0][0]))
        assert (minor == int(version[0][1]))
        assert (patch == int(version[0][2]))

    @contextmanager
    def test_trx_send(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_send_with_data_field(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000),
            b'CryptoChain-TronSR Ledger Transactions Tests')
        self.sign_and_validate(client, firmware, 0, tx, warning_approve=True)

    def test_trx_send_wrong_path(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        if firmware.is_nano:
            text = "Sign"
        else:
            text = "Hold to sign"
        path = Path(currentframe().f_code.co_name)
        resp = client.sign("m/44'/195'/1'/1/0", tx, snappath=path, text=text)
        assert not check_tx_signature(tx, resp.data[0:65],
                                      client.getAccount(0)['publicKey'][2:])

    def test_trx_send_asset_without_name(self, backend, configuration,
                                         firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_send_asset_with_name(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        # BTT token ID 1002000 - 6 decimals
        tokenSignature = [
            "0a0a426974546f7272656e7410061a46304402202e2502f36b00e57be785fc79ec4043abcdd4fdd1b58d737ce123599dffad2cb602201702c307f009d014a553503b499591558b3634ceee4c054c61cedd8aca94c02b"
        ]
        self.sign_and_validate(client, firmware, 0, tx, tokenSignature)

    def test_trx_send_asset_with_name_wrong_signature(self, backend, firmware,
                                                      navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        # BTT token ID 1002000 - 6 decimals
        tokenSignature = [
            "0a0a4e6577416765436f696e10001a473045022100d8d73b4fad5200aa40b5cdbe369172b5c3259c10f1fb17dfb9c3fa6aa934ace702204e7ef9284969c74a0e80b7b7c17e027d671f3a9b3556c05269e15f7ce45986c8"
        ]
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'],
                        tx,
                        tokenSignature,
                        navigate=False)
        assert e.value.status == Errors.INCORRECT_DATA

    def test_trx_exchange_create(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        self.sign_and_validate(client, firmware, 1, tx)

    def test_trx_exchange_create_with_token_name(self, backend, configuration,
                                                 firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        tokenSignature = [
            "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c0a6371adcb6992db94487f66c7",
            "0a0b43727970746f436861696e10001a4730450221008417d04d1caeae31f591ae50f7d19e53e0dfb827bd51c18e66081941bf04639802203c73361a521c969e3fd7f62e62b46d61aad00e47d41e7da108546d954278a6b1"
        ]

        self.sign_and_validate(client, firmware, 1, tx, tokenSignature)

    def test_trx_exchange_inject(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeInjectContract,
            contract.ExchangeInjectContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            exchange_id=6,
                                            token_id="1000166".encode(),
                                            quant=10000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_exchange_withdraw(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeWithdrawContract,
            contract.ExchangeWithdrawContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                              exchange_id=6,
                                              token_id="1000166".encode(),
                                              quant=1000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_exchange_transaction(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeTransactionContract,
            contract.ExchangeTransactionContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                                 exchange_id=6,
                                                 token_id="1000166".encode(),
                                                 quant=10000,
                                                 expected=100))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_vote_witness(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TTcYhypP8m4phDhN6oRexz2174zAerjEWP")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9")),
                        vote_count=100),
                ]))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_vote_witness_more_than_5(self, backend, configuration,
                                          firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TTcYhypP8m4phDhN6oRexz2174zAerjEWP")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TSzoLaVCdSNDpNxgChcFt9rSRF5wWAZiR4")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TSNbzxac4WhxN91XvaUfPTKP2jNT18mP6T")),
                        vote_count=100),
                ]))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == Errors.INCORRECT_DATA

    def test_trx_freeze_balance_bw(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.BANDWIDTH))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_freeze_balance_energy(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.ENERGY))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_freeze_balance_delegate_energy(self, backend, configuration,
                                                firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                frozen_balance=10000000000,
                frozen_duration=3,
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreeze_balance_bw(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.BANDWIDTH,
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreeze_balance_delegate_energy(self, backend, configuration,
                                                  firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_withdraw_balance(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawBalanceContract,
            contract.WithdrawBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_create(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={
                                                1: 100000,
                                                2: 400000
                                            }))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_approve(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=10,
                                             is_add_approval=True))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_delete(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                proposal_id=10,
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_account_update(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'CryptoChainTest',
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_send(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=bytes.fromhex(
                    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_approve(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=bytes.fromhex(
                    "095ea7b3000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_sign_message(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        # Magic define
        SIGN_MAGIC = b'\x19TRON Signed Message:\n'
        message = 'CryptoChain-TronSR Ledger Transactions Tests'.encode()
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += struct.pack(">I", len(message)) + message

        with backend.exchange_async(CLA, InsType.SIGN_PERSONAL_MESSAGE, 0x00,
                                    0x00, data):
            if firmware.is_nano:
                text = "message"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        signedMessage = SIGN_MAGIC + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signedMessage)
        hash_to_sign = keccak_hash.digest()

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_sign_hash(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        hash_to_sign = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                     "101112131415161718191a1b1c1d1e1f")
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += hash_to_sign

        with backend.exchange_async(CLA, InsType.SIGN_TXN_HASH, 0x00, 0x00,
                                    data):
            if firmware.is_nano:
                text = "Sign"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_sign_tip712(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        domainHash = bytes.fromhex(
            '6137beb405d9ff777172aa879e33edb34a1460e701802746c5ef96e741710e59')
        messageHash = bytes.fromhex(
            'eb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8')
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += domainHash
        data += messageHash

        with backend.exchange_async(CLA, InsType.SIGN_TIP_712_MESSAGE, 0x00,
                                    0x00, data):
            if firmware.is_nano:
                text = "message"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        # Magic define
        SIGN_MAGIC = b'\x19\x01'
        msg_to_sign = SIGN_MAGIC + domainHash + messageHash
        hash = keccak.new(digest_bits=256, data=msg_to_sign).digest()

        assert check_hash_signature(hash, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_send_permissioned(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000), None, 2)
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_ecdh_key(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        # get ledger public key
        data = pack_derivation_path(client.getAccount(0)['path'])
        resp = backend.exchange(CLA, InsType.GET_PUBLIC_KEY, 0x00, 0x00, data)
        assert (resp.data[0] == 65)
        pubKey = bytes(resp.data[1:66])

        # get pair key
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += bytearray.fromhex(f"04{client.getAccount(1)['publicKey'][2:]}")
        with backend.exchange_async(CLA, InsType.GET_ECDH_SECRET, 0x00, 0x01,
                                    data):
            if firmware.is_nano:
                text = "Accept"
            else:
                text = "Hold to sign"
            client.navigate(Path(currentframe().f_code.co_name), text)
        resp = backend.last_async_response

        # check if pair key matchs
        pubKeyDH = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pubKey)
        shared_key = client.getAccount(1)['dh'].exchange(ec.ECDH(), pubKeyDH)
        assert (shared_key.hex() == resp.data[1:33].hex())

    def test_trx_custom_contract(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
                data=bytes.fromhex('{:08x}{:064x}'.format(
                    0x0a857040, int(10001)))))
        self.sign_and_validate(client, firmware, 0, tx, warning_approve=True)

    def test_trx_unknown_trc20_send(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TVGLX58e3uBx1fmmwLCENkrgKqmpEjhtfG")),
                data=bytes.fromhex(
                    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx, warning_approve=True)

    def test_trx_freezeV2_balance(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             frozen_balance=100000000,
                                             resource=contract.ENERGY))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreezeV2_balance(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                               unfreeze_balance=100000000,
                                               resource=contract.ENERGY))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_delegate_resource(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.DelegateResourceContract,
            contract.DelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
                lock=0))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_undelegate_resource(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnDelegateResourceContract,
            contract.UnDelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"))))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_withdraw_unfreeze(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawExpireUnfreezeContract,
            contract.WithdrawExpireUnfreezeContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_sign_personal_message(self, backend, firmware, navigator):
        if firmware.device == 'nanos':
            pytest.skip("Not supported on LNS")
        client = TronClient(backend, firmware, navigator)
        # Magic define
        SIGN_MAGIC = b'\x19TRON Signed Message:\n'
        message = ''
        for i in range(6):
            message += 'CryptoChain-TronSR Ledger Transactions Tests %d. ' % i
        message = message.encode()
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += struct.pack(">I", len(message)) + message

        chunk_cnt = (len(data) + MAX_APDU_LEN - 1) // MAX_APDU_LEN
        index = 0

        def gen_apdu(data, index):
            data_chunk = data[index * MAX_APDU_LEN:(index + 1) * MAX_APDU_LEN]
            return bytearray([
                CLA, InsType.SIGN_PERSONAL_MESSAGE_FULL_DISPLAY,
                0x00 if index == 0 else 0x80, 0x00
            ]) + data_chunk

        for _ in range(chunk_cnt - 1):
            apdu = gen_apdu(data, index)
            backend.exchange(apdu[0], apdu[1], apdu[2], apdu[3], apdu[4:])
            index += 1
        else:
            apdu = gen_apdu(data, index)
            with backend.exchange_async(apdu[0], apdu[1], apdu[2], apdu[3],
                                        apdu[4:]):
                if firmware.is_nano:
                    text = "message"
                else:
                    text = "Hold to sign"
                client.navigate(Path(currentframe().f_code.co_name), text)

        resp = backend.last_async_response

        signedMessage = SIGN_MAGIC + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signedMessage)
        hash_to_sign = keccak_hash.digest()
        print(hash_to_sign)

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_tip712_new(self, firmware: Firmware,
                            backend: BackendInterface, navigator: Navigator,
                            default_screenshot_path: Path, input_file: Path,
                            verbose: bool, filtering: bool, test_name: str):

        global unfiltered_flow
        # global snapshots_dirname
        # snapshots_dirname = 'test_trx_tip712_new'
        settings_to_toggle: list[SettingID] = []
        client = TronClient(backend, firmware, navigator)

        if firmware == Firmware.NANOS:
            pytest.skip("Not supported on LNS")

        test_path = f"{input_file.parent}/{'-'.join(input_file.stem.split('-')[:-1])}"
        cmd_builder = CommandBuilder()

        filters = None
        if filtering:
            try:
                filterfile = Path(f"{test_path}-filter.json")
                with open(filterfile, encoding="utf-8") as f:
                    filters = json.load(f)
            except (IOError, json.decoder.JSONDecodeError) as e:
                pytest.skip(f"{filterfile.name}: {e.strerror}")

            # Due to this option(FLOW_4 or HASH_TX_ID) has been enabled in conftest.py
            # So it is different with ethereum
            setting_id = NanoSettingID.FLOW_4 if firmware.is_nano else NonNanoSettingID.HASH_TX_ID
            settings_to_toggle.append(setting_id)
        else:
            pass

        if verbose:
            setting_id = NanoSettingID.VERBOSE_TIP712 if firmware.is_nano else NonNanoSettingID.VERBOSE_TIP712
            settings_to_toggle.append(setting_id)

        if not filters or verbose:
            unfiltered_flow = True
        if len(settings_to_toggle) > 0:
            settings_toggle(firmware, navigator, settings_to_toggle)

        with open(input_file, encoding="utf-8") as file:
            data = json.load(file)
            extra_left = test_path.endswith('01-addresses_array_mail') and verbose and filters is None
            vrs = tip712_new_common(firmware, navigator,
                                    default_screenshot_path, client,
                                    cmd_builder, data, filters, verbose, False,
                                    extra_left = extra_left)
            recovered_addr = recover_message(data, vrs)

        assert recovered_addr == get_wallet_addr(client)
        if len(settings_to_toggle) > 0:
            settings_toggle(firmware, navigator, settings_to_toggle)


    def test_trx_tip712_advanced_filtering(self, firmware: Firmware,
                                           backend: BackendInterface,
                                           navigator: Navigator,
                                           default_screenshot_path: Path,
                                           test_name: str, data_set: DataSet,
                                           golden_run: bool):
        global snapshots_dirname

        client = TronClient(backend, firmware, navigator)
        if firmware == Firmware.NANOS:
            pytest.skip("Not supported on LNS")
        cmd_builder = CommandBuilder()
        snapshots_dirname = test_name + data_set.suffix

        vrs = tip712_new_common(firmware, navigator, default_screenshot_path,
                                client, cmd_builder, data_set.data,
                                data_set.filters, False, golden_run)
        recovered_addr = recover_message(data_set.data, vrs)
        assert client.getAccount(
            0)['addressHex'][2:] == recovered_addr.hex().upper()

        assert recovered_addr == get_wallet_addr(client)

    def test_trx_tip712_filtering_empty_array(self, firmware: Firmware,
                                              backend: BackendInterface,
                                              navigator: Navigator,
                                              default_screenshot_path: Path,
                                              test_name: str,
                                              golden_run: bool):
        global snapshots_dirname

        client = TronClient(backend, firmware, navigator)
        if firmware == Firmware.NANOS:
            pytest.skip("Not supported on LNS")

        snapshots_dirname = test_name
        from dataset import filtering_empty_array_test_data
        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(firmware,
                                navigator,
                                default_screenshot_path,
                                client,
                                cmd_builder,
                                filtering_empty_array_test_data['data'],
                                filtering_empty_array_test_data['filters'],
                                False,
                                golden_run)

        # verify signature
        addr = recover_message(filtering_empty_array_test_data['data'], vrs)
        assert addr == get_wallet_addr(client)

    def test_trx_tip712_advanced_missing_token(self, firmware: Firmware,
                                               backend: BackendInterface,
                                               navigator: Navigator,
                                               default_screenshot_path: Path,
                                               test_name: str,
                                               tokens: list[dict],
                                               golden_run: bool):
        global snapshots_dirname

        test_name += "-%s-%s" % (len(tokens[0]) == 0, len(tokens[1]) == 0)
        snapshots_dirname = test_name

        client = TronClient(backend, firmware, navigator)
        if firmware == Firmware.NANOS:
            pytest.skip("Not supported on LNS")

        from dataset import advanced_missing_token_test_data
        advanced_missing_token_test_data['filters']['tokens'] = tokens
        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(firmware,
                                navigator,
                                default_screenshot_path,
                                client,
                                cmd_builder,
                                advanced_missing_token_test_data['data'],
                                advanced_missing_token_test_data['filters'],
                                False,
                                golden_run)

        # verify signature
        addr = recover_message(advanced_missing_token_test_data['data'], vrs)
        assert addr == get_wallet_addr(client)


    def test_trx_tip712_advanced_trusted_name(self,
                                              firmware: Firmware,
                                              backend: BackendInterface,
                                              navigator: Navigator,
                                              default_screenshot_path: Path,
                                              test_name: str,
                                              trusted_name: tuple,
                                              filt_tn_types: list[InputData.TrustedNameType],
                                              golden_run: bool):
        global snapshots_dirname
        test_name += "_%s_with" % (str(trusted_name[0]).split(".")[-1].lower())
        for t in filt_tn_types:
            test_name += "_%s" % (str(t).split(".")[-1].lower())
        snapshots_dirname = test_name

        client = TronClient(backend, firmware, navigator)
        if firmware == Firmware.NANOS:
            pytest.skip("Not supported on LNS")

        cmd_builder = CommandBuilder()
        if trusted_name[0] is InputData.TrustedNameType.ACCOUNT:
            challenge = ResponseParser.challenge(client.exchange_raw(cmd_builder.get_challenge()).data)
        else:
            challenge = None

        from dataset import advanced_trusted_name_test_data
        advanced_trusted_name_test_data['filters']['fields']['validator']['tn_type'] = filt_tn_types
        print(advanced_trusted_name_test_data)
        InputData.provide_trusted_name_v2(client,
                                          cmd_builder,
                                          bytes.fromhex(advanced_trusted_name_test_data['data']["message"]["validator"][2:]),
                                        trusted_name[2],
                                        trusted_name[0],
                                        trusted_name[1],
                                        advanced_trusted_name_test_data['data']["domain"]["chainId"],
                                        challenge=challenge)

        vrs = tip712_new_common(firmware,
                                navigator,
                                default_screenshot_path,
                                client,
                                cmd_builder,
                                advanced_trusted_name_test_data['data'],
                                advanced_trusted_name_test_data['filters'],
                                False,
                                golden_run)

        # verify signature
        addr = recover_message(advanced_trusted_name_test_data['data'], vrs)
        assert addr == get_wallet_addr(client)


    def test_trx_tip712_bs_not_activated_error(self, firmware: Firmware,
                                               backend: BackendInterface,
                                               navigator: Navigator,
                                               default_screenshot_path: Path):
        client = TronClient(backend, firmware, navigator)
        if firmware == Firmware.NANOS:
            pytest.skip("Not supported on LNS")
        setting_id = NanoSettingID.FLOW_4 if firmware.is_nano else NonNanoSettingID.HASH_TX_ID
        settings_toggle(firmware, navigator, [setting_id])
        cmd_builder = CommandBuilder()
        with pytest.raises(ExceptionRAPDU) as e:
            tip712_new_common(firmware,
                              navigator,
                              default_screenshot_path,
                              client,
                              cmd_builder,
                              ADVANCED_DATA_SETS[0].data,
                              None,
                              False,
                              False)
        InputData.disable_autonext()  # so the timer stops firing
        assert e.value.status == InputData.StatusWord.INVALID_DATA

        if firmware.is_nano:
            navigator.navigate([NavInsID.BOTH_CLICK], screen_change_before_first_instruction=True)
        elif firmware == Firmware.STAX:
            navigator.navigate([NavIns(NavInsID.TOUCH, (100, 620))], screen_change_before_first_instruction=True)
        elif firmware == Firmware.FLEX:
            navigator.navigate([NavIns(NavInsID.TOUCH, (130, 550))], screen_change_before_first_instruction=True)
        settings_toggle(firmware, navigator, [setting_id])

    def test_trx_tip712_skip(self, firmware: Firmware,
                             backend: BackendInterface,
                             navigator: Navigator,
                             default_screenshot_path: Path,
                             test_name: str,
                             golden_run: bool):
        global unfiltered_flow
        global skip_flow

        client = TronClient(backend, firmware, navigator)
        if firmware.is_nano:
            pytest.skip("Not supported on Nano devices")

        unfiltered_flow = True
        skip_flow = True

        with open(input_files()[0], encoding="utf-8") as file:
            data = json.load(file)

        cmd_builder = CommandBuilder()
        vrs = tip712_new_common(firmware,
                                navigator,
                                default_screenshot_path,
                                client,
                                cmd_builder,
                                data,
                                None,
                                False,
                                golden_run)

        # verify signature
        addr = recover_message(data, vrs)
        assert addr == get_wallet_addr(client)