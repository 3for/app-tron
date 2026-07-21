#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/ragger/test_trx.py
'''
from decimal import Decimal

import pytest
import sys
import struct
import re

from ragger.error import ExceptionRAPDU
from pathlib import Path
from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric import ec
from inspect import currentframe
from client.command_builder import CLA, MAX_APDU_LEN, InsType
from client.status_word import StatusWord
from tron import TronClient
from ragger.bip import pack_derivation_path
from utils import check_tx_signature, check_hash_signature, build_trc20_calldata

from ragger.navigator import NavInsID
from ragger.navigator.navigation_scenario import (NavigateWithScenario,
                                                 NavigationScenarioData,
                                                 UseCase)

from settings import settings_toggle, SettingID
'''
Tron Protobuf
'''
PROTO_PATH = str(Path(__file__).resolve().parents[2] / "proto")
if PROTO_PATH not in sys.path:
    sys.path.insert(0, PROTO_PATH)
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron


@pytest.mark.usefixtures('configuration')
class TestTRX():
    '''Test TRX client.'''

    NANO_TRANSACTION_SIGN_PATTERN = r"(?is)^sign( transaction.*)?$"
    NANO_MESSAGE_SIGN_PATTERN = r"(?is)^sign message$"

    @pytest.fixture(autouse=True)
    def setup_scenario(self, scenario_navigator: NavigateWithScenario):
        self.scenario_navigator = scenario_navigator

    def review_approve(self,
                       test_name: str,
                       warning: bool = False,
                       custom_screen_text=None,
                       warning_instruction=None,
                       do_comparison: bool = True):
        if not warning:
            self.scenario_navigator.review_approve(
                test_name=test_name,
                custom_screen_text=custom_screen_text,
                do_comparison=do_comparison)
            return

        if warning_instruction is not None:
            scenario = NavigationScenarioData(self.scenario_navigator.device,
                                              self.scenario_navigator.backend,
                                              UseCase.TX_REVIEW,
                                              True,
                                              nb_warnings=1)
            scenario.dismiss_warning = [warning_instruction]
            self.scenario_navigator._navigate_warning(scenario, test_name,
                                                      do_comparison, "warning")
            self.scenario_navigator._navigate_with_scenario(
                scenario, None, test_name, custom_screen_text, do_comparison)
            return

        self.scenario_navigator.review_approve_with_warning(
            test_name=test_name,
            custom_screen_text=custom_screen_text,
            do_comparison=do_comparison)

    def sign_and_validate(self,
                          client,
                          device,
                          text_index,
                          tx,
                          signatures=None,
                          warning_approve=False,
                          warning_instruction=None,
                          ins: InsType = InsType.SIGN,
                          include_tx_len: bool = False,
                          do_comparison: bool = True):
        path = Path(currentframe().f_back.f_code.co_name)
        if signatures is None:
            signatures = []
        custom_screen_text = self.NANO_TRANSACTION_SIGN_PATTERN if device.is_nano else None

        with client.sign_async(client.getAccount(0)['path'],
                               tx,
                               signatures=signatures,
                               ins=ins,
                               include_tx_len=include_tx_len):
            self.review_approve(str(path),
                                warning=warning_approve,
                                custom_screen_text=custom_screen_text,
                                warning_instruction=warning_instruction,
                                do_comparison=do_comparison)

        resp = client.response()
        assert check_tx_signature(tx, resp.data[0:65],
                                  client.getAccount(0)['publicKey'][2:])

    @staticmethod
    def make_witness_votes(count: int):
        return [
            contract.VoteWitnessContract.Vote(
                vote_address=b'\x41' + index.to_bytes(20, 'big'),
                vote_count=100)
            for index in range(1, count + 1)
        ]

    def test_trx_get_version(self, backend):
        client = TronClient(backend)
        resp = client.getVersion()
        major, minor, patch = client.unpackGetVersionResponse(resp.data)
        path = str(Path(__file__).parent.parent.parent.resolve()) + "/VERSION"
        version_file = open(path, "r").read()
        version = re.findall(r"(\d)\.(\d)\.(\d)", version_file)
        assert (major == int(version[0][0]))
        assert (minor == int(version[0][1]))
        assert (patch == int(version[0][2]))

    def test_trx_send(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_send_with_data_field(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000),
            b'CryptoChain-TronSR Ledger Transactions Tests')
        self.sign_and_validate(
            client,
            device,
            0,
            tx,
            warning_approve=True,
            warning_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM
            if device.touchable else None)

    def test_trx_send_display_hash(self, backend, device, navigator):
        # With the "Transaction hash" setting (app-ethereum's displayHash) enabled,
        # the review of a clear-signed transfer gains an extra "Transaction hash" field.
        client = TronClient(backend)
        settings_toggle(device, navigator, [SettingID.DISPLAY_HASH])
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_send_wrong_path(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000))
        path = Path(currentframe().f_code.co_name)
        with client.sign_async("m/44'/195'/1'/1/0", tx):
            self.review_approve(
                str(path),
                custom_screen_text=self.NANO_TRANSACTION_SIGN_PATTERN if device.is_nano else None)
        resp = client.response()
        assert not check_tx_signature(tx, resp.data[0:65],
                                      client.getAccount(0)['publicKey'][2:])

    def test_trx_send_asset_without_name(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name="1002000".encode()))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_send_asset_with_name(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx, tokenSignature)

    def test_trx_send_asset_with_name_wrong_signature(self, backend):
        client = TronClient(backend)
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
            client.sign_sync(client.getAccount(0)['path'], tx, tokenSignature)
        assert e.value.status == StatusWord.INVALID_DATA

    @pytest.mark.parametrize(
        "token_id",
        [
            b"10000000",  # 8 digits
            b"1000000000000000",  # 16 digits
            b"10000000000000000",  # 17 digits
            b"9223372036854775807",  # INT64_MAX
        ])
    def test_trx_send_asset_future_token_id(self, backend, device, token_id):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name=token_id))
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize(
        "token_id",
        [
            b"",
            b"_",
            b"0",
            b"01002000",
            b"10020A0",
            b"9223372036854775808",  # INT64_MAX + 1
            b"10000000000000000000",  # 20 digits
        ])
    def test_trx_send_asset_invalid_token_id(self, backend, token_id):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=1000000,
                asset_name=token_id))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_exchange_create(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        self.sign_and_validate(client, device, 1, tx)

    @pytest.mark.parametrize("exchange_contract", [
        "create",
        "inject",
        "withdraw",
        "transaction",
    ])
    def test_trx_exchange_max_token_id(self, backend, device,
                                       exchange_contract):
        client = TronClient(backend)
        owner_address = bytes.fromhex(client.getAccount(0)['addressHex'])
        token_id = b"9223372036854775807"

        if exchange_contract == "create":
            contract_type = tron.Transaction.Contract.ExchangeCreateContract
            message = contract.ExchangeCreateContract(
                owner_address=owner_address,
                first_token_id=b"_",
                first_token_balance=10000000000,
                second_token_id=token_id,
                second_token_balance=10000000)
        elif exchange_contract == "inject":
            contract_type = tron.Transaction.Contract.ExchangeInjectContract
            message = contract.ExchangeInjectContract(
                owner_address=owner_address,
                exchange_id=6,
                token_id=token_id,
                quant=10000000)
        elif exchange_contract == "withdraw":
            contract_type = tron.Transaction.Contract.ExchangeWithdrawContract
            message = contract.ExchangeWithdrawContract(
                owner_address=owner_address,
                exchange_id=6,
                token_id=token_id,
                quant=1000000)
        else:
            contract_type = tron.Transaction.Contract.ExchangeTransactionContract
            message = contract.ExchangeTransactionContract(
                owner_address=owner_address,
                exchange_id=6,
                token_id=token_id,
                quant=10000,
                expected=100)

        tx = client.packContract(contract_type, message)
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    def test_trx_exchange_create_with_token_name(self, backend, device):
        client = TronClient(backend)
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

        self.sign_and_validate(client, device, 1, tx, tokenSignature)

    def test_trx_exchange_inject(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx, exchangeSignature)

    def test_trx_exchange_inject_trx_with_name(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeInjectContract,
            contract.ExchangeInjectContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            exchange_id=6,
                                            token_id=b"_",
                                            quant=10000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client,
                               device,
                               0,
                               tx,
                               exchangeSignature,
                               do_comparison=False)

    def test_trx_exchange_withdraw(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx, exchangeSignature)

    def test_trx_exchange_transaction(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx, exchangeSignature)

    def test_trx_create_witness(self, backend, device):
        client = TronClient(backend)
        print(client.getAccount(0)['addressHex'])
        tx = client.packContract(
            tron.Transaction.Contract.WitnessCreateContract,
            contract.WitnessCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           url="http://sr-1t.com".encode()))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_create_witness_max_url(self, backend, device):
        # 256-byte url: the contract field exceeds one APDU, so the raw tx must be
        # split across multiple APDUs and reassembled by the firmware before signing.
        client = TronClient(backend)
        MAX_URL_LEN = 256
        prefix = "http://example.com/"
        url = (prefix + "a" * (MAX_URL_LEN - len(prefix))).encode()
        assert len(url) == MAX_URL_LEN
        tx = client.packContract(
            tron.Transaction.Contract.WitnessCreateContract,
            contract.WitnessCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           url=url))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_update_witness(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.WitnessUpdateContract,
            contract.WitnessUpdateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           update_url="http://sr-1t-updated.com".encode()))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_update_witness_empty_url(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.WitnessUpdateContract,
            contract.WitnessUpdateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex'])))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_vote_witness(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_vote_witness_max_count(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=self.make_witness_votes(30)))
        # Exercising all 30 review entries is the boundary assertion. Avoid
        # storing dozens of redundant screenshots for this navigation-only case.
        self.sign_and_validate(client,
                               device,
                               0,
                               tx,
                               do_comparison=False)

    def test_trx_vote_witness_more_than_30(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=self.make_witness_votes(31)))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_freeze_balance_bw(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.BANDWIDTH))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_freeze_balance_energy(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.ENERGY))

        self.sign_and_validate(client, device, 0, tx)

    def test_trx_freeze_balance_delegate_energy(self, backend, device):
        client = TronClient(backend)
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

        self.sign_and_validate(client, device, 0, tx)

    def test_trx_unfreeze_balance_bw(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.BANDWIDTH,
            ))

        self.sign_and_validate(client, device, 0, tx)

    def test_trx_unfreeze_balance_delegate_energy(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, device, 0, tx)

    def test_trx_withdraw_balance(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawBalanceContract,
            contract.WithdrawBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_create(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={
                                                1: 100000,
                                                2: 400000
                                            }))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_create_multi_apdu(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={
                                                0: 81000,
                                                1: 100000,
                                                2: 400000,
                                                3: 10,
                                                4: 1024,
                                                5: 16000000,
                                                6: 115200000000,
                                                7: 0,
                                                8: 1,
                                                9: 1,
                                                13: 400,
                                                22: 1000000,
                                                24: 0,
                                                29: 10000,
                                                33: 1000,
                                                45: 0,
                                                61: 100000,
                                                70: 365,
                                                82: 10000,
                                                92: 31536002999,
                                            }))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_create_empty_parameters(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={}))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_proposal_create_dynamic_parameter(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={
                                                27: 1,
                                                9: 2
                                            }))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_approve(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=10,
                                             is_add_approval=True))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_approve_remove(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=10,
                                             is_add_approval=False))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_approve_multi_apdu(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=10,
                                             is_add_approval=True),
            data=b"A" * 320)
        assert len(tx) > MAX_APDU_LEN
        self.sign_and_validate(
            client,
            device,
            0,
            tx,
            warning_approve=True,
            warning_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM
            if device.touchable else None)

    def test_trx_proposal_approve_invalid_proposal_id(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=0,
                                             is_add_approval=True))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_proposal_approve_invalid_owner_address(self, backend):
        client = TronClient(backend)
        owner_address = bytearray.fromhex(client.getAccount(0)['addressHex'])
        owner_address[0] = 0x42
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes(owner_address),
                                             proposal_id=10,
                                             is_add_approval=True))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_proposal_delete(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                proposal_id=10,
            ))

        self.sign_and_validate(client, device, 0, tx)

    def test_trx_proposal_delete_multi_apdu(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                proposal_id=10,
            ),
            data=b"A" * 320)
        assert len(tx) > MAX_APDU_LEN
        self.sign_and_validate(
            client,
            device,
            0,
            tx,
            warning_approve=True,
            warning_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM
            if device.touchable else None)

    def test_trx_proposal_delete_invalid_proposal_id(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                proposal_id=0,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_proposal_delete_invalid_owner_address(self, backend):
        client = TronClient(backend)
        owner_address = bytearray.fromhex(client.getAccount(0)['addressHex'])
        owner_address[0] = 0x42
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes(owner_address),
                proposal_id=10,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_account_create(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountCreateContract,
            contract.AccountCreateContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                account_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
                type=tron.Normal,
            ))
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize('account_type', [
        tron.AssetIssue,
        tron.Contract,
    ])
    def test_trx_account_create_valid_types(self, backend, device, account_type):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountCreateContract,
            contract.AccountCreateContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                account_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
                type=account_type,
            ))
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize(('field', 'invalid_address'), [
        ('owner_address', b'\x41' + b'\x00' * 19),
        ('owner_address', b'\x41' + b'\x00' * 21),
        ('owner_address', b'\x42' + b'\x00' * 20),
        ('account_address', b'\x41' + b'\x00' * 19),
        ('account_address', b'\x41' + b'\x00' * 21),
        ('account_address', b'\x42' + b'\x00' * 20),
    ])
    def test_trx_account_create_invalid_address(self,
                                                backend,
                                                field,
                                                invalid_address):
        client = TronClient(backend)
        addresses = {
            'owner_address': bytes.fromhex(
                client.getAccount(0)['addressHex']),
            'account_address': bytes.fromhex(
                client.getAccount(1)['addressHex']),
        }
        addresses[field] = invalid_address
        tx = client.packContract(
            tron.Transaction.Contract.AccountCreateContract,
            contract.AccountCreateContract(
                **addresses,
                type=tron.Normal,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_account_create_invalid_type(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountCreateContract,
            contract.AccountCreateContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                account_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
                type=3,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def asset_issue_contract(self, client, **overrides):
        values = {
            'owner_address': bytes.fromhex(client.getAccount(0)['addressHex']),
            'name': b'LedgerAsset',
            'abbr': b'LAS',
            'total_supply': 1_000_000,
            'frozen_supply': [
                contract.AssetIssueContract.FrozenSupply(
                    frozen_amount=100_000,
                    frozen_days=30,
                ),
            ],
            'trx_num': 1,
            'precision': 6,
            'num': 100,
            'start_time': 2_000_000_000_000,
            'end_time': 2_000_086_400_000,
            'order': 0,
            'vote_score': 1,
            'description': b'Ledger TRC10 asset',
            'url': b'https://ledger.com/trc10',
            'free_asset_net_limit': 1_000,
            'public_free_asset_net_limit': 10_000,
            'public_free_asset_net_usage': 0,
            'public_latest_free_net_time': 0,
        }
        values.update(overrides)
        return contract.AssetIssueContract(**values)

    def test_trx_asset_issue(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AssetIssueContract,
            self.asset_issue_contract(client),
        )
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_asset_issue_valid_boundaries(self, backend, device):
        client = TronClient(backend)
        frozen_supply = [
            contract.AssetIssueContract.FrozenSupply(
                frozen_amount=1,
                frozen_days=i + 1,
            ) for i in range(10)
        ]
        tx = client.packContract(
            tron.Transaction.Contract.AssetIssueContract,
            self.asset_issue_contract(
                client,
                name=b'n' * 32,
                abbr=b'a' * 32,
                total_supply=2**63 - 1,
                frozen_supply=frozen_supply,
                precision=0,
                order=2**63 - 1,
                vote_score=2**31 - 1,
                description=b'\x00' * 200,
                url=b'\xff' * 256,
                public_latest_free_net_time=2**63 - 1,
            ),
        )
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    def test_trx_asset_issue_empty_optional_metadata(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AssetIssueContract,
            self.asset_issue_contract(
                client,
                abbr=b'',
                frozen_supply=[],
                description=b'',
            ),
        )
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize('case', [
        'invalid_owner',
        'empty_name',
        'reserved_name',
        'invalid_name_character',
        'name_too_long',
        'invalid_abbreviation',
        'abbreviation_too_long',
        'zero_total_supply',
        'zero_trx_amount',
        'negative_precision',
        'precision_too_large',
        'zero_token_amount',
        'zero_start_time',
        'end_before_start',
        'empty_url',
        'description_too_long',
        'url_too_long',
        'negative_free_bandwidth',
        'negative_public_bandwidth',
        'nonzero_public_usage',
        'zero_frozen_amount',
        'zero_frozen_days',
        'frozen_supply_exceeds_total',
        'too_many_frozen_supplies',
        'preset_asset_id',
    ])
    def test_trx_asset_issue_invalid(self, backend, case):
        client = TronClient(backend)
        overrides = {}
        if case == 'invalid_owner':
            overrides['owner_address'] = b'\x42' + b'\x00' * 20
        elif case == 'empty_name':
            overrides['name'] = b''
        elif case == 'reserved_name':
            overrides['name'] = b'TrX'
        elif case == 'invalid_name_character':
            overrides['name'] = b'Invalid Name'
        elif case == 'name_too_long':
            overrides['name'] = b'n' * 33
        elif case == 'invalid_abbreviation':
            overrides['abbr'] = b'BAD ABBR'
        elif case == 'abbreviation_too_long':
            overrides['abbr'] = b'a' * 33
        elif case == 'zero_total_supply':
            overrides['total_supply'] = 0
        elif case == 'zero_trx_amount':
            overrides['trx_num'] = 0
        elif case == 'negative_precision':
            overrides['precision'] = -1
        elif case == 'precision_too_large':
            overrides['precision'] = 7
        elif case == 'zero_token_amount':
            overrides['num'] = 0
        elif case == 'zero_start_time':
            overrides['start_time'] = 0
        elif case == 'end_before_start':
            overrides['end_time'] = 2_000_000_000_000
        elif case == 'empty_url':
            overrides['url'] = b''
        elif case == 'description_too_long':
            overrides['description'] = b'd' * 201
        elif case == 'url_too_long':
            overrides['url'] = b'u' * 257
        elif case == 'negative_free_bandwidth':
            overrides['free_asset_net_limit'] = -1
        elif case == 'negative_public_bandwidth':
            overrides['public_free_asset_net_limit'] = -1
        elif case == 'nonzero_public_usage':
            overrides['public_free_asset_net_usage'] = 1
        elif case == 'zero_frozen_amount':
            overrides['frozen_supply'] = [
                contract.AssetIssueContract.FrozenSupply(
                    frozen_amount=0,
                    frozen_days=1,
                ),
            ]
        elif case == 'zero_frozen_days':
            overrides['frozen_supply'] = [
                contract.AssetIssueContract.FrozenSupply(
                    frozen_amount=1,
                    frozen_days=0,
                ),
            ]
        elif case == 'frozen_supply_exceeds_total':
            overrides['frozen_supply'] = [
                contract.AssetIssueContract.FrozenSupply(
                    frozen_amount=1_000_001,
                    frozen_days=1,
                ),
            ]
        elif case == 'too_many_frozen_supplies':
            overrides['frozen_supply'] = [
                contract.AssetIssueContract.FrozenSupply(
                    frozen_amount=1,
                    frozen_days=1,
                ) for _ in range(11)
            ]
        elif case == 'preset_asset_id':
            overrides['id'] = '1000001'

        tx = client.packContract(
            tron.Transaction.Contract.AssetIssueContract,
            self.asset_issue_contract(client, **overrides),
        )
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def participate_asset_issue_contract(self, client, **overrides):
        values = {
            'owner_address': bytes.fromhex(client.getAccount(0)['addressHex']),
            'to_address': bytes.fromhex(client.getAccount(1)['addressHex']),
            'asset_name': b'1000001',
            'amount': 1_000_000,
        }
        values.update(overrides)
        return contract.ParticipateAssetIssueContract(**values)

    def test_trx_participate_asset_issue(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ParticipateAssetIssueContract,
            self.participate_asset_issue_contract(client),
        )
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize(('asset_id', 'amount'), [
        (b'1', 1),
        (b'9223372036854775807', 2**63 - 1),
    ])
    def test_trx_participate_asset_issue_valid_boundaries(self,
                                                          backend,
                                                          device,
                                                          asset_id,
                                                          amount):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ParticipateAssetIssueContract,
            self.participate_asset_issue_contract(
                client,
                asset_name=asset_id,
                amount=amount,
            ),
        )
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize('case', [
        'invalid_owner',
        'invalid_issuer',
        'same_address',
        'zero_amount',
        'negative_amount',
        'empty_asset_id',
        'zero_asset_id',
        'leading_zero_asset_id',
        'nonnumeric_asset_id',
        'trx_alias',
        'asset_id_overflow',
        'asset_id_too_long',
    ])
    def test_trx_participate_asset_issue_invalid(self, backend, case):
        client = TronClient(backend)
        overrides = {}
        if case == 'invalid_owner':
            overrides['owner_address'] = b'\x42' + b'\x00' * 20
        elif case == 'invalid_issuer':
            overrides['to_address'] = b'\x42' + b'\x00' * 20
        elif case == 'same_address':
            overrides['to_address'] = bytes.fromhex(
                client.getAccount(0)['addressHex'])
        elif case == 'zero_amount':
            overrides['amount'] = 0
        elif case == 'negative_amount':
            overrides['amount'] = -1
        elif case == 'empty_asset_id':
            overrides['asset_name'] = b''
        elif case == 'zero_asset_id':
            overrides['asset_name'] = b'0'
        elif case == 'leading_zero_asset_id':
            overrides['asset_name'] = b'01000001'
        elif case == 'nonnumeric_asset_id':
            overrides['asset_name'] = b'TOKEN'
        elif case == 'trx_alias':
            overrides['asset_name'] = b'_'
        elif case == 'asset_id_overflow':
            overrides['asset_name'] = b'9223372036854775808'
        elif case == 'asset_id_too_long':
            overrides['asset_name'] = b'1' * 20

        tx = client.packContract(
            tron.Transaction.Contract.ParticipateAssetIssueContract,
            self.participate_asset_issue_contract(client, **overrides),
        )
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_unfreeze_asset(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeAssetContract,
            contract.UnfreezeAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ),
        )
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize('owner_address', [
        b'\x41' + b'\x00' * 19,
        b'\x41' + b'\x00' * 21,
        b'\x42' + b'\x00' * 20,
    ])
    def test_trx_unfreeze_asset_invalid_address(self,
                                                backend,
                                                owner_address):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeAssetContract,
            contract.UnfreezeAssetContract(owner_address=owner_address),
        )
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def update_asset_contract(self, client, **overrides):
        values = {
            'owner_address': bytes.fromhex(client.getAccount(0)['addressHex']),
            'description': b'Updated TRC10 asset',
            'url': b'https://ledger.com/updated-trc10',
            'new_limit': 1_000,
            'new_public_limit': 10_000,
        }
        values.update(overrides)
        return contract.UpdateAssetContract(**values)

    def test_trx_update_asset(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateAssetContract,
            self.update_asset_contract(client),
        )
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_update_asset_valid_boundaries(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateAssetContract,
            self.update_asset_contract(
                client,
                description=b'\x00' * 200,
                url=b'\xff' * 256,
                new_limit=0,
                new_public_limit=2**63 - 1,
            ),
        )
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize('case', [
        'invalid_owner',
        'empty_url',
        'description_too_long',
        'url_too_long',
        'negative_limit',
        'negative_public_limit',
    ])
    def test_trx_update_asset_invalid(self, backend, case):
        client = TronClient(backend)
        overrides = {}
        if case == 'invalid_owner':
            overrides['owner_address'] = b'\x42' + b'\x00' * 20
        elif case == 'empty_url':
            overrides['url'] = b''
        elif case == 'description_too_long':
            overrides['description'] = b'd' * 201
        elif case == 'url_too_long':
            overrides['url'] = b'u' * 257
        elif case == 'negative_limit':
            overrides['new_limit'] = -1
        elif case == 'negative_public_limit':
            overrides['new_public_limit'] = -1

        tx = client.packContract(
            tron.Transaction.Contract.UpdateAssetContract,
            self.update_asset_contract(client, **overrides),
        )
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_account_update(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'CryptoChainTest',
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_account_update_max_name(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'a' * 200,
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_account_update_empty_name(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'',
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_account_update_name_too_long(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'a' * 201,
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_set_account_id(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.SetAccountIdContract,
            contract.SetAccountIdContract(
                account_id=b'account1',
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_set_account_id_max_length(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.SetAccountIdContract,
            contract.SetAccountIdContract(
                account_id=b'a' * 32,
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize('account_id', [
        b'',
        b'a' * 7,
        b'a' * 33,
        b'validid ',
        b'validid\x7f',
    ])
    def test_trx_set_account_id_invalid(self, backend, account_id):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.SetAccountIdContract,
            contract.SetAccountIdContract(
                account_id=account_id,
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_set_account_id_invalid_owner_address(self, backend):
        client = TronClient(backend)
        owner_address = bytearray.fromhex(client.getAccount(0)['addressHex'])
        owner_address[0] = 0x42
        tx = client.packContract(
            tron.Transaction.Contract.SetAccountIdContract,
            contract.SetAccountIdContract(
                account_id=b'account1',
                owner_address=bytes(owner_address),
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_account_permission_update(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.AccountPermissionUpdateContract,
            contract.AccountPermissionUpdateContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                owner=tron.Permission(
                    type=tron.Permission.Owner,
                    permission_name="ownerA",
                    threshold=1,
                    keys=[
                        tron.Key(
                            address=bytes.fromhex(
                                client.getAccount(0)['addressHex']),
                            weight=1,
                        ),
                    ],
                ),
                witness=tron.Permission(
                    type=tron.Permission.Witness,
                    permission_name="witnessA",
                    threshold=1,
                    keys=[
                        tron.Key(
                            address=bytes.fromhex(
                                client.getAccount(0)['addressHex']),
                            weight=1,
                        ),
                    ],
                ),
                actives=[
                    tron.Permission(
                        type=tron.Permission.Active,
                        permission_name="activeA",
                        threshold=2,
                        operations=bytes.fromhex(
                            "7fff1fc0037e0000000000000000000000000000000000000000000000000000"
                        ),
                        keys=[
                            tron.Key(
                                address=bytes.fromhex(
                                    client.getAccount(0)['addressHex']),
                                weight=1,
                            ),
                            tron.Key(
                                address=bytes.fromhex(
                                    client.getAccount(1)['addressHex']),
                                weight=1,
                            ),
                        ],
                    )
                ],
            ))
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize("case", [
        "active_missing_operations",
        "owner_has_operations",
        "duplicate_active_key",
        "threshold_too_high",
    ])
    def test_trx_account_permission_update_rejects_invalid_permissions(
            self, backend, case):
        client = TronClient(backend)
        owner = tron.Permission(
            type=tron.Permission.Owner,
            permission_name="ownerA",
            threshold=1,
            keys=[
                tron.Key(
                    address=bytes.fromhex(client.getAccount(0)['addressHex']),
                    weight=1,
                ),
            ],
        )
        active_keys = [
            tron.Key(
                address=bytes.fromhex(client.getAccount(0)['addressHex']),
                weight=1,
            ),
            tron.Key(
                address=bytes.fromhex(client.getAccount(1)['addressHex']),
                weight=1,
            ),
        ]
        active = tron.Permission(
            type=tron.Permission.Active,
            permission_name="activeA",
            threshold=2,
            operations=bytes.fromhex(
                "7fff1fc0037e0000000000000000000000000000000000000000000000000000"
            ),
            keys=active_keys,
        )

        if case == "active_missing_operations":
            active.operations = b""
        elif case == "owner_has_operations":
            owner.operations = b"\x00" * 32
        elif case == "duplicate_active_key":
            active.keys[1].address = active.keys[0].address
        elif case == "threshold_too_high":
            active.threshold = 3

        tx = client.packContract(
            tron.Transaction.Contract.AccountPermissionUpdateContract,
            contract.AccountPermissionUpdateContract(
                owner_address=bytes.fromhex(client.getAccount(0)['addressHex']),
                owner=owner,
                actives=[active],
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_trc20_send(self, backend, device):
        client = TronClient(backend)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=tx_calldata))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_trc20_send_zero_amount(self, backend, device):
        client = TronClient(backend)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(0))
        print(tx_calldata)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")),
                data=tx_calldata))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_trc20_send_e20_amount(self, backend, device):
        client = TronClient(backend)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7",
            Decimal(3.1415 * 10**21))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")),
                data=tx_calldata))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_trc20_approve(self, backend, device):
        client = TronClient(backend)
        tx_calldata = build_trc20_calldata(
            "364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=tx_calldata))
        self.sign_and_validate(client, device, 0, tx)

    def create_smart_contract_tx(self,
                                 client,
                                 new_contract_overrides=None,
                                 outer_overrides=None,
                                 fee_limit=100_000_000,
                                 include_new_contract=True):
        owner = bytes.fromhex(client.getAccount(0)['addressHex'])
        new_contract_values = {
            'origin_address': owner,
            'bytecode': bytes.fromhex('608060405260008055600160005260206000f3'),
            'call_value': 1_000_000,
            'consume_user_resource_percent': 30,
            'name': 'LedgerContract',
            'origin_energy_limit': 10_000_000,
        }
        if new_contract_overrides:
            new_contract_values.update(new_contract_overrides)

        outer_values = {
            'owner_address': owner,
            'call_token_value': 123,
            'token_id': 1_000_001,
        }
        if outer_overrides:
            outer_values.update(outer_overrides)
        if include_new_contract:
            outer_values['new_contract'] = contract.SmartContract(
                **new_contract_values)

        return client.packContract(
            tron.Transaction.Contract.CreateSmartContract,
            contract.CreateSmartContract(**outer_values),
            fee_limit=fee_limit,
        )

    def test_trx_create_smart_contract(self, backend, device):
        client = TronClient(backend)
        tx = self.create_smart_contract_tx(client)
        self.sign_and_validate(client,
                               device,
                               0,
                               tx,
                               warning_approve=True)

    @pytest.mark.parametrize('case', ['minimum', 'maximum'])
    def test_trx_create_smart_contract_valid_boundaries(self,
                                                        backend,
                                                        device,
                                                        case):
        client = TronClient(backend)
        if case == 'minimum':
            tx = self.create_smart_contract_tx(
                client,
                new_contract_overrides={
                    'bytecode': b'',
                    'call_value': 0,
                    'consume_user_resource_percent': 0,
                    'name': '',
                    'origin_energy_limit': 1,
                },
                outer_overrides={
                    'call_token_value': 0,
                    'token_id': 0,
                },
                fee_limit=0,
            )
        else:
            tx = self.create_smart_contract_tx(
                client,
                new_contract_overrides={
                    'bytecode': b'\xff' * 3_000,
                    'call_value': 2**63 - 1,
                    'consume_user_resource_percent': 100,
                    'name': 'N' * 32,
                    'origin_energy_limit': 2**63 - 1,
                },
                outer_overrides={
                    'call_token_value': 2**63 - 1,
                    'token_id': 2**63 - 1,
                },
                fee_limit=2**63 - 1,
            )
        self.sign_and_validate(client,
                               device,
                               0,
                               tx,
                               warning_approve=True,
                               do_comparison=False)

    @pytest.mark.parametrize('case', [
        'invalid_owner',
        'invalid_origin',
        'origin_mismatch',
        'missing_new_contract',
        'preset_contract_address',
        'preset_code_hash',
        'preset_trx_hash',
        'preset_version',
        'name_too_long',
        'negative_call_value',
        'negative_resource_percent',
        'resource_percent_too_large',
        'zero_origin_energy_limit',
        'negative_origin_energy_limit',
        'negative_token_value',
        'negative_token_id',
        'token_id_too_small',
        'minimum_reserved_token_id',
        'token_value_without_id',
        'negative_fee_limit',
    ])
    def test_trx_create_smart_contract_invalid(self, backend, case):
        client = TronClient(backend)
        new_overrides = {}
        outer_overrides = {}
        fee_limit = 100_000_000
        include_new_contract = True

        if case == 'invalid_owner':
            outer_overrides['owner_address'] = b'\x42' + b'\x00' * 20
        elif case == 'invalid_origin':
            new_overrides['origin_address'] = b'\x42' + b'\x00' * 20
        elif case == 'origin_mismatch':
            new_overrides['origin_address'] = bytes.fromhex(
                client.getAccount(1)['addressHex'])
        elif case == 'missing_new_contract':
            include_new_contract = False
        elif case == 'preset_contract_address':
            new_overrides['contract_address'] = bytes.fromhex(
                client.getAccount(1)['addressHex'])
        elif case == 'preset_code_hash':
            new_overrides['code_hash'] = b'\x01' * 32
        elif case == 'preset_trx_hash':
            new_overrides['trx_hash'] = b'\x01' * 32
        elif case == 'preset_version':
            new_overrides['version'] = 1
        elif case == 'name_too_long':
            new_overrides['name'] = 'N' * 33
        elif case == 'negative_call_value':
            new_overrides['call_value'] = -1
        elif case == 'negative_resource_percent':
            new_overrides['consume_user_resource_percent'] = -1
        elif case == 'resource_percent_too_large':
            new_overrides['consume_user_resource_percent'] = 101
        elif case == 'zero_origin_energy_limit':
            new_overrides['origin_energy_limit'] = 0
        elif case == 'negative_origin_energy_limit':
            new_overrides['origin_energy_limit'] = -1
        elif case == 'negative_token_value':
            outer_overrides['call_token_value'] = -1
        elif case == 'negative_token_id':
            outer_overrides['token_id'] = -1
        elif case == 'token_id_too_small':
            outer_overrides['token_id'] = 1
        elif case == 'minimum_reserved_token_id':
            outer_overrides['token_id'] = 1_000_000
        elif case == 'token_value_without_id':
            outer_overrides['token_id'] = 0
        elif case == 'negative_fee_limit':
            fee_limit = -1

        tx = self.create_smart_contract_tx(
            client,
            new_contract_overrides=new_overrides,
            outer_overrides=outer_overrides,
            fee_limit=fee_limit,
            include_new_contract=include_new_contract,
        )
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_clear_abi(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.ClearABIContract,
            contract.ClearABIContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
            ))
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize(('field', 'invalid_address'), [
        ('owner_address', b'\x41' + b'\x00' * 19),
        ('owner_address', b'\x41' + b'\x00' * 21),
        ('owner_address', b'\x42' + b'\x00' * 20),
        ('contract_address', b'\x41' + b'\x00' * 19),
        ('contract_address', b'\x41' + b'\x00' * 21),
        ('contract_address', b'\x42' + b'\x00' * 20),
    ])
    def test_trx_clear_abi_invalid_address(self,
                                           backend,
                                           field,
                                           invalid_address):
        client = TronClient(backend)
        addresses = {
            'owner_address': bytes.fromhex(
                client.getAccount(0)['addressHex']),
            'contract_address': bytes.fromhex(
                client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
        }
        addresses[field] = invalid_address
        tx = client.packContract(
            tron.Transaction.Contract.ClearABIContract,
            contract.ClearABIContract(**addresses))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_update_setting(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateSettingContract,
            contract.UpdateSettingContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                consume_user_resource_percent=50,
            ))
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize('percent', [0, 100])
    def test_trx_update_setting_valid_boundaries(self,
                                                 backend,
                                                 device,
                                                 percent):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateSettingContract,
            contract.UpdateSettingContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                consume_user_resource_percent=percent,
            ))
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize('percent', [-1, 101])
    def test_trx_update_setting_invalid_percent(self, backend, percent):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateSettingContract,
            contract.UpdateSettingContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                consume_user_resource_percent=percent,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    @pytest.mark.parametrize(('field', 'invalid_address'), [
        ('owner_address', b'\x41' + b'\x00' * 19),
        ('owner_address', b'\x41' + b'\x00' * 21),
        ('owner_address', b'\x42' + b'\x00' * 20),
        ('contract_address', b'\x41' + b'\x00' * 19),
        ('contract_address', b'\x41' + b'\x00' * 21),
        ('contract_address', b'\x42' + b'\x00' * 20),
    ])
    def test_trx_update_setting_invalid_address(self,
                                                backend,
                                                field,
                                                invalid_address):
        client = TronClient(backend)
        addresses = {
            'owner_address': bytes.fromhex(
                client.getAccount(0)['addressHex']),
            'contract_address': bytes.fromhex(
                client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
        }
        addresses[field] = invalid_address
        tx = client.packContract(
            tron.Transaction.Contract.UpdateSettingContract,
            contract.UpdateSettingContract(
                **addresses,
                consume_user_resource_percent=50,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_update_energy_limit(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateEnergyLimitContract,
            contract.UpdateEnergyLimitContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                origin_energy_limit=10_000_000,
            ))
        self.sign_and_validate(client, device, 0, tx)

    @pytest.mark.parametrize('energy_limit', [1, 2**63 - 1])
    def test_trx_update_energy_limit_valid_boundaries(self,
                                                      backend,
                                                      device,
                                                      energy_limit):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateEnergyLimitContract,
            contract.UpdateEnergyLimitContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                origin_energy_limit=energy_limit,
            ))
        self.sign_and_validate(client, device, 0, tx, do_comparison=False)

    @pytest.mark.parametrize('energy_limit', [-1, 0])
    def test_trx_update_energy_limit_invalid_value(self,
                                                   backend,
                                                   energy_limit):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateEnergyLimitContract,
            contract.UpdateEnergyLimitContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                origin_energy_limit=energy_limit,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    @pytest.mark.parametrize(('field', 'invalid_address'), [
        ('owner_address', b'\x41' + b'\x00' * 19),
        ('owner_address', b'\x41' + b'\x00' * 21),
        ('owner_address', b'\x42' + b'\x00' * 20),
        ('contract_address', b'\x41' + b'\x00' * 19),
        ('contract_address', b'\x41' + b'\x00' * 21),
        ('contract_address', b'\x42' + b'\x00' * 20),
    ])
    def test_trx_update_energy_limit_invalid_address(self,
                                                     backend,
                                                     field,
                                                     invalid_address):
        client = TronClient(backend)
        addresses = {
            'owner_address': bytes.fromhex(
                client.getAccount(0)['addressHex']),
            'contract_address': bytes.fromhex(
                client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
        }
        addresses[field] = invalid_address
        tx = client.packContract(
            tron.Transaction.Contract.UpdateEnergyLimitContract,
            contract.UpdateEnergyLimitContract(
                **addresses,
                origin_energy_limit=10_000_000,
            ))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_sign_message(self, backend, device):
        client = TronClient(backend)
        # Magic define
        SIGN_MAGIC = b'\x19TRON Signed Message:\n'
        message = 'CryptoChain-TronSR Ledger Transactions Tests'.encode()
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += struct.pack(">I", len(message)) + message

        with backend.exchange_async(CLA, InsType.SIGN_PERSONAL_MESSAGE, 0x00,
                                    0x00, data):
            self.review_approve(
                currentframe().f_code.co_name,
                custom_screen_text=self.NANO_MESSAGE_SIGN_PATTERN if device.is_nano else None)

        resp = backend.last_async_response

        signedMessage = SIGN_MAGIC + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signedMessage)
        hash_to_sign = keccak_hash.digest()

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_sign_hash(self, backend, device):
        client = TronClient(backend)
        hash_to_sign = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                                     "101112131415161718191a1b1c1d1e1f")
        data = pack_derivation_path(client.getAccount(0)['path'])
        data += hash_to_sign

        with backend.exchange_async(CLA, InsType.SIGN_TXN_HASH, 0x00, 0x00,
                                    data):
            self.review_approve(
                currentframe().f_code.co_name,
                custom_screen_text=self.NANO_TRANSACTION_SIGN_PATTERN if device.is_nano else None)

        resp = backend.last_async_response

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])

    def test_trx_send_permissioned(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                amount=100000000), None, 2)
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_ecdh_key(self, backend, device):
        client = TronClient(backend)
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
            self.review_approve(
                currentframe().f_code.co_name,
                custom_screen_text=self.NANO_TRANSACTION_SIGN_PATTERN if device.is_nano else None)
        resp = backend.last_async_response

        # check if pair key matchs
        pubKeyDH = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pubKey)
        shared_key = client.getAccount(1)['dh'].exchange(ec.ECDH(), pubKeyDH)
        assert (shared_key.hex() == resp.data[1:33].hex())

    def test_trx_custom_contract(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
                data=bytes.fromhex('{:08x}{:064x}'.format(
                    0x0a857040, int(10001)))))
        self.sign_and_validate(client, device, 0, tx, warning_approve=True)

    def test_trx_unknown_trc20_send(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx, warning_approve=True)

    def test_trx_freezeV2_balance(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             frozen_balance=100000000,
                                             resource=contract.ENERGY))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_freezeV2_balance_multi_apdu(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             frozen_balance=100000000,
                                             resource=contract.BANDWIDTH),
            data=b"A" * 320)
        assert len(tx) > MAX_APDU_LEN
        self.sign_and_validate(
            client,
            device,
            0,
            tx,
            warning_approve=True,
            warning_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM
            if device.touchable else None)

    def test_trx_freezeV2_balance_invalid_owner_address(self, backend):
        client = TronClient(backend)
        owner_address = bytearray.fromhex(client.getAccount(0)['addressHex'])
        owner_address[0] = 0x42
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes(owner_address),
                                             frozen_balance=100000000,
                                             resource=contract.ENERGY))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_freezeV2_balance_invalid_amount(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             frozen_balance=999999,
                                             resource=contract.ENERGY))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_freezeV2_balance_invalid_resource(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceV2Contract,
            contract.FreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             frozen_balance=100000000,
                                             resource=3))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_unfreezeV2_balance(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                               unfreeze_balance=100000000,
                                               resource=contract.ENERGY))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_unfreezeV2_balance_multi_apdu(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                               unfreeze_balance=100000000,
                                               resource=contract.BANDWIDTH),
            data=b"A" * 320)
        assert len(tx) > MAX_APDU_LEN
        self.sign_and_validate(
            client,
            device,
            0,
            tx,
            warning_approve=True,
            warning_instruction=NavInsID.USE_CASE_CHOICE_CONFIRM
            if device.touchable else None)

    def test_trx_unfreezeV2_balance_invalid_owner_address(self, backend):
        client = TronClient(backend)
        owner_address = bytearray.fromhex(client.getAccount(0)['addressHex'])
        owner_address[0] = 0x42
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes(owner_address),
                                               unfreeze_balance=100000000,
                                               resource=contract.ENERGY))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_unfreezeV2_balance_invalid_amount(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                               unfreeze_balance=0,
                                               resource=contract.ENERGY))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_unfreezeV2_balance_invalid_resource(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceV2Contract,
            contract.UnfreezeBalanceV2Contract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                               unfreeze_balance=100000000,
                                               resource=3))

        with pytest.raises(ExceptionRAPDU) as e:
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_delegate_resource(self, backend, device):
        client = TronClient(backend)
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
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_delegate_resource_lock_without_period(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.DelegateResourceContract,
            contract.DelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
                lock=True))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_delegate_resource_lock_with_period(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.DelegateResourceContract,
            contract.DelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
                lock=True,
                lock_period=86400))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_undelegate_resource(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UnDelegateResourceContract,
            contract.UnDelegateResourceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                balance=100000000,
                receiver_address=bytes.fromhex(
                    client.address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"))))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_withdraw_unfreeze(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawExpireUnfreezeContract,
            contract.WithdrawExpireUnfreezeContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_cancel_all_unfreeze_v2(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.CancelAllUnfreezeV2Contract,
            contract.CancelAllUnfreezeV2Contract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_update_brokerage(self, backend, device):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateBrokerageContract,
            contract.UpdateBrokerageContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                brokerage=20))
        self.sign_and_validate(client, device, 0, tx)

    def test_trx_update_brokerage_out_of_range(self, backend):
        client = TronClient(backend)
        tx = client.packContract(
            tron.Transaction.Contract.UpdateBrokerageContract,
            contract.UpdateBrokerageContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                brokerage=101))
        with pytest.raises(ExceptionRAPDU) as e:
            client.sign_sync(client.getAccount(0)['path'], tx)
        assert e.value.status == StatusWord.INVALID_DATA

    def test_trx_sign_personal_message(self, backend, device):
        client = TronClient(backend)
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
                self.review_approve(
                    currentframe().f_code.co_name,
                    custom_screen_text=self.NANO_MESSAGE_SIGN_PATTERN if device.is_nano else None)

        resp = backend.last_async_response

        signedMessage = SIGN_MAGIC + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signedMessage)
        hash_to_sign = keccak_hash.digest()
        print(hash_to_sign)

        assert check_hash_signature(hash_to_sign, resp.data[0:65],
                                    client.getAccount(0)['publicKey'][2:])
