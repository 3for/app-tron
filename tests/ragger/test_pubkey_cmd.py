from ragger.backend import SpeculosBackend
from ragger.backend.interface import RaisePolicy
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice

from client.status_word import StatusWord
from tron import TronClient
from conftest import MNEMONIC

# Proposed TRX derivation paths for tests ###
TRX_PATH = "m/44'/195'/1'/0/0"


def check_get_public_key_resp(backend, path, public_key, chaincode):
    if isinstance(backend, SpeculosBackend):
        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(
            CurveChoice.Secp256k1, path, mnemonic=MNEMONIC)
        # Check against nominal Speculos seed expected results
        assert public_key.hex() == ref_public_key
        assert chaincode.hex() == ref_chain_code


class Test_GET_PUBLIC_KEY():

    def test_get_public_key_non_confirm(self, backend, device, navigator):
        client = TronClient(backend)

        with client.get_public_addr(display=False,
                                    chaincode=True,
                                    bip32_path=TRX_PATH):
            pass
        rapdu = client.response()
        public_key, address, chaincode = client.parse_get_public_key_response(
            rapdu.data, True)
        check_get_public_key_resp(backend, TRX_PATH, public_key, chaincode)

        # Check that with NO_CHAINCODE, value stay the same
        with client.get_public_addr(display=False,
                                    chaincode=False,
                                    bip32_path=TRX_PATH):
            pass
        rapdu = client.response()
        public_key_2, address_2, chaincode_2 = client.parse_get_public_key_response(
            rapdu.data, False)
        assert public_key_2 == public_key
        assert address_2 == address
        assert chaincode_2 is None

    def test_get_public_key_confirm_accepted(self, scenario_navigator,
                                             test_name):
        backend = scenario_navigator.backend
        client = TronClient(backend)

        with client.get_public_addr(display=True,
                                    chaincode=True,
                                    bip32_path=TRX_PATH):
            scenario_navigator.address_review_approve(test_name=test_name)

        response = client.response().data
        public_key, address, chaincode = client.parse_get_public_key_response(
            response, True)
        check_get_public_key_resp(backend, TRX_PATH, public_key, chaincode)

        # Check that with NO_CHAINCODE, value and screens stay the same
        with client.get_public_addr(display=True,
                                    chaincode=False,
                                    bip32_path=TRX_PATH):
            scenario_navigator.address_review_approve(test_name=test_name)
        response = client.response().data
        public_key_2, address_2, chaincode_2 = client.parse_get_public_key_response(
            response, False)
        assert public_key_2 == public_key
        assert address_2 == address
        assert chaincode_2 is None

    # In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
    def test_get_public_key_confirm_refused(self, scenario_navigator,
                                            test_name):
        backend = scenario_navigator.backend
        client = TronClient(backend)

        for chaincode_param in [True, False]:
            with client.get_public_addr(display=True,
                                        chaincode=chaincode_param,
                                        bip32_path=TRX_PATH):
                backend.raise_policy = RaisePolicy.RAISE_NOTHING
                scenario_navigator.address_review_reject()
            rapdu = client.response()
            assert rapdu.status == StatusWord.CONDITION_NOT_SATISFIED
            assert len(rapdu.data) == 0
