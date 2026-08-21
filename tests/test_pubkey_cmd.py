import pytest

from ragger.backend import SpeculosBackend
from ragger.backend.interface import RaisePolicy
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.navigator import NavInsID, NavIns

from tron import CLA, InsType, TronClient, Errors, ROOT_SCREENSHOT_PATH
from conftest import MNEMONIC

# Proposed TRX derivation paths for tests ###
TRX_PATH = "m/44'/195'/1'/0/0"
OTHER_TRX_PATH = "m/44'/195'/2'/0/0"


def check_get_public_key_resp(backend, path, public_key, chaincode):
    if isinstance(backend, SpeculosBackend):
        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(
            CurveChoice.Secp256k1, path, mnemonic=MNEMONIC)
        # Check against nominal Speculos seed expected results
        assert public_key.hex() == ref_public_key
        assert chaincode.hex() == ref_chain_code


class Test_GET_PUBLIC_KEY():

    def test_get_public_key_non_confirm(self, backend, firmware, navigator):
        client = TronClient(backend, firmware, navigator)

        rapdu = client.send_get_public_key_non_confirm(TRX_PATH, True)
        public_key, address, chaincode = client.parse_get_public_key_response(
            rapdu.data, True)
        check_get_public_key_resp(backend, TRX_PATH, public_key, chaincode)

        # Check that with NO_CHAINCODE, value stay the same
        rapdu = client.send_get_public_key_non_confirm(TRX_PATH, False)
        public_key_2, address_2, chaincode_2 = client.parse_get_public_key_response(
            rapdu.data, False)
        assert public_key_2 == public_key
        assert address_2 == address
        assert chaincode_2 is None

    def test_get_public_key_confirm_accepted(self, firmware, backend,
                                             navigator, test_name):
        client = TronClient(backend, firmware, navigator)
        with client.send_async_get_public_key_confirm(TRX_PATH, True):
            if firmware.is_nano:
                navigator.navigate_until_text_and_compare(
                    NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Approve",
                    ROOT_SCREENSHOT_PATH, test_name)
            else:
                instructions = [
                    NavInsID.SWIPE_CENTER_TO_LEFT,
                    NavIns(
                        NavInsID.TOUCH,
                        (100 if firmware.device.startswith("stax") else
                         100 if firmware.device.startswith("flex") else
                         65 if firmware.device.startswith("apex") else 100,
                         500 if firmware.device.startswith("stax") else
                         400 if firmware.device.startswith("flex") else
                         300 if firmware.device.startswith("apex") else 500)),
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name,
                                               instructions)

        response = client.get_async_response().data
        public_key, address, chaincode = client.parse_get_public_key_response(
            response, True)
        check_get_public_key_resp(backend, TRX_PATH, public_key, chaincode)

        # Check that with NO_CHAINCODE, value and screens stay the same
        with client.send_async_get_public_key_confirm(TRX_PATH, False):
            if firmware.is_nano:
                navigator.navigate_until_text_and_compare(
                    NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Approve",
                    ROOT_SCREENSHOT_PATH, test_name)
            else:
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name,
                                               instructions)
        response = client.get_async_response().data
        public_key_2, address_2, chaincode_2 = client.parse_get_public_key_response(
            response, False)
        assert public_key_2 == public_key
        assert address_2 == address
        assert chaincode_2 is None

    def test_pending_address_review_rejects_interleaved_apdus(
            self, firmware, backend, navigator):
        if not isinstance(backend, SpeculosBackend):
            pytest.skip("Concurrent APDU injection requires the Speculos backend")

        client = TronClient(backend, firmware, navigator)
        previous_raise_policy = backend.raise_policy
        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        try:
            with client.send_async_get_public_key_confirm(TRX_PATH, True):
                # A non-confirming request used to overwrite the public-key
                # context consumed by the pending approval callback. An
                # unrelated command exercises the same dispatcher boundary.
                blocked = client.send_get_public_key_non_confirm(
                    OTHER_TRX_PATH, True)
                assert blocked.status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED
                assert blocked.data == b""

                blocked = backend.exchange(CLA, InsType.GET_APP_CONFIGURATION,
                                           0x00, 0x00)
                assert blocked.status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED
                assert blocked.data == b""

                if firmware.is_nano:
                    navigator.navigate_until_text(
                        NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Approve")
                else:
                    navigator.navigate([
                        NavInsID.SWIPE_CENTER_TO_LEFT,
                        NavIns(
                            NavInsID.TOUCH,
                            (100 if firmware.device.startswith("stax") else
                             100 if firmware.device.startswith("flex") else
                             65 if firmware.device.startswith("apex") else 100,
                             500 if firmware.device.startswith("stax") else
                             400 if firmware.device.startswith("flex") else
                             300 if firmware.device.startswith("apex") else 500)),
                        NavInsID.USE_CASE_ADDRESS_CONFIRMATION_EXIT_QR,
                        NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                        NavInsID.USE_CASE_STATUS_DISMISS
                    ])

            # Speculos associates the fail-closed response with the oldest
            # outstanding exchange. No public-key response is emitted for the
            # attacked sequence, so substituted data cannot escape.
            response = client.get_async_response()
            assert response.status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED
            assert response.data == b""
        finally:
            backend.raise_policy = previous_raise_policy

        # The rejected sequence must not poison ordinary commands after the
        # review ends.
        response = client.send_get_public_key_non_confirm(TRX_PATH, True)
        public_key, _, chaincode = client.parse_get_public_key_response(
            response.data, True)
        check_get_public_key_resp(backend, TRX_PATH, public_key, chaincode)

    # In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
    def test_get_public_key_confirm_refused(self, firmware, backend, navigator,
                                            test_name):
        client = TronClient(backend, firmware, navigator)
        for chaincode_param in [True, False]:
            if firmware.is_nano:
                with client.send_async_get_public_key_confirm(
                        TRX_PATH, chaincode_param):
                    backend.raise_policy = RaisePolicy.RAISE_NOTHING
                    navigator.navigate_until_text_and_compare(
                        NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Cancel",
                        ROOT_SCREENSHOT_PATH, test_name)
                rapdu = client.get_async_response()
                assert rapdu.status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED
                assert len(rapdu.data) == 0
            else:
                instructions_set = [
                    [
                        NavInsID.USE_CASE_REVIEW_REJECT,
                        NavInsID.USE_CASE_STATUS_DISMISS
                    ],
                    [
                        NavInsID.SWIPE_CENTER_TO_LEFT,
                        NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL,
                        NavInsID.USE_CASE_STATUS_DISMISS
                    ]
                ]
                for i, instructions in enumerate(instructions_set):
                    for chaincode_param in [True, False]:
                        with client.send_async_get_public_key_confirm(
                                TRX_PATH, chaincode_param):
                            backend.raise_policy = RaisePolicy.RAISE_NOTHING
                            navigator.navigate_and_compare(
                                ROOT_SCREENSHOT_PATH, test_name + f"/part{i}",
                                instructions)
                        rapdu = client.get_async_response()
                        assert rapdu.status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED
                        assert len(rapdu.data) == 0
