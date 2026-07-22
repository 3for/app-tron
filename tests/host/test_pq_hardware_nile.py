#!/usr/bin/env python3
"""Host-only unit tests for pq_hardware_nile.py (no device or network)."""

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "pq_hardware_nile.py"
SPEC = importlib.util.spec_from_file_location("pq_hardware_nile", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class HardwareNileHelpersTest(unittest.TestCase):
    def test_missing_chain_parameter_value_is_disabled(self):
        parameters = {"chainParameter": [{"key": "getAllowMlDsa44"}]}
        self.assertEqual(MODULE.chain_parameter_value(
            parameters, "getAllowMlDsa44"), 0)

    def test_enabled_chain_parameter(self):
        parameters = {
            "chainParameter": [{"key": "getAllowMlDsa44", "value": 1}]
        }
        self.assertEqual(MODULE.chain_parameter_value(
            parameters, "getAllowMlDsa44"), 1)

    def test_base58check_round_trip(self):
        address = bytes.fromhex("411111111111111111111111111111111111111111")
        encoded = MODULE.base58check_encode(address)
        self.assertEqual(MODULE.base58check_decode(encoded), address)

    def test_signed_transaction_wire_layout(self):
        raw = b"raw-data"
        public_key = b"p" * MODULE.PUBLIC_KEY_SIZE
        signature = b"s" * MODULE.SIGNATURE_SIZE
        transaction = MODULE.assemble_pq_transaction(raw, public_key, signature)
        pq_auth_sig = (
            MODULE.uint_field(1, MODULE.SCHEME_ML_DSA_44) +
            MODULE.bytes_field(2, public_key) +
            MODULE.bytes_field(3, signature))
        self.assertEqual(
            transaction,
            MODULE.bytes_field(1, raw) + MODULE.bytes_field(6, pq_auth_sig))

    def test_private_chain_funder_address(self):
        address, _ = MODULE.ecdsa_address_and_signer(
            "1234567890123456789012345678901234567890123456789012345678901234")
        self.assertEqual(MODULE.base58check_encode(address),
                         "TEDapYSVvAZ3aYH7w8N9tMEEFKaNKUD5Bp")


if __name__ == "__main__":
    unittest.main()
