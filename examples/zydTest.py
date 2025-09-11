#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

# `pip3 install tron-sdk-py` to make sure tron-sdk-py is installed
# `pip3 install --upgrade protobuf` to fix `cannot import name 'runtime_version' from 'google.protobuf'`
# `python3 runTest.py`
sys.path.append("./examples/proto")

from pprint import pprint
import logging
import time
from pathlib import Path
from ledgerblue.comm import getDongle
import argparse
from base import parse_bip32_path

import validateSignature
import binascii
import base58

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def apduMessage(INS, P1, P2, PATH, MESSAGE):
    hexString = ""
    if PATH:
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{:02x}{}".format(
            INS, P1, P2, (len(PATH) + len(MESSAGE)) // 2 + 1,
            len(PATH) // 4 // 2, PATH + MESSAGE)
    else:
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{}".format(
            INS, P1, P2,
            len(MESSAGE) // 2, MESSAGE)
    print(hexString)
    return bytearray.fromhex(hexString)


def ledgerSign(PATH, tx, tokenSignature=[]):
    raw_tx = tx.raw_data.SerializeToString().hex()
    print("tx info: " + raw_tx)
    print("tx len: " + str(len(raw_tx)))
    # Sign in chunks
    chunkList = list(chunks(raw_tx, 410))
    if len(tokenSignature) > 0:
        chunkList.extend(tokenSignature)
    assert len(chunkList) > 0
    # P1 = P1_FIRST = 0x00
    if len(chunkList) > 1:
        result = dongle.exchange(
            apduMessage(0x04, 0x00, 0x00, PATH, chunkList[0]))
    else:
        result = dongle.exchange(
            apduMessage(0x04, 0x10, 0x00, PATH, chunkList[0]))

    for i in range(1, len(chunkList) - 1 - len(tokenSignature)):
        # P1 = P1_MORE = 0x80
        result = dongle.exchange(
            apduMessage(0x04, 0x80, 0x00, None, chunkList[i]))

    for i in range(0, len(tokenSignature) - 1):
        result = dongle.exchange(
            apduMessage(0x04, 0xA0 | (0x00 + i), 0x00, None,
                        tokenSignature[i]))

    # P1 = P1_LAST = 0x90
    if len(chunkList) > 1:
        if len(tokenSignature) > 0:
            result = dongle.exchange(
                apduMessage(0x04,
                            0xA0 | 0x08 | (0x00 + len(tokenSignature) - 1),
                            0x00, None, chunkList[len(chunkList) - 1]))
        else:
            result = dongle.exchange(
                apduMessage(0x04, 0x90, 0x00, None,
                            chunkList[len(chunkList) - 1]))

    return raw_tx, result


def address_hex(address):
    return base58.b58decode_check(address).hex().upper()


accounts = [{
    "path": parse_bip32_path("44'/195'/0'/0/0"),
}, {
    "path": parse_bip32_path("44'/195'/1'/0/0"),
}]

# Get Addresses
logger.debug('-= Tron Ledger =-')
logger.debug('Requesting Public Keys...')
dongle = getDongle(True)
for i in range(2):
    result = dongle.exchange(
        apduMessage(0x02, 0x00, 0x00, accounts[i]['path'], ""))
    size = result[0]
    if size == 65:
        accounts[i]['publicKey'] = result[1:1 + size].hex()
        size = result[size + 1]
        if size == 34:
            accounts[i]['address'] = result[67:67 + size].decode()
            accounts[i]['addressHex'] = address_hex(accounts[i]['address'])
        else:
            logger.error('Error... Address Size: {:d}'.format(size))
    else:
        logger.error('Error... Public Key Size: {:d}'.format(size))

logger.debug('Test Accounts:')
for i in range(2):
    logger.debug('- Public Key {}: {}'.format(i, accounts[i]['publicKey']))
    logger.debug('- Address {}: {}'.format(i, accounts[i]['address']))
'''
Tron Protobuf
'''
from tron_sdk_py.proto.core.contract import balance_contract_pb2 as balance_contract
from tron_sdk_py.proto.core.contract import asset_issue_contract_pb2 as asset_issue_contract
from tron_sdk_py.proto.core.contract import exchange_contract_pb2 as exchange_contract
from tron_sdk_py.proto.core.contract import witness_contract_pb2 as witness_contract
from tron_sdk_py.proto.core.contract import proposal_contract_pb2 as proposal_contract
from tron_sdk_py.proto.core.contract import account_contract_pb2 as account_contract
from tron_sdk_py.proto.core.contract import smart_contract_pb2 as smart_contract
from tron_sdk_py.proto.core.contract import common_pb2 as common
from tron_sdk_py.proto.api import api_pb2 as api
from tron_sdk_py.proto.api.api_pb2_grpc import WalletStub
from tron_sdk_py.proto.core import Tron_pb2 as tron
from google.protobuf.any_pb2 import Any
import grpc

# Start Channel and WalletStub
channel = grpc.insecure_channel("grpc.nile.trongrid.io:50051")
stub = WalletStub(channel)

logger.debug('''
   Tron Transactions tests
''')

#####################
# Apply SR Candidate # 
#####################
logger.debug('\n\nApply SR Candidate:')

tx = stub.CreateWitness(
    witness_contract.WitnessCreateContract(
        owner_address=bytes.fromhex(accounts[0]['addressHex']),
        url="http://sr-mia.com".encode()
    ))

print(tx)
raw_tx, result = ledgerSign(accounts[0]['path'], tx)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[0]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx)
