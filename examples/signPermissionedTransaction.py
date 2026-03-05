#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from pathlib import Path

# `./buildproto.sh` to generate local python protobuf files
sys.path.append(str(Path(__file__).resolve().parent / "proto"))

from pprint import pprint
import logging
import time

from ledgerblue.comm import getDongle
import argparse
from base import parse_bip32_path
from google.protobuf.internal.decoder import _DecodeVarint32

import validateSignature
import binascii
import base58

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Start Ledger
dongle = getDongle(True)


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

MAX_APDU_LEN: int = 255

def get_next_length(tx):
        field, pos = _DecodeVarint32(tx, 0)
        size, newpos = _DecodeVarint32(tx, pos)
        if (field & 0x07 == 0):
            return newpos
        return size + newpos


def ledgerSignWithAutoSplit(PATH, tx, tokenSignatures=[]):
        messages = []
        raw_tx = tx.raw_data.SerializeToString().hex()
        tx_data = bytearray.fromhex(raw_tx)

        # Split transaction in multiples APDU
        path_len = "{:02x}".format(len(PATH) // 4 // 2)
        data = bytearray.fromhex(path_len) + bytearray.fromhex(PATH)
        print(PATH)
        print(data)
        while len(tx_data) > 0:
            # get next message field
            newpos = get_next_length(tx_data)
            assert (newpos < MAX_APDU_LEN)
            if (len(data) + newpos) < MAX_APDU_LEN:
                # append to data
                data += tx_data[:newpos]
                tx_data = tx_data[newpos:]
            else:
                # add chunk
                messages.append(data)
                data = bytearray()
                continue
        # append last
        messages.append(data)
        token_pos = len(messages)

        for tokenSignature in tokenSignatures:
            messages.append(bytearray.fromhex(tokenSignature))

        # Send all the messages except the last
        for i, data in enumerate(messages[:-1]):
            if i == 0:
                # P1 = P1_FIRST = 0x00
                p1 = 0x00
            else:
                if i < token_pos:
                    # P1 = P1_MORE = 0x80
                    p1 = 0x80
                else:
                    # P1_TRC10_NAME = 0xa0
                    p1 = 0xa0 | 0x00 | i - token_pos

            result = dongle.exchange(apduMessage(0x04, p1, 0x00, None, binascii.hexlify(data).decode()))

        # Send last message
        if len(messages) == 1:
            # P1 = P1_SIGN = 0x10
            p1 = 0x10
        elif tokenSignatures:
            # SIGN_PERSONAL_MESSAGE = 0x08
            # P1_TRC10_NAME = 0xa0
            p1 = 0xa0 | 0x08 | len(
                tokenSignatures) - 1
        else:
            # P1 = P1_LAST = 0x90
            p1 = 0x90

        result = dongle.exchange(apduMessage(0x04, p1, 0x00, None, binascii.hexlify(messages[-1]).decode()))
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

logger.debug('-= Tron Ledger =-')
'''
Tron Protobuf
'''
from core.contract import balance_contract_pb2 as balance_contract
from core.contract import account_contract_pb2 as account_contract
from core import Tron_pb2 as tron
from api.api_pb2_grpc import WalletStub
import grpc

# Start Channel and WalletStub
channel = grpc.insecure_channel("grpc.nile.trongrid.io:50051")
stub = WalletStub(channel)

logger.debug('''
   Tron Update Account Permission tests
''')

tx=stub.AccountPermissionUpdate(
    account_contract.AccountPermissionUpdateContract(
        owner_address=bytes.fromhex(
            accounts[0]['addressHex']),
        owner=tron.Permission(
            type=tron.Permission.Owner,
            permission_name="ownerA",
            threshold=1,
            keys=[
                tron.Key(
                    address=bytes.fromhex(
                        accounts[0]['addressHex']),
                    weight=1,
                ),
            ],
        ),
        actives=[
            tron.Permission(
                type=tron.Permission.Active,
                permission_name="activeA",
                threshold=1,
                operations=bytes.fromhex("7fff1fc0037e0000000000000000000000000000000000000000000000000000"),
                keys=[
                    tron.Key(
                        address=bytes.fromhex(
                            accounts[0]['addressHex']),
                        weight=1,
                    ),
                    tron.Key(
                        address=bytes.fromhex(
                            accounts[1]['addressHex']),
                        weight=1,
                    ),
                ],
            )],
        ))

print(tx)
raw_tx, sign0 = ledgerSignWithAutoSplit(accounts[0]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, sign0[0:65],
                                                  accounts[0]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(sign0[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(sign0[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

logger.debug('''
   Tron MultiSign tests
''')

tx = stub.CreateTransaction2(
    balance_contract.TransferContract(
        owner_address=bytes.fromhex(
            accounts[0]['addressHex']),
        to_address=bytes.fromhex(
            address_hex("TPnYqC2ukKyhEDAjqRRobSVygMAb8nAcXM")),
        amount=100000))
print("tx info:", tx)
if len(tx.transaction.raw_data.contract) > 0:
    # use permission 2
    tx.transaction.raw_data.contract[0].Permission_id = 2

    raw_tx, sign1 = ledgerSignWithAutoSplit(accounts[1]['path'], tx.transaction)

    tx.transaction.signature.extend([bytes(sign1[0:65])])
    r = stub.BroadcastTransaction(tx.transaction)
    print("result:", r)
    if r.result == True:
        print("Success")
    else:
        print("Fail")
