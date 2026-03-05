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
from core.contract import balance_contract_pb2 as balance_contract
from core.contract import asset_issue_contract_pb2 as asset_issue_contract
from core.contract import exchange_contract_pb2 as exchange_contract
from core.contract import witness_contract_pb2 as witness_contract
from core.contract import proposal_contract_pb2 as proposal_contract
from core.contract import account_contract_pb2 as account_contract
from core.contract import smart_contract_pb2 as smart_contract
from core.contract import common_pb2 as common
from api import api_pb2 as api
from api.api_pb2_grpc import WalletStub
from core import Tron_pb2 as tron
from google.protobuf.any_pb2 import Any
import grpc

# Start Channel and WalletStub
channel = grpc.insecure_channel("grpc.nile.trongrid.io:50051")
stub = WalletStub(channel)

logger.debug('''
   Tron Transactions tests
''')

############
# Send TRX #
############
logger.debug('\n\nTransfer Contract:')

tx = stub.CreateTransaction2(
    balance_contract.TransferContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        to_address=bytes.fromhex(accounts[0]['addressHex']),
        amount=1))
print("tx info:", tx)
raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast Example
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

######################
# Send TRX with DATA #
######################
logger.debug('\n\nTransfer Contract with Data:')

# check if device have data enable
result = dongle.exchange(bytearray.fromhex("E006000000"))
print("resutl:", result)
dataAllowed = result[0] & 0x01
if dataAllowed == 0:
    print("Data field not allowed, test should fail...")
    sys.exit(0)

tx = stub.CreateTransaction2(
    balance_contract.TransferContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        to_address=bytes.fromhex(accounts[0]['addressHex']),
        amount=1))

tx.transaction.raw_data.data = b'CryptoChain-TronSR Ledger Transactions Tests'

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

####################
# Send TRC10 Token #
####################
logger.debug('\n\nTransfer Asset Contract:')

tx = stub.TransferAsset2(
    asset_issue_contract.TransferAssetContract(
        asset_name="1005466".encode(),
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        to_address=bytes.fromhex(accounts[0]['addressHex']),
        amount=1))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

### Can't emulate the tokenSignature valid in Nile testnet.
### Omit this case.
""" #######################################
# Send TRC10 Token with Name/Decimals #
#######################################
logger.debug('\n\nTransfer Asset Contract with Name/Decimals:')

tx = stub.TransferAsset2(
    asset_issue_contract.TransferAssetContract(
        asset_name="1002000".encode(),
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        to_address=bytes.fromhex(accounts[0]['addressHex']),
        amount=1))
# BitTorrent 1002000 -> Decimals: 6
tokenSignature = [
    "0a0a426974546f7272656e7410061a46304402202e2502f36b00e57be785fc79ec4043abcdd4fdd1b58d737ce123599dffad2cb602201702c307f009d014a553503b499591558b3634ceee4c054c61cedd8aca94c02b"
]
raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction,
                            tokenSignature)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0) """

#########################
# TRC10 Exchange Create #
#########################
logger.debug('\n\nExchange Create Contract:')

tx = stub.ExchangeCreate(
    exchange_contract.ExchangeCreateContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        first_token_id="_".encode(),
        first_token_balance=1000000,
        second_token_id="1005466".encode(),
        second_token_balance=1000000))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

########################################
# TRC10 Exchange Create with Token Name#
########################################
logger.debug('\n\nExchange Create Contract with token name:')

tx = tron.Transaction()
newContract = exchange_contract.ExchangeCreateContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
    first_token_id="_".encode(),
    first_token_balance=10000000000,
    second_token_id="1000166".encode(),
    second_token_balance=10000000)
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.ExchangeCreateContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

# Token Signature
# Token 1: _ TRX
# Token 2: 1000166 CCT
tokenSignature = [
    "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c0a6371adcb6992db94487f66c7",
    "0a0b43727970746f436861696e10001a4730450221008417d04d1caeae31f591ae50f7d19e53e0dfb827bd51c18e66081941bf04639802203c73361a521c969e3fd7f62e62b46d61aad00e47d41e7da108546d954278a6b1"
]
raw_tx, result = ledgerSign(accounts[1]['path'], tx, tokenSignature)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

#########################
# TRC10 Exchange Inject #
#########################
logger.debug('\n\nExchange Inject Contract:')

tx = stub.ExchangeInject(
    exchange_contract.ExchangeInjectContract(owner_address=bytes.fromhex(
        accounts[1]['addressHex']),
        exchange_id=91,
        token_id="1005466".encode(),
        quant=1000000))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

###########################
# TRC10 Exchange Withdraw #
###########################
logger.debug('\n\nExchange Withdraw Contract:')

tx = stub.ExchangeWithdraw(
    exchange_contract.ExchangeWithdrawContract(owner_address=bytes.fromhex(
        accounts[1]['addressHex']),
        exchange_id=91,
        token_id="1005466".encode(),
        quant=200000))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

##############################
# TRC10 Exchange Transaction #
##############################
logger.debug('\n\nExchange Transaction Contract:')

tx = stub.ExchangeTransaction(
    exchange_contract.ExchangeTransactionContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        exchange_id=91,
        token_id="1005466".encode(),
        quant=10000,
        expected=100))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

#####################
# Freeze Balance BW #
#####################
logger.debug('\n\nFreeze Contract bandwidth:')

tx = stub.FreezeBalanceV2(
    balance_contract.FreezeBalanceV2Contract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        frozen_balance=100000000,
        resource=common.BANDWIDTH))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

################
# Vote Witness #
################
logger.debug('\n\nVote Witness Contract, make sure to use the right SRs:')

tx = stub.VoteWitnessAccount(
    witness_contract.VoteWitnessContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        votes=[
            witness_contract.VoteWitnessContract.Vote(
                vote_address = bytes.fromhex(address_hex("TEp1ru7opCexkbFM9ChK6DFfL2XFSfUo2N")),
                vote_count = 1
            ),
            witness_contract.VoteWitnessContract.Vote(
                vote_address = bytes.fromhex(address_hex("TFFLWM7tmKiwGtbh2mcz2rBssoFjHjSShG")),
                vote_count = 1
            ),
            witness_contract.VoteWitnessContract.Vote(
                vote_address = bytes.fromhex(address_hex("TPffmvjxEcvZefQqS7QYvL1Der3uiguikE")),
                vote_count = 1
            ),
        ]
        ))

print(tx)
raw_tx, result = ledgerSign(accounts[1]['path'], tx)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
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

#####################
# Freeze Balance Energy #
#####################
logger.debug('\n\nFreeze Contract energy:')

tx = stub.FreezeBalanceV2(
    balance_contract.FreezeBalanceV2Contract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        frozen_balance=100000000,
        resource=common.ENERGY))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

#################################
# Freeze Balance Delegate Energy#
#################################
logger.debug('\n\nFreeze Contract delegate energy:')

tx = stub.DelegateResource(
    balance_contract.DelegateResourceContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        balance=30000000,
        resource=common.ENERGY,
        receiver_address=bytes.fromhex(accounts[0]['addressHex']),
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

######################
# Unfreeze Balance Energy#
######################
logger.debug('\n\nUnfreeze Contract energy:')

tx = stub.UnfreezeBalanceV2(
    balance_contract.UnfreezeBalanceV2Contract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        unfreeze_balance=1000000,
        resource=common.ENERGY))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

####################################
# Unfreeze Balance Delegate Energy #
####################################
logger.debug('\n\nUnfreeze Contract delegate energy:')

tx = stub.UnDelegateResource(
    balance_contract.UnDelegateResourceContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        resource=common.ENERGY,
        balance=10000000,
        receiver_address=bytes.fromhex(accounts[0]['addressHex'])
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

####################################
# Withdraw Unfrozen Balance in Stake2.0 #
####################################
logger.debug('\n\nWithdraw unfrozen balance:')

tx = stub.WithdrawExpireUnfreeze(
    balance_contract.WithdrawExpireUnfreezeContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex'])
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

#####################
# Widthdraw Balance # 
#####################
logger.debug('\n\nWidthdraw Balance:')

tx = stub.WithdrawBalance2(
    balance_contract.WithdrawBalanceContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex'])
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

#####################
# Apply SR Candidate # 
#####################
logger.debug('\n\nApply SR Candidate:')

tx = stub.CreateWitness(
    witness_contract.WitnessCreateContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        url="http://sr-1t.com".encode()
    ))

print(tx)
raw_tx, result = ledgerSign(accounts[1]['path'], tx)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
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

###################
# Proposal Create #
###################
# Delegate Only
logger.debug('\n\Proposal Create Contract:')

tx = stub.ProposalCreate(
    proposal_contract.ProposalCreateContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        parameters={
            1: 100000,
            2: 400000
            },
        ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

####################
# Proposal Approve #
####################
# Delegate Only
logger.debug('\n\Proposal Approve Contract:')

tx = stub.ProposalApprove(
    proposal_contract.ProposalApproveContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        proposal_id=19819,
        is_add_approval=True
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

###################
# Proposal Delete #
###################
# Delegate Only
logger.debug('\n\Proposal Delete Contract:')

tx = stub.ProposalDelete(
    proposal_contract.ProposalDeleteContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        proposal_id=19819,
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

##################
# Account Update #
##################
logger.debug('\n\Account Update Contract:')

tx = stub.UpdateAccount(
    account_contract.AccountUpdateContract(
        account_name=b'CryptoChainTest',
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
    ))

raw_tx, result = ledgerSign(accounts[1]['path'], tx)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
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

##################
# TRC20 Transfer #
##################
logger.debug('\n\SmartContract Trigger TRC20 Transfer:')

tx = stub.TriggerContract(
    smart_contract.TriggerSmartContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        contract_address=bytes.fromhex(
            address_hex("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf")),
        data=bytes.fromhex(
            "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
        )))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)

##################
# TRC20 Approve  #
##################
logger.debug('\n\SmartContract Trigger TRC20 Approve Transfer:')

tx = stub.TriggerContract(
    smart_contract.TriggerSmartContract(
        owner_address=bytes.fromhex(accounts[1]['addressHex']),
        contract_address=bytes.fromhex(
            address_hex("TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf")),
        data=bytes.fromhex(
            "095ea7b3000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
        )))

raw_tx, result = ledgerSign(accounts[1]['path'], tx.transaction)
validSignature, txID = validateSignature.validate(raw_tx, result[0:65],
                                                  accounts[1]['publicKey'][2:])
logger.debug('- RAW: {}'.format(raw_tx))
logger.debug('- txID: {}'.format(txID))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# Broadcast
tx.transaction.signature.extend([bytes(result[0:65])])
r = stub.BroadcastTransaction(tx.transaction)
