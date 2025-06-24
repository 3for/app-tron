#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

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
    print(raw_tx)
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
from tron_sdk_py.proto.core import contract_pb2 as contract
from tron_sdk_py.proto.api import api_pb2 as api
from tron_sdk_py.proto.api.api_pb2_grpc import WalletStub
from tron_sdk_py.proto.core import chain_pb2 as tron
from google.protobuf.any_pb2 import Any
import grpc

# Start Channel and WalletStub
channel = grpc.insecure_channel("grpc.nile.trongrid.io:50051")
stub = WalletStub(channel)

logger.debug('''
   Tron Transactions tests
''')
""" 
############
# Send TRX #
############
logger.debug('\n\nTransfer Contract:')

tx = stub.CreateTransaction2(
    contract.TransferContract(
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
    contract.TransferContract(
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
    contract.TransferAssetContract(
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
r = stub.BroadcastTransaction(tx.transaction) """

### Can't emulate the tokenSignature valid in Nile testnet.
### Omit this case.
""" #######################################
# Send TRC10 Token with Name/Decimals #
#######################################
logger.debug('\n\nTransfer Asset Contract with Name/Decimals:')

tx = stub.TransferAsset2(
    contract.TransferAssetContract(
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

""" #########################
# TRC10 Exchange Create #
#########################
logger.debug('\n\nExchange Create Contract:')

tx = stub.ExchangeCreate(
    contract.ExchangeCreateContract(
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
newContract = contract.ExchangeCreateContract(
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
    contract.ExchangeInjectContract(owner_address=bytes.fromhex(
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
    contract.ExchangeWithdrawContract(owner_address=bytes.fromhex(
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
    contract.ExchangeTransactionContract(
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
r = stub.BroadcastTransaction(tx.transaction) """

################
# Vote Witness #
################
logger.debug('\n\nVote Witness Contract:')

tx = tron.Transaction()
newContract = contract.VoteWitnessContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']))
tx.raw_data.ref_block_bytes = b'0000'
tx.raw_data.timestamp = 110101010101
# Vote list
v1 = newContract.votes.add()
v1.vote_address = bytes.fromhex(
    address_hex("TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF"))
v1.vote_count = 1
v2 = newContract.votes.add()
v2.vote_address = bytes.fromhex(
    address_hex("TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt"))
v2.vote_count = 1
v3 = newContract.votes.add()
v3.vote_address = bytes.fromhex(
    address_hex("TTcYhypP8m4phDhN6oRexz2174zAerjEWP"))
v3.vote_count = 1000
v4 = newContract.votes.add()
v4.vote_address = bytes.fromhex(
    address_hex("TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9"))
v4.vote_count = 1000
v5 = newContract.votes.add()
v5.vote_address = bytes.fromhex(
    address_hex("TSNbzxac4WhxN91XvaUfPTKP2jNT18mP6T"))
v5.vote_count = 1000
# End vote list
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.VoteWitnessContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

print(tx.raw_data.SerializeToString().hex())
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

#####################
# Freeze Balance BW #
#####################
logger.debug('\n\nFreeze Contract bandwidth:')

tx = tron.Transaction()
newContract = contract.FreezeBalanceContract(owner_address=bytes.fromhex(
    accounts[1]['addressHex']),
                                             frozen_balance=10000000000,
                                             frozen_duration=3,
                                             resource=contract.BANDWIDTH)
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.FreezeBalanceContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

#################################
# Freeze Balance Delegate Energy#
#################################
logger.debug('\n\nFreeze Contract delegate energy:')

tx = tron.Transaction()
newContract = contract.FreezeBalanceContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
    frozen_balance=10000000000,
    frozen_duration=3,
    resource=contract.ENERGY,
    receiver_address=bytes.fromhex(accounts[0]['addressHex']),
)
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.FreezeBalanceContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

######################
# Unfreeze Balance BW#
######################
logger.debug('\n\nUnfreeze Contract bandwidth:')

tx = tron.Transaction()
newContract = contract.UnfreezeBalanceContract(owner_address=bytes.fromhex(
    accounts[1]['addressHex']),
                                               resource=contract.BANDWIDTH)
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.UnfreezeBalanceContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

####################################
# Unfreeze Balance Delegate Energy #
####################################
logger.debug('\n\nUnfreeze Contract delegate energy:')

tx = tron.Transaction()
newContract = contract.UnfreezeBalanceContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
    resource=contract.ENERGY,
    receiver_address=bytes.fromhex(accounts[0]['addressHex']),
)
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.UnfreezeBalanceContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

#####################
# Widthdraw Balance #
#####################
# Delegate Only
logger.debug('\n\nWidthdraw Balance:')

tx = tron.Transaction()
newContract = contract.WithdrawBalanceContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']))
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.WithdrawBalanceContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

###################
# Proposal Create #
###################
# Delegate Only
logger.debug('\n\Proposal Create Contract:')

tx = tron.Transaction()
newContract = contract.ProposalCreateContract(owner_address=bytes.fromhex(
    accounts[1]['addressHex']), )
newContract.parameters[1] = 10000000
c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.ProposalCreateContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

####################
# Proposal Approve #
####################
# Delegate Only
logger.debug('\n\Proposal Approve Contract:')

tx = tron.Transaction()

newContract = contract.ProposalApproveContract(owner_address=bytes.fromhex(
    accounts[1]['addressHex']),
                                               proposal_id=10,
                                               is_add_approval=True)

c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.ProposalApproveContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

###################
# Proposal Delete #
###################
# Delegate Only
logger.debug('\n\Proposal Delete Contract:')

tx = tron.Transaction()

newContract = contract.ProposalDeleteContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
    proposal_id=10,
)

c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.ProposalDeleteContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

##################
# Account Update #
##################
logger.debug('\n\Account Update Contract:')

tx = tron.Transaction()

newContract = contract.AccountUpdateContract(
    account_name=b'CryptoChainTest',
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
)

c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.AccountUpdateContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

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

##################
# TRC20 Transfer #
##################
logger.debug('\n\SmartContract Trigger TRC20 Transfer:')

tx = tron.Transaction()

newContract = contract.TriggerSmartContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
    contract_address=bytes.fromhex(
        address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
    data=bytes.fromhex(
        "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
    ))

c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.TriggerSmartContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

pprint(newContract)

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

##################
# TRC20 Approve  #
##################
logger.debug('\n\SmartContract Trigger TRC20 Approve Transfer:')

tx = tron.Transaction()

newContract = contract.TriggerSmartContract(
    owner_address=bytes.fromhex(accounts[1]['addressHex']),
    contract_address=bytes.fromhex(
        address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
    data=bytes.fromhex(
        "095ea7b3000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
    ))

c = tx.raw_data.contract.add()
c.type = tron.Transaction.Contract.TriggerSmartContract
param = Any()
param.Pack(newContract)
c.parameter.CopyFrom(param)

pprint(newContract)

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
