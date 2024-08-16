#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ledgerblue.comm import getDongle
import argparse
from base import parse_bip32_path
import logging
import time

import validateSignature
import binascii
import base58
import struct
from Crypto.Hash import keccak

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()


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


# Magic define
SIGN_MAGIC = b'\x19TRON Signed Message:\n'

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to sign with", default=None)
parser.add_argument('--message', help="Message to sign", default='Hello Tron! ' * 32)
parser.add_argument('--fulldisplay', help="Enable full display mode", default='disable')
args = parser.parse_args()

args.message = args.message.encode()
if args.path == None:
    args.path = "44'/195'/0'/0/0"

MSG_INS = 0x08
if args.fulldisplay == 'enable':
    MSG_INS = 0xC8

encodedTx = struct.pack(">I", len(args.message))
encodedTx += args.message

donglePath = parse_bip32_path(args.path)

dongle = getDongle(True)

result = dongle.exchange(apduMessage(0x02, 0x00, 0x00, donglePath, ""))
size = result[0]
if size == 65:
    publicKey = result[1:1 + size].hex()

index = 0

while True:
    if index == 0:
        index = len(encodedTx)
        if index > 255-len(donglePath)/2 - 1:
            index = int(255-len(donglePath)/2) - 1
        print(index)
        result = dongle.exchange(apduMessage(MSG_INS, 0x00, 0x00, donglePath, encodedTx[0:index].hex()))
    else:
        if index >= len(encodedTx):
            break
        last = index
        index += 255
        if index > len(encodedTx):
            index = len(encodedTx)
        result = dongle.exchange(apduMessage(MSG_INS, 0x80, 0x00, None, encodedTx[last:index].hex()))

# result = dongle.exchange(
    # apduMessage(0x08, 0x00, 0x00, donglePath, encodedTx.hex()))

signedMessage = SIGN_MAGIC + str(len(args.message)).encode() + args.message
keccak_hash = keccak.new(digest_bits=256)
keccak_hash.update(signedMessage)
hash = keccak_hash.digest()

validSignature = validateSignature.validateHASH(hash, result[0:65],
                                                publicKey[2:])
logger.debug('- HASH: {}'.format(hash))
logger.debug('- Signature: {}'.format(binascii.hexlify(result[0:65])))
logger.debug('- Valid: {}'.format(validSignature))
