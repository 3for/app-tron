/*******************************************************************************
 *   TRON Ledger
 *   (c) 2018 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "base58.h"
#include "io.h"
#include "crypto_helpers.h"
#include "parse.h"
#include "helpers.h"
#include "app_errors.h"
#include "bip32_path_parser.h"

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t address[static ADDRESS_SIZE]) {
    uint8_t hashAddress[HASH_SIZE];
    cx_sha3_t sha3;

    CX_ASSERT(cx_keccak_init_no_throw(&sha3, 256));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &sha3,
                               CX_LAST,
                               publicKey + 1,
                               PUBLIC_KEY_SIZE - 1,
                               hashAddress,
                               HASH_SIZE));

    memmove(address, hashAddress + 11, ADDRESS_SIZE);
    address[0] = ADD_PRE_FIX_BYTE_MAINNET;
}

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out) {
    uint8_t sha256[HASH_SIZE];
    uint8_t addchecksum[ADDRESS_SIZE + 4];

    cx_hash_sha256(address, ADDRESS_SIZE, sha256, HASH_SIZE);
    cx_hash_sha256(sha256, HASH_SIZE, sha256, HASH_SIZE);

    memmove(addchecksum, address, ADDRESS_SIZE);
    memmove(addchecksum + ADDRESS_SIZE, sha256, 4);

    base58_encode(addchecksum, sizeof(addchecksum), out, BASE58CHECK_ADDRESS_SIZE);
    out[BASE58CHECK_ADDRESS_SIZE] = '\0';
}

void getBase58FromPublicKey(const uint8_t *publicKey, char *address58) {
    uint8_t address[ADDRESS_SIZE];

    // Get address from public key
    getAddressFromPublicKey(publicKey, address);

    // Get base58 address
    getBase58FromAddress(address, address58);
}

int signTransaction(transactionContext_t *transactionContext) {
    cx_err_t err;
    unsigned int info = 0;

    // Get Private key from BIP32 path
    io_seproxyhal_io_heartbeat();
    err = bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                              transactionContext->bip32_path.indices,
                                              transactionContext->bip32_path.length,
                                              CX_RND_RFC6979 | CX_LAST,
                                              CX_SHA256,
                                              transactionContext->hash,
                                              sizeof(transactionContext->hash),
                                              transactionContext->signature,
                                              transactionContext->signature + 32,
                                              &info);
    if (err != CX_OK) {
        return -1;
    }
    transactionContext->signature[64] = 0x00;
    if (info & CX_ECCINFO_PARITY_ODD) {
        transactionContext->signature[64] |= 0x01;
    }
    transactionContext->signatureLength = 65;

    return 0;
}

int helper_send_response_pubkey(const publicKeyContext_t *pub_key_ctx) {
    uint32_t tx = 0;

    G_io_apdu_buffer[tx++] = PUBLIC_KEY_SIZE;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->publicKey, PUBLIC_KEY_SIZE);
    tx += PUBLIC_KEY_SIZE;
    G_io_apdu_buffer[tx++] = BASE58CHECK_ADDRESS_SIZE;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->address58, BASE58CHECK_ADDRESS_SIZE);
    tx += BASE58CHECK_ADDRESS_SIZE;
    if (pub_key_ctx->getChaincode) {
        memcpy(G_io_apdu_buffer + tx, pub_key_ctx->chainCode, CHAIN_CODE_SIZE);
        tx += CHAIN_CODE_SIZE;
    }
    return io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
}

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path) {
    off_t parsed =
        read_bip32_path_words(buffer, length, &path->length, path->indices, MAX_BIP32_PATH);

    if (parsed < 0) {
        PRINTF("Invalid path\n");
        return parsed;
    }
    return parsed;
}

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712) {
    off_t parsed = read_bip32_path_words(buffer,
                                         length,
                                         &ctx_712->pathLength,
                                         ctx_712->bip32Path,
                                         MAX_BIP32_PATH);

    if (parsed < 0) {
        PRINTF("Invalid path\n");
        return parsed;
    }
    return parsed;
}

int initPublicKeyContext(bip32_path_t *bip32_path,
                         char *address58,
                         publicKeyContext_t *public_key_ctx) {
    if (bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    bip32_path->indices,
                                    bip32_path->length,
                                    public_key_ctx->publicKey,
                                    public_key_ctx->chainCode,
                                    CX_SHA512) != CX_OK) {
        return -1;
    }

    // Get base58 address from public key
    getBase58FromPublicKey(public_key_ctx->publicKey, address58);

    return 0;
}
