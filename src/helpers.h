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
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "os.h"
#include "cx.h"

#include "parse.h"

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t address[static ADDRESS_SIZE]);

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out, bool truncate);

bool getAddressFromBase58(const char *in, size_t in_len, uint8_t out[static ADDRESS_SIZE]);

void getBase58FromPublicKey(const uint8_t *publicKey, char *address58, bool truncate);

int signTransaction(transactionContext_t *transactionContext);

int helper_send_response_pubkey(const publicKeyContext_t *pub_key_ctx);

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path);

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712);

int initPublicKeyContext(bip32_path_t *bip32_path,
                         char *address58,
                         publicKeyContext_t *public_key_ctx);
