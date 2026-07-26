/*******************************************************************************
 *   TRON Ledger
 *   (c) 2024 Ledger
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

#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include <stdint.h>
#include "common_utils.h"           // INT256_LENGTH, MAX_TICKER_LEN, TRON_ADDRESS_SIZE
#include "asset_info.h"             // union extraInfo_t
#include "tx_content.h"             // txContent_t
#include "bip32_utils.h"            // bip32_path_t
#include "chain_config.h"           // chain_config_t

// Sizes & limits shared across the application contexts
#define MAX_BIP32_PATH 10

#define BASE58CHECK_ADDRESS_SIZE 34
#define PUBLIC_KEY_SIZE          65
#define CHAIN_CODE_SIZE          32
#define HASH_SIZE                32
#define MAX_RAW_SIGNATURE        65

#define SHARED_CTX_FIELD_1_SIZE 256
#define SHARED_CTX_FIELD_2_SIZE 40

#define MAX_ASSETS 5

// must be able to hold in decimal up to : floor(MAX_UINT64 / 2) - 36
#define NETWORK_STRING_MAX_SIZE 19

typedef enum {
    APP_STATE_IDLE,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY,
    APP_STATE_REVIEWING_PERSONAL_MESSAGE,
    APP_STATE_SIGNING,
    APP_STATE_SIGNING_GCS_STORE,
    APP_STATE_SIGNING_TIP712,
    // Used while a TriggerSmartContract is being clear-signed through the
    // generic_tx_parser (GCS) module ported from app-ethereum.
    APP_STATE_SIGNING_TX,
    APP_STATE_GCS_FIELDS_AUTHENTICATED,
    APP_STATE_REVIEWING_GCS
} app_state_t;

// The GCS module (generic_tx_parser) ported from app-ethereum refers to the
// EIP712 signing state by its Ethereum name. Tron's equivalent is TIP712.
#define APP_STATE_SIGNING_EIP712 APP_STATE_SIGNING_TIP712


typedef struct txContext_t {
    cx_sha256_t sha2;
    bool initialized;
    // --- generic_tx_parser (GCS) fields, mirrored from app-ethereum ---
    // Total number of transactions in the current GCS batch and how many have
    // been consumed so far. The parser uses these (together) to decide whether
    // to render per-transaction "intent" separators. A plain
    // TriggerSmartContract is a single-transaction batch.
    uint8_t current_batch_size;
    uint8_t batch_nb_tx;
    // Points at the transaction content being clear-signed (Tron's global
    // `txContent`). Used by the GCS field formatters to reach tx-level data.
    txContent_t *content;
} txContext_t;

typedef struct publicKeyContext_t {
    uint8_t publicKey[PUBLIC_KEY_SIZE];
    char address58[BASE58CHECK_ADDRESS_SIZE + 1];
    uint8_t chainCode[CHAIN_CODE_SIZE];
    bool getChaincode;
} publicKeyContext_t;

typedef struct transactionContext_t {
    bip32_path_t bip32_path;
    uint8_t hash[HASH_SIZE];
    uint8_t signature[MAX_RAW_SIGNATURE];
    uint8_t signatureLength;
    union extraInfo_t extraInfo[MAX_ASSETS];
    bool assetSet[MAX_ASSETS];
    asset_kind_t assetKind[MAX_ASSETS];
    uint8_t currentAssetIndex;
} transactionContext_t;

typedef struct messageSigningContext712_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t domainHash[32];
    uint8_t messageHash[32];
} messageSigningContext712_t;

typedef union {
    transactionContext_t transactionContext;
    publicKeyContext_t publicKeyContext;
    messageSigningContext712_t messageSigningContext712;
} tmpCtx_t;


typedef struct txStringProperties_s {
    char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
    char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
    char addressSummary[40];
    char fullContract[TOKEN_DISPLAY_BUFFER_SIZE];
    char url[MAX_URL_SIZE + 1];  // +1 for NUL terminator at max length (256)
    char TRC20Action[9];
    char TRC20ActionSendAllow[8];
    // Either "0x" + 64 hex chars or a 64-char personal-message hash, plus NUL.
    char fullHash[2 + HASH_SIZE * 2 + 1];
} txStringProperties_t;

typedef struct strDataTmp_t {
    char tmp[SHARED_CTX_FIELD_1_SIZE];
    char tmp2[SHARED_CTX_FIELD_2_SIZE];
} strDataTmp_t;

typedef union {
    txStringProperties_t common;
    strDataTmp_t tmp;
} strings_t;

extern const chain_config_t *chainConfig;

// Defined in src/nbgl/ui_globals.c. Re-declared here (matching app-ethereum's
// shared_context.h) so the ported generic_tx_parser module can use `strings`
// for scratch formatting without depending on the UI headers.
extern strings_t strings;

extern tmpCtx_t tmpCtx;
extern txContent_t txContent;
extern txContext_t txContext;
extern uint8_t appState;
extern uint16_t apdu_response_code;

void reset_app_context(void);
void app_quit(void);
