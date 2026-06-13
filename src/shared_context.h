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
#include "tron_plugin_interface.h"  // PLUGIN_CONTEXT_SIZE
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
#define SHARED_BUFFER_SIZE      SHARED_CTX_FIELD_1_SIZE

#define MAX_ASSETS 5

#define SELECTOR_LENGTH  4
#define PLUGIN_ID_LENGTH 30

// must be able to hold in decimal up to : floor(MAX_UINT64 / 2) - 36
#define NETWORK_STRING_MAX_SIZE 19

typedef enum {
    APP_STATE_IDLE,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY,
    APP_STATE_SIGNING,
    APP_STATE_SIGNING_TIP712,
    // Used while a TriggerSmartContract is being clear-signed through the
    // generic_tx_parser (GCS) module ported from app-ethereum.
    APP_STATE_SIGNING_TX
} app_state_t;

// The GCS module (generic_tx_parser) ported from app-ethereum refers to the
// EIP712 signing state by its Ethereum name. Tron's equivalent is TIP712.
#define APP_STATE_SIGNING_EIP712 APP_STATE_SIGNING_TIP712

typedef enum {
    PLUGIN_TYPE_NONE = 0,
    // External plugin, set by setExternalPlugin
    PLUGIN_TYPE_EXTERNAL,
    // Specific SWAP_WITH_CALLDATA internal plugin
    // set as fallback when started if calldata is provided in swap mode
    PLUGIN_TYPE_SWAP_WITH_CALLDATA,
    // Specific ERC721 internal plugin, set by setPlugin
    PLUGIN_TYPE_ERC721,
    // Specific ERC1155 internal plugin, set by setPlugin
    PLUGIN_TYPE_ERC1155,
    // Old internal plugin, not set by any command
    PLUGIN_TYPE_OLD_INTERNAL,
} pluginType_t;

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

typedef struct tokenContext_t {
    char pluginName[PLUGIN_ID_LENGTH];

    uint8_t data[INT256_LENGTH];
    uint16_t fieldIndex;
    uint8_t fieldOffset;

    uint8_t pluginUiMaxItems;
    uint8_t pluginUiCurrentItem;
    uint8_t pluginUiState;

    union {
        struct {
            uint8_t contractAddress[TRON_ADDRESS_SIZE];
            uint8_t methodSelector[SELECTOR_LENGTH];
        };
        // This needs to be strictly 4 bytes aligned since pointers to it will be casted as
        // plugin context struct pointers (structs that contain up to 4 bytes wide elements)
        uint8_t pluginContext[PLUGIN_CONTEXT_SIZE] __attribute__((aligned(4)));
    };

    uint8_t pluginStatus;

} tokenContext_t;

_Static_assert((offsetof(tokenContext_t, pluginContext) % 4) == 0, "Plugin context not aligned");

typedef union {
    tokenContext_t tokenContext;
} dataContext_t;

typedef struct txStringProperties_s {
    char fromAddress[43];
    char toAddress[43];
    char fullAmount[MAX_TICKER_LEN + 1 + 78 + 1];  // 2^256 is 78 digits long
    char maxFee[50];
    char nonce[8];  // 10M tx per account ought to be enough for everybody
    char network_name[NETWORK_STRING_MAX_SIZE + 1];
    char tx_hash[2 + (INT256_LENGTH * 2) + 1];
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
extern dataContext_t dataContext;
extern pluginType_t pluginType;
extern uint8_t appState;
extern uint16_t apdu_response_code;

void reset_app_context(void);
void app_quit(void);
