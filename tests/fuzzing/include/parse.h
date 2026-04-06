#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "asset_info.h"
#include "common_utils.h"
#include "tx_content.h"

#define MAX_BIP32_PATH 10
#define HASH_SIZE 32
#define BASE58CHECK_ADDRESS_SIZE 34
#define SHARED_CTX_FIELD_1_SIZE 256
#define SHARED_CTX_FIELD_2_SIZE 40
#define MAX_ASSETS 5
#define PLUGIN_CONTEXT_SIZE 128

typedef struct {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t domainHash[HASH_SIZE];
    uint8_t messageHash[HASH_SIZE];
} messageSigningContext712_t;

typedef struct {
    extraInfo_t extraInfo[MAX_ASSETS];
    bool assetSet[MAX_ASSETS];
    uint8_t currentAssetIndex;
} transactionContext_t;

typedef union {
    transactionContext_t transactionContext;
    messageSigningContext712_t messageSigningContext712;
} tmpCtx_t;

typedef struct {
    char tmp[SHARED_CTX_FIELD_1_SIZE];
    char tmp2[SHARED_CTX_FIELD_2_SIZE];
} strDataTmp_t;

typedef union {
    strDataTmp_t tmp;
} strings_t;

typedef struct {
    uint64_t chainId;
} chain_config_t;

typedef union {
    struct {
        uint8_t pluginContext[PLUGIN_CONTEXT_SIZE];
    } tokenContext;
} dataContext_t;

typedef struct {
    bool initialized;
} txContext_t;

typedef enum {
    PLUGIN_TYPE_NONE = 0,
    PLUGIN_TYPE_EXTERNAL,
    PLUGIN_TYPE_SWAP_WITH_CALLDATA,
    PLUGIN_TYPE_ERC721,
    PLUGIN_TYPE_ERC1155,
    PLUGIN_TYPE_OLD_INTERNAL,
} pluginType_t;

typedef enum {
    APP_STATE_IDLE,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY,
    APP_STATE_SIGNING,
    APP_STATE_SIGNING_TIP712,
} app_state_t;

extern tmpCtx_t tmpCtx;
extern txContent_t txContent;
extern txContext_t txContext;
extern dataContext_t dataContext;
extern pluginType_t pluginType;
extern uint8_t appState;
extern uint16_t apdu_response_code;
extern const chain_config_t *chainConfig;

void forget_known_assets(void);
extraInfo_t *get_current_asset_info(void);
int get_asset_index_by_addr(const uint8_t *addr);
extraInfo_t *get_asset_info_by_addr(const uint8_t *addr);
void validate_current_asset_info(void);
