#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "asset_info.h"
#include "bip32_utils.h"
#include "common_utils.h"
#include "tx_content.h"

#define MAX_BIP32_PATH 10
#define HASH_SIZE 32
#define ADDRESS_SIZE TRON_ADDRESS_SIZE
#define BASE58CHECK_ADDRESS_SIZE 34
#define MAX_RAW_SIGNATURE 65
#define SUN_DIG 6
#define SHARED_CTX_FIELD_1_SIZE 256
#define SHARED_CTX_FIELD_2_SIZE 40
#define MAX_ASSETS 5

typedef struct {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t domainHash[HASH_SIZE];
    uint8_t messageHash[HASH_SIZE];
} messageSigningContext712_t;

typedef struct {
    bip32_path_t bip32_path;
    uint8_t hash[HASH_SIZE];
    uint8_t signature[MAX_RAW_SIGNATURE];
    uint8_t signatureLength;
    extraInfo_t extraInfo[MAX_ASSETS];
    bool assetSet[MAX_ASSETS];
    uint8_t currentAssetIndex;
} transactionContext_t;

typedef union {
    transactionContext_t transactionContext;
    messageSigningContext712_t messageSigningContext712;
} tmpCtx_t;

typedef struct {
    cx_sha256_t sha2;
    bool initialized;
} txContext_t;

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
extern uint8_t appState;
extern uint16_t apdu_response_code;
extern const chain_config_t *chainConfig;

void forget_known_assets(void);
extraInfo_t *get_current_asset_info(void);
int get_asset_index_by_addr(const uint8_t *addr);
extraInfo_t *get_asset_info_by_addr(const uint8_t *addr);
void validate_current_asset_info(void);
tokenDefinition_t *getKnownToken(txContent_t *context);
unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun);
void initTx(txContext_t *context, txContent_t *content);
