#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "asset_info.h"
#include "bip32_utils.h"
#include "chain_config.h"  // chain_config_t (real app header, lightweight)
#include "common_utils.h"
#include "tx_content.h"
// The application contexts (tmpCtx_t, txContext_t, strings_t, app_state_t,
// chainConfig, ...) are defined in the real shared_context.h, which is fully
// standalone-includable against these mocks. Deferring to it keeps a single
// definition source so the GCS sources (which pull the real apdu_constants.h ->
// shared_context.h) never clash with this header.
#include "shared_context.h"

#define ADDRESS_SIZE TRON_ADDRESS_SIZE
#define SUN_DIG      6

// App-side asset/token/amount helpers (declared in the firmware's parse.h).
void forget_known_assets(void);
extraInfo_t *get_current_asset_info(void);
int get_asset_index_by_addr(const uint8_t *addr);
extraInfo_t *get_asset_info_by_addr(const uint8_t *addr);
void validate_current_asset_info(void);
tokenDefinition_t *getKnownToken(txContent_t *context);
unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun);
void initTx(txContext_t *context, txContent_t *content);
