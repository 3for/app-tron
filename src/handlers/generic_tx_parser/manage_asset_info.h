#pragma once

// ---------------------------------------------------------------------------
// GCS dependency header.
//
// The generic_tx_parser TOKEN / TOKEN_AMOUNT / NFT field formatters use strict
// typed lookups so metadata from one asset class can never be interpreted as
// another union member.
// ---------------------------------------------------------------------------

#include <stdint.h>
// Mirrors app-ethereum's manage_asset_info.h, which includes shared_context.h.
// That transitively provides union extraInfo_t (via asset_info.h) as well as the
// `strings` / `chainConfig` globals several field formatters rely on through
// this header.
#include "shared_context.h"

const tokenDefinition_t *get_token_info_by_addr(const uint8_t *contractAddress);
#ifndef TARGET_NANOS
const nftInfo_t *get_nft_info_by_addr(const uint8_t *contractAddress);
#endif
