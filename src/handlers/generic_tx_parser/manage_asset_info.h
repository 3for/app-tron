#pragma once

// ---------------------------------------------------------------------------
// GCS dependency header.
//
// The generic_tx_parser TOKEN / TOKEN_AMOUNT / NFT field formatters look up
// token/NFT metadata (ticker, decimals, collection name) via
// get_asset_info_by_addr(). app-ethereum declares this in manage_asset_info.h;
// app-tron already implements it in parse.c (backed by the TRC20 token registry
// populated through INS_PROVIDE_TRC20_TOKEN_INFORMATION), so this header just
// re-declares it for the ported module with app-ethereum's signature.
// ---------------------------------------------------------------------------

#include <stdint.h>
// Mirrors app-ethereum's manage_asset_info.h, which includes shared_context.h.
// That transitively provides union extraInfo_t (via asset_info.h) as well as the
// `strings` / `chainConfig` globals several field formatters rely on through
// this header.
#include "shared_context.h"

// Returns metadata for the given contract address, or NULL when unknown
// (always NULL in the P1 stub).
extraInfo_t *get_asset_info_by_addr(const uint8_t *contractAddress);
