#pragma once

// ---------------------------------------------------------------------------
// GCS P1 STUB.
//
// app-ethereum resolves proxy contracts (INS_PROVIDE_PROXY_INFO, 0x2A) so that
// the generic_tx_parser can match a transaction's "to" address against the
// implementation contract behind a proxy. Tron does not support 0x2A yet, so
// this stub keeps the same public interface as app-ethereum's proxy_info.h but
// always reports "no proxy known". To be replaced when proxy support lands.
// ---------------------------------------------------------------------------

#include <stdint.h>
#include "common_utils.h"  // ADDRESS_LENGTH

// Returns the implementation contract for the given proxy address, or NULL when
// no matching proxy descriptor is known (always NULL in the P1 stub).
const uint8_t *get_implem_contract(const uint64_t *chain_id,
                                   const uint8_t *addr,
                                   const uint8_t *selector);

// Returns the proxy address fronting the given implementation address, or NULL
// when none is known (always NULL in the P1 stub).
const uint8_t *get_proxy_contract(const uint64_t *chain_id,
                                  const uint8_t *addr,
                                  const uint8_t *selector);

void proxy_cleanup(void);
