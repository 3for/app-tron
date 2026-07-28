#pragma once

#include <stdint.h>

// Retrieve the signer's own 20-byte (EVM-style, no 0x41 prefix) address,
// derived from the active signing BIP32 path (tmpCtx.transactionContext).
// The generic_tx_parser uses it to fill a transaction's "from" field and to
// substitute the wallet address into trusted-name lookups.
// Signature matches app-ethereum's get_public_key.h.
uint16_t get_public_key(uint8_t *out, uint8_t outLength);
uint16_t get_public_key_from_path(uint8_t *out,
                                  uint8_t outLength,
                                  const uint32_t *path,
                                  uint8_t pathLength);
