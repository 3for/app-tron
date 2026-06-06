#pragma once

// ---------------------------------------------------------------------------
// GCS P1 STUB.
//
// app-ethereum exposes get_public_key() to retrieve the signer's own 20-byte
// (EVM-style, no 0x41 prefix) address. The generic_tx_parser uses it to fill a
// transaction's "from" field and to substitute the wallet address into
// trusted-name lookups.
//
// P1 only exercises PARAM_TYPE_RAW, where the sender address is not displayed,
// so this stub returns a zeroed address. A proper derivation from the active
// signing BIP32 path must be implemented before the AMOUNT / TRUSTED_NAME field
// types are enabled. Signature matches app-ethereum's get_public_key.h.
// ---------------------------------------------------------------------------

#include <stdint.h>

uint16_t get_public_key(uint8_t *out, uint8_t outLength);
