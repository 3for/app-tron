#pragma once
// Host-side shim for the SDK <ox_ec.h> (low-level EC definitions). Routed through
// the cx.h mock, which defines the curve ids the GCS sources reference.
#include "cx.h"

// Uncompressed secp256 public key size (0x04 prefix + X + Y), per the SDK.
#ifndef CX_SECP256_PUB_KEY_SIZE
#define CX_SECP256_PUB_KEY_SIZE 65
#endif
