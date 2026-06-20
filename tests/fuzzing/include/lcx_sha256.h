#pragma once

// Host-side shim for the Ledger SDK <lcx_sha256.h>. The TIP-712 sources include
// it directly (context_712.h) for the SHA-2 context types and the SHA-224 digest
// size. The standalone fuzz build routes the actual type/function definitions
// through the existing cx.h mock; here we only add the size constant that the
// real lcx_sha256.h would provide.

#include "cx.h"

#ifndef CX_SHA224_SIZE
#define CX_SHA224_SIZE 28
#endif
