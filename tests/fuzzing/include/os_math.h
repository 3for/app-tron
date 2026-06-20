#pragma once

// Host-side mock of the Ledger SDK <os_math.h> (MIN/MAX helpers), copied
// verbatim from the SDK so the GCS sources behave identically.

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
