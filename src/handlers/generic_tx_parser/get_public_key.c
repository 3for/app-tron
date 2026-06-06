#include <string.h>
#include "get_public_key.h"
#include "app_errors.h"

// GCS P1 STUB - see get_public_key.h.
// TODO(GCS): derive the real signer address from the active signing BIP32 path
// before enabling AMOUNT / TRUSTED_NAME field types.

uint16_t get_public_key(uint8_t *out, uint8_t outLength) {
    memset(out, 0, outLength);
    return E_OK;
}
