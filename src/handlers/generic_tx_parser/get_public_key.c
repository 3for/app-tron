#include "get_public_key.h"
#include "shared_context.h"  // tmpCtx
#include "common_utils.h"    // getEthAddressFromRawKey, ADDRESS_LENGTH
#include "crypto_helpers.h"  // bip32_derive_get_pubkey_256
#include "apdu_constants.h"  // SWO_* status words
#include "ox_ec.h"           // CX_SECP256_PUB_KEY_SIZE

uint16_t get_public_key_from_path(uint8_t *out,
                                  uint8_t outLength,
                                  const uint32_t *path,
                                  uint8_t pathLength) {
    uint8_t raw_pubkey[CX_SECP256_PUB_KEY_SIZE];
    cx_err_t error;

    if ((out == NULL) || (outLength < ADDRESS_LENGTH) || (path == NULL) ||
        (pathLength == 0U) || (pathLength > MAX_BIP32_PATH)) {
        return SWO_WRONG_DATA_LENGTH;
    }
    if ((error = bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                             path,
                                             pathLength,
                                             raw_pubkey,
                                             NULL,
                                             CX_SHA512)) != CX_OK) {
        PRINTF("Error: could not derive pubkey!\n");
        explicit_bzero(raw_pubkey, sizeof(raw_pubkey));
        return error;
    }
    // Canonical 20-byte EVM address (no 0x41 prefix), matching the generic_tx_parser.
    getEthAddressFromRawKey(raw_pubkey, out);
    explicit_bzero(raw_pubkey, sizeof(raw_pubkey));
    return SWO_SUCCESS;
}

uint16_t get_public_key(uint8_t *out, uint8_t outLength) {
    return get_public_key_from_path(out,
                                    outLength,
                                    tmpCtx.transactionContext.bip32_path.indices,
                                    tmpCtx.transactionContext.bip32_path.length);
}
