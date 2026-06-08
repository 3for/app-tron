#include "get_public_key.h"
#include "shared_context.h"  // tmpCtx
#include "common_utils.h"    // getEthAddressFromRawKey, ADDRESS_LENGTH
#include "crypto_helpers.h"  // bip32_derive_get_pubkey_256
#include "apdu_constants.h"  // SWO_* status words
#include "ox_ec.h"           // CX_SECP256_PUB_KEY_SIZE

uint16_t get_public_key(uint8_t *out, uint8_t outLength) {
    uint8_t raw_pubkey[CX_SECP256_PUB_KEY_SIZE];
    cx_err_t error;

    if (outLength < ADDRESS_LENGTH) {
        return SWO_WRONG_DATA_LENGTH;
    }
    // TRON adaptation: the signing BIP32 path lives in
    // tmpCtx.transactionContext.bip32_path (indices/length), set by
    // handleSignExternalPlugin (including the GCS STORE flow).
    if ((error = bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                             tmpCtx.transactionContext.bip32_path.indices,
                                             tmpCtx.transactionContext.bip32_path.length,
                                             raw_pubkey,
                                             NULL,
                                             CX_SHA512)) != CX_OK) {
        PRINTF("Error: could not derive pubkey!\n");
        return error;
    }
    // Canonical 20-byte EVM address (no 0x41 prefix), matching the generic_tx_parser.
    getEthAddressFromRawKey(raw_pubkey, out);
    return SWO_SUCCESS;
}
