#include <stdint.h>

#include "io.h"
#include "public_keys.h"
#include "common_utils.h"
#include "parse.h"
#include "ui_globals.h"
#include "app_errors.h"
#include "os_pki.h"
#include "helpers.h"

int handleProvideTrc20TokenInformation(uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t *workBuffer,
                                       uint8_t dataLength) {
    UNUSED(p1);
    UNUSED(p2);
    uint32_t offset = 0;
    uint8_t tickerLength;
    uint64_t chain_id;
    uint8_t hash[INT256_LENGTH];
    tokenDefinition_t *token = &get_current_asset_info()->token;
    cx_err_t error = CX_INTERNAL_ERROR;

    PRINTF("Provisioning currentAssetIndex %d\n", tmpCtx.transactionContext.currentAssetIndex);

    if (dataLength < 1) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    tickerLength = workBuffer[offset++];
    dataLength--;
    if ((tickerLength + 1) > sizeof(token->ticker)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    if (dataLength < tickerLength + BASE58CHECK_ADDRESS_SIZE + 4 + 4) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    cx_hash_sha256(workBuffer + offset, tickerLength + BASE58CHECK_ADDRESS_SIZE + 4 + 4, hash, 32);
    memmove(token->ticker, workBuffer + offset, tickerLength);
    token->ticker[tickerLength] = '\0';
    offset += tickerLength;
    dataLength -= tickerLength;

    {
        uint8_t decoded_address[TRON_ADDRESS_SIZE];
        if (!getAddressFromBase58((const char *) (workBuffer + offset),
                                  BASE58CHECK_ADDRESS_SIZE,
                                  decoded_address)) {
            return io_send_sw(E_INCORRECT_DATA);
        }
        // Internally only the last 20 bytes (the canonical EVM address) are retained.
        // So the existing `get_asset_info_by_addr()` and UI/token comparison logic
        // do not need to be refactored.
        memmove(token->address, decoded_address + 1, ADDRESS_LENGTH);
    }
    offset += BASE58CHECK_ADDRESS_SIZE;
    dataLength -= BASE58CHECK_ADDRESS_SIZE;
    // TODO: 4 bytes for this is overkill
    token->decimals = U4BE(workBuffer, offset);
    offset += 4;
    dataLength -= 4;
    // TODO: Handle 64-bit long chain IDs
    chain_id = U4BE(workBuffer, offset);
    if (chainConfig->chainId != chain_id) {
        UNSUPPORTED_CHAIN_ID_MSG(chain_id);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += 4;
    dataLength -= 4;

    error = check_signature_with_pubkey("TRC20 Token Info",
                                        hash,
                                        sizeof(hash),
                                        LEDGER_SIGNATURE_PUBLIC_KEY,
                                        sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                        CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
                                        (uint8_t *) (workBuffer + offset),
                                        dataLength);
    if (error != CX_OK) {
        PRINTF("Invalid token signature\n");
#ifndef HAVE_BYPASS_SIGNATURES
        return io_send_sw(E_INCORRECT_DATA);
#endif
    }
    G_io_apdu_buffer[0] = tmpCtx.transactionContext.currentAssetIndex;
    validate_current_asset_info();
    return io_send_response_pointer(G_io_apdu_buffer, 1, E_OK);
}
