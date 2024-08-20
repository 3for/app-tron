#include <stdint.h>

#include "public_keys.h"
#include "common_utils.h"
#include "parse.h"
#include "ui_globals.h"
#include "app_errors.h"

#ifdef HAVE_LEDGER_PKI
#include "os_pki.h"
#endif

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

    PRINTF("Provisioning currentAssetIndex %d\n", global_ctx.transactionContext.currentAssetIndex);

    if (dataLength < 1) {
        THROW(APDU_RESPONSE_INVALID_DATA);
    }
    tickerLength = workBuffer[offset++];
    dataLength--;
    if ((tickerLength + 1) > sizeof(token->ticker)) {
        THROW(APDU_RESPONSE_INVALID_DATA);
    }
    if (dataLength < tickerLength + 20 + 4 + 4) {
        THROW(APDU_RESPONSE_INVALID_DATA);
    }

    cx_hash_sha256(workBuffer + offset, tickerLength + 20 + 4 + 4, hash, 32);
    memmove(token->ticker, workBuffer + offset, tickerLength);
    token->ticker[tickerLength] = '\0';
    offset += tickerLength;
    dataLength -= tickerLength;
    memmove(token->address, workBuffer + offset, 20);
    offset += 20;
    dataLength -= 20;
    // TODO: 4 bytes for this is overkill
    token->decimals = U4BE(workBuffer, offset);
    offset += 4;
    dataLength -= 4;
    // TODO: Handle 64-bit long chain IDs
    chain_id = U4BE(workBuffer, offset);
    if (chainConfig->chainId != chain_id) {
        UNSUPPORTED_CHAIN_ID_MSG(chain_id);
        THROW(APDU_RESPONSE_INVALID_DATA);
    }
    offset += 4;
    dataLength -= 4;

    error = check_signature_with_pubkey("TRC20 Token Info",
                                        hash,
                                        sizeof(hash),
                                        LEDGER_SIGNATURE_PUBLIC_KEY,
                                        sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
#ifdef HAVE_LEDGER_PKI
                                        CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
#endif
                                        (uint8_t *) (workBuffer + offset),
                                        dataLength);
#ifndef HAVE_BYPASS_SIGNATURES
    if (error != CX_OK) {
        THROW(APDU_RESPONSE_INVALID_DATA);
    }
#endif
    G_io_apdu_buffer[0] = global_ctx.transactionContext.currentAssetIndex;
    validate_current_asset_info();
    U2BE_ENCODE(G_io_apdu_buffer, 1, APDU_RESPONSE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 3);
    return 0;
}
