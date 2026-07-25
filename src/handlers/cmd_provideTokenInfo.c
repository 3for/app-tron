#include <stdint.h>

#include "io.h"
#include "public_keys.h"
#include "common_utils.h"
#include "network.h"
#include "ui_globals.h"
#include "app_errors.h"
#include "os_pki.h"
#include "parse.h"

int handleProvideTrc20TokenInformation(uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t *workBuffer,
                                       uint8_t dataLength) {
    uint32_t offset = 0;
    uint32_t decimals;
    uint8_t tickerLength;
    uint64_t chain_id;
    uint8_t hash[INT256_LENGTH];
    extraInfo_t candidate = {0};
    tokenDefinition_t *token = &candidate.token;
    int asset_index;

    PRINTF("Provisioning currentAssetIndex %d\n", tmpCtx.transactionContext.currentAssetIndex);

    if ((p1 != 0x00) || (p2 != 0x00)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    if (dataLength < 1) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    tickerLength = workBuffer[offset++];
    dataLength--;
    if ((tickerLength + 1) > sizeof(token->ticker)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    if (dataLength < tickerLength + TRON_BASE58CHECK_ADDRESS_SIZE + 4 + 4) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    cx_hash_sha256(workBuffer + offset,
                   tickerLength + TRON_BASE58CHECK_ADDRESS_SIZE + 4 + 4,
                   hash,
                   32);
    memmove(token->ticker, workBuffer + offset, tickerLength);
    token->ticker[tickerLength] = '\0';
    offset += tickerLength;
    dataLength -= tickerLength;
    // The address is a 34-char TRON Base58Check string ("T..."); decode +
    // checksum-validate it to the canonical 20-byte (EVM) form retained internally,
    // so typed asset lookup and the UI/token comparison logic are unchanged.
    if (!tronBase58ToBinaryLen((const char *) (workBuffer + offset),
                               TRON_BASE58CHECK_ADDRESS_SIZE,
                               token->address)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += TRON_BASE58CHECK_ADDRESS_SIZE;
    dataLength -= TRON_BASE58CHECK_ADDRESS_SIZE;
    // TODO: 4 bytes for this is overkill
    decimals = U4BE(workBuffer, offset);
    if (decimals > UINT8_MAX) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    token->decimals = (uint8_t) decimals;
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

    if (!check_signature_with_pubkey(hash,
                                     sizeof(hash),
                                     LEDGER_SIGNATURE_PUBLIC_KEY,
                                     sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                     CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
                                     (uint8_t *) (workBuffer + offset),
                                     dataLength)) {
        PRINTF("Invalid token signature\n");
#ifndef HAVE_BYPASS_SIGNATURES
        return io_send_sw(E_INCORRECT_DATA);
#endif
    }
    asset_index = commit_current_asset_info(ASSET_KIND_TOKEN, &candidate);
    if (asset_index < 0) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    G_io_apdu_buffer[0] = (uint8_t) asset_index;
    return io_send_response_pointer(G_io_apdu_buffer, 1, E_OK);
}
