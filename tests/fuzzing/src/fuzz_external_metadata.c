#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu_constants.h"
#include "cmd_enum_value.h"
#include "cmd_proxy_info.h"
#include "cmd_trusted_name.h"
#include "enum_value.h"
#include "proxy_info.h"
#include "trusted_name.h"
#include "tlv_apdu.h"
#include "shared_context.h"
#include "app_errors.h"
#include "lcx_ecdsa.h"
#include "ui_globals.h"
#include "parse.h"

void fuzz_external_metadata_set_certificate_status(uint8_t control);
void fuzz_external_metadata_reset_assets(void);
int handleProvideTrc20TokenInformation(uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t *workBuffer,
                                       uint8_t dataLength);
int handleProvideNFTInformation(uint8_t p1,
                                uint8_t p2,
                                const uint8_t *workBuffer,
                                uint8_t dataLength);

/*
 * Byte stream format:
 *   certificate status (1 byte), followed by zero or more APDU records:
 *   ins (1), p1 (1), p2 (1), payload length (1), payload (length).
 *
 * First chunks contain the production two-byte total TLV length prefix. The
 * fuzzer controls instruction interleaving and p1, so complete, fragmented,
 * restarted, oversized and truncated metadata streams all share one harness.
 */
static void fuzz_external_metadata_apdu_stream(const uint8_t *data, size_t size) {
    uint8_t payload[UINT8_MAX];

    while (size >= 4U) {
        const uint8_t ins = data[0];
        const uint8_t p1 = data[1];
        const uint8_t p2 = data[2];
        size_t payload_len = data[3];
        data += 4U;
        size -= 4U;

        if (payload_len > size) {
            payload_len = size;
        }
        if (payload_len != 0U) {
            memcpy(payload, data, payload_len);
        }

        switch (ins) {
            case INS_PROVIDE_TRUSTED_NAME:
                (void) handle_trusted_name(p1, p2, payload, (uint8_t) payload_len);
                break;
            case INS_PROVIDE_PROXY_INFO:
                (void) handle_proxy_info(p1, p2, (uint8_t) payload_len, payload);
                break;
            case INS_PROVIDE_ENUM_VALUE:
                (void) handle_enum_value(p1, p2, (uint8_t) payload_len, payload);
                break;
            case INS_PROVIDE_TRC20_TOKEN_INFORMATION:
            case INS_PROVIDE_NFT_INFORMATION: {
                transactionContext_t before = tmpCtx.transactionContext;
                int sw = (ins == INS_PROVIDE_TRC20_TOKEN_INFORMATION)
                             ? handleProvideTrc20TokenInformation(p1,
                                                                 p2,
                                                                 payload,
                                                                 (uint8_t) payload_len)
                             : handleProvideNFTInformation(p1,
                                                           p2,
                                                           payload,
                                                           (uint8_t) payload_len);
                if (sw != E_OK) {
                    if (memcmp(&before,
                               &tmpCtx.transactionContext,
                               sizeof(before)) != 0) {
                        __builtin_trap();
                    }
                } else {
                    asset_kind_t expected_kind =
                        (ins == INS_PROVIDE_TRC20_TOKEN_INFORMATION)
                            ? ASSET_KIND_TOKEN
                            : ASSET_KIND_NFT;
                    if (!asset_slot_is_kind(G_io_apdu_buffer[0], expected_kind)) {
                        __builtin_trap();
                    }
                }
                break;
            }
            default:
                break;
        }

        data += payload_len;
        size -= payload_len;
    }
}

static void reset_external_metadata_context(void) {
    tlv_apdu_reset();
    trusted_name_cleanup();
    proxy_cleanup();
    enum_value_cleanup();
    fuzz_external_metadata_reset_assets();
}

static void assert_metadata_lookup_null_guards(void) {
    static const uint64_t chain_id = 1U;
    static const uint8_t address[ADDRESS_LENGTH] = {0};
    static const uint8_t selector[4] = {0};
    static const e_name_type type = TN_TYPE_ACCOUNT;
    static const e_name_source source = TN_SOURCE_ENS;

    if ((get_matching_enum(NULL, address, selector, 0, 0) != NULL) ||
        (get_matching_enum(&chain_id, NULL, selector, 0, 0) != NULL) ||
        (get_matching_enum(&chain_id, address, NULL, 0, 0) != NULL) ||
        (get_trusted_name(1, NULL, 1, &source, &chain_id, address) != NULL) ||
        (get_trusted_name(1, &type, 1, NULL, &chain_id, address) != NULL) ||
        (get_trusted_name(1, &type, 1, &source, NULL, address) != NULL) ||
        (get_trusted_name(1, &type, 1, &source, &chain_id, NULL) != NULL)) {
        __builtin_trap();
    }
}

static void assert_trc20_signature_length_guards(void) {
    static const uint8_t address[] = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH";
    static const size_t signature_lengths[] = {
        0U,
        CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH - 1U,
        CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH,
        CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH,
        CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH + 1U,
    };
    uint8_t payload[1U + 3U + sizeof(address) - 1U + 4U + 4U +
                    CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH + 1U] = {0};
    size_t offset = 0U;

    payload[offset++] = 3U;
    memcpy(payload + offset, "TOK", 3U);
    offset += 3U;
    memcpy(payload + offset, address, sizeof(address) - 1U);
    offset += sizeof(address) - 1U;
    payload[offset + 3U] = 6U;
    offset += 4U;
    payload[offset++] = 0x2bU;
    payload[offset++] = 0x66U;
    payload[offset++] = 0x53U;
    payload[offset++] = 0xdcU;

    /* The PKI stub reports success, so only the handler's explicit length
     * guard can reject the non-canonical cases. */
    fuzz_external_metadata_set_certificate_status(0U);
    for (size_t i = 0U; i < ARRAY_SIZE(signature_lengths); i++) {
        const size_t signature_len = signature_lengths[i];
        const bool canonical =
            (signature_len >= CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH) &&
            (signature_len <= CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH);

        fuzz_external_metadata_reset_assets();
        memset(payload + offset, 0x30, signature_len);
        int sw = handleProvideTrc20TokenInformation(0U,
                                                    0U,
                                                    payload,
                                                    (uint8_t) (offset + signature_len));
        if ((sw == E_OK) != canonical) {
            __builtin_trap();
        }
    }
    fuzz_external_metadata_reset_assets();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    reset_external_metadata_context();
    assert_metadata_lookup_null_guards();
    assert_trc20_signature_length_guards();
    if (size != 0U) {
        fuzz_external_metadata_set_certificate_status(*data++);
        size--;
        fuzz_external_metadata_apdu_stream(data, size);
    }
    /* Valid corpus entries leave populated enum/trusted-name lists here, so
     * repeat the checks after parsing to exercise the guards before iteration. */
    assert_metadata_lookup_null_guards();
    reset_external_metadata_context();
    return 0;
}
