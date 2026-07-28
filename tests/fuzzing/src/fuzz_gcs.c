#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu_constants.h"
#include "cmd_field.h"
#include "cmd_tx_info.h"
#include "gcs_calldata_bridge.h"
#include "gcs_signing_context.h"
#include "gcs_memory.h"
#include "gtp_field.h"
#include "gtp_param_raw.h"
#include "gtp_path_slice.h"
#include "gtp_value.h"
#include "tlv_apdu.h"
#include "tron_tx_stream.h"
#include "tx_ctx.h"
#include "parse.h"
#include "shared_context.h"
#include "utils.h"

void init_tip712_fuzz_environment(void);
void fuzz_set_settings(uint8_t value);
void reset_app_context(void);

static void assert_gcs_parser_guards(void) {
    s_field field = {0};
    s_parsed_value parsed = {0};
    s_value signed_def = {.type_family = TF_INT, .type_size = 1U};
    s_value signed16_def = {.type_family = TF_INT, .type_size = 2U};
    uint8_t signed16_encoded[] = {0xffU, 0xfeU};
    uint8_t encoded[INT256_LENGTH] = {0};
    char formatted[80] = {0};
    bool displayed = false;
    uint8_t wide[INT256_LENGTH + 1U] = {0};
    uint8_t canonical_word[INT256_LENGTH] = {0};
    uint8_t normalized[INT256_LENGTH] = {0};
    uint8_t address[ADDRESS_LENGTH] = {0};
    uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0};

    field.param_type = PARAM_TYPE_RAW;
    field.visibility = PARAM_VISIBILITY_ALWAYS;
    memcpy(field.name, "guard", sizeof("guard"));
    field.param_raw.value.source = SOURCE_CONSTANT;

    /* A C-string renderer must never accept a value whose signed calldata
     * suffix would be hidden after an embedded NUL or layout control byte. */
    field.param_raw.value.type_family = TF_STRING;
    memcpy(field.param_raw.value.constant.buf, "pay Alice\0pay Mallory", 21U);
    field.param_raw.value.constant.size = 21U;
    if (format_param_raw(&field)) {
        __builtin_trap();
    }
    memcpy(field.param_raw.value.constant.buf, "line1\nline2", 11U);
    field.param_raw.value.constant.size = 11U;
    if (format_param_raw(&field)) {
        __builtin_trap();
    }

    field.param_raw.value.type_family = TF_BOOL;
    field.param_raw.value.constant.buf[0] = 2U;
    field.param_raw.value.constant.size = 1U;
    if (format_param_raw(&field)) {
        __builtin_trap();
    }

    /* A full ABI address word may only discard its canonical zero padding. */
    memset(field.param_raw.value.constant.buf, 0, sizeof(field.param_raw.value.constant.buf));
    field.param_raw.value.type_family = TF_ADDRESS;
    field.param_raw.value.constant.buf[0] = 1U;
    field.param_raw.value.constant.size = INT256_LENGTH;
    if (format_param_raw(&field)) {
        __builtin_trap();
    }

    /* Narrow unsigned values reject non-zero discarded bytes. The optional
     * width still defaults to uint256 for existing descriptors. */
    encoded[0] = 1U;
    encoded[INT256_LENGTH - 1U] = 7U;
    field.param_raw.value.type_family = TF_UINT;
    field.param_raw.value.type_size = 1U;
    parsed.ptr = encoded;
    parsed.length = sizeof(encoded);
    if (format_uint(&field, &displayed, &parsed, formatted, sizeof(formatted))) {
        __builtin_trap();
    }
    field.param_raw.value.type_size = 0U;
    if (!format_uint(&field, &displayed, &parsed, formatted, sizeof(formatted))) {
        __builtin_trap();
    }

    /* Signed narrow integers require canonical sign extension and must retain
     * their sign in the rendered decimal string. */
    memset(encoded, 0xff, sizeof(encoded));
    if (!format_int(&signed_def, &parsed, formatted, sizeof(formatted)) ||
        (strcmp(formatted, "-1") != 0)) {
        __builtin_trap();
    }
    memset(encoded, 0, sizeof(encoded));
    encoded[INT256_LENGTH - 1U] = 0xffU;
    if (format_int(&signed_def, &parsed, formatted, sizeof(formatted))) {
        __builtin_trap();
    }
    parsed.ptr = signed16_encoded;
    parsed.length = sizeof(signed16_encoded);
    if (!format_int(&signed16_def, &parsed, formatted, sizeof(formatted)) ||
        (strcmp(formatted, "-2") != 0)) {
        __builtin_trap();
    }

    /* Specialized formatters share these canonical conversion guards. Values
     * that would lose a non-zero high byte must never be silently truncated. */
    parsed.ptr = wide;
    parsed.length = sizeof(wide);
    if (parsed_value_to_uint_be(&parsed, normalized, sizeof(normalized))) {
        __builtin_trap();
    }
    parsed.ptr = canonical_word;
    parsed.length = sizeof(canonical_word);
    canonical_word[0] = 1U;
    if (parsed_value_to_uint_be(&parsed, normalized, sizeof(uint64_t))) {
        __builtin_trap();
    }
    canonical_word[0] = 0U;
    canonical_word[INT256_LENGTH - 1U] = 7U;
    if (!parsed_value_to_uint_be(&parsed, normalized, sizeof(uint64_t)) ||
        (normalized[sizeof(uint64_t) - 1U] != 7U)) {
        __builtin_trap();
    }

    memset(canonical_word, 0, sizeof(canonical_word));
    canonical_word[INT256_LENGTH - TRON_ADDRESS_SIZE] = TRON_MAINNET_ADDRESS_PREFIX;
    canonical_word[INT256_LENGTH - 1U] = 0xaaU;
    if (!parsed_value_to_address(&parsed, address) ||
        (address[ADDRESS_LENGTH - 1U] != 0xaaU)) {
        __builtin_trap();
    }
    canonical_word[0] = 1U;
    if (parsed_value_to_address(&parsed, address)) {
        __builtin_trap();
    }
    parsed.ptr = canonical_word;
    parsed.length = CALLDATA_SELECTOR_SIZE;
    if (!parsed_value_to_selector(&parsed, selector)) {
        __builtin_trap();
    }
    parsed.ptr = NULL;
    parsed.length = 0U;
    memset(normalized, 0xa5, sizeof(normalized));
    if (parsed_value_to_uint_be(&parsed, normalized, sizeof(normalized)) ||
        !buf_shrink_expand(NULL, 0U, normalized, sizeof(normalized)) ||
        !allzeroes(normalized, sizeof(normalized))) {
        __builtin_trap();
    }

    /* Repeated calls must have deterministic duplicate-tag state. */
    {
        static uint8_t valid_slice[] = {0x01, 0x02, 0x00, 0x01,
                                        0x02, 0x02, 0x00, 0x03};
        static uint8_t duplicate_start[] = {0x01, 0x02, 0x00, 0x01,
                                            0x01, 0x02, 0x00, 0x02};
        buffer_t valid = {.ptr = valid_slice, .size = sizeof(valid_slice), .offset = 0U};
        buffer_t duplicate = {.ptr = duplicate_start,
                              .size = sizeof(duplicate_start),
                              .offset = 0U};
        s_slice_args args = {0};
        s_path_slice_context context = {.args = &args};

        if (!handle_slice_struct(&valid, &context) || !args.has_start ||
            !args.has_end || (args.start != 1) || (args.end != 3)) {
            __builtin_trap();
        }
        memset(&args, 0, sizeof(args));
        if (handle_slice_struct(&duplicate, &context)) {
            __builtin_trap();
        }
    }
}

static void assert_asset_type_isolation(void) {
#ifndef TARGET_NANOS
    static const uint8_t nft_address[ADDRESS_LENGTH] = {
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
        0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    };
    const uint8_t index = MAX_ASSETS - 1U;

    memcpy(tmpCtx.transactionContext.extraInfo[index].nft.contractAddress,
           nft_address,
           sizeof(nft_address));
    tmpCtx.transactionContext.assetSet[index] = true;
    tmpCtx.transactionContext.assetKind[index] = ASSET_KIND_NFT;
    if ((get_token_info_by_addr(nft_address) != NULL) ||
        (get_nft_info_by_addr(nft_address) == NULL)) {
        __builtin_trap();
    }
#endif
}

/*
 * Byte stream format:
 *   settings (1 byte), followed by zero or more APDU records:
 *   ins (1), p1 (1), p2 (1), payload length (1), payload (length).
 *
 * The supported instructions form the complete Generic Clear Signing flow:
 * SIGN_GCS/STORE streams and parks a TriggerSmartContract, GTP_TRANSACTION_INFO
 * and GTP_FIELD provide its signed descriptors, and SIGN_GCS/START_FLOW checks
 * the field hash and starts review. Keeping the APDU framing under fuzzer
 * control also covers restarts, invalid ordering and truncated streams.
 */
static void fuzz_gcs_apdu_stream(const uint8_t *data, size_t size) {
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
            case INS_SIGN_GCS:
                (void) handleSignGcs(p1, p2, payload, (uint16_t) payload_len);
                break;
            case INS_GTP_TRANSACTION_INFO:
                if (handle_tx_info(p1, p2, (uint8_t) payload_len, payload) != SWO_SUCCESS) {
                    reset_app_context();
                }
                break;
            case INS_GTP_FIELD:
                if (handle_field(p1, p2, (uint8_t) payload_len, payload) != SWO_SUCCESS) {
                    reset_app_context();
                }
                break;
            default:
                break;
        }

        data += payload_len;
        size -= payload_len;
    }
}

/* Complete the firmware reset semantics for this target's GCS-owned globals. */
void fuzz_reset_extra_context(void) {
    tlv_apdu_reset();
    tron_tx_stream_free();
    gcs_bridge_abort();
    gcs_cleanup();
    gcs_signing_context_cleanup();
    (void) gcs_budget_end();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_tip712_fuzz_environment();
    assert_gcs_parser_guards();
    assert_asset_type_isolation();
    if (size != 0U) {
        fuzz_set_settings(*data++);
        size--;
        fuzz_gcs_apdu_stream(data, size);
    }
    fuzz_reset_extra_context();
    return 0;
}
