/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2025 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#include "io.h"
#include "os_io_seproxyhal.h"

#include "helpers.h"          // read_bip32_path
#include "apdu_constants.h"   // INS/P2, appState, handler decl, shared_context
#include "app_errors.h"       // E_*, SWO_*
#include "ui_globals.h"       // customContractField
#include "parse.h"            // initTx, txContext, txContent
#include "transaction_trigger_decode.h"  // tron_decode_result_t
#include "gcs_calldata_bridge.h"          // gcs_bridge_*
#include "cmd_sign_flow.h"                // handle_gcs_start_flow
#include "tron_tx_stream.h"               // shared TriggerSmartContract decoder
#include "chain_config.h"                 // TRON_MAINNET_CHAINID
#include "settings.h"
#include "format.h"
#include "common_utils.h"
#include "gtp_field_table.h"
#include "gcs_limits.h"
#include "gcs_signing_context.h"
#include "gcs_memory.h"

extern void reset_app_context();

#define GCS_MEMO_DISPLAY_MAX 32U

typedef struct {
    bool active;
    bool memo_hash_initialized;
    bool memo_hash_ready;
    bool forced_fields_added;
    size_t raw_data_size;
    size_t raw_data_received;
    size_t store_apdu_count;
    size_t descriptor_bytes;
    size_t descriptor_count;
    size_t rendered_fields;
    size_t memo_received;
    tron_decode_result_t tx;
    cx_sha256_t memo_hash_ctx;
    uint8_t memo_hash[32];
} gcs_signing_context_t;

static gcs_signing_context_t g_gcs;

void gcs_signing_context_cleanup(void) {
    explicit_bzero(&g_gcs, sizeof(g_gcs));
}

bool gcs_signing_in_progress(void) {
    return g_gcs.active;
}

bool gcs_account_descriptor(size_t descriptor_size, bool rendered_field) {
    size_t next_bytes;
    size_t next_count;
    size_t next_fields;

    if (!g_gcs.active || (descriptor_size == 0U) ||
        (descriptor_size > GCS_MAX_DESCRIPTOR_SIZE) ||
        __builtin_add_overflow(g_gcs.descriptor_bytes, descriptor_size, &next_bytes) ||
        __builtin_add_overflow(g_gcs.descriptor_count, 1U, &next_count) ||
        __builtin_add_overflow(g_gcs.rendered_fields,
                               rendered_field ? 1U : 0U,
                               &next_fields) ||
        (next_bytes > GCS_MAX_DESCRIPTOR_THROUGHPUT_BYTES) ||
        (next_count > GCS_MAX_DESCRIPTOR_COUNT) ||
        (next_fields > GCS_MAX_RENDERED_FIELDS)) {
        return false;
    }
    g_gcs.descriptor_bytes = next_bytes;
    g_gcs.descriptor_count = next_count;
    g_gcs.rendered_fields = next_fields;
    return true;
}

static bool gcs_memo_observer(void *ctx,
                              const uint8_t *chunk,
                              size_t chunk_len,
                              size_t chunk_offset,
                              size_t total_len) {
    gcs_signing_context_t *session = ctx;
    size_t next;

    if ((session == NULL) || (chunk == NULL) || !session->memo_hash_initialized ||
        (chunk_offset != session->memo_received) ||
        __builtin_add_overflow(session->memo_received, chunk_len, &next) ||
        (next > total_len)) {
        return false;
    }
    if (cx_hash_no_throw((cx_hash_t *) &session->memo_hash_ctx,
                         0,
                         chunk,
                         chunk_len,
                         NULL,
                         0) != CX_OK) {
        return false;
    }
    session->memo_received = next;
    return true;
}

static bool format_sun(uint64_t value, char *out, size_t out_size) {
    uint8_t amount[INT256_LENGTH] = {0};

    for (size_t i = 0; i < sizeof(value); i++) {
        amount[INT256_LENGTH - 1U - i] = (uint8_t) (value >> (8U * i));
    }
    return amountToString(amount,
                          sizeof(amount),
                          SUN_TO_TRX,
                          chainConfig->coinName,
                          out,
                          out_size);
}

static bool memo_is_safely_printable(const tron_decode_result_t *tx) {
    if (!tx->has_custom_data || (tx->custom_data_len == 0U) ||
        (tx->custom_data_len > GCS_MEMO_DISPLAY_MAX) ||
        (tx->custom_data_prefix_len != tx->custom_data_len)) {
        return false;
    }
    for (size_t i = 0; i < tx->custom_data_len; i++) {
        if ((tx->custom_data_prefix[i] < 0x20U) || (tx->custom_data_prefix[i] > 0x7eU)) {
            return false;
        }
    }
    return true;
}

/*
 * Stateless TriggerSmartContract rules under the currently active mainnet
 * chain parameters:
 *   getAllowTvmTransferTrc10 = 1
 *   getAllowMultiSign = 1
 *
 * This mirrors VMActuator.checkTokenValueAndId(). Account/contract existence,
 * balances and mutable limits such as getMaxFeeLimit require current chain
 * state and therefore remain node-side checks.
 */
static bool trigger_values_match_mainnet(const tron_decode_result_t *tx) {
    const int64_t token_value = tx->has_call_token_value ? tx->call_token_value : 0;
    const int64_t token_id = tx->has_token_id ? tx->token_id : 0;

    return (!tx->has_call_value || (tx->call_value >= 0)) &&
           (token_value >= 0) && (token_id >= 0) &&
           ((token_id == 0) || (token_id > MIN_TRC10_TOKEN_ID)) &&
           ((token_value == 0) || (token_id != 0)) &&
           (!tx->has_fee_limit || (tx->fee_limit >= 0));
}

bool gcs_add_forced_fields(void) {
    char *buf = strings.tmp.tmp;
    const size_t buf_size = sizeof(strings.tmp.tmp);

    if (!g_gcs.active || g_gcs.forced_fields_added) {
        return false;
    }
    if (!tronBase58FromBinary(g_gcs.tx.owner_address + 1U, buf, buf_size) ||
        !add_to_field_table(PARAM_TYPE_RAW, "Account", buf, NULL)) {
        return false;
    }
    if (g_gcs.tx.has_permission_id && (g_gcs.tx.permission_id != 0U)) {
        if (!u64_to_string(g_gcs.tx.permission_id, buf, UINT8_MAX) ||
            !add_to_field_table(PARAM_TYPE_RAW, "Permission ID", buf, NULL)) {
            return false;
        }
    }
    if (g_gcs.tx.has_call_value && (g_gcs.tx.call_value != 0)) {
        if (!format_sun((uint64_t) g_gcs.tx.call_value, buf, buf_size) ||
            !add_to_field_table(PARAM_TYPE_AMOUNT, "TRX sent", buf, NULL)) {
            return false;
        }
    }
    if ((g_gcs.tx.has_call_token_value && (g_gcs.tx.call_token_value != 0)) ||
        (g_gcs.tx.has_token_id && (g_gcs.tx.token_id != 0))) {
        if (!u64_to_string((uint64_t) (g_gcs.tx.has_token_id ? g_gcs.tx.token_id : 0),
                           buf,
                           UINT8_MAX) ||
            !add_to_field_table(PARAM_TYPE_RAW, "TRC10 ID", buf, NULL) ||
            !u64_to_string(
                (uint64_t) (g_gcs.tx.has_call_token_value ? g_gcs.tx.call_token_value : 0),
                buf,
                UINT8_MAX) ||
            !add_to_field_table(PARAM_TYPE_RAW, "TRC10 amount", buf, NULL)) {
            return false;
        }
    }
    if (g_gcs.tx.has_custom_data) {
        if (!g_gcs.memo_hash_ready) {
            return false;
        }
        if (memo_is_safely_printable(&g_gcs.tx)) {
            memcpy(buf, g_gcs.tx.custom_data_prefix, g_gcs.tx.custom_data_len);
            buf[g_gcs.tx.custom_data_len] = '\0';
            if (!add_to_field_table(PARAM_TYPE_RAW, "Memo", buf, NULL)) {
                return false;
            }
        } else {
            if (bytes_to_lowercase_hex(buf,
                                       buf_size,
                                       g_gcs.memo_hash,
                                       sizeof(g_gcs.memo_hash)) < 0 ||
                !add_to_field_table(PARAM_TYPE_RAW, "Memo SHA-256", buf, NULL)) {
                return false;
            }
        }
        if (snprintf(buf, buf_size, "%u bytes", (unsigned int) g_gcs.tx.custom_data_len) <= 0 ||
            !add_to_field_table(PARAM_TYPE_RAW, "Memo size", buf, NULL)) {
            return false;
        }
    }
    if (!format_sun(g_gcs.tx.has_fee_limit ? (uint64_t) g_gcs.tx.fee_limit : 0U,
                    buf,
                    buf_size) ||
        !add_to_field_table(PARAM_TYPE_AMOUNT, "Energy fee limit", buf, NULL)) {
        return false;
    }
    if (snprintf(buf, buf_size, "%u bytes", (unsigned int) g_gcs.raw_data_size) <= 0 ||
        !add_to_field_table(PARAM_TYPE_RAW, "Transaction data size", buf, NULL) ||
        !add_to_field_table(PARAM_TYPE_RAW,
                            "Fee notice",
                            "Bandwidth, memo and multisig fees may apply",
                            NULL)) {
        return false;
    }
    g_gcs.forced_fields_added = true;
    return true;
}

static int send_gcs_status(uint16_t sw) {
    if (sw != E_OK) {
        reset_app_context();
    }
    return io_send_sw(sw);
}

// Generic Clear Signing signing instruction (INS_SIGN_GCS):
//   - P2_GCS_START_FLOW: run the GCS review UI and sign (no streamed data).
//   - P2_GCS_STORE: stream a TriggerSmartContract and park its calldata into the
//     generic_tx_parser context for the 0x26 / 0x28 descriptors. No UI here.
// The TriggerSmartContract streaming is done through the neutral tron_tx_stream module.
int handleSignGcs(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    // Generic Clear Signing "start flow": carries no streamed data, so handle it
    // before the streaming logic below.
    if (p2 == P2_GCS_START_FLOW) {
        (void) workBuffer;
        if ((p1 != P1_FIRST) || (dataLength != 0)) {
            return send_gcs_status(E_INCORRECT_LENGTH);
        }
        return handle_gcs_start_flow();
    }

    if (p2 != P2_GCS_STORE) {
        return send_gcs_status(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            return send_gcs_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        appState = APP_STATE_SIGNING_GCS_STORE;
        off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
        if (ret < 0) {
            return send_gcs_status(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        if (dataLength < 4) {
            return send_gcs_status(E_INCORRECT_LENGTH);
        }
        uint32_t total_len = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;

        if ((total_len == 0U) || (total_len > GCS_MAX_RAW_DATA_SIZE)) {
            return send_gcs_status(E_INCORRECT_LENGTH);
        }

        /* Metadata is immutable once STORE starts. Include all tracked
         * pre-session metadata in the 12 KiB live-memory ceiling. */
        if (!gcs_budget_begin()) {
            return send_gcs_status(SWO_INSUFFICIENT_MEMORY);
        }

        initTx(&txContext, &txContent);
        customContractField = 0;
        gcs_bridge_reset();
        gcs_signing_context_cleanup();
        g_gcs.active = true;
        g_gcs.raw_data_size = total_len;
        g_gcs.store_apdu_count = 1U;
        cx_sha256_init(&g_gcs.memo_hash_ctx);
        g_gcs.memo_hash_initialized = true;
        if (!tron_tx_stream_begin(total_len, gcs_bridge_feed_data_chunk, NULL)) {
            return send_gcs_status(SWO_INSUFFICIENT_MEMORY);
        }
        tron_tx_stream_set_custom_data_observer(gcs_memo_observer, &g_gcs);
    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return send_gcs_status(E_INCORRECT_P1_P2);
    }

    if (((p1 == P1_MORE) || (p1 == P1_LAST)) &&
        appState != APP_STATE_SIGNING_GCS_STORE) {
        PRINTF("Signature not initialized\n");
        return send_gcs_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // Context must be initialized first
    if (!txContext.initialized || !g_gcs.active) {
        PRINTF("Context not initialized\n");
        return send_gcs_status(E_INCORRECT_P1_P2);
    }

    if ((p1 == P1_MORE) || (p1 == P1_LAST)) {
        if ((dataLength == 0U) ||
            (++g_gcs.store_apdu_count > GCS_MAX_STORE_APDUS)) {
            return send_gcs_status(E_INCORRECT_LENGTH);
        }
    }
    if (dataLength > (g_gcs.raw_data_size - g_gcs.raw_data_received)) {
        return send_gcs_status(E_INCORRECT_LENGTH);
    }

    // hash data
    if (cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                         0,
                         workBuffer,
                         dataLength,
                         NULL,
                         0) != CX_OK) {
        return send_gcs_status(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    // process buffer
    if (!tron_tx_stream_feed(workBuffer, dataLength)) {
        return send_gcs_status(gcs_mem_take_allocation_failure()
                                   ? SWO_INSUFFICIENT_MEMORY
                                   : E_INCORRECT_DATA);
    }
    g_gcs.raw_data_received += dataLength;

    if (p1 != P1_LAST && p1 != P1_SIGN) {
        return send_gcs_status(E_OK);
    }

    if (!tron_tx_stream_is_done() ||
        (g_gcs.raw_data_received != g_gcs.raw_data_size)) {
        return send_gcs_status(E_INCORRECT_DATA);
    }

    // The observer rebuilt the full EVM calldata into g_parked_calldata while
    // streaming. Register it as the root tx context, then wait for the
    // generic_tx_parser descriptors (0x26 / 0x28). No UI is shown here.
    tron_decode_result_t decoded = {0};
    if (!tron_tx_stream_get_result(&decoded) ||
        !trigger_values_match_mainnet(&decoded) ||
        (decoded.data_len > GCS_MAX_ROOT_CALLDATA_TOTAL_SIZE) ||
        (decoded.has_custom_data && (g_gcs.memo_received != decoded.custom_data_len)) ||
        (decoded.has_custom_data && (decoded.custom_data_len != 0U) &&
         !N_storage.dataAllowed)) {
        uint16_t sw = (decoded.has_custom_data && (decoded.custom_data_len != 0U) &&
                       !N_storage.dataAllowed)
                          ? E_MISSING_SETTING_DATA_ALLOWED
                          : E_INCORRECT_DATA;
        tron_tx_stream_free();
        gcs_bridge_abort();
        return send_gcs_status(sw);
    }
    if (cx_hash_no_throw((cx_hash_t *) &g_gcs.memo_hash_ctx,
                         CX_LAST,
                         NULL,
                         0,
                         g_gcs.memo_hash,
                         sizeof(g_gcs.memo_hash)) != CX_OK) {
        tron_tx_stream_free();
        gcs_bridge_abort();
        return send_gcs_status(E_SECURITY_STATUS_NOT_SATISFIED);
    }
    g_gcs.memo_hash_ready = true;
    g_gcs.tx = decoded;
    bool ok = gcs_bridge_finalize(decoded.owner_address,
                                  decoded.contract_address,
                                  decoded.has_call_value ? (uint64_t) decoded.call_value : 0,
                                  TRON_MAINNET_CHAINID);
    tron_tx_stream_free();
    if (!ok) {
        gcs_bridge_abort();
        return send_gcs_status(gcs_mem_take_allocation_failure()
                                   ? SWO_INSUFFICIENT_MEMORY
                                   : E_INCORRECT_DATA);
    }
    // Finalize the transaction hash now (all tx bytes were fed into txContext.sha2
    // above). The GCS START_FLOW signs tmpCtx.transactionContext.hash, so it must be
    // populated here.
    if (cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                         CX_LAST,
                         NULL,
                         0,
                         tmpCtx.transactionContext.hash,
                         32) != CX_OK) {
        return send_gcs_status(E_SECURITY_STATUS_NOT_SATISFIED);
    }
    // Accept the incoming generic_tx_parser descriptors.
    appState = APP_STATE_SIGNING_TX;
    return send_gcs_status(E_OK);
}
