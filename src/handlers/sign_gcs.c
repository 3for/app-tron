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

extern void reset_app_context();

// Generic Clear Signing signing instruction (INS_SIGN_GCS). Split out of
// handleSignExternalPlugin so GCS no longer rides on the external-plugin opcode:
//   - P2_GCS_START_FLOW: run the GCS review UI and sign (no streamed data).
//   - P2_GCS_STORE: stream a TriggerSmartContract and park its calldata into the
//     generic_tx_parser context for the 0x26 / 0x28 descriptors. No UI here.
// The streaming scaffolding is identical to the legacy path but uses the neutral
// tron_tx_stream module instead of sign_external_plugin.c internals.
int handleSignGcs(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    // Generic Clear Signing "start flow": carries no streamed data, so handle it
    // before the streaming logic below.
    if (p2 == P2_GCS_START_FLOW) {
        (void) p1;
        (void) workBuffer;
        if (dataLength != 0) {
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        return handle_gcs_start_flow();
    }

    if (p2 != P2_GCS_STORE) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        }
        appState = APP_STATE_SIGNING;
        off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
        if (ret < 0) {
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        if (dataLength < 4) {
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        uint32_t total_len = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;

        initTx(&txContext, &txContent);
        customContractField = 0;
        gcs_bridge_reset();
        if (!tron_tx_stream_begin(total_len, gcs_bridge_feed_data_chunk, NULL)) {
            reset_app_context();
            return io_send_sw(SWO_INSUFFICIENT_MEMORY);
        }
    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if (p1 == P1_MORE && appState != APP_STATE_SIGNING) {
        PRINTF("Signature not initialized\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // hash data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2, 0, workBuffer, dataLength, NULL, 32));

    // process buffer
    if (!tron_tx_stream_feed(workBuffer, dataLength)) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (p1 != P1_LAST && p1 != P1_SIGN) {
        return io_send_sw(E_OK);
    }

    if (!tron_tx_stream_is_done()) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    // The observer rebuilt the full EVM calldata into g_parked_calldata while
    // streaming. Register it as the root tx context, then wait for the
    // generic_tx_parser descriptors (0x26 / 0x28). No UI is shown here.
    const tron_decode_result_t *res = tron_tx_stream_result();
    bool ok = gcs_bridge_finalize(res->has_owner_address ? res->owner_address : NULL,
                                  res->has_contract_address ? res->contract_address : NULL,
                                  res->has_call_value ? (uint64_t) res->call_value : 0,
                                  TRON_MAINNET_CHAINID);
    tron_tx_stream_free();
    if (!ok) {
        gcs_bridge_abort();
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }
    // Finalize the transaction hash now (all tx bytes were fed into txContext.sha2
    // above). The GCS START_FLOW signs tmpCtx.transactionContext.hash, so it must be
    // populated here.
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                               CX_LAST,
                               workBuffer,
                               0,
                               tmpCtx.transactionContext.hash,
                               32));
    // Accept the incoming generic_tx_parser descriptors.
    appState = APP_STATE_SIGNING_TX;
    return io_send_sw(E_OK);
}
