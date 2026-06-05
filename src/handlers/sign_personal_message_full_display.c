/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#include <ctype.h>
#include <stdint.h>
#include <string.h>

#include "app_mem_utils.h"
#include "cx.h"
#include "format.h"
#include "io.h"

#include "app_errors.h"
#include "helpers.h"
#include "apdu_constants.h"
#include "parse.h"
#include "ui_globals.h"

// Kept structurally aligned with app-ethereum's
// src/features/sign_message/cmd_sign_message.c (handle_sign_personal_message)
// to ease side-by-side audit. Tron-specific differences are limited to the wire
// protocol (P1_SIGN / p2 check / direct-return IO model), the SIGN_MAGIC string
// (shared, defined in ui_globals.h) and the signature production path, which
// stays routed through ui_callback_signMessage_ok / signTransaction reading
// tmpCtx.transactionContext.

typedef struct {
    uint16_t msg_length;
    uint16_t processed_size;
    char *received_buffer;
    char *display_buffer;
} signMsgCtx_t;

static cx_sha3_t *g_msg_hash_ctx = NULL;
static signMsgCtx_t *signMsgCtx = NULL;

extern void reset_app_context();

/**
 * Cleanup the TIP-191 signing context
 *
 * Frees the message buffers, the signing context and the dedicated hash
 * context. Called from reset_app_context().
 */
void message_cleanup(void) {
    if (signMsgCtx != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &signMsgCtx->received_buffer);
        APP_MEM_FREE_AND_NULL((void **) &signMsgCtx->display_buffer);
    }
    APP_MEM_FREE_AND_NULL((void **) &signMsgCtx);
    APP_MEM_FREE_AND_NULL((void **) &g_msg_hash_ctx);
}

/**
 * Handle the data specific to the first APDU of an TIP-191 signature
 *
 * @param[in,out] work_buffer the APDU payload
 * @param[in,out] data_length the payload size
 * @return whether it was successful or not
 */
static int first_apdu_data(uint8_t **work_buffer, uint16_t *data_length) {
    // Initialize the message context
    message_cleanup();

    // Parse the derivation path
    off_t ret = read_bip32_path(*work_buffer, *data_length, &tmpCtx.transactionContext.bip32_path);
    if (ret < 0) {
        return E_INCORRECT_BIP32_PATH;
    }

    publicKeyContext_t tmp_public_key_ctx;
    if (initPublicKeyContext(&tmpCtx.transactionContext.bip32_path,
                             fromAddress,
                             &tmp_public_key_ctx) != 0) {
        return E_SECURITY_STATUS_NOT_SATISFIED;
    }

    *work_buffer += ret;
    *data_length -= ret;

    // Check if the length is valid
    if (*data_length < sizeof(uint32_t)) {
        return E_INCORRECT_LENGTH;
    }

    if (APP_MEM_CALLOC((void **) &signMsgCtx, sizeof(signMsgCtx_t)) == false) {
        PRINTF("Memory allocation failed for Sign Context\n");
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }

    // Get the message length. The wire format uses 4 bytes but the rest of the
    // flow tracks it as a uint16_t, so reject anything that would not fit.
    uint32_t msg_length = U4BE(*work_buffer, 0);
    if (msg_length > UINT16_MAX) {
        return E_INCORRECT_LENGTH;
    }
    signMsgCtx->msg_length = (uint16_t) msg_length;

    // Allocate the buffer for the message
    if (signMsgCtx->msg_length > 0) {
        if (APP_MEM_CALLOC((void **) &signMsgCtx->received_buffer, signMsgCtx->msg_length) ==
            false) {
            PRINTF("Error: Not enough memory!\n");
            return APDU_RESPONSE_INSUFFICIENT_MEMORY;
        }
    }

    // Skip data & length to the message itself
    *work_buffer += sizeof(uint32_t);
    *data_length -= sizeof(uint32_t);

    if (APP_MEM_CALLOC((void **) &g_msg_hash_ctx, sizeof(cx_sha3_t)) == false) {
        PRINTF("Memory allocation failed for Sign Hash\n");
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }

    // Initialize message header + length hash
    CX_ASSERT(cx_keccak_init_no_throw(g_msg_hash_ctx, 256));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx,
                               0,
                               (const uint8_t *) SIGN_MAGIC,
                               sizeof(SIGN_MAGIC) - 1,
                               NULL,
                               0));

    char length_str[11];
    snprintf(length_str, sizeof(length_str), "%u", signMsgCtx->msg_length);
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx,
                               0,
                               (const uint8_t *) length_str,
                               strlen(length_str),
                               NULL,
                               0));

    return E_OK;
}

/**
 * Process the received data and hash it
 *
 * @param[in] data the new data
 * @param[in] length the data length
 * @return whether it was successful or not
 */
static int process_data(const uint8_t *data, uint16_t length) {
    // Hash the data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx, 0, data, length, NULL, 0));

    // Copy the data to the buffer
    if (length > 0) {
        memcpy(&signMsgCtx->received_buffer[signMsgCtx->processed_size], data, length);
        signMsgCtx->processed_size += length;
    }

    return E_OK;
}

/**
 * Finalize the hash computation, and prepare the display buffer
 *
 * @return whether it was successful or not
 */
static int final_process(void) {
    bool is_hex = false;
    uint16_t buffer_length;

    // Finalize hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx,
                               CX_LAST,
                               NULL,
                               0,
                               tmpCtx.transactionContext.hash,
                               HASH_SIZE));

    // Guard against uint16_t overflow in the display buffer length calculation.
    // In the worst case (hex path) the length becomes msg_length * 2 + 3, so
    // reject messages that would cause that expression to exceed UINT16_MAX.
    if (signMsgCtx->msg_length > ((UINT16_MAX - 3) / 2)) {
        PRINTF("Error: message too long (%u > %u)\n",
               signMsgCtx->msg_length,
               ((UINT16_MAX - 3) / 2));
        return E_INCORRECT_LENGTH;
    }

    // Display buffer length
    buffer_length = signMsgCtx->msg_length;

    // Determine if the buffer is Ascii or hex
    for (uint16_t i = 0; i < signMsgCtx->msg_length; i++) {
        uint8_t c = (uint8_t) signMsgCtx->received_buffer[i];
        if (!isprint((int) c) && !isspace((int) c)) {
            // Hexadecimal message
            is_hex = true;
            buffer_length *= 2;  // To convert hex byte to char
            buffer_length += 2;  // for "0x"
            break;
        }
    }

    // Allocate the buffer for the display
    buffer_length++;  // for the NULL byte
    if (APP_MEM_CALLOC((void **) &signMsgCtx->display_buffer, buffer_length) == false) {
        PRINTF("Error: Not enough memory!\n");
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }

    if (is_hex) {
        // Copy the "0x" prefix
        memcpy(signMsgCtx->display_buffer, "0x", 2);
        // Convert the message to ascii
        if (bytes_to_lowercase_hex(signMsgCtx->display_buffer + 2,
                                   buffer_length - 2,
                                   (const uint8_t *) signMsgCtx->received_buffer,
                                   signMsgCtx->msg_length) < 0) {
            // Should never happen, buffer is large enough
            PRINTF("Error: Not enough memory!\n");
            return APDU_RESPONSE_INSUFFICIENT_MEMORY;
        }
    } else {
#ifdef SCREEN_SIZE_NANO
        uint16_t j = 0;
        for (uint16_t i = 0; i < signMsgCtx->msg_length; i++) {
            char c = signMsgCtx->received_buffer[i];
            // to replace all white-space characters as spaces
            signMsgCtx->display_buffer[j++] = isspace((int) c) ? ' ' : c;
        }
        signMsgCtx->display_buffer[j] = '\0';
#else   // SCREEN_SIZE_NANO
        // Copy the message to the display buffer
        memcpy(signMsgCtx->display_buffer, signMsgCtx->received_buffer, signMsgCtx->msg_length);
        signMsgCtx->display_buffer[signMsgCtx->msg_length] = '\0';
#endif  // SCREEN_SIZE_NANO
    }

    // The dedicated hash context is no longer needed
    APP_MEM_FREE_AND_NULL((void **) &g_msg_hash_ctx);
    return E_OK;
}

/**
 * TIP-191 (full display) APDU handler
 *
 * @param[in] p1 instruction parameter 1
 * @param[in] p2 instruction parameter 2
 * @param[in] workBuffer received data
 * @param[in] dataLength data length
 * @return whether the handling of the APDU was successful or not
 */
int handleSignPersonalMessageFullDisplay(uint8_t p1,
                                         uint8_t p2,
                                         uint8_t *workBuffer,
                                         uint16_t dataLength) {
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        appState = APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY;

        int sw = first_apdu_data(&workBuffer, &dataLength);
        if (sw != E_OK) {
            reset_app_context();
            return io_send_sw(sw);
        }
    } else if (p1 != P1_MORE) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_P1_P2);
    } else if (appState != APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY) {
        PRINTF("Error: App not already in signing state!\n");
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (p2 != 0) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // Check if the context is valid
    if (signMsgCtx == NULL) {
        PRINTF("Error: Invalid data received!\n");
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }

    // Check if the received chunk data is too long
    if ((dataLength + signMsgCtx->processed_size) > signMsgCtx->msg_length) {
        PRINTF("Error: Length mismatch ! (%u > %u)!\n",
               (dataLength + signMsgCtx->processed_size),
               signMsgCtx->msg_length);
        reset_app_context();
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    int sw = process_data(workBuffer, dataLength);
    if (sw != E_OK) {
        reset_app_context();
        return io_send_sw(sw);
    }

    // Start the UI if the buffer is fully received
    if (signMsgCtx->processed_size == signMsgCtx->msg_length) {
        sw = final_process();
        if (sw != E_OK) {
            reset_app_context();
            return io_send_sw(sw);
        }
        ui_191_start(signMsgCtx->display_buffer);
        return 0;
    }

    return io_send_sw(E_OK);
}
