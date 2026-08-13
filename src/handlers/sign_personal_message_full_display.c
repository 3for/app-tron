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
#include <stdint.h>
#include <string.h>

#include "app_mem_utils.h"
#include "cx.h"
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
    uint16_t apdu_count;
    size_t message_buffer_size;
    char *message_buffer;
} signMsgCtx_t;

#define PERSONAL_MESSAGE_HEX_PREFIX       "\\hex:0x"
#define PERSONAL_MESSAGE_DISPLAY_OVERHEAD 8U

_Static_assert(PERSONAL_MESSAGE_DISPLAY_OVERHEAD >= sizeof(PERSONAL_MESSAGE_HEX_PREFIX),
               "personal-message display overhead must include hex prefix and terminator");

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
    ui_191_cleanup();
    if (signMsgCtx != NULL) {
        if (signMsgCtx->message_buffer != NULL) {
            explicit_bzero(signMsgCtx->message_buffer, signMsgCtx->message_buffer_size);
        }
        APP_MEM_FREE_AND_NULL((void **) &signMsgCtx->message_buffer);
        explicit_bzero(signMsgCtx, sizeof(*signMsgCtx));
    }
    APP_MEM_FREE_AND_NULL((void **) &signMsgCtx);
    if (g_msg_hash_ctx != NULL) {
        explicit_bzero(g_msg_hash_ctx, sizeof(*g_msg_hash_ctx));
    }
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
    uint32_t msg_length;

    // Initialize the message context
    message_cleanup();

    // Parse the derivation path
    off_t ret = read_bip32_path(*work_buffer, *data_length, &tmpCtx.transactionContext.bip32_path);
    if (ret < 0) {
        return SWO_INCORRECT_DATA;
    }

    *work_buffer += ret;
    *data_length -= ret;

    // Check if the length is valid
    if (*data_length < sizeof(uint32_t)) {
        return SWO_INCORRECT_DATA;
    }

    // Apply the real display/heap limit before doing key work or allocating.
    msg_length = U4BE(*work_buffer, 0);
    if (msg_length > MAX_PERSONAL_MESSAGE_LENGTH) {
        PRINTF("Error: message too long (%u > %u)\n",
               msg_length,
               MAX_PERSONAL_MESSAGE_LENGTH);
        return SWO_INCORRECT_DATA;
    }

    publicKeyContext_t tmp_public_key_ctx;
    if (initPublicKeyContext(&tmpCtx.transactionContext.bip32_path,
                             strings.common.fromAddress,
                             &tmp_public_key_ctx) != 0) {
        return E_INTERNAL_ERROR;
    }

    if (APP_MEM_CALLOC((void **) &signMsgCtx, sizeof(signMsgCtx_t)) == false) {
        PRINTF("Memory allocation failed for Sign Context\n");
        return SWO_INSUFFICIENT_MEMORY;
    }
    signMsgCtx->msg_length = (uint16_t) msg_length;
    signMsgCtx->apdu_count = 1;

    // Allocate the final worst-case representation up front. The same buffer
    // first receives the raw message and is later expanded backwards in place,
    // avoiding the raw + hex allocation peak and reporting OOM in the first
    // APDU rather than after the complete message has been transferred.
    signMsgCtx->message_buffer_size =
        ((size_t) signMsgCtx->msg_length * 2U) + PERSONAL_MESSAGE_DISPLAY_OVERHEAD;
    if (APP_MEM_CALLOC((void **) &signMsgCtx->message_buffer,
                       signMsgCtx->message_buffer_size) == false) {
        PRINTF("Error: Not enough memory!\n");
        return SWO_INSUFFICIENT_MEMORY;
    }

    // Skip data & length to the message itself
    *work_buffer += sizeof(uint32_t);
    *data_length -= sizeof(uint32_t);

    if (APP_MEM_CALLOC((void **) &g_msg_hash_ctx, sizeof(cx_sha3_t)) == false) {
        PRINTF("Memory allocation failed for Sign Hash\n");
        return SWO_INSUFFICIENT_MEMORY;
    }

    // Initialize message header + length hash
    if ((cx_keccak_init_no_throw(g_msg_hash_ctx, 256) != CX_OK) ||
        (cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx,
                          0,
                          (const uint8_t *) SIGN_MAGIC,
                          sizeof(SIGN_MAGIC) - 1,
                          NULL,
                          0) != CX_OK)) {
        return E_INTERNAL_ERROR;
    }

    char length_str[11];
    snprintf(length_str, sizeof(length_str), "%u", signMsgCtx->msg_length);
    if (cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx,
                         0,
                         (const uint8_t *) length_str,
                         strlen(length_str),
                         NULL,
                         0) != CX_OK) {
        return E_INTERNAL_ERROR;
    }

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
    if (cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx, 0, data, length, NULL, 0) != CX_OK) {
        return E_INTERNAL_ERROR;
    }

    // Copy the data to the buffer
    if (length > 0) {
        memcpy(&signMsgCtx->message_buffer[signMsgCtx->processed_size], data, length);
        signMsgCtx->processed_size += length;
    }

    return E_OK;
}

/**
 * Format a raw personal message in place for an unambiguous review.
 *
 * Printable ASCII remains readable. Backslash and common whitespace controls
 * use visible C-style escapes; any other byte makes the whole message use a
 * lowercase 0x-prefixed hexadecimal representation. Expanding from the end
 * permits source and destination to share the same allocation.
 *
 * @return the display length, or -1 when the supplied capacity is insufficient
 */
int personal_message_format_for_display(char *buffer, size_t raw_length, size_t capacity) {
    static const char HEX_DIGITS[] = "0123456789abcdef";
    // Raw backslashes are doubled in the text path, so no text message can
    // collide with this single-backslash binary marker.
    static const char HEX_PREFIX[] = PERSONAL_MESSAGE_HEX_PREFIX;
    bool is_hex = false;
    size_t display_length = 0;

    if ((buffer == NULL) ||
        (raw_length > ((SIZE_MAX - PERSONAL_MESSAGE_DISPLAY_OVERHEAD) / 2U))) {
        return -1;
    }

    for (size_t i = 0; i < raw_length; i++) {
        const uint8_t c = (uint8_t) buffer[i];
        if (((c < 0x20U) || (c > 0x7eU)) &&
            (c != '\n') && (c != '\r') && (c != '\t') &&
            (c != '\v') && (c != '\f')) {
            is_hex = true;
            break;
        }
        display_length += ((c == '\\') || (c == '\n') || (c == '\r') ||
                           (c == '\t') || (c == '\v') || (c == '\f'))
                              ? 2U
                              : 1U;
    }

    if (is_hex) {
        display_length = (sizeof(HEX_PREFIX) - 1U) + (raw_length * 2U);
    }
    if (capacity <= display_length) {
        return -1;
    }

    if (is_hex) {
        for (size_t i = raw_length; i > 0U; i--) {
            const uint8_t c = (uint8_t) buffer[i - 1U];
            const size_t out = (sizeof(HEX_PREFIX) - 1U) + ((i - 1U) * 2U);
            buffer[out] = HEX_DIGITS[c >> 4];
            buffer[out + 1U] = HEX_DIGITS[c & 0x0fU];
        }
        memcpy(buffer, HEX_PREFIX, sizeof(HEX_PREFIX) - 1U);
    } else {
        size_t out = display_length;
        for (size_t i = raw_length; i > 0U; i--) {
            const uint8_t c = (uint8_t) buffer[i - 1U];
            char escaped = '\0';
            switch (c) {
                case '\\': escaped = '\\'; break;
                case '\n': escaped = 'n'; break;
                case '\r': escaped = 'r'; break;
                case '\t': escaped = 't'; break;
                case '\v': escaped = 'v'; break;
                case '\f': escaped = 'f'; break;
                default: break;
            }
            if (escaped != '\0') {
                out -= 2U;
                buffer[out] = '\\';
                buffer[out + 1U] = escaped;
            } else {
                out--;
                buffer[out] = (char) c;
            }
        }
    }
    buffer[display_length] = '\0';
    return (int) display_length;
}

/**
 * Finalize the hash computation, and prepare the display buffer
 *
 * @return whether it was successful or not
 */
static int final_process(void) {
    // Finalize hash
    if (cx_hash_no_throw((cx_hash_t *) g_msg_hash_ctx,
                         CX_LAST,
                         NULL,
                         0,
                         tmpCtx.transactionContext.hash,
                         HASH_SIZE) != CX_OK) {
        return E_INTERNAL_ERROR;
    }

    if (personal_message_format_for_display(signMsgCtx->message_buffer,
                                            signMsgCtx->msg_length,
                                            signMsgCtx->message_buffer_size) < 0) {
        return E_INCORRECT_DATA;
    }

    // The dedicated hash context is no longer needed
    explicit_bzero(g_msg_hash_ctx, sizeof(*g_msg_hash_ctx));
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
    if (personal_message_review_in_progress()) {
        return io_send_sw(SWO_COMMAND_NOT_ALLOWED);
    }
    if (p2 != 0) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        }
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
            return io_send_sw(SWO_COMMAND_NOT_ALLOWED);
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
        return io_send_sw(SWO_COMMAND_NOT_ALLOWED);
    }

    // Check if the context is valid
    if ((signMsgCtx == NULL) || (g_msg_hash_ctx == NULL)) {
        PRINTF("Error: Invalid data received!\n");
        reset_app_context();
        return io_send_sw(E_INCORRECT_DATA);
    }
    if (p1 == P1_MORE) {
        if ((signMsgCtx->apdu_count >= MAX_PERSONAL_MESSAGE_APDUS) ||
            ((dataLength == 0) &&
             (signMsgCtx->processed_size != signMsgCtx->msg_length))) {
            reset_app_context();
            return io_send_sw(SWO_INCORRECT_DATA);
        }
        signMsgCtx->apdu_count++;
    }

    // Check if the received chunk data is too long
    if ((dataLength + signMsgCtx->processed_size) > signMsgCtx->msg_length) {
        PRINTF("Error: Length mismatch ! (%u > %u)!\n",
               (dataLength + signMsgCtx->processed_size),
               signMsgCtx->msg_length);
        reset_app_context();
        return io_send_sw(SWO_INCORRECT_DATA);
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
        appState = APP_STATE_REVIEWING_PERSONAL_MESSAGE;
        ui_191_start(signMsgCtx->message_buffer);
        return 0;
    }

    return io_send_sw(E_OK);
}
