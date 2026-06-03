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
#include "io.h"

#include "app_errors.h"
#include "helpers.h"
#include "handlers.h"
#include "parse.h"
#include "ui_globals.h"

states191_t states191;

uint8_t processed_size_191;

typedef struct {
    uint32_t msg_length;
    uint32_t processed_size;
    uint8_t *received_buffer;
    char *display_buffer;
} signMessageFullDisplayContext_t;

static signMessageFullDisplayContext_t g_sign_msg_ctx;

extern void reset_app_context();

static void bytes_to_lowercase_hex_string(const uint8_t *data, size_t data_len, char *out) {
    static const char HEXDIGITS[] = "0123456789abcdef";

    for (size_t i = 0; i < data_len; i++) {
        out[2 * i] = HEXDIGITS[data[i] >> 4];
        out[2 * i + 1] = HEXDIGITS[data[i] & 0x0F];
    }
    out[2 * data_len] = '\0';
}

void cleanupSignPersonalMessageFullDisplay(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_sign_msg_ctx.received_buffer);
    APP_MEM_FREE_AND_NULL((void **) &g_sign_msg_ctx.display_buffer);
    explicit_bzero(&g_sign_msg_ctx, sizeof(g_sign_msg_ctx));
    processed_size_191 = 0;
    explicit_bzero(&states191, sizeof(states191));
}

static int first_apdu_data(uint8_t **work_buffer, uint16_t *data_length) {
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

    if (*data_length < sizeof(uint32_t)) {
        return E_INCORRECT_LENGTH;
    }

    cleanupSignPersonalMessageFullDisplay();
    g_sign_msg_ctx.msg_length = U4BE(*work_buffer, 0);
    if (g_sign_msg_ctx.msg_length > UINT16_MAX) {
        cleanupSignPersonalMessageFullDisplay();
        return E_INCORRECT_LENGTH;
    }
    txContent.dataBytes = g_sign_msg_ctx.msg_length;

    if (g_sign_msg_ctx.msg_length > 0) {
        if (APP_MEM_CALLOC((void **) &g_sign_msg_ctx.received_buffer,
                           (uint16_t) g_sign_msg_ctx.msg_length) == false) {
            cleanupSignPersonalMessageFullDisplay();
            return APDU_RESPONSE_INSUFFICIENT_MEMORY;
        }
    }

    *work_buffer += sizeof(uint32_t);
    *data_length -= sizeof(uint32_t);
    processed_size_191 += ret + sizeof(uint32_t);

    CX_ASSERT(cx_keccak_init_no_throw(&global_sha3, 256));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                               0,
                               (const uint8_t *) SIGN_MAGIC,
                               sizeof(SIGN_MAGIC) - 1,
                               NULL,
                               0));

    char length_str[11];
    snprintf(length_str, sizeof(length_str), "%d", (uint32_t) g_sign_msg_ctx.msg_length);
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                               0,
                               (const uint8_t *) length_str,
                               strlen(length_str),
                               NULL,
                               0));

    reset_ui_191_buffer();
    states191.sign_state = STATE_191_HASH_DISPLAY;
    states191.ui_started = false;

    return E_OK;
}

static int process_data(const uint8_t *data, uint16_t data_length) {
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3, 0, data, data_length, NULL, 0));
    txContent.dataBytes -= data_length;

    if (data_length > 0) {
        memcpy(g_sign_msg_ctx.received_buffer + g_sign_msg_ctx.processed_size, data, data_length);
        g_sign_msg_ctx.processed_size += data_length;
    }

    return E_OK;
}

static int final_process(const uint8_t *data) {
    bool is_hex = false;
    size_t display_buffer_length = g_sign_msg_ctx.msg_length;

    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                               CX_LAST,
                               data,
                               0,
                               tmpCtx.transactionContext.hash,
                               HASH_SIZE));

    for (uint32_t i = 0; i < g_sign_msg_ctx.msg_length; i++) {
        uint8_t c = g_sign_msg_ctx.received_buffer[i];
        if (!isprint((int) c) && !isspace((int) c)) {
            is_hex = true;
            display_buffer_length = (g_sign_msg_ctx.msg_length * 2U) + 2U;
            break;
        }
    }

    if ((display_buffer_length > (SIZE_MAX - 1U)) ||
        ((display_buffer_length + 1U) > UINT16_MAX)) {
        return E_INCORRECT_LENGTH;
    }

    if (APP_MEM_CALLOC((void **) &g_sign_msg_ctx.display_buffer,
                       (uint16_t) (display_buffer_length + 1U)) == false) {
        return APDU_RESPONSE_INSUFFICIENT_MEMORY;
    }

    if (is_hex) {
        memcpy(g_sign_msg_ctx.display_buffer, "0x", 2);
        bytes_to_lowercase_hex_string(g_sign_msg_ctx.received_buffer,
                                      g_sign_msg_ctx.msg_length,
                                      g_sign_msg_ctx.display_buffer + 2);
    } else {
#ifdef SCREEN_SIZE_NANO
        size_t out = 0;
        for (uint32_t i = 0; i < g_sign_msg_ctx.msg_length; i++) {
            char c = (char) g_sign_msg_ctx.received_buffer[i];
            g_sign_msg_ctx.display_buffer[out++] = isspace((int) c) ? ' ' : c;
        }
        g_sign_msg_ctx.display_buffer[out] = '\0';
#else
        memcpy(g_sign_msg_ctx.display_buffer,
               g_sign_msg_ctx.received_buffer,
               g_sign_msg_ctx.msg_length);
        g_sign_msg_ctx.display_buffer[g_sign_msg_ctx.msg_length] = '\0';
#endif
    }

    return E_OK;
}

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
    if (dataLength > txContent.dataBytes) {
        reset_app_context();
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    int sw = process_data(workBuffer, dataLength);
    if (sw != E_OK) {
        reset_app_context();
        return io_send_sw(sw);
    }

    if (txContent.dataBytes == 0) {
        sw = final_process(workBuffer);
        if (sw != E_OK) {
            reset_app_context();
            return io_send_sw(sw);
        }
        ui_191_start(g_sign_msg_ctx.display_buffer);
        return 0;
    }

    return io_send_sw(E_OK);
}
