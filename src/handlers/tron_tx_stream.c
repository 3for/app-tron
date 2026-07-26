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
#include "tron_tx_stream.h"
#include "app_mem_utils.h"  // APP_MEM_CALLOC, APP_MEM_FREE_AND_NULL

static tron_stream_decoder_t *g_decoder = NULL;

bool tron_tx_stream_begin(size_t total_len, tron_trigger_data_observer_t observer, void *ctx) {
    tron_tx_stream_free();
    if (APP_MEM_CALLOC((void **) &g_decoder, sizeof(*g_decoder)) == false) {
        return false;
    }
    tron_stream_decoder_init_raw(g_decoder, total_len);
    tron_stream_decoder_set_trigger_data_observer(g_decoder, observer, ctx);
    return true;
}

void tron_tx_stream_set_custom_data_observer(tron_trigger_data_observer_t observer, void *ctx) {
    if (g_decoder != NULL) {
        tron_stream_decoder_set_custom_data_observer(g_decoder, observer, ctx);
    }
}

bool tron_tx_stream_feed(const uint8_t *data, size_t len) {
    return (g_decoder != NULL) && tron_stream_decoder_feed(g_decoder, data, len);
}

bool tron_tx_stream_is_done(void) {
    return (g_decoder != NULL) && tron_stream_decoder_is_done(g_decoder);
}

const tron_decode_result_t *tron_tx_stream_result(void) {
    return (g_decoder != NULL) ? &g_decoder->result : NULL;
}

bool tron_tx_stream_get_result(tron_decode_result_t *out) {
    return (g_decoder != NULL) && tron_stream_decoder_get_result(g_decoder, out);
}

void tron_tx_stream_free(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_decoder);
}
