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
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "transaction_trigger_decode.h"  // tron_stream_decoder_t, observer, result

// Neutral owner of the streamed TriggerSmartContract decoder, shared by the GCS
// signing path (INS_SIGN_GCS) and the legacy external-plugin path
// (INS_SIGN_EXTERNAL_PLUGIN). Decoupling the decoder lets the GCS handler avoid any
// dependency on sign_external_plugin.c so the latter can be removed wholesale later.

// (Re)allocate the decoder for `total_len` bytes and install `observer`. Any previous
// decoder is freed first. Returns false on allocation failure.
bool tron_tx_stream_begin(size_t total_len, tron_trigger_data_observer_t observer, void *ctx);

// Feed one chunk of streamed data. Returns false if the decoder is inactive or the
// chunk fails to decode.
bool tron_tx_stream_feed(const uint8_t *data, size_t len);

// Whether the full declared length has been streamed and decoded.
bool tron_tx_stream_is_done(void);

// The (possibly partial) decode result, or NULL when no stream is active.
const tron_decode_result_t *tron_tx_stream_result(void);

// Free the decoder (no-op when inactive).
void tron_tx_stream_free(void);
