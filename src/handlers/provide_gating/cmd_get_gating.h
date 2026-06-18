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
 *
 ********************************************************************************/

#pragma once

#ifdef HAVE_GATING_SUPPORT

#include <stdint.h>
#include <stdbool.h>

// Mirrors app-ethereum's src/features/provide_gating/cmd_get_gating.h.
// TRON divergences: handle_gating() uses the (p1, p2, lc, data) argument order of
// the other TRON TLV handlers, and the TX path reads the shared txContent struct
// (legacy protobuf signing) instead of app-ethereum's RLP tx structures.
uint16_t handle_gating(uint8_t p1, uint8_t p2, uint8_t length, const uint8_t *data);

void clear_gating(void);
bool set_gating_warning(void);

// Legacy blind-signing (custom contract) entry point: resets the NBGL warning set,
// flags blind+gated signing, and runs the gating descriptor match. Returns false
// when a provided descriptor does not match the transaction (caller must abort).
// Mirrors the gating block of app-ethereum's ux_approve_tx().
bool set_blind_sign_gating_warning(void);

#endif  // HAVE_GATING_SUPPORT
