/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ui_logic.h"  // e_tip712_filtering_mode

/**
 * Common TIP-712 primitives shared by the legacy (v0 domain/message hash)
 * review and the full filtered TIP-712 flow.
 *
 * Mirrors app-ethereum's src/features/sign_message_eip712_common/common_712.{c,h}
 * to keep the two apps structurally aligned and minimise audit complexity.
 */

uint16_t ui_712_start(e_tip712_filtering_mode filtering);

bool tip712_hash_to_sign(uint8_t hash[static 32]);

void tip712_format_hash(uint8_t index, const char **item, const char **value);

// NB: app-ethereum exposes `void ui_712_{approve,reject}_cb(void)`. TRON keeps a
// `display_menu` flag that gates the trailing ui_idle() redraw (the v0 review
// path passes false, the full flow passes true) and returns the signing status,
// which reviewChoice() inspects. These are deliberate, documented divergences.
bool ui_712_approve_cb(bool display_menu);
bool ui_712_reject_cb(bool display_menu);
