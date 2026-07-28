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
#include "parse.h"
#include "shared_context.h"

#define MAX_VOTE_COUNT        30
#define VOTE_ADDRESS          0
#define VOTE_ADDRESS_SIZE     BASE58CHECK_ADDRESS_SIZE + 1
#define VOTE_AMOUNT           VOTE_ADDRESS_SIZE
#define VOTE_AMOUNT_SIZE      21
// Wallet-size devices keep address and amount in separate regions. Nano devices
// reuse the whole pack for the single-screen "<address>\n<amount>" string.
#define VOTE_PACK             (VOTE_ADDRESS_SIZE + VOTE_AMOUNT_SIZE)
#define voteSlot(index, type) ((index * VOTE_PACK) + type)

// Stable G_io_apdu_buffer/reviewDisplayBuffer slots used by the custom-contract
// review. Decimal uint64 values need at most 20 digits plus the terminator.
#define CUSTOM_CONTRACT_TRX_OFFSET          0
#define CUSTOM_CONTRACT_TRC10_ID_OFFSET     100
#define CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET 124
#define CUSTOM_CONTRACT_UINT64_SLOT_SIZE     24

// AccountPermissionUpdate clear-sign display. Expanded fields:
// name, operations, threshold, and each authorized key/weight.
#define PERM_MAX_FIELDS 80
#define PERM_ITEM_LEN   32
#define PERM_VAL_LEN    96
extern uint8_t perm_field_count;
extern const char *perm_field_items[PERM_MAX_FIELDS];
extern char (*perm_field_labels)[PERM_ITEM_LEN];
extern char (*perm_field_values)[PERM_VAL_LEN];

#if defined(LARGE_ICON_SIZE) && (LARGE_ICON_SIZE == 64)
#define APP_TRON_ICON C_app_tron_64px
#elif defined(LARGE_ICON_SIZE) && (LARGE_ICON_SIZE == 48)
#define APP_TRON_ICON C_app_tron_48px
#else
#define APP_TRON_ICON C_app_tron_48px
#endif  // LARGE_ICON_SIZE

#if !defined(SCREEN_SIZE_WALLET)
#define APP_TRON_HOME_ICON C_icon
#else
#define APP_TRON_HOME_ICON APP_TRON_ICON
#endif

extern volatile uint8_t customContractField;
// The transaction display strings (fromAddress, toAddress, addressSummary,
// fullContract, url, TRC20Action, TRC20ActionSendAllow, fullHash) live in
// txStringProperties_t (shared_context.h) and are accessed via `strings.common.*`,
// mirroring app-ethereum.
extern uint8_t votes_count;
extern char *vote_display_buffer;
extern cx_sha3_t global_sha3;
extern strings_t strings;

static const char SIGN_MAGIC[] = "\x19TRON Signed Message:\n";

bool ui_callback_tx_ok(bool display_menu);
bool ui_callback_tx_cancel(bool display_menu);
bool ui_callback_address_ok(bool display_menu);
bool ui_callback_signMessage_ok(bool display_menu);
bool ui_callback_ecdh_ok(bool display_menu);

// TIP-191 personal-message review entry point. The message is rendered from a
// heap-allocated display buffer (signMsgCtx, see sign_personal_message_full_display.c),
// mirroring app-ethereum's ui_191_start(const char *message).
void ui_191_start(const char *message);
void ui_191_cleanup(void);

// ui_typed_message_review_choice() is declared in ui_message_signing.h.

void ui_error_blind_signing(void);
void ui_error_custom_contract(void);
