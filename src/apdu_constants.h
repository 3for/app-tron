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
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "parser.h"
#include "app_errors.h"
// Pulled in so the ported generic_tx_parser command handlers see `appState` and
// the APP_STATE_* enum (app-ethereum's apdu_constants.h includes it likewise).
// The SWO_* status words used by that module come from the SDK's status_words.h.
#include "shared_context.h"

// Define command events
#define CLA 0xE0  // Start byte for any communications

// GET_APP_CONFIGURATION flag byte (resp[0]). Mirrors app-ethereum's APP_FLAG_*; the
// bit positions are the wire contract the host decodes, so they must stay stable.
#define APP_FLAG_DATA_ALLOWED     0x01
#define APP_FLAG_CUSTOM_CONTRACT  0x02
#define APP_FLAG_TRUNCATE_ADDRESS 0x04  // Deprecated; reserved and always returned clear.
#define APP_FLAG_SIGN_BY_HASH     0x08
#define APP_FLAG_VERBOSE_TIP712   0x10
#define APP_FLAG_DISPLAY_HASH     0x20

#define INS_GET_PUBLIC_KEY                     0x02
#define INS_SIGN                               0x04
#define INS_SIGN_TXN_HASH                      0x05  // unsafe
#define INS_GET_APP_CONFIGURATION              0x06  // version and settings
#define INS_SIGN_PERSONAL_MESSAGE              0x08
#define INS_SIGN_PERSONAL_MESSAGE_FULL_DISPLAY 0xC8
#define INS_GET_ECDH_SECRET                    0x0A
#define INS_SIGN_TIP_712_MESSAGE               0x0C
#define INS_TIP712_STRUCT_DEF                  0x1A
#define INS_TIP712_STRUCT_IMPL                 0x1C
#define INS_TIP712_FILTERING                   0x1E
// Generic Clear Signing signing instruction.
#define INS_SIGN_GCS                           0xD4

#define INS_PROVIDE_TRC20_TOKEN_INFORMATION 0xCA  // 0x0A in eth
#define INS_PROVIDE_NFT_INFORMATION         0x14  // same opcode as app-ethereum

#define INS_GET_CHALLENGE 0x20
#define INS_PROVIDE_TRUSTED_NAME  0x22
#define INS_PROVIDE_ENUM_VALUE    0x24  // same opcode as app-ethereum

// Generic Clear Signing (GCS / generic_tx_parser). Same opcodes as app-ethereum.
#define INS_GTP_TRANSACTION_INFO 0x26
#define INS_GTP_FIELD            0x28
#define INS_PROVIDE_PROXY_INFO   0x2A

// Gated/"dated" signing descriptor. Same opcode as app-ethereum.
#define INS_PROVIDE_GATING 0x38

#define P1_CONFIRM     0x01
#define P1_NON_CONFIRM 0x00

#define P1_SIGN        0x10
#define P1_FIRST       0x00
#define P1_MORE        0x80
#define P1_FIRST_CHUNK 0x01
#define P1_LAST        0x90

#define P1_TRC10_NAME 0xA0
#define P1_FOLLOWING_CHUNK 0x00

#define MAX_PERSONAL_MESSAGE_LENGTH 4096U
#define MAX_PERSONAL_MESSAGE_APDUS   64U

#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE    0x01

// INS_SIGN_GCS (0xD4): store the TriggerSmartContract calldata into the
// generic_tx_parser context (Generic Clear Signing). No approval is shown; the
// 0x26/0x28 descriptors and the start-of-flow command follow.
#define P2_GCS_STORE 0x10
// Generic Clear Signing "start flow": sent after the 0x26/0x28 descriptors to run
// the GCS review UI and sign. Sibling of P2_GCS_STORE on INS_SIGN_GCS.
#define P2_GCS_START_FLOW 0x11

#define P2_TIP712_LEGACY_IMPLEM 0x00
#define P2_TIP712_FULL_IMPLEM   0x01

/* Full TIP-712 uses P1=1 to initialize and lock the signing path before any
 * schema/filter/calldata APDU, then P1=0 for the final sign command. */
#define P1_TIP712_SIGN 0x00
#define P1_TIP712_INIT 0x01

int apdu_dispatcher(const command_t *cmd);

int handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength);
int handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleSignByHash(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleSignPersonalMessage(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleECDHSecret(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
uint16_t handleSignTIP712Message(uint8_t p1, const uint8_t *workBuffer, uint8_t dataLength);
int handleSignPersonalMessageFullDisplay(uint8_t p1,
                                         uint8_t p2,
                                         uint8_t *workBuffer,
                                         uint16_t dataLength);
int personal_message_format_for_display(char *buffer, size_t raw_length, size_t capacity);
void message_cleanup(void);
void personal_message_legacy_cleanup(void);
bool personal_message_review_in_progress(void);
void sign_cleanup(void);
bool sign_review_in_progress(void);
int handleProvideTrc20TokenInformation(uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t *workBuffer,
                                       uint8_t dataLength);
int handleProvideNFTInformation(uint8_t p1,
                                uint8_t p2,
                                const uint8_t *workBuffer,
                                uint8_t dataLength);
// Generic Clear Signing signing (INS_SIGN_GCS): P2_GCS_STORE streams the
// TriggerSmartContract, P2_GCS_START_FLOW runs the review + signs.
int handleSignGcs(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
