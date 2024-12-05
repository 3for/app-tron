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

#include <stdint.h>

#include "parser.h"

// Define command events
#define CLA 0xE0  // Start byte for any communications

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

#define INS_PROVIDE_TRC20_TOKEN_INFORMATION 0xCA  // 0x0A in eth

#define INS_ENS_GET_CHALLENGE 0x20
#define INS_ENS_PROVIDE_INFO  0x22

#define P1_CONFIRM     0x01
#define P1_NON_CONFIRM 0x00

#define P1_SIGN  0x10
#define P1_FIRST 0x00
#define P1_MORE  0x80
#define P1_LAST  0x90

#define P1_TRC10_NAME 0xA0

#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE    0x01

#define P2_TIP712_LEGACY_IMPLEM 0x00
#define P2_TIP712_FULL_IMPLEM   0x01

int apdu_dispatcher(const command_t *cmd);

int handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength);
int handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleSignByHash(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleSignPersonalMessage(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleECDHSecret(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleSignTIP712Message(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength);
int handleSignPersonalMessageFullDisplay(uint8_t p1,
                                         uint8_t p2,
                                         uint8_t *workBuffer,
                                         uint16_t dataLength);
#ifndef TARGET_NANOS
int handleProvideTrc20TokenInformation(uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t *workBuffer,
                                       uint8_t dataLength);
#endif