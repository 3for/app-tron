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
#include <stdint.h>

// swap_lib_calls.h defines Exchange amounts as at most 16-byte integers.
#define MAX_SWAP_AMOUNT_LENGTH 16
#define MAX_SWAP_TOKEN_LENGTH  15

bool swap_check_validity(const char *amount,
                         const char *tokenName,
                         const char *action,
                         const uint8_t *recipient,
                         const uint8_t *contractAddress,
                         uint64_t callValue,
                         uint64_t callTokenValue,
                         uint64_t tokenId,
                         uint64_t feeLimit,
                         bool feeLimitApplies);
