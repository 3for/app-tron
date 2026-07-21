/*******************************************************************************
 *   Ledger TRON App
 *   (c) 2026-2029 Ledger
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

#include "common_utils.h"
#include "cx.h"
#include "os.h"

/*
--8<-- [start:tx_content_explanation]
Transaction data are provided to the plugin by the TRON application through
the `txContent_t` structure.

This structure is provided in every handler.
--8<-- [end:tx_content_explanation]
*/

// --8<-- [start:tx_content_structures]
typedef enum contractType_e {
    ACCOUNTCREATECONTRACT = 0,
    TRANSFERCONTRACT,
    TRANSFERASSETCONTRACT,
    VOTEASSETCONTRACT,
    VOTEWITNESSCONTRACT,
    WITNESSCREATECONTRACT,
    ASSETISSUECONTRACT,
    WITNESSUPDATECONTRACT = 8,
    PARTICIPATEASSETISSUECONTRACT,
    ACCOUNTUPDATECONTRACT,
    FREEZEBALANCECONTRACT,
    UNFREEZEBALANCECONTRACT,
    WITHDRAWBALANCECONTRACT,
    UNFREEZEASSETCONTRACT,
    UPDATEASSETCONTRACT,
    PROPOSALCREATECONTRACT,
    PROPOSALAPPROVECONTRACT,
    PROPOSALDELETECONTRACT,
    SETACCOUNTIDCONTRACT,
    CUSTOMCONTRACT,
    CREATESMARTCONTRACT = 30,
    TRIGGERSMARTCONTRACT,
    UPDATESETTINGCONTRACT = 33,
    EXCHANGECREATECONTRACT = 41,
    EXCHANGEINJECTCONTRACT,
    EXCHANGEWITHDRAWCONTRACT,
    EXCHANGETRANSACTIONCONTRACT,
    UPDATEENERGYLIMITCONTRACT,
    ACCOUNTPERMISSIONUPDATECONTRACT,
    CLEARABICONTRACT = 48,
    UPDATEBROKERAGECONTRACT = 49,
    FREEZEBALANCEV2CONTRACT = 54,
    UNFREEZEBALANCEV2CONTRACT,
    WITHDRAWEXPIREUNFREEZECONTRACT,
    DELEGATERESOURCECONTRACT,
    UNDELEGATERESOURCECONTRACT,
    CANCELALLUNFREEZEV2CONTRACT,

    UNKNOWN_CONTRACT = 254,
    INVALID_CONTRACT = 255
} contractType_e;

typedef struct txContent_t {
    // Keep 64-bit fields together to avoid alignment holes on ARM.
    uint64_t amount[2];
    uint64_t exchangeID;
    uint64_t feeLimit;
    uint64_t bytecodeSize;
    int64_t lockPeriod;
    uint64_t dataBytes;
    uint8_t account[TRON_ADDRESS_SIZE];
    uint8_t destination[TRON_ADDRESS_SIZE];
    uint8_t contractAddress[TRON_ADDRESS_SIZE];
    uint8_t bytecodeHash[32];
    uint8_t TRC20Amount[32];
    uint8_t decimals[2];
    uint8_t url[MAX_URL_SIZE + 1];  // +1 for NUL terminator at max length (256)
    char accountName[MAX_ACCOUNT_NAME_DISPLAY_SIZE];
    uint16_t accountNameLength;
    char tokenNames[2][MAX_TOKEN_LENGTH];
    uint8_t tokenNamesLength[2];
    uint8_t resource;
    uint8_t accountType;
    uint8_t TRC20Method;
    uint32_t customSelector;
    contractType_e contractType;
    uint8_t permission_id;
    bool lock;
} txContent_t;
// --8<-- [end:tx_content_structures]
