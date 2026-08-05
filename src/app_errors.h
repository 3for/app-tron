
// Adapted from:
// https://github.com/LedgerHQ/ledgerjs/blob/master/packages/errors/src/index.ts

#pragma once

#include "status_words.h"  // SWO_* status words

#define E_OK                              SWO_SUCCESS
#define E_USER_REJECTED                   SWO_CONDITIONS_NOT_SATISFIED
#define E_INTERNAL_ERROR                  SWO_UNKNOWN
#define E_INCORRECT_DATA                  SWO_INCORRECT_DATA
#define E_INCORRECT_P1_P2                 SWO_WRONG_P1_P2

// TRON defined:
#define E_MISSING_SETTING_DATA_ALLOWED    0x6a8b
#define E_MISSING_SETTING_SIGN_BY_HASH    0x6a8c
#define E_MISSING_SETTING_CUSTOM_CONTRACT 0x6a8d
#define E_SWAP_CHECKING_FAIL              0x6a8e

// Official:
#define E_WRONG_DATA_LENGTH SWO_WRONG_DATA_LENGTH
#define E_INS_NOT_SUPPORTED SWO_INVALID_INS
#define E_CLA_NOT_SUPPORTED SWO_INVALID_CLA

#define APDU_NO_RESPONSE 0x0000
