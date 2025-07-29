
// Adapted from:
// https://github.com/LedgerHQ/ledgerjs/blob/master/packages/errors/src/index.ts

#ifndef _ERRORS_H
#define _ERRORS_H

#define E_OK 0x9000

// NOTE: The follow codes have alt status messages defined.
// "Incorrect length"
#define E_INCORRECT_LENGTH 0x6700
// "Security not satisfied (dongle locked or have invalid access rights)"
#define E_SECURITY_STATUS_NOT_SATISFIED 0x6982
// "Condition of use not satisfied (denied by the user?)";
#define E_CONDITIONS_OF_USE_NOT_SATISFIED 0x6985
// "Invalid data received"
#define E_INCORRECT_DATA 0x6a80
// "Invalid parameter received"
#define E_INCORRECT_P1_P2 0x6b00

// TRON defined:
#define E_INCORRECT_BIP32_PATH            0x6a8a
#define E_MISSING_SETTING_DATA_ALLOWED    0x6a8b
#define E_MISSING_SETTING_SIGN_BY_HASH    0x6a8c
#define E_MISSING_SETTING_CUSTOM_CONTRACT 0x6a8d
#define E_SWAP_CHECKING_FAIL              0x6a8e

// Official:
#define E_WRONG_DATA_LENGTH                   0x6a87
#define E_INS_NOT_SUPPORTED                   0x6d00
#define E_CLA_NOT_SUPPORTED                   0x6e00

#define APDU_RESPONSE_OK                      0x9000
#define APDU_RESPONSE_CMD_CODE_NOT_SUPPORTED  0x911c
#define APDU_RESPONSE_ERROR_NO_INFO           0x6a00
#define APDU_RESPONSE_INVALID_DATA            0x6a80
#define APDU_RESPONSE_INSUFFICIENT_MEMORY     0x6a84
#define APDU_RESPONSE_INVALID_INS             0x6d00
#define APDU_RESPONSE_INVALID_P1_P2           0x6b00
#define APDU_RESPONSE_CONDITION_NOT_SATISFIED 0x6985
#define APDU_RESPONSE_REF_DATA_NOT_FOUND      0x6a88
#define APDU_RESPONSE_UNKNOWN                 0x6f00

#define APDU_NO_RESPONSE                0x0000
#define APDU_RESPONSE_MODE_CHECK_FAILED 0x6001
#endif  // once
