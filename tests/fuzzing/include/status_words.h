#pragma once

// Host-side mock of the Ledger SDK <status_words.h>. app-tron's TIP-712 code
// returns these SWO_* status words (the SWO_* refactor replaced the old
// APDU_RESPONSE_* codes). Values are copied verbatim from the SDK header so the
// fuzz build observes the same status codes as the firmware.

#define SWO_COMMAND_NOT_ALLOWED       0x6980
#define SWO_CONDITIONS_NOT_SATISFIED  0x6985
#define SWO_NOT_SUPPORTED_ERROR_NO_INFO 0x6800
#define SWO_PARAMETER_ERROR_NO_INFO   0x6a00
#define SWO_INCORRECT_DATA            0x6a80
#define SWO_INSUFFICIENT_MEMORY       0x6a84
#define SWO_REFERENCED_DATA_NOT_FOUND 0x6a88
#define SWO_WRONG_DATA_LENGTH         0x6a87
#define SWO_WRONG_P1_P2               0x6b00
#define SWO_INVALID_INS               0x6d00
#define SWO_INVALID_CLA               0x6e00
#define SWO_UNKNOWN                   0x6f00
#define SWO_SUCCESS                   0x9000
