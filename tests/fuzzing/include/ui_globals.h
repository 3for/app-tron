#pragma once

#include "shared_context.h"  // parse.h contexts + strings_t / strings
#include "cx.h"

extern cx_sha3_t global_sha3;
extern strings_t strings;
extern volatile uint8_t customContractField;
extern char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
extern char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
extern char fullContract[MAX_TOKEN_LENGTH];
extern char TRC20Action[9];
extern uint8_t G_io_apdu_buffer[260];

#define VOTE_ADDRESS          0
#define VOTE_ADDRESS_SIZE     (BASE58CHECK_ADDRESS_SIZE + 1)
#define VOTE_AMOUNT           VOTE_ADDRESS_SIZE
#define VOTE_AMOUNT_SIZE      15
#define VOTE_PACK             (VOTE_ADDRESS_SIZE + VOTE_AMOUNT_SIZE)
#define voteSlot(index, type) (((index) * VOTE_PACK) + (type))

#define PERM_MAX_FIELDS 80
#define PERM_ITEM_LEN   32
#define PERM_VAL_LEN    96
extern uint8_t perm_field_count;
extern const char *perm_field_items[PERM_MAX_FIELDS];
extern char (*perm_field_labels)[PERM_ITEM_LEN];
extern char (*perm_field_values)[PERM_VAL_LEN];
extern int8_t votes_count;

// ui_712_start is declared by the real common_712.h (uint16_t / filtering arg).
void ui_712_switch_to_message(void);
void ui_712_start_unfiltered(void);
void ui_712_switch_to_sign(void);
void ui_error_blind_signing(void);
void ui_error_custom_contract(void);
bool ui_callback_signMessage712_v0_ok(bool display_menu);
bool ui_callback_signMessage712_v0_cancel(bool display_menu);
