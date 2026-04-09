#pragma once

#include "parse.h"
#include "cx.h"

extern cx_sha3_t global_sha3;
extern strings_t strings;
extern volatile uint8_t customContractField;
extern char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
extern char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
extern char fullContract[MAX_TOKEN_LENGTH];
extern char TRC20Action[9];
extern uint8_t G_io_apdu_buffer[260];

void ui_712_start(void);
void ui_712_switch_to_message(void);
void ui_712_start_unfiltered(void);
void ui_712_switch_to_sign(void);
void ui_error_blind_signing(void);
bool ui_callback_signMessage712_v0_ok(bool display_menu);
bool ui_callback_signMessage712_v0_cancel(bool display_menu);
