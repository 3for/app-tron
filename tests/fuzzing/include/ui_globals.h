#pragma once

#include "parse.h"
#include "cx.h"

extern cx_sha3_t global_sha3;
extern strings_t strings;

void ui_712_start(void);
void ui_712_switch_to_message(void);
void ui_712_start_unfiltered(void);
void ui_712_switch_to_sign(void);
void ui_error_blind_signing(void);
bool ui_callback_signMessage712_v0_ok(bool display_menu);
bool ui_callback_signMessage712_v0_cancel(bool display_menu);
