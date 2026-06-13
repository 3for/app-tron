#pragma once

#include <stdbool.h>

// Typed-message (TIP-712) review choice callback.
// Mirrors app-ethereum's src/nbgl/ui_message_signing.h.
void ui_typed_message_review_choice(bool confirm);
