#pragma once

#include <stdbool.h>

// Generic Clear Signing review UI (implemented in src/nbgl/ui_gcs.c).
//
// ui_gcs() builds the review screen from the parsed field table and runs the
// NBGL transaction review (sign/reject). ui_gcs_cleanup() is called from
// gcs_cleanup() (tx_ctx.c) to free the UI state. Signatures match
// app-ethereum's entry points.
bool ui_gcs(void);
bool ui_gcs_owns_shared_ui(void);
void ui_gcs_cleanup(void);
