#pragma once

// ---------------------------------------------------------------------------
// GCS P1 STUB.
//
// tx_ctx.c calls ui_gcs_cleanup() from gcs_cleanup() to tear down any GCS review
// UI state. The actual GCS review screen is added in a later phase (P2); until
// then this is a no-op. Signature matches app-ethereum's common_ui.h entry.
// ---------------------------------------------------------------------------

void ui_gcs_cleanup(void);
