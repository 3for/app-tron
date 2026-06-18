#pragma once

// Generic Clear Signing "start flow" trigger.
//
// Sent by the host (INS_SIGN_GCS, P2_GCS_START_FLOW) after the GCS
// STORE has parked the calldata and all 0x26/0x28 descriptors have been
// provided. It checks the field set is complete, then runs the GCS review UI
// (ui_gcs) and signs on approval. Mirrors app-ethereum's SIGN_MODE_START_FLOW.
//
// Returns 0 on success (the APDU reply is sent asynchronously by the review
// callback) or the int returned by io_send_sw() on error.
int handle_gcs_start_flow(void);
