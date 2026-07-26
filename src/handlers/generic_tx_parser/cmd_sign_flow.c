#include "cmd_sign_flow.h"
#include "io.h"               // io_send_sw
#include "apdu_constants.h"   // app_errors (E_*), shared_context (appState), PRINTF
#include "tx_ctx.h"           // validate_instruction_hash, process_empty_txs_after,
                              // get_tx_ctx_count
#include "common_ui.h"        // ui_gcs

static int send_gcs_flow_status(uint16_t sw) {
    reset_app_context();
    return io_send_sw(sw);
}

bool gcs_review_in_progress(void) {
    return appState == APP_STATE_REVIEWING_GCS;
}

int handle_gcs_start_flow(void) {
    // The GCS STORE must have run first (it sets APP_STATE_SIGNING_TX).
    if (appState != APP_STATE_SIGNING_TX) {
        PRINTF("GCS start flow: not in TX signing mode!\n");
        return send_gcs_flow_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    // All declared fields must have been received: the running fields_hash must
    // match the value committed in TX_INFO.
    if (!validate_instruction_hash()) {
        PRINTF("GCS start flow: fields hash mismatch!\n");
        return send_gcs_flow_status(E_INCORRECT_DATA);
    }
    // Drain any trailing empty sub-transactions (no-op for the single-tx P1 case).
    if (!process_empty_txs_after()) {
        return send_gcs_flow_status(E_INCORRECT_DATA);
    }
    // Exactly one (root) tx context must remain -- otherwise descriptors are
    // still unprocessed (e.g. an unfinished nested calldata).
    if (get_tx_ctx_count() != 1) {
        PRINTF("GCS start flow: remnant unprocessed TX context!\n");
        return send_gcs_flow_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    appState = APP_STATE_GCS_FIELDS_AUTHENTICATED;
    // Build and display the review screen. ui_gcs() starts the async NBGL review
    // and signs through review_choice -> io_seproxyhal_touch_tx_ok on approval, so
    // the APDU reply is sent later, not here.
    if (!ui_gcs()) {
        PRINTF("GCS start flow: ui_gcs() failed!\n");
        return send_gcs_flow_status(E_INCORRECT_DATA);
    }
    appState = APP_STATE_REVIEWING_GCS;
    return 0;
}
