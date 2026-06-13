#include "nbgl_use_case.h"
#include "ui_logic.h"  // ui_712_approve / ui_712_reject
#include "ui_utils.h"  // ui_all_cleanup
#include "ui_message_signing.h"

// Mirrors app-ethereum's src/nbgl/ui_message_signing.c (the typed-message review
// choice lives in its own translation unit).
//
// TRON divergence: app-ethereum signs in the choice callback *before* showing the
// "signed" status screen. TRON's ui_712_approve()/reject() send the APDU response
// through ui_712_*_cb + reset_app_context; on Nano that must happen *after* the
// status screen is dismissed, otherwise the response return interrupts the NBGL
// flow (timeout). So the approve/reject are run as the status-dismiss callbacks.
static void ui_message_712_approved(void) {
    ui_all_cleanup();
    ui_712_approve();
}

static void ui_message_712_rejected(void) {
    ui_all_cleanup();
    ui_712_reject();
}

void ui_typed_message_review_choice(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_message_712_approved);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_message_712_rejected);
    }
}
