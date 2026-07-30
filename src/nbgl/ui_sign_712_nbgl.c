#include <string.h>

#include "app_errors.h"
#include "nbgl_use_case.h"
#include "settings.h"
#include "shared_context.h"  // apdu_response_code
#include "utils.h"
#include "common_712.h"
#include "ui_logic.h"
#include "ui_message_signing.h"
#include "ui_utils.h"  // g_pairsList
#include "ui_nbgl.h"

#ifdef HAVE_GATING_SUPPORT
#include "cmd_get_gating.h"  // set_gating_warning
#endif  // HAVE_GATING_SUPPORT

// Global Warning struct for the NBGL review flow (TIP-712 blind-signing warning).
nbgl_warning_t warning;

/**
 * @brief Trigger the TIP712 review flow
 *
 * @param filtering_mode the filtering mode to use
 * @param operation_type the type of operation to review
 * @param choice_callback the callback to call when the user makes a choice
 *
 * Mirrors app-ethereum's ui_712_start_review() (src/nbgl/ui_sign_712.c). TRON
 * divergences: no transaction-checks/gating, and the finish title comes from the
 * blind-signing warning state rather than the tx-simulation string.
 */
static uint16_t ui_712_start_review(e_tip712_filtering_mode filtering_mode,
                                    nbgl_operationType_t operation_type,
                                    nbgl_choiceCallback_t choice_callback) {
#ifdef SCREEN_SIZE_WALLET
    const char *sign_label = (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))
                                 ? TEXT_BLIND_SIGN_TIP712
                                 : TEXT_SIGN_TIP712;

    // Use review with skip button when not fully filtered or in verbose mode.
    if ((filtering_mode == TIP712_FILTERING_BASIC) || N_storage.verbose_tip712) {
        operation_type |= SKIPPABLE_OPERATION;
    }
#else
    UNUSED(filtering_mode);
    const char *sign_label = (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))
                                 ? "Accept risk and sign"
                                 : "Sign message";
#endif
    // Allocate the finish title buffer (app-ethereum parity: g_finishMsg).
    uint8_t finish_len = strlen(sign_label) + 1;  // +1 for '\0'
    if (!ui_buffers_init(0, 0, finish_len)) {
        return SWO_INSUFFICIENT_MEMORY;
    }
    snprintf(g_finishMsg, finish_len, "%s", sign_label);

    if (!tip712_mark_reviewing()) {
        return SWO_INCORRECT_DATA;
    }
#ifndef FUZZ
    nbgl_useCaseAdvancedReview(operation_type,
                               g_pairsList,
                               &ICON_APP_REVIEW,
                               TEXT_REVIEW_TIP712,
                               NULL,
                               g_finishMsg,
                               NULL,
                               &warning,
                               choice_callback);
#endif
    return SWO_SUCCESS;
}

/**
 * @brief Start TIP712 signature review flow
 *
 * @param filtering the filtering mode to use
 * @return status code indicating success or failure
 */
uint16_t ui_sign_712(e_tip712_filtering_mode filtering) {
    uint16_t status;

    // Build the global tag/value pairs list from the accumulated TIP-712 pairs.
    if (!ui_712_push_pairs()) {
        // ui_712_push_pairs() distinguishes allocation failures from malformed
        // or inconsistent UI state. Preserve that status for the host instead
        // of reporting every construction failure as OOM. Fall back to a data
        // error if a future failure path forgets to set a status code.
        return (apdu_response_code == SWO_SUCCESS) ? SWO_INCORRECT_DATA
                                                   : apdu_response_code;
    }

#ifdef HAVE_GATING_SUPPORT
    if (filtering == TIP712_FILTERING_BASIC) {
        // A gated-signing descriptor (INS_PROVIDE_GATING) may augment the review
        // with a "discover safer signing" prelude. Mirrors app-ethereum's
        // ui_sign_712().
        if (set_gating_warning() == false) {
            return SWO_INCORRECT_DATA;
        }
    }
#endif  // HAVE_GATING_SUPPORT

    status = ui_712_start_review(filtering,
                                 TYPE_MESSAGE,
                                 ui_typed_message_review_choice);
    if (status != SWO_SUCCESS) {
        return status;
    }
    return SWO_SUCCESS;
}
