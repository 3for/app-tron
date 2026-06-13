#include <string.h>

#include "app_errors.h"
#include "nbgl_use_case.h"
#include "shared_context.h"  // SHARED_BUFFER_SIZE (used by ui_nbgl.h)
#include "settings.h"
#include "utils.h"
#include "common_712.h"
#include "ui_logic.h"
#include "ui_message_signing.h"
#include "ui_utils.h"  // g_pairsList
#include "ui_nbgl.h"

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
static void ui_712_start_review(e_tip712_filtering_mode filtering_mode,
                                nbgl_operationType_t operation_type,
                                nbgl_choiceCallback_t choice_callback) {
#ifdef SCREEN_SIZE_WALLET
    const char *sign_label = (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))
                                 ? TEXT_BLIND_SIGN_TIP712
                                 : TEXT_SIGN_TIP712;

    // Use review with skip button when not fully filtered or in verbose mode.
    if ((filtering_mode == TIP712_FILTERING_BASIC) || HAS_SETTING(S_VERBOSE_TIP712)) {
        operation_type |= SKIPPABLE_OPERATION;
    }
#else
    UNUSED(filtering_mode);
    const char *sign_label = (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))
                                 ? "Accept risk and sign"
                                 : "Sign message";
#endif
    strlcpy(g_stax_shared_buffer, sign_label, sizeof(g_stax_shared_buffer));

#ifndef FUZZ
    nbgl_useCaseAdvancedReview(operation_type,
                               g_pairsList,
                               &ICON_APP_REVIEW,
                               TEXT_REVIEW_TIP712,
                               NULL,
                               g_stax_shared_buffer,
                               NULL,
                               &warning,
                               choice_callback);
#endif
}

/**
 * @brief Start TIP712 signature review flow
 *
 * @param filtering the filtering mode to use
 * @return status code indicating success or failure
 */
uint16_t ui_sign_712(e_tip712_filtering_mode filtering) {
    // Build the global tag/value pairs list from the accumulated TIP-712 pairs.
    ui_712_push_pairs();

    ui_712_start_review(filtering, TYPE_MESSAGE, ui_typed_message_review_choice);
    return SWO_SUCCESS;
}
