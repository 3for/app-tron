#include <string.h>

#include "app_mem_utils.h"
#include "app_errors.h"
#include "nbgl_use_case.h"
#include "settings.h"
#include "utils.h"
#include "commands_712.h"
#include "common_712.h"
#include "ui_globals.h"
#include "ui_idle_menu.h"
#include "ui_logic.h"
#include "ui_utils.h"  // g_pairsList, ui_pairs_cleanup
#include "ui_nbgl.h"

nbgl_warning_t warning;

static void ui_message_712_approved(void) {
    ui_pairs_cleanup();
    ui_712_approve();
}

static void ui_message_712_rejected(void) {
    ui_pairs_cleanup();
    ui_712_reject();
}

void ui_typed_message_review_choice(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_message_712_approved);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_message_712_rejected);
    }
}

uint16_t ui_sign_712(e_tip712_filtering_mode filtering) {
    nbgl_operationType_t operation_type = TYPE_MESSAGE;

    UNUSED(filtering);
    // Build the global tag/value pairs list from the accumulated TIP-712 pairs
    ui_712_push_pairs();

#ifdef SCREEN_SIZE_WALLET
    const char *sign_label = TEXT_SIGN_TIP712;

    if (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN)) {
        sign_label = TEXT_BLIND_SIGN_TIP712;
    }

    if ((ui_712_get_filtering_mode() == TIP712_FILTERING_BASIC) || HAS_SETTING(S_VERBOSE_TIP712)) {
        operation_type |= SKIPPABLE_OPERATION;
    }
    strlcpy(g_stax_shared_buffer, sign_label, sizeof(g_stax_shared_buffer));
#else
    if (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN)) {
        strlcpy(g_stax_shared_buffer, "Accept risk and sign", sizeof(g_stax_shared_buffer));
    } else {
        strlcpy(g_stax_shared_buffer, "Sign message", sizeof(g_stax_shared_buffer));
    }
#endif

    nbgl_useCaseAdvancedReview(operation_type,
                               g_pairsList,
                               &ICON_APP_REVIEW,
                               TEXT_REVIEW_TIP712,
                               NULL,
                               g_stax_shared_buffer,
                               NULL,
                               &warning,
                               ui_typed_message_review_choice);
    return SWO_SUCCESS;
}
