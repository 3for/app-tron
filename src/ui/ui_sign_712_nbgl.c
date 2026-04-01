#ifdef HAVE_NBGL
#include <string.h>

#include "app_errors.h"
#include "mem.h"
#include "mem_utils.h"
#include "nbgl_use_case.h"
#include "settings.h"
#include "utils.h"
#include "commands_712.h"
#include "ui_globals.h"
#include "ui_idle_menu.h"
#include "ui_logic.h"
#include "ui_nbgl.h"

nbgl_warning_t warning;

extern void reset_app_context(void);

static nbgl_contentTagValueList_t pairs_list;
static nbgl_contentTagValue_t *pairs;

static bool ui_712_prepare_pairs(void) {
    uint16_t pairs_count = ui_712_pairs_count();
    const char *item;
    const char *value;

    if (pairs_count == 0) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    pairs = mem_rev_alloc_and_align(sizeof(*pairs) * pairs_count, __alignof__(*pairs));
    if (pairs == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }

    explicit_bzero(pairs, sizeof(*pairs) * pairs_count);
    explicit_bzero(&pairs_list, sizeof(pairs_list));
    pairs_list.nbPairs = pairs_count;
    pairs_list.pairs = pairs;
    pairs_list.wrapping = true;

    for (uint16_t i = 0; i < pairs_count; i++) {
        if (!ui_712_get_pair(i, &item, &value)) {
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return false;
        }
        pairs[i].item = item;
        pairs[i].value = value;
    }

    return true;
}

static void ui_712_start_common(void) {
    pairs = NULL;
    explicit_bzero(&pairs_list, sizeof(pairs_list));
    if (appState != APP_STATE_IDLE) {
        reset_app_context();
    }
    appState = APP_STATE_SIGNING_TIP712;
    explicit_bzero(&warning, sizeof(nbgl_warning_t));
}

void ui_712_start_unfiltered(void) {
    ui_712_start_common();
    warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
}

void ui_712_start(void) {
    ui_712_start_common();
}

void ui_712_switch_to_message(void) {
    // NBGL TIP-712 review is displayed once all pairs have been accumulated.
}

void ui_712_switch_to_sign(void) {
    nbgl_operationType_t operation_type = TYPE_MESSAGE;

    if (!ui_712_prepare_pairs()) {
        handle_tip712_return_code(false);
        return;
    }

#ifdef SCREEN_SIZE_WALLET
    if ((ui_712_get_filtering_mode() == TIP712_FILTERING_BASIC) || HAS_SETTING(S_VERBOSE_TIP712)) {
        operation_type |= SKIPPABLE_OPERATION;
    }
    strlcpy(g_stax_shared_buffer, "Sign typed message?", sizeof(g_stax_shared_buffer));
#else
    strlcpy(g_stax_shared_buffer, "Sign message", sizeof(g_stax_shared_buffer));
#endif

    nbgl_useCaseAdvancedReview(operation_type,
                               &pairs_list,
                               &ICON_APP_REVIEW,
                               TEXT_REVIEW_TIP712,
                               NULL,
                               g_stax_shared_buffer,
                               NULL,
                               &warning,
                               ui_typed_message_review_choice);
}

static void ui_message_712_approved(void) {
    ui_712_approve(true);
}

static void ui_message_712_rejected(void) {
    ui_712_reject(true);
}

void ui_typed_message_review_choice(bool confirm) {
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_message_712_approved);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_message_712_rejected);
    }
}

#endif  // HAVE_NBGL
