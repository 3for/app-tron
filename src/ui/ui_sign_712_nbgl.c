#ifdef HAVE_NBGL
#include <string.h>  // explicit_bzero
#include "ui_logic.h"
#include "nbgl_use_case.h"
#include "ledger_assert.h"
#include "ui_globals.h"
#include "ui_nbgl.h"
#include "utils.h"
#include "ui_idle_menu.h"

static nbgl_contentTagValue_t pairs[7];
static nbgl_contentTagValueList_t pairs_list;
static uint8_t pair_idx;
static size_t buf_idx;
static bool review_skipped;
nbgl_callback_t skip_callback = NULL;

// Global Warning struct for NBGL review flows
nbgl_warning_t warning;

extern void reset_app_context();

static void message_progress(bool confirm) {
    char *buf;
    size_t buf_size;
    size_t shift_off;

    if (!review_skipped) {
        if (pairs_list.nbPairs < pair_idx) {
            buf = get_ui_pairs_buffer(&buf_size);
            memmove(&pairs[0], &pairs[pairs_list.nbPairs], sizeof(pairs[0]));
            memmove(buf, pairs[0].item, (buf + buf_idx) - pairs[0].item);
            shift_off = pairs[0].item - buf;
            buf_idx -= shift_off;
            pairs[0].value -= shift_off;
            pairs[0].item = buf;
            pair_idx = 1;
        }
    }
    if (confirm) {
        if (ui_712_next_field() == TIP712_NO_MORE_FIELD) {
            ui_712_switch_to_sign();
        }
    } else {
        ui_typed_message_review_choice(false);
    }
}

#ifdef SCREEN_SIZE_WALLET
static void review_skip(void) {
    review_skipped = true;
    message_progress(true);
}
#endif  // SCREEN_SIZE_WALLET

static void message_update(bool confirm) {
    char *buf;
    size_t buf_size;
    size_t buf_off;
    bool flag;
    bool skippable;

    buf = get_ui_pairs_buffer(&buf_size);
    if (confirm) {
        if (!review_skipped) {
            buf_off = strlen(strings.tmp.tmp2) + 1;
            LEDGER_ASSERT((buf_idx + buf_off) < buf_size, "UI pairs buffer overflow");
            pairs[pair_idx].item = memmove(buf + buf_idx, strings.tmp.tmp2, buf_off);
            buf_idx += buf_off;
            buf_off = strlen(strings.tmp.tmp) + 1;
            LEDGER_ASSERT((buf_idx + buf_off) < buf_size, "UI pairs buffer overflow");
            pairs[pair_idx].value = memmove(buf + buf_idx, strings.tmp.tmp, buf_off);
            buf_idx += buf_off;
            pair_idx += 1;
            skippable = warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN);
            pairs_list.nbPairs =
                nbgl_useCaseGetNbTagValuesInPageExt(pair_idx, &pairs_list, 0, skippable, &flag);
        }
        if (!review_skipped && ((pair_idx == ARRAYLEN(pairs)) || (pairs_list.nbPairs < pair_idx))) {
            nbgl_useCaseReviewStreamingContinueExt(&pairs_list, message_progress, skip_callback);
        } else {
            message_progress(true);
        }
    } else {
        ui_typed_message_review_choice(false);
    }
}

static void ui_712_start_common(void) {
    explicit_bzero(&pairs, sizeof(pairs));
    explicit_bzero(&pairs_list, sizeof(pairs_list));
    pairs_list.pairs = pairs;
    pair_idx = 0;
    buf_idx = 0;
    review_skipped = false;
#ifdef SCREEN_SIZE_WALLET
    skip_callback = review_skip;
#endif  // SCREEN_SIZE_WALLET
    if (appState != APP_STATE_IDLE) {
        reset_app_context();
    }
    appState = APP_STATE_SIGNING_TIP712;
    explicit_bzero(&warning, sizeof(nbgl_warning_t));
}

void ui_712_start_unfiltered(void) {
    ui_712_start_common();
    warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
    nbgl_useCaseAdvancedReviewStreamingStart(TYPE_MESSAGE | SKIPPABLE_OPERATION,
                                             &ICON_APP_REVIEW,
                                             "Review typed message",
                                             NULL,
                                             &warning,
                                             message_update);
}

void ui_712_start(void) {
    ui_712_start_common();
    if (warning.predefinedSet == 0) {
        nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                         &ICON_APP_REVIEW,
                                         "Review typed message",
                                         NULL,
                                         message_update);
    } else {
        nbgl_useCaseAdvancedReviewStreamingStart(TYPE_MESSAGE,
                                                 &ICON_APP_REVIEW,
                                                 "Review typed message",
                                                 NULL,
                                                 &warning,
                                                 message_update);
    }
}

void ui_712_switch_to_message(void) {
    message_update(true);
}

void ui_712_switch_to_sign(void) {
    if (!review_skipped && (pair_idx > 0)) {
        pairs_list.nbPairs = pair_idx;
        pair_idx = 0;
        nbgl_useCaseReviewStreamingContinueExt(&pairs_list, message_progress, skip_callback);
    } else {
#ifdef SCREEN_SIZE_WALLET
        if ((warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))) {
            snprintf(g_stax_shared_buffer,
                     sizeof(g_stax_shared_buffer),
                     "Accept risk and sign typed message?");
        } else {
            snprintf(g_stax_shared_buffer, sizeof(g_stax_shared_buffer), "Sign typed message?");
        }
#else
        snprintf(g_stax_shared_buffer, sizeof(g_stax_shared_buffer), "Sign message");
#endif
        nbgl_useCaseReviewStreamingFinish(g_stax_shared_buffer, ui_typed_message_review_choice);
    }
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