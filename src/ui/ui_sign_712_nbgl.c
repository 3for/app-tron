#ifdef HAVE_TIP712_FULL_SUPPORT
#ifdef HAVE_NBGL
#include <string.h>  // explicit_bzero
#include "ui_logic.h"
#include "nbgl_use_case.h"
#include "ledger_assert.h"
#include "ui_globals.h"
#include "ui_nbgl.h"

static nbgl_contentTagValue_t pairs[7];
static nbgl_contentTagValueList_t pairs_list;
static uint8_t pair_idx;
static size_t buf_idx;
static bool filtered;
static bool review_skipped;

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

static void review_skip(void) {
    review_skipped = true;
    message_progress(true);
}

static void message_update(bool confirm) {
    char *buf;
    size_t buf_size;
    size_t buf_off;
    bool flag;

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
            pairs_list.nbPairs =
                nbgl_useCaseGetNbTagValuesInPageExt(pair_idx, &pairs_list, 0, !filtered, &flag);
        }
        if (!review_skipped && ((pair_idx == ARRAYLEN(pairs)) || (pairs_list.nbPairs < pair_idx))) {
            nbgl_useCaseReviewStreamingContinueExt(&pairs_list, message_progress, review_skip);
        } else {
            message_progress(true);
        }
    } else {
        ui_typed_message_review_choice(false);
    }
}

static void ui_712_start_common(bool has_filtering) {
    explicit_bzero(&pairs, sizeof(pairs));
    explicit_bzero(&pairs_list, sizeof(pairs_list));
    pairs_list.pairs = pairs;
    pair_idx = 0;
    buf_idx = 0;
    filtered = has_filtering;
    review_skipped = false;
}

void ui_712_start_unfiltered(void) {
    ui_712_start_common(true);
    nbgl_useCaseReviewStreamingBlindSigningStart(TYPE_MESSAGE | SKIPPABLE_OPERATION,
                                                 &C_Review_64px,
                                                 TEXT_REVIEW_TIP712,
                                                 NULL,
                                                 message_update);
}

void ui_712_start(void) {
    ui_712_start_common(true);
    nbgl_useCaseReviewStreamingStart(TYPE_MESSAGE,
                                     &C_Review_64px,
                                     TEXT_REVIEW_TIP712,
                                     NULL,
                                     message_update);
}

void ui_712_switch_to_message(void) {
    message_update(true);
}

void ui_712_switch_to_sign(void) {
    if (!review_skipped && (pair_idx > 0)) {
        pairs_list.nbPairs = pair_idx;
        pair_idx = 0;
        nbgl_useCaseReviewStreamingContinueExt(&pairs_list, message_progress, review_skip);
    } else {
        nbgl_useCaseReviewStreamingFinish(filtered ? TEXT_SIGN_TIP712 : TEXT_BLIND_SIGN_TIP712,
                                          ui_typed_message_review_choice);
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
#endif  // HAVE_TIP712_FULL_SUPPORT
