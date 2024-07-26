#ifdef HAVE_NBGL
#include <nbgl_page.h>
// #include "shared_context.h"
// #include "ui_callbacks.h"
// #include "ui_nbgl.h"
// #include "sign_message.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
// #include "common_ui.h"
// #include "ui_message_signing.h"
// #include "ui_signing.h"
#include "ui_globals.h"

#define TEXT_REVIEW_TIP191 REVIEW(TEXT_MESSAGE)
#define TEXT_SIGN_TIP191   SIGN(TEXT_MESSAGE)

typedef enum {
    UI_191_ACTION_IDLE = 0,
    UI_191_ACTION_ADVANCE_IN_MESSAGE,
    UI_191_ACTION_GO_TO_SIGN
} e_ui_191_action;

static e_ui_191_action g_action;

static bool skip_message;

static nbgl_contentTagValue_t pair;

static uint32_t tip191MessageIdx = 0;
static uint32_t stringsTmpTmpIdx = 0;

static void (*g_approved_func)(void) = NULL;
static void (*g_rejected_func)(void) = NULL;

static void ui_message_rejection_handler() {
    nbgl_useCaseStatus("Message signing\ncancelled", false, g_rejected_func);
}

static void ui_message_confirm_rejection(void) {
    nbgl_useCaseConfirm(REJECT_QUESTION(TEXT_MESSAGE),
                        NULL,
                        REJECT_CONFIRM_BUTTON,
                        RESUME(TEXT_MESSAGE),
                        ui_message_rejection_handler);
}

void ui_message_review_choice(bool confirm) {
    if (confirm) {
        nbgl_useCaseStatus("MESSAGE\nSIGNED", true, g_approved_func);
    } else {
        ui_message_confirm_rejection();
    }
}

void ui_message_start(const char *title,
                      void (*start_func)(void),
                      void (*approved_func)(void),
                      void (*rejected_func)(void)) {
    g_approved_func = approved_func;
    g_rejected_func = rejected_func;
    nbgl_useCaseReviewStart(&C_Review_64px,
                            title,
                            NULL,
                            REJECT_BUTTON,
                            start_func,
                            ui_message_confirm_rejection);
}

static void reject_message(void) {
    ui_callback_tx_cancel(false);
}

static void sign_message(void) {
    ui_callback_signMessage_ok(false);
}

static bool display_message(nbgl_pageContent_t *content) {
    uint16_t len = 0;
    bool reached;

    if (g_action == UI_191_ACTION_ADVANCE_IN_MESSAGE) {
        strncpy(g_stax_shared_buffer + tip191MessageIdx,
                strings.tmp.tmp + stringsTmpTmpIdx,
                SHARED_BUFFER_SIZE - tip191MessageIdx);
        reached = nbgl_getTextMaxLenInNbLines(LARGE_MEDIUM_FONT,
                                              (char *) g_stax_shared_buffer,
                                              SCREEN_WIDTH - (2 * BORDER_MARGIN),
                                              NB_MAX_LINES_IN_REVIEW,
#if (API_LEVEL == 0 || API_LEVEL >= 14)
                                              &len,
                                              false);
#else
                                              &len);
#endif

        stringsTmpTmpIdx = len - tip191MessageIdx;
        tip191MessageIdx = len;
        g_stax_shared_buffer[tip191MessageIdx] = '\0';

        if (!reached && tip191MessageIdx < SHARED_BUFFER_SIZE) {
            stringsTmpTmpIdx = 0;
            question_switcher();

            if (g_action != UI_191_ACTION_GO_TO_SIGN) {
                return false;
            }
        } else if (reached || tip191MessageIdx == SHARED_BUFFER_SIZE) {
            tip191MessageIdx = 0;
        }
    }

    pair.value = g_stax_shared_buffer;
    pair.item = "Message";
    content->type = TAG_VALUE_LIST;
    content->tagValueList.nbPairs = 1;
    content->tagValueList.pairs = &pair;
    content->tagValueList.smallCaseForValue = false;
    content->tagValueList.nbMaxLinesForValue = NB_MAX_LINES_IN_REVIEW;
    content->tagValueList.wrapping = false;

    if ((g_action != UI_191_ACTION_IDLE) && (stringsTmpTmpIdx >= strlen(strings.tmp.tmp))) {
        // Fetch the next content to display into strings.tmp.tmp buffer.
        stringsTmpTmpIdx = 0;
        question_switcher();
    }
    return true;
}

static bool display_sign(nbgl_pageContent_t *content) {
    bool ret = false;

    if (g_position != UI_SIGNING_POSITION_SIGN) {
        content->type = INFO_LONG_PRESS, content->infoLongPress.icon = &C_Review_64px;
        content->infoLongPress.text = TEXT_SIGN_TIP191;
        content->infoLongPress.longPressText = SIGN_BUTTON;
        g_position = UI_SIGNING_POSITION_SIGN;
        ret = true;
    }
    return ret;
}

static bool nav_callback(uint8_t page, nbgl_pageContent_t *content) {
    bool ret = true;

    if (page == LAST_PAGE_FOR_REVIEW) {  // was skipped
        skip_message = true;
        skip_rest_of_message();
    }
    if ((g_action != UI_191_ACTION_GO_TO_SIGN) && (g_position != UI_SIGNING_POSITION_SIGN)) {
        if (skip_message) {
            // do not refresh when this callback triggers after user validation
            ret = false;
        } else {
            ret = display_message(content);
        }
    } else {
        // the last page must contain a long press button
        ret = display_sign(content);
    }
    return ret;
}

static void continue_review(void) {
    nbgl_useCaseForwardOnlyReview(REJECT_BUTTON, NULL, nav_callback, ui_message_review_choice);
}

void ui_191_start(void) {
    g_position = UI_SIGNING_POSITION_START;

    skip_message = false;
    tip191MessageIdx = 0;
    stringsTmpTmpIdx = 0;

    ui_message_start(TEXT_REVIEW_TIP191, &ui_191_switch_to_message, &sign_message, &reject_message);
}

void ui_191_switch_to_message(void) {
    g_position = UI_SIGNING_POSITION_REVIEW;
    g_action = UI_191_ACTION_ADVANCE_IN_MESSAGE;
    // No question mechanism on Stax:
    // Message is already displayed
    continue_review();
}

void ui_191_switch_to_sign(void) {
    g_action = UI_191_ACTION_GO_TO_SIGN;
    // Next nav_callback callback must display
    // the hold to approve screen
    if (skip_message) {
        continue_review();  // to force screen refresh
    }
}

void ui_191_switch_to_question(void) {
    // No question mechanism on Stax:
    // Always display the next message chunk.
    continue_displaying_message();
}

#endif