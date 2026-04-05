#include <string.h>
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "app_errors.h"
#include "io.h"
#include "ui_globals.h"
#include "ui_idle_menu.h"
#include "ui_nbgl.h"

#define TEXT_REVIEW_TIP191 REVIEW(TEXT_MESSAGE)
#define TEXT_SIGN_TIP191   SIGN(TEXT_MESSAGE)

char g_stax_shared_buffer[SHARED_BUFFER_SIZE] = {0};

static nbgl_contentTagValue_t pair;
static nbgl_contentTagValueList_t pairs_list;
static const char *g_message;

extern void reset_app_context(void);

static void ui_191_rejected(void) {
    reset_app_context();
    ui_idle();
    io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
}

static void ui_191_finish_cb(bool confirm) {
    if (confirm) {
        if (ui_callback_signMessage_ok(false)) {
            nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_idle);
        } else {
            nbgl_useCaseStatus("Transaction failure", false, ui_idle);
        }
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_191_rejected);
    }
}

static void ui_191_show_message(void) {
    explicit_bzero(&pair, sizeof(pair));
    explicit_bzero(&pairs_list, sizeof(pairs_list));

    pair.value = (g_message != NULL) ? g_message : "";
    pair.item = "Message";
    pairs_list.nbPairs = 1;
    pairs_list.pairs = &pair;
    pairs_list.wrapping = true;
    nbgl_useCaseReview(TYPE_MESSAGE,
                       &pairs_list,
                       &ICON_APP_REVIEW,
                       TEXT_REVIEW_TIP191,
                       NULL,
                       TEXT_SIGN_TIP191,
                       ui_191_finish_cb);
}

void ui_191_start(const char *message) {
    g_message = message;
    ui_191_show_message();
}

void ui_191_switch_to_message(void) {
    ui_191_show_message();
}

void ui_191_switch_to_sign(void) {
    ui_191_show_message();
}

void ui_191_switch_to_question(void) {
    ui_191_show_message();
}
