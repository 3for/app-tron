#include "ui_globals.h"
#include "app_errors.h"
#include "ux.h"
#include "io.h"
#include <ctype.h>

typedef enum { UI_191_POS_REVIEW, UI_191_POS_QUESTION, UI_191_POS_END } e_ui_191_position;

static uint8_t ui_pos;

/**
 * Get unprocessed data from last received APDU
 *
 * @return pointer to data in APDU buffer
 */
const uint8_t *unprocessed_data(void) {
    return &G_io_apdu_buffer[OFFSET_CDATA] + processed_size_191;
}

/**
 * Get size of unprocessed data from last received APDU
 *
 * @return size of data in bytes
 */
size_t unprocessed_length(void) {
    return G_io_apdu_buffer[OFFSET_LC] - processed_size_191;
}


/**
 * Decide whether to show the question to show more of the message or not
 */
void question_switcher(void) {
    if ((states191.sign_state == STATE_191_HASH_DISPLAY) &&
        ((txContent.dataBytes > 0) || (unprocessed_length() > 0))) {
        ui_191_switch_to_question();
    } else {
        // Go to Sign / Cancel
        ui_191_switch_to_sign();
    }
}

/**
 * The user has decided to skip the rest of the message
 */
void skip_rest_of_message(void) {
    states191.sign_state = STATE_191_HASH_ONLY;
    if (txContent.dataBytes > 0) {
        io_send_sw(E_OK);
    } else {
        ui_191_switch_to_sign();
    }
}

/**
 * The user has decided to see the next chunk of the message
 */
void continue_displaying_message(void) {
    reset_ui_191_buffer();
    if (unprocessed_length() > 0) {
        feed_display();
    }
}

static void dummy_pre_cb(void) {
    if (ui_pos == UI_191_POS_REVIEW) {
        question_switcher();
    } else {
        ux_flow_prev();
        ui_pos = UI_191_POS_REVIEW;
    }
}

static void dummy_post_cb(void) {
    if (ui_pos == UI_191_POS_QUESTION) {
        // temporarily disable button clicks, they will be re-enabled as soon as new data
        // is received and the page is redrawn with ux_flow_init()
        G_ux.stack[0].button_push_callback = NULL;
        continue_displaying_message();
    } else  // UI_191_END
    {
        ui_191_switch_to_message_end();
    }
}

UX_STEP_NOCB(ux_191_step_review,
    pnn,
    {
        &C_icon_certificate,
        "Review",
        "Message",
    });
UX_STEP_NOCB(
    ux_191_step_message,
    bnnn_paging,
    {
      .title = "Message",
      .text = strings.tmp.tmp,
    });
UX_STEP_INIT(
    ux_191_step_dummy_pre,
    NULL,
    NULL,
    {
      dummy_pre_cb();
    });
UX_STEP_CB(
    ux_191_step_theres_more,
#ifdef TARGET_NANOS
    nn,
#else
    nnn,
#endif
    G_ux.stack[0].button_push_callback = NULL; // disable button clicks
    skip_rest_of_message(),
    {
#ifndef TARGET_NANOS
      "Press right to",
      "continue message",
#else
      "Press right to read",
#endif
      "Double-press to skip"
    });
UX_STEP_INIT(
    ux_191_step_dummy_post,
    NULL,
    NULL,
    {
      dummy_post_cb();
    });
UX_STEP_VALID(
    ux_191_step_sign,
    pbb,
    ui_callback_signMessage_ok(true),
    {
      &C_icon_validate_14,
      "Sign",
      "message",
    });
UX_STEP_VALID(
    ux_191_step_cancel,
    pbb,
    ui_callback_tx_cancel(true),
    {
      &C_icon_crossmark,
      "Cancel",
      "signature",
    });

UX_FLOW(ux_191_flow,
        &ux_191_step_review,
        &ux_191_step_message,
        // &ux_sign_flow_13_step,
        // &ux_191_step_dummy_pre,
        // &ux_191_step_theres_more,
        // &ux_191_step_dummy_post,
        &ux_191_step_sign,
        &ux_191_step_cancel);

void ui_191_start(void) {
    ux_flow_init(0, ux_191_flow, NULL);
    ui_pos = UI_191_POS_REVIEW;
}

void ui_191_switch_to_message(void) {
    ux_flow_init(0, ux_191_flow, &ux_191_step_message);
    ui_pos = UI_191_POS_REVIEW;
}

void ui_191_switch_to_message_end(void) {
    // Force it to a value that will make it automatically do a prev()
    ui_pos = UI_191_POS_QUESTION;
    ux_flow_init(0, ux_191_flow, &ux_191_step_dummy_pre);
}

void ui_191_switch_to_sign(void) {
    ux_flow_init(0, ux_191_flow, &ux_191_step_sign);
    ui_pos = UI_191_POS_END;
}

void ui_191_switch_to_question(void) {
    ux_flow_init(0, ux_191_flow, &ux_191_step_theres_more);
    ui_pos = UI_191_POS_QUESTION;
}

/**
 * Feed the UI with new data
 */
uint8_t feed_display(void) {
    int c;

    while ((unprocessed_length() > 0) && (remaining_ui_191_buffer_length() > 0)) {
        c = *(char *) unprocessed_data();
        if (isspace(c))  // to replace all white-space characters as spaces
        {
            c = ' ';
        }
        if (isprint(c)) {
            sprintf(remaining_ui_191_buffer(), "%c", (char) c);
            processed_size_191 += 1;
        } else {
            if (remaining_ui_191_buffer_length() >= 4)  // 4 being the fixed length of \x00
            {
                snprintf(remaining_ui_191_buffer(), remaining_ui_191_buffer_length(), "\\x%02x", c);
                processed_size_191 += 1;
            } else {
                // fill the rest of the UI buffer spaces, to consider the buffer full
                memset(remaining_ui_191_buffer(), ' ', remaining_ui_191_buffer_length());
            }
        }
    }

    if ((remaining_ui_191_buffer_length() == 0) ||
        (txContent.dataBytes == 0)) {
        if (!states191.ui_started) {
            ux_flow_init(0, ux_191_flow, NULL);
            // ui_191_start();
            states191.ui_started = true;
        } else {
            ui_191_switch_to_message();
        }
    }

    if ((unprocessed_length() == 0) && (txContent.dataBytes > 0)) {
        return 1;
    }

    return 0;
}
