#include "ui_globals.h"
#include "app_errors.h"
#include "ux.h"
#include "io.h"
#include <ctype.h>

#include "ui_globals.h"

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
 * The user has decided to see the next chunk of the message
 */
void continue_displaying_message(void) {
    reset_ui_191_buffer();
    if (unprocessed_length() > 0) {
        feed_display();
    }
}

/**
 * Feed the UI with new data
 */
void feed_display(void) {
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

    if ((remaining_ui_191_buffer_length() == 0) || (txContent.dataBytes == 0)) {
        if (!states191.ui_started) {
            ui_191_start();
            states191.ui_started = true;
        } else {
            ui_191_switch_to_message();
        }
    }

    if (unprocessed_length() == 0 && txContent.dataBytes > 0) {
        io_send_sw(E_OK);
    }
}
