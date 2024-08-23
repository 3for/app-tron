#ifdef HAVE_TIP712_FULL_SUPPORT

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "commands_712.h"
#include "context_712.h"
#include "field_hash.h"
#include "path.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "schema_hash.h"
#include "filtering.h"
#include "parse.h"
#include "ui_globals.h"
#include "ui_idle_menu.h"  // ui_idle
#include "helpers.h"
#include "app_errors.h"
#include "settings.h"

// APDUs P1
#define P1_COMPLETE 0x00
#define P1_PARTIAL  0xFF

// APDUs P2
#define P2_DEF_NAME               0x00
#define P2_DEF_FIELD              0xFF
#define P2_IMPL_NAME              P2_DEF_NAME
#define P2_IMPL_ARRAY             0x0F
#define P2_IMPL_FIELD             P2_DEF_FIELD
#define P2_FILT_ACTIVATE          0x00
#define P2_FILT_MESSAGE_INFO      0x0F
#define P2_FILT_DATE_TIME         0xFC
#define P2_FILT_AMOUNT_JOIN_TOKEN 0xFD
#define P2_FILT_AMOUNT_JOIN_VALUE 0xFE
#define P2_FILT_RAW_FIELD         0xFF

/**
 * Send the response to the previous APDU command
 *
 * In case of an error it uses the global variable to retrieve the error code and resets
 * the app context
 *
 * @param[in] success whether the command was successful
 */
void handle_tip712_return_code(bool success) {
    if (success) {
        apdu_response_code = APDU_RESPONSE_OK;
    } else if (apdu_response_code == APDU_RESPONSE_OK) {  // somehow not set
        apdu_response_code = APDU_RESPONSE_ERROR_NO_INFO;
    }

    G_io_apdu_buffer[0] = (apdu_response_code >> 8) & 0xff;
    G_io_apdu_buffer[1] = apdu_response_code & 0xff;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);

    if (!success) {
        tip712_context_deinit();
        ui_idle();
    }
}

/**
 * Process the TIP712 struct definition command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
bool handleTIP712StructDef(uint8_t p1,
                           uint8_t p2,
                           uint8_t *workBuffer,
                           uint16_t dataLength,
                           uint8_t ins) {
    UNUSED(p1);
    UNUSED(ins);
    bool ret = true;

    if (tip712_context == NULL) {
        ret = tip712_context_init();
    }

    if (struct_state == DEFINED) {
        ret = false;
    }

    if (ret) {
        switch (p2) {
            case P2_DEF_NAME:
                ret = set_struct_name(dataLength, workBuffer);
                break;
            case P2_DEF_FIELD:
                ret = set_struct_field(dataLength, workBuffer);
                break;
            default:
                PRINTF("Unknown P2 0x%x for APDU 0x%x\n", p2, ins);
                apdu_response_code = APDU_RESPONSE_INVALID_P1_P2;
                ret = false;
        }
    }
    handle_tip712_return_code(ret);
    return ret;
}

/**
 * Process the TIP712 struct implementation command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
bool handleTIP712StructImpl(uint8_t p1,
                            uint8_t p2,
                            uint8_t *workBuffer,
                            uint16_t dataLength,
                            uint8_t ins) {
    UNUSED(ins);
    bool ret = false;
    bool reply_apdu = true;
    if (tip712_context == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    } else {
        switch (p2) {
            case P2_IMPL_NAME:
                // set root type
                ret = path_set_root((char *) workBuffer, dataLength);
                if (ret) {
                    if (HAS_SETTING(S_VERBOSE_TIP712)) {
                        ui_712_review_struct(path_get_root());
                        reply_apdu = false;
                    }
                    ui_712_field_flags_reset();
                }
                break;
            case P2_IMPL_FIELD:
                if ((ret = field_hash(workBuffer, dataLength, p1 != P1_COMPLETE))) {
                    reply_apdu = false;
                }
                break;
            case P2_IMPL_ARRAY:
                ret = path_new_array_depth(workBuffer, dataLength);
                break;
            default:
                PRINTF("Unknown P2 0x%x for APDU 0x%x\n", p2, ins);
                apdu_response_code = APDU_RESPONSE_INVALID_P1_P2;
        }
    }
    if (reply_apdu) {
        handle_tip712_return_code(ret);
    }
    return ret;
}

/**
 * Process the TIP712 filtering command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
bool handleTIP712Filtering(uint8_t p1,
                           uint8_t p2,
                           uint8_t *workBuffer,
                           uint16_t dataLength,
                           uint8_t ins) {
    UNUSED(p1);
    UNUSED(ins);
    bool ret = true;
    bool reply_apdu = true;

    if (tip712_context == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }
    if ((p2 != P2_FILT_ACTIVATE) && (ui_712_get_filtering_mode() != TIP712_FILTERING_FULL)) {
        handle_tip712_return_code(true);
        return true;
    }
    switch (p2) {
        case P2_FILT_ACTIVATE:
            if (!HAS_SETTING(S_VERBOSE_TIP712)) {
                ui_712_set_filtering_mode(TIP712_FILTERING_FULL);
                ret = compute_schema_hash();
            }
            forget_known_assets();
            break;
        case P2_FILT_MESSAGE_INFO:
            ret = filtering_message_info(workBuffer, dataLength);
            if (ret) {
                reply_apdu = false;
            }
            break;
        case P2_FILT_DATE_TIME:
            ret = filtering_date_time(workBuffer, dataLength);
            break;
        case P2_FILT_AMOUNT_JOIN_TOKEN:
            ret = filtering_amount_join_token(workBuffer, dataLength);
            break;
        case P2_FILT_AMOUNT_JOIN_VALUE:
            ret = filtering_amount_join_value(workBuffer, dataLength);
            break;
        case P2_FILT_RAW_FIELD:
            ret = filtering_raw_field(workBuffer, dataLength);
            break;
        default:
            PRINTF("Unknown P2 0x%x for APDU 0x%x\n", p2, ins);
            apdu_response_code = APDU_RESPONSE_INVALID_P1_P2;
            ret = false;
    }
    if ((p2 > P2_FILT_MESSAGE_INFO) && ret) {
        if (ui_712_push_new_filter_path()) {
            if (!ui_712_filters_counter_incr()) {
                ret = false;
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            }
        }
    }
    if (reply_apdu) {
        handle_tip712_return_code(ret);
    }
    return ret;
}

/**
 * Process the TIP712 sign command
 *
 * @param[in] apdu_buf the APDU payload
 * @return whether the command was successful or not
 */
bool handleTIP712Sign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    bool ret = false;
    UNUSED(p1);
    UNUSED(p2);
    if (tip712_context == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    }
    // if the final hashes are still zero or if there are some unimplemented fields
    else if (allzeroes(global_ctx.messageSigningContext712.domainHash,
                       sizeof(global_ctx.messageSigningContext712.domainHash)) ||
             allzeroes(global_ctx.messageSigningContext712.messageHash,
                       sizeof(global_ctx.messageSigningContext712.messageHash)) ||
             (path_get_field() != NULL)) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    } else if ((ui_712_get_filtering_mode() == TIP712_FILTERING_FULL) &&
               (ui_712_remaining_filters() != 0)) {
        PRINTF("%d TIP712 filters are missing\n", ui_712_remaining_filters());
        apdu_response_code = APDU_RESPONSE_REF_DATA_NOT_FOUND;
    } else if (read_bip32_path_712(workBuffer, dataLength, &global_ctx.messageSigningContext712) !=
               0) {
        if (!HAS_SETTING(S_VERBOSE_TIP712) &&
            (ui_712_get_filtering_mode() == TIP712_FILTERING_BASIC)) {
            ui_712_message_hash();
        }
        ret = true;
        ui_712_end_sign();
    }
    if (!ret) {
        handle_tip712_return_code(ret);
    }
    return ret;
}

#endif  // HAVE_TIP712_FULL_SUPPORT
