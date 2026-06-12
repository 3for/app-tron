#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "app_mem_utils.h"
#include "ui_logic.h"
#include "os_io.h"
#include "context_712.h"  // tip712_context_deinit
#include "path.h"         // path_get_root_type
#include "typed_data.h"
#include "commands_712.h"
#include "common_712.h"
#include "filtering.h"
#include "ui_globals.h"
#include "app_errors.h"
#include "parse.h"
#include "settings.h"
#include "trusted_name.h"
#include "common_utils.h"
#include "network.h"
#include "tx_ctx.h"
#include "utils.h"
#include "read.h"

// --- Local accessors over the list-based typed-data model --------------------
// Mirror the semantics of the typed-data accessors that used to live in
// typed_data.c, kept local so the rest of the file keeps operating on opaque
// `const void *` field/struct pointers.

static e_type struct_field_type(const void *ptr) {
    return ((const s_struct_712_field *) ptr)->type;
}

static uint8_t get_struct_field_typesize(const void *ptr) {
    return ((const s_struct_712_field *) ptr)->type_size;
}

static const char *get_struct_field_keyname(const void *ptr, uint8_t *length) {
    const s_struct_712_field *field_ptr = ptr;

    if ((field_ptr == NULL) || (field_ptr->key_name == NULL)) {
        return NULL;
    }
    if (length != NULL) {
        *length = (uint8_t) strlen(field_ptr->key_name);
    }
    return field_ptr->key_name;
}

static const char *get_struct_name(const void *ptr, uint8_t *length) {
    const s_struct_712 *struct_ptr = ptr;

    if ((struct_ptr == NULL) || (struct_ptr->name == NULL)) {
        return NULL;
    }
    if (length != NULL) {
        *length = (uint8_t) strlen(struct_ptr->name);
    }
    return struct_ptr->name;
}

#define AMOUNT_JOIN_FLAG_TOKEN (1 << 0)
#define AMOUNT_JOIN_FLAG_VALUE (1 << 1)

typedef struct {
    // display name, not NULL-terminated
    char name[25];
    uint8_t name_length;
    uint8_t value[INT256_LENGTH];
    uint8_t value_length;
    // indicates the steps the token join has gone through
    uint8_t flags;
} s_amount_join;

typedef enum {
    AMOUNT_JOIN_STATE_TOKEN,
    AMOUNT_JOIN_STATE_VALUE,
} e_amount_join_state;

#define UI_712_FIELD_SHOWN         (1 << 0)
#define UI_712_FIELD_NAME_PROVIDED (1 << 1)
#define UI_712_AMOUNT_JOIN         (1 << 2)
#define UI_712_DATETIME            (1 << 3)
#define UI_712_TRUSTED_NAME        (1 << 4)
#define UI_712_CALLDATA            (1 << 5)

typedef struct {
    s_amount_join joins[MAX_ASSETS];
    uint8_t idx;
    e_amount_join_state state;
} s_amount_context;

typedef struct ui_712_pair_s {
    struct ui_712_pair_s *next;
    const char *raw_key;
    size_t raw_key_length;
    const char *key;
    const char *value;
    size_t value_length;
} s_ui_712_pair;

typedef struct {
    bool shown;
    bool end_reached;
    e_tip712_filtering_mode filtering_mode;
    uint8_t filters_to_process;
    uint8_t field_flags;
    uint8_t structs_to_review;
    s_amount_context amount;
    uint8_t filters_received;
    uint32_t filters_crc[MAX_FILTERS];
    uint8_t discarded_path_length;
    char discarded_path[255];
    uint8_t tn_type_count;
    uint8_t tn_source_count;
    e_name_type tn_types[TN_TYPE_COUNT];
    e_name_source tn_sources[TN_SOURCE_COUNT];
    s_ui_712_pair *ui_pairs;
    s_ui_712_pair *ui_pairs_tail;
    s_tip712_calldata_info *calldata_info;
    uint8_t calldata_index;
    uint16_t ui_pairs_count;
    uint16_t ui_pairs_consecutive_identical_count;
} t_ui_context;

static t_ui_context *ui_ctx = NULL;

__attribute__((weak)) void ui_712_nbgl_cleanup(void) {}

static bool ui_712_bounded_strlen(const char *str, size_t max_len, size_t *out_len) {
    size_t length;

    if ((str == NULL) || (out_len == NULL)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    length = strnlen(str, max_len);
    if (length >= max_len) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    *out_len = length;
    return true;
}

static bool ui_712_copy_bounded_string(char *dst,
                                       size_t dst_size,
                                       const char *src,
                                       size_t src_max_len) {
    size_t src_len;

    if ((dst == NULL) || (src == NULL) || (dst_size == 0U)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    if (!ui_712_bounded_strlen(src, src_max_len, &src_len)) {
        return false;
    }
    memcpy(dst, src, MIN(dst_size - 1U, src_len));
    dst[MIN(dst_size - 1U, src_len)] = '\0';
    return true;
}

static char *ui_712_alloc_review_string(const char *src, size_t length) {
    char *dst = APP_MEM_ALLOC(length + 1);

    if (dst == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return NULL;
    }

    memcpy(dst, src, length);
    dst[length] = '\0';
    return dst;
}

static char *ui_712_alloc_review_key(const char *key, uint16_t suffix) {
    size_t key_length;
    char suffix_buffer[6];
    int suffix_length;
    char *dst;

    if (!ui_712_bounded_strlen(key, sizeof(strings.tmp.tmp2), &key_length)) {
        return NULL;
    }
    if (suffix == 0) {
        return ui_712_alloc_review_string(key, key_length);
    }

    suffix_length = snprintf(suffix_buffer, sizeof(suffix_buffer), "%u", suffix);
    if ((suffix_length <= 0) || ((size_t) suffix_length >= sizeof(suffix_buffer))) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return NULL;
    }

    dst = APP_MEM_ALLOC(key_length + 1 + (size_t) suffix_length + 1);
    if (dst == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return NULL;
    }

    memcpy(dst, key, key_length);
    dst[key_length] = '-';
    memcpy(dst + key_length + 1U, suffix_buffer, (size_t) suffix_length);
    dst[key_length + 1U + (size_t) suffix_length] = '\0';
    return dst;
}

static bool ui_712_push_pair(const char *key, const char *value) {
    s_ui_712_pair *pair = NULL;
    size_t key_length;
    size_t value_length;
    uint16_t key_suffix = 0;

    if ((ui_ctx == NULL) || (key == NULL) || (value == NULL)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    if (!ui_712_bounded_strlen(key, sizeof(strings.tmp.tmp2), &key_length) ||
        !ui_712_bounded_strlen(value, sizeof(strings.tmp.tmp), &value_length)) {
        return false;
    }
    if (key_length == 0) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    if ((ui_ctx->ui_pairs_tail != NULL) && (ui_ctx->ui_pairs_tail->raw_key_length == key_length) &&
        (ui_ctx->ui_pairs_tail->value_length == value_length) &&
        (memcmp(ui_ctx->ui_pairs_tail->raw_key, key, key_length) == 0) &&
        (memcmp(ui_ctx->ui_pairs_tail->value, value, value_length) == 0)) {
        // Only identical adjacent key/value pages are renamed into a numbered
        // run: "key-1", "key-2", "key-3", etc.
        if (ui_ctx->ui_pairs_consecutive_identical_count == 1) {
            APP_MEM_FREE((void *) ui_ctx->ui_pairs_tail->key);
            ui_ctx->ui_pairs_tail->key = ui_712_alloc_review_key(key, 1);
            if (ui_ctx->ui_pairs_tail->key == NULL) {
                return false;
            }
        }
        ui_ctx->ui_pairs_consecutive_identical_count += 1;
        key_suffix = ui_ctx->ui_pairs_consecutive_identical_count;
    } else {
        ui_ctx->ui_pairs_consecutive_identical_count = 1;
    }

    if (APP_MEM_CALLOC((void **) &pair, sizeof(*pair)) == false) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }

    pair->raw_key = ui_712_alloc_review_string(key, key_length);
    if (pair->raw_key == NULL) {
        return false;
    }
    pair->raw_key_length = key_length;

    pair->key = ui_712_alloc_review_key(key, key_suffix);
    if (pair->key == NULL) {
        return false;
    }

    pair->value = ui_712_alloc_review_string(value, value_length);
    if (pair->value == NULL) {
        return false;
    }
    pair->value_length = value_length;

    if (ui_ctx->ui_pairs == NULL) {
        ui_ctx->ui_pairs = pair;
    } else {
        ui_ctx->ui_pairs_tail->next = pair;
    }
    ui_ctx->ui_pairs_tail = pair;
    ui_ctx->ui_pairs_count += 1;
    return true;
}

bool ui_712_prepare_current_pair(void) {
    return ui_712_push_pair(strings.tmp.tmp2, strings.tmp.tmp);
}

/**
 * Checks on the UI context to determine if the next TIP 712 field should be shown
 *
 * @return whether the next field should be shown
 */
static bool ui_712_field_shown(void) {
    bool ret = false;
    if (ui_ctx->filtering_mode == TIP712_FILTERING_BASIC) {
#ifdef SCREEN_SIZE_WALLET
        if (true) {
#else
        if (HAS_SETTING(S_VERBOSE_TIP712) || (path_get_root_type() == ROOT_DOMAIN)) {
#endif
            ret = true;
        }
    } else {  // TIP712_FILTERING_FULL
        if (ui_ctx->field_flags & UI_712_FIELD_SHOWN) {
            ret = true;
        }
    }
    return ret;
}

/**
 * Set UI buffer
 *
 * @param[in] src source buffer
 * @param[in] src_length source buffer size
 * @param[in] dst destination buffer
 * @param[in] dst_length destination buffer length
 * @param[in] explicit_trunc if truncation should be explicitly shown
 */
static void ui_712_set_buf(const char *src,
                           size_t src_length,
                           char *dst,
                           size_t dst_length,
                           bool explicit_trunc) {
    size_t cpy_length;

    if ((src == NULL) || (dst == NULL) || (dst_length == 0)) {
        return;
    }

    if (src_length < dst_length) {
        cpy_length = src_length;
    } else {
        cpy_length = dst_length - 1;
    }
    memcpy(dst, src, cpy_length);
    dst[cpy_length] = '\0';
    if (explicit_trunc && (cpy_length < src_length) && (dst_length > 4) && (cpy_length >= 3)) {
        memcpy(dst + cpy_length - 3, "...", 3);
    }
}

/**
 * Skip the field if needed and reset its UI flags
 */
void ui_712_finalize_field(void) {
    if (!ui_712_field_shown()) {
        ui_712_next_field();
    }
    ui_712_field_flags_reset();
}

/**
 * Set a new title for the TIP-712 generic UX_STEP
 *
 * @param[in] str the new title
 * @param[in] length its length
 */
void ui_712_set_title(const char *str, size_t length) {
    ui_712_set_buf(str, length, strings.tmp.tmp2, sizeof(strings.tmp.tmp2), false);
}

/**
 * Set a new value for the TIP-712 generic UX_STEP
 *
 * @param[in] str the new value
 * @param[in] length its length
 */
void ui_712_set_value(const char *str, size_t length) {
    ui_712_set_buf(str, length, strings.tmp.tmp, sizeof(strings.tmp.tmp), true);
}

// Used by the generic_tx_parser when grouping batched transactions under an
// "intent" separator. Not reached by the current TIP712 flow; no-op stub.
void ui_712_set_intent(void) {
}

/**
 * Redraw the dynamic UI step that shows TIP712 information
 *
 * @return whether it was successful or not
 */
bool ui_712_redraw_generic_step(void) {
    if (!ui_ctx->shown) {  // Initialize if it is not already
        if ((ui_ctx->filtering_mode == TIP712_FILTERING_BASIC) && !HAS_SETTING(S_SIGN_BY_HASH) &&
            !HAS_SETTING(S_VERBOSE_TIP712)) {
            // Both settings not enabled => Error.
            ui_error_blind_signing();
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            tip712_context->go_home_on_failure = false;
            if (tip712_context != NULL) {
                tip712_context->go_home_on_failure = false;
            }
            return false;
        }
        apdu_response_code = ui_712_start(ui_ctx->filtering_mode);
        ui_ctx->shown = true;
    } else {
        ui_712_switch_to_message();
    }

    if (!ui_ctx->end_reached) {
        handle_tip712_return_code(true);
        explicit_bzero(&strings, sizeof(strings));
    }
    return true;
}

/**
 * Called to fetch the next field if they have not all been processed yet
 *
 * Also handles the special "Review struct" screen of the verbose mode
 *
 * @return the next field state
 */
e_tip712_nfs ui_712_next_field(void) {
    e_tip712_nfs state = TIP712_NO_MORE_FIELD;
    const void *review_struct = NULL;
    uint8_t depth_count = 0;

    if (ui_ctx == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    } else {
        if (ui_ctx->structs_to_review > 0) {
            depth_count = path_get_depth_count();
            if ((depth_count == 0U) || (ui_ctx->structs_to_review > depth_count)) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                ui_ctx->structs_to_review = 0;
                return TIP712_NO_MORE_FIELD;
            }
            review_struct = path_get_nth_field_to_last(ui_ctx->structs_to_review);
            if ((review_struct == NULL) || !ui_712_review_struct(review_struct)) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                ui_ctx->structs_to_review = 0;
                return TIP712_NO_MORE_FIELD;
            }
            ui_ctx->structs_to_review -= 1;
            state = TIP712_FIELD_LATER;
        } else if (!ui_ctx->end_reached) {
            handle_tip712_return_code(true);
            state = TIP712_FIELD_INCOMING;
            // So that later when we append to them, we start from an empty string
            explicit_bzero(&strings, sizeof(strings));
        }
    }
    return state;
}

/**
 * Used to notify of a new struct to review
 *
 * @param[in] struct_ptr pointer to the structure to be shown
 * @return whether it was successful or not
 */
bool ui_712_review_struct(const void *struct_ptr) {
    const char *struct_name;
    uint8_t struct_name_length;
    const char *title = "Review struct";

    if ((ui_ctx == NULL) || (struct_ptr == NULL)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    ui_712_set_title(title, sizeof("Review struct") - 1U);
    struct_name = get_struct_name(struct_ptr, &struct_name_length);
    if (struct_name == NULL) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    ui_712_set_value(struct_name, struct_name_length);
    if (!ui_712_prepare_current_pair()) {
        return false;
    }
    return ui_712_redraw_generic_step();
}

bool ui_712_review_network(const uint64_t *chain_id) {
    const char *title = "Network";
    const char *buf;

    if (*chain_id == chainConfig->chainId) {
        return true;
    }
    ui_712_set_title(title, sizeof("Network") - 1U);
    if ((buf = get_network_name_from_chain_id(chain_id)) == NULL) {
        if (!u64_to_string(*chain_id, strings.tmp.tmp, NETWORK_STRING_MAX_SIZE)) {
            return false;
        }
        buf = strings.tmp.tmp;
    }
    ui_712_set_value(buf, strlen(buf));
    if (!ui_712_prepare_current_pair()) {
        return false;
    }
    return ui_712_redraw_generic_step();
}

/**
 * Show the hash of the message on the generic UI step
 */
bool ui_712_message_hash(void) {
    const char *title = "Message hash";

    ui_712_set_title(title, sizeof("Message hash") - 1U);
    array_bytes_string(strings.tmp.tmp,
                       sizeof(strings.tmp.tmp),
                       tmpCtx.messageSigningContext712.messageHash,
                       KECCAK256_HASH_BYTESIZE);
    ui_ctx->end_reached = true;
    if (!ui_712_prepare_current_pair()) {
        return false;
    }
    return ui_712_redraw_generic_step();
}

/**
 * Format a given data as a string
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] last if this is the last chunk
 */
static void ui_712_format_str(const uint8_t *data, uint8_t length, bool last) {
    size_t max_len = sizeof(strings.tmp.tmp) - 1;
    size_t cur_len;

    if (!ui_712_bounded_strlen(strings.tmp.tmp, sizeof(strings.tmp.tmp), &cur_len)) {
        return;
    }

    memcpy(strings.tmp.tmp + cur_len, data, MIN(max_len - cur_len, length));
    strings.tmp.tmp[MIN(max_len, cur_len + (size_t) length)] = '\0';
    // truncated
    if (last && ((max_len - cur_len) < length)) {
        memcpy(strings.tmp.tmp + max_len - 3, "...", 3);
    }
}

/**
 * Format a given data as a string representation of an address
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] first if this is the first chunk
 * @return if the formatting was successful
 */
static bool ui_712_format_addr(const uint8_t *data, uint8_t length, bool first) {
    // no reason for an address to be received over multiple chunks
    if (!first) {
        PRINTF("TIP712 addr: unexpected continuation chunk\n");
        return false;
    }
    if (length != ADDRESS_LENGTH) {
        PRINTF("TIP712 addr: invalid length %u\n", length);
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    char ethAddr[43];
    if (!getEthDisplayableAddress((uint8_t *) data,
                                  /* strings.tmp.tmp,
                                  sizeof(strings.tmp.tmp), */
                                  ethAddr,
                                  sizeof(ethAddr),
                                  chainConfig->chainId)) {
        PRINTF("TIP712 addr: getEthDisplayableAddress failed\n");
        apdu_response_code = APDU_RESPONSE_ERROR_NO_INFO;
        return false;
    }

    if (!ethToTronBase58(ethAddr, strings.tmp.tmp, sizeof(strings.tmp.tmp))) {
        PRINTF("TIP712 addr: ethToTronBase58 failed\n");
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    return true;
}

/**
 * Format given data as a string representation of a boolean
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] first if this is the first chunk
 * @return if the formatting was successful
 */
static bool ui_712_format_bool(const uint8_t *data, uint8_t length, bool first) {
    size_t max_len = sizeof(strings.tmp.tmp) - 1;
    const char *true_str = "true";
    const char *false_str = "false";
    const char *str;
    size_t str_len;

    // no reason for a boolean to be received over multiple chunks
    if (!first) {
        return false;
    }
    if (length != 1) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    str = *data ? true_str : false_str;
    str_len = *data ? (sizeof("true") - 1U) : (sizeof("false") - 1U);
    memcpy(strings.tmp.tmp, str, MIN(max_len, str_len));
    strings.tmp.tmp[MIN(max_len, str_len)] = '\0';
    return true;
}

/**
 * Format given data as a string representation of bytes
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] first if this is the first chunk
 * @param[in] last if this is the last chunk
 * @return if the formatting was successful
 */
static bool ui_712_format_bytes(const uint8_t *data, uint8_t length, bool first, bool last) {
    size_t max_len = sizeof(strings.tmp.tmp) - 1;
    size_t cur_len;

    if ((data == NULL) && (length > 0U)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    if (!ui_712_bounded_strlen(strings.tmp.tmp, sizeof(strings.tmp.tmp), &cur_len)) {
        return false;
    }

    if (first) {
        memcpy(strings.tmp.tmp, "0x", MIN(max_len, 2));
        cur_len += 2;
    }
    if (format_hex(data,
                   MIN((max_len - cur_len) / 2, length),
                   strings.tmp.tmp + cur_len,
                   max_len + 1 - cur_len) < 0) {
        return false;
    }
    // truncated
    if (last && (((max_len - cur_len) / 2) < length)) {
        memcpy(strings.tmp.tmp + max_len - 3, "...", 3);
    }
    return true;
}

/**
 * Format given data as a string representation of an integer
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] first if this is the first chunk
 * @param[in] field_ptr pointer to the TIP-712 field
 * @return if the formatting was successful
 */
static bool ui_712_format_int(const uint8_t *data,
                              uint8_t length,
                              bool first,
                              const void *field_ptr) {
    uint256_t value256;
    uint128_t value128;
    int32_t value32;
    int16_t value16;
    uint16_t bit_size;

    // no reason for an integer to be received over multiple chunks
    if (!first) {
        return false;
    }
    bit_size = (uint16_t) get_struct_field_typesize(field_ptr) * 8U;
    switch (bit_size) {
        case 256:
            if (length > INT256_LENGTH) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            convertUint256BE(data, length, &value256);
            tostring256_signed(&value256, 10, strings.tmp.tmp, sizeof(strings.tmp.tmp));
            break;
        case 128:
            if (length > INT128_LENGTH) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            convertUint128BE(data, length, &value128);
            tostring128_signed(&value128, 10, strings.tmp.tmp, sizeof(strings.tmp.tmp));
            break;
        case 64:
            if (length > sizeof(uint64_t)) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            convertUint64BEto128(data, length, &value128);
            tostring128_signed(&value128, 10, strings.tmp.tmp, sizeof(strings.tmp.tmp));
            break;
        case 32:
            if (length > sizeof(value32)) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            value32 = 0;
            for (int i = 0; i < length; ++i) {
                ((uint8_t *) &value32)[length - 1 - i] = data[i];
            }
            snprintf(strings.tmp.tmp, sizeof(strings.tmp.tmp), "%d", value32);
            break;
        case 16:
            if (length > sizeof(value16)) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            value16 = 0;
            for (int i = 0; i < length; ++i) {
                ((uint8_t *) &value16)[length - 1 - i] = data[i];
            }
            snprintf(strings.tmp.tmp,
                     sizeof(strings.tmp.tmp),
                     "%d",
                     value16);  // expanded to 32 bits
            break;
        case 8:
            if (length != 1U) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            snprintf(strings.tmp.tmp,
                     sizeof(strings.tmp.tmp),
                     "%d",
                     ((int8_t *) data)[0]);  // expanded to 32 bits
            break;
        default:
            PRINTF("Unhandled field typesize\n");
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return false;
    }
    return true;
}

/**
 * Format given data as a string representation of an unsigned integer
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] first if this is the first chunk
 * @return if the formatting was successful
 */
static bool ui_712_format_uint(const uint8_t *data, uint8_t length, bool first) {
    uint256_t value256;

    // no reason for an integer to be received over multiple chunks
    if (!first) {
        return false;
    }
    if (length > INT256_LENGTH) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    convertUint256BE(data, length, &value256);
    tostring256(&value256, 10, strings.tmp.tmp, sizeof(strings.tmp.tmp));
    return true;
}

/**
 * Format given data as an amount with its ticker and value with correct decimals
 *
 * @return whether it was successful or not
 */
static bool ui_712_format_amount_join(void) {
    const tokenDefinition_t *token = NULL;
    char ticker_buf[MAX_TICKER_LEN];
    const char *ticker = "???";
    size_t current_length;
    size_t ticker_length;

    if (tmpCtx.transactionContext.assetSet[ui_ctx->amount.idx]) {
        token = &tmpCtx.transactionContext.extraInfo[ui_ctx->amount.idx].token;
    }
    if ((token != NULL) && (token->ticker[0] != '\0')) {
        if (!ui_712_copy_bounded_string(ticker_buf,
                                        sizeof(ticker_buf),
                                        token->ticker,
                                        sizeof(token->ticker))) {
            return false;
        }
        ticker = ticker_buf;
    }
    if ((ui_ctx->amount.joins[ui_ctx->amount.idx].value_length == INT256_LENGTH) &&
        ismaxint(ui_ctx->amount.joins[ui_ctx->amount.idx].value,
                 ui_ctx->amount.joins[ui_ctx->amount.idx].value_length)) {
        if (!ui_712_copy_bounded_string(strings.tmp.tmp,
                                        sizeof(strings.tmp.tmp),
                                        "Unlimited ",
                                        sizeof("Unlimited "))) {
            return false;
        }
        if (!ui_712_bounded_strlen(strings.tmp.tmp, sizeof(strings.tmp.tmp), &current_length) ||
            !ui_712_bounded_strlen(ticker, MAX_TOKEN_LENGTH, &ticker_length)) {
            return false;
        }
        memcpy(strings.tmp.tmp + current_length,
               ticker,
               MIN(sizeof(strings.tmp.tmp) - current_length - 1U, ticker_length));
        strings.tmp.tmp[current_length +
                        MIN(sizeof(strings.tmp.tmp) - current_length - 1U, ticker_length)] = '\0';
    } else {
        if (!amountToString(ui_ctx->amount.joins[ui_ctx->amount.idx].value,
                            ui_ctx->amount.joins[ui_ctx->amount.idx].value_length,
                            (token != NULL) ? token->decimals : 0,
                            ticker,
                            strings.tmp.tmp,
                            sizeof(strings.tmp.tmp))) {
            return false;
        }
    }
    ui_ctx->field_flags |= UI_712_FIELD_SHOWN;
    ui_712_set_title(ui_ctx->amount.joins[ui_ctx->amount.idx].name,
                     ui_ctx->amount.joins[ui_ctx->amount.idx].name_length);
    explicit_bzero(&ui_ctx->amount.joins[ui_ctx->amount.idx],
                   sizeof(ui_ctx->amount.joins[ui_ctx->amount.idx]));
    return true;
}

/**
 * Simply mark the current amount-join's token address as received
 */
void amount_join_set_token_received(void) {
    ui_ctx->amount.joins[ui_ctx->amount.idx].flags |= AMOUNT_JOIN_FLAG_TOKEN;
}

/**
 * Update the state of the amount-join
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @return whether it was successful or not
 */
static bool update_amount_join(const uint8_t *data, uint8_t length) {
    const tokenDefinition_t *token = NULL;

    if (tmpCtx.transactionContext.assetSet[ui_ctx->amount.idx]) {
        token = &tmpCtx.transactionContext.extraInfo[ui_ctx->amount.idx].token;
    } else {
        if (tmpCtx.transactionContext.currentAssetIndex == ui_ctx->amount.idx) {
            // So that the following amount-join find their tokens in the expected indices
            tmpCtx.transactionContext.currentAssetIndex =
                (tmpCtx.transactionContext.currentAssetIndex + 1) % MAX_ASSETS;
        }
    }
    switch (ui_ctx->amount.state) {
        case AMOUNT_JOIN_STATE_TOKEN:
            if (token != NULL) {
                if (memcmp(data, token->address, ADDRESS_LENGTH) != 0) {
                    return false;
                }
            }
            amount_join_set_token_received();
            break;

        case AMOUNT_JOIN_STATE_VALUE:
            if (length > sizeof(ui_ctx->amount.joins[ui_ctx->amount.idx].value)) {
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
            }
            memcpy(ui_ctx->amount.joins[ui_ctx->amount.idx].value, data, length);
            ui_ctx->amount.joins[ui_ctx->amount.idx].value_length = length;
            ui_ctx->amount.joins[ui_ctx->amount.idx].flags |= AMOUNT_JOIN_FLAG_VALUE;
            break;

        default:
            return false;
    }
    return true;
}

/**
 * Try to substitute given address by a matching contract name
 *
 * Fallback on showing the address if no match is found.
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @return whether it was successful or not
 */
static bool ui_712_format_trusted_name(const uint8_t *data, uint8_t length) {
    const s_trusted_name *trusted_name;

    if (length != ADDRESS_LENGTH) {
        return false;
    }
    trusted_name = get_trusted_name(ui_ctx->tn_type_count,
                                    ui_ctx->tn_types,
                                    ui_ctx->tn_source_count,
                                    ui_ctx->tn_sources,
                                    &tip712_context->chain_id,
                                    data);
    if (trusted_name != NULL) {
        if (!ui_712_copy_bounded_string(strings.tmp.tmp,
                                        sizeof(strings.tmp.tmp),
                                        trusted_name->name,
                                        sizeof(trusted_name->name))) {
            return false;
        }
    }
    return true;
}

/**
 * Format given data as a human-readable date/time representation
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @return whether it was successful or not
 */
static bool ui_712_format_datetime(const uint8_t *data, uint8_t length) {
    struct tm tstruct;
    int shown_hour;
    time_t timestamp = u64_from_BE(data, length);

    if (gmtime_r(&timestamp, &tstruct) == NULL) {
        return false;
    }
    if (tstruct.tm_hour == 0) {
        shown_hour = 12;
    } else {
        shown_hour = tstruct.tm_hour;
        if (shown_hour > 12) {
            shown_hour -= 12;
        }
    }
    snprintf(strings.tmp.tmp,
             sizeof(strings.tmp.tmp),
             "%04d-%02d-%02d\n%02d:%02d:%02d %s UTC",
             tstruct.tm_year + 1900,
             tstruct.tm_mon + 1,
             tstruct.tm_mday,
             shown_hour,
             tstruct.tm_min,
             tstruct.tm_sec,
             (tstruct.tm_hour < 12) ? "AM" : "PM");
    return true;
}

static void ui_712_set_intent_field(const char *value) {
    const char key[] = "Transaction type";

    ui_712_set_title(key, strlen(key));
    ui_712_set_value(value, strlen(value));
}

static bool ui_712_set_displayable_address(const uint8_t addr[ADDRESS_LENGTH]) {
    char eth_addr[43];

    if (!getEthDisplayableAddress((uint8_t *) addr, eth_addr, sizeof(eth_addr), chainConfig->chainId)) {
        return false;
    }
    return ethToTronBase58(eth_addr, strings.tmp.tmp, sizeof(strings.tmp.tmp));
}

static bool handle_fallback_empty_calldata(const s_tip712_calldata_info *calldata_info) {
    char *buf = strings.tmp.tmp;
    size_t buf_size = sizeof(strings.tmp.tmp);
    uint64_t chain_id;
    const char *ticker;
    e_name_type types[] = {TN_TYPE_ACCOUNT};
    e_name_source sources[] = {TN_SOURCE_ENS, TN_SOURCE_LAB, TN_SOURCE_MAB};
    const s_trusted_name *trusted_name;

    if (calldata_info->amount_state == CALLDATA_INFO_PARAM_SET) {
        ui_712_set_intent_field("Send");
        if (!ui_712_prepare_current_pair()) return false;

        if (calldata_info->chain_id != 0) {
            chain_id = calldata_info->chain_id;
        } else {
            chain_id = tip712_context->chain_id;
        }

        ticker = get_displayable_ticker(&chain_id, chainConfig, true);
        if (!amountToString(calldata_info->amount,
                            sizeof(calldata_info->amount),
                            SUN_TO_TRX,
                            ticker,
                            buf,
                            buf_size)) {
            return false;
        }
        ui_712_set_title("Amount", 6);
        ui_712_set_value(buf, strlen(buf));
        if (!ui_712_prepare_current_pair()) return false;
    } else {
        ui_712_set_intent_field("Empty transaction");
        if (!ui_712_prepare_current_pair()) return false;
    }

    ui_712_set_title("To", 2);
    if ((trusted_name = get_trusted_name(ARRAYLEN(types),
                                         types,
                                         ARRAYLEN(sources),
                                         sources,
                                         &calldata_info->chain_id,
                                         calldata_info->callee)) != NULL) {
        ui_712_set_value(trusted_name->name, strlen(trusted_name->name));
    } else {
        if (!ui_712_set_displayable_address(calldata_info->callee)) {
            return false;
        }
    }
    if (!ui_712_prepare_current_pair()) return false;
    return ui_712_redraw_generic_step();
}

static bool update_calldata_value(const uint8_t *data,
                                  uint8_t length,
                                  const uint16_t *complete_length,
                                  bool last,
                                  s_tip712_calldata_info *calldata_info) {
    const uint8_t *selector = NULL;
    size_t calldata_size;

    if (calldata_info->value_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (complete_length != NULL) {
        calldata_size = *complete_length;
        if (calldata_size > 0) {
            if (calldata_info->selector_state == CALLDATA_INFO_PARAM_NONE) {
                if ((length < CALLDATA_SELECTOR_SIZE) || (calldata_size < CALLDATA_SELECTOR_SIZE)) {
                    return false;
                }
                selector = data;
                data += CALLDATA_SELECTOR_SIZE;
                length -= CALLDATA_SELECTOR_SIZE;
                calldata_size -= CALLDATA_SELECTOR_SIZE;
            } else if (calldata_info->selector_state == CALLDATA_INFO_PARAM_SET) {
                selector = calldata_info->selector;
            }
            if ((g_parked_calldata = calldata_init(calldata_size, selector)) == NULL) {
                return false;
            }
        }
    }
    if (g_parked_calldata != NULL) {
        if (!calldata_append(g_parked_calldata, data, length)) {
            return false;
        }
    } else {
        // won't receive a TX info & descriptors about a non-existent calldata
        calldata_info->processed = true;
    }
    if (last) calldata_info->value_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_callee(const uint8_t *data,
                                   uint8_t length,
                                   bool last,
                                   s_tip712_calldata_info *calldata_info) {
    if (calldata_info->callee_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last) return false;
    buf_shrink_expand(data, length, calldata_info->callee, sizeof(calldata_info->callee));
    calldata_info->callee_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_chain_id(const uint8_t *data,
                                     uint8_t length,
                                     bool last,
                                     s_tip712_calldata_info *calldata_info) {
    uint8_t chain_id_buf[sizeof(uint64_t)];

    if (calldata_info->chain_id_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last) return false;
    buf_shrink_expand(data, length, chain_id_buf, sizeof(chain_id_buf));
    calldata_info->chain_id = read_u64_be(chain_id_buf, 0);
    calldata_info->chain_id_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_selector(const uint8_t *data,
                                     uint8_t length,
                                     bool last,
                                     s_tip712_calldata_info *calldata_info) {
    if (calldata_info->selector_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last) return false;
    buf_shrink_expand(data, length, calldata_info->selector, sizeof(calldata_info->selector));
    calldata_info->selector_state = CALLDATA_INFO_PARAM_SET;
    if ((calldata_info->value_state == CALLDATA_INFO_PARAM_SET) && (g_parked_calldata != NULL)) {
        calldata_set_selector(g_parked_calldata, calldata_info->selector);
    }
    return true;
}

static bool update_calldata_amount(const uint8_t *data,
                                   uint8_t length,
                                   bool last,
                                   s_tip712_calldata_info *calldata_info) {
    if (calldata_info->amount_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last) return false;
    buf_shrink_expand(data, length, calldata_info->amount, sizeof(calldata_info->amount));
    calldata_info->amount_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_spender(const uint8_t *data,
                                    uint8_t length,
                                    bool last,
                                    s_tip712_calldata_info *calldata_info) {
    if (calldata_info->spender_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last) return false;
    buf_shrink_expand(data, length, calldata_info->spender, sizeof(calldata_info->spender));
    calldata_info->spender_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata(const uint8_t *data,
                            uint8_t length,
                            const uint16_t *complete_length,
                            bool last) {
    s_tip712_calldata_info *calldata_info = get_calldata_info(ui_ctx->calldata_index);

    if (calldata_info == NULL) return false;
    switch (calldata_info->state) {
        case EIP712_CALLDATA_VALUE:
            if (!update_calldata_value(data, length, complete_length, last, calldata_info))
                return false;
            break;
        case EIP712_CALLDATA_CALLEE:
            if (!update_calldata_callee(data, length, last, calldata_info)) return false;
            break;
        case EIP712_CALLDATA_CHAIN_ID:
            if (!update_calldata_chain_id(data, length, last, calldata_info)) return false;
            break;
        case EIP712_CALLDATA_SELECTOR:
            if (!update_calldata_selector(data, length, last, calldata_info)) return false;
            break;
        case EIP712_CALLDATA_AMOUNT:
            if (!update_calldata_amount(data, length, last, calldata_info)) return false;
            break;
        case EIP712_CALLDATA_SPENDER:
            if (!update_calldata_spender(data, length, last, calldata_info)) return false;
            break;
        default:
            return false;
    }
    if (calldata_info_all_received(calldata_info)) {
        if (g_parked_calldata == NULL) {
            if (!handle_fallback_empty_calldata(calldata_info)) return false;
        } else {
            if (!tx_ctx_init(g_parked_calldata,
                             calldata_info->spender,
                             calldata_info->callee,
                             calldata_info->amount,
                             &calldata_info->chain_id)) {
                calldata_delete(g_parked_calldata);
                g_parked_calldata = NULL;
                return false;
            }
            g_parked_calldata = NULL;
        }
    }
    return true;
}

/**
 * Formats and feeds the given input data to the display buffers
 *
 * @param[in] field_ptr pointer to the new struct field
 * @param[in] data pointer to the field's raw value
 * @param[in] length field's raw value byte-length
 * @param[in] complete_length pointer to complete length if first chunk, \ref NULL otherwise
 * @param[in] last if this is the last chunk
 */
bool ui_712_feed_to_display(const void *field_ptr,
                            const uint8_t *data,
                            uint8_t length,
                            const uint16_t *complete_length,
                            bool last) {
    size_t current_length;
    bool first = complete_length != NULL;

    if (ui_ctx == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }
    if (data == NULL) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }

    if (first &&
        (!ui_712_bounded_strlen(strings.tmp.tmp, sizeof(strings.tmp.tmp), &current_length) ||
         (current_length > 0))) {
        return false;
    }

    // Value
    if (ui_712_field_shown()) {
        switch (struct_field_type(field_ptr)) {
            case TYPE_SOL_STRING:
                ui_712_format_str(data, length, last);
                break;
            case TYPE_SOL_ADDRESS:
                if (ui_712_format_addr(data, length, first) == false) {
                    return false;
                }
                break;
            case TYPE_SOL_BOOL:
                if (ui_712_format_bool(data, length, first) == false) {
                    return false;
                }
                break;
            case TYPE_SOL_BYTES_FIX:
            case TYPE_SOL_BYTES_DYN:
                if (ui_712_format_bytes(data, length, first, last) == false) {
                    return false;
                }
                break;
            case TYPE_SOL_INT:
                if (ui_712_format_int(data, length, first, field_ptr) == false) {
                    return false;
                }
                break;
            case TYPE_SOL_UINT:
                if (ui_712_format_uint(data, length, first) == false) {
                    return false;
                }
                break;
            case TYPE_SOL_TRCTOKEN:
                if (ui_712_format_uint(data, length, first) == false) {
                    return false;
                }
                break;
            default:
                PRINTF("Unhandled type\n");
                return false;
        }
    }
    if (ui_ctx->field_flags & UI_712_AMOUNT_JOIN) {
        if (!update_amount_join(data, length)) {
            return false;
        }

        if (ui_ctx->amount.joins[ui_ctx->amount.idx].flags ==
            (AMOUNT_JOIN_FLAG_TOKEN | AMOUNT_JOIN_FLAG_VALUE)) {
            if (!ui_712_format_amount_join()) {
                return false;
            }
        }
    }

    if (ui_ctx->field_flags & UI_712_DATETIME) {
        if (!ui_712_format_datetime(data, length)) {
            return false;
        }
    }

    if (ui_ctx->field_flags & UI_712_TRUSTED_NAME) {
        if (!ui_712_format_trusted_name(data, length)) {
            return false;
        }
    }

    if (ui_ctx->field_flags & UI_712_CALLDATA) {
        if (!update_calldata(data, length, complete_length, last)) {
            return false;
        }
    }

    // Check if this field is supposed to be displayed
    if (last && ui_712_field_shown()) {
        if (!ui_712_prepare_current_pair()) {
            return false;
        }
        if (!ui_712_redraw_generic_step()) return false;
    }
    return true;
}

/**
 * Used to signal that we are done with reviewing the structs and we can now have
 * the option to approve or reject the signature
 */
void ui_712_end_sign(void) {
    if (ui_ctx == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return;
    }
    ui_ctx->end_reached = true;
    ui_712_switch_to_sign();
}

/**
 * Initializes the UI context structure in memory
 */
bool ui_712_init(void) {
    if (ui_ctx != NULL) {
        ui_712_deinit();
        return false;
    }
    if (APP_MEM_CALLOC((void **) &ui_ctx, sizeof(*ui_ctx)) == false) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    ui_ctx->filtering_mode = TIP712_FILTERING_BASIC;
    explicit_bzero(&strings, sizeof(strings));
    return true;
}

static void delete_calldata_info(s_tip712_calldata_info *node) {
    APP_MEM_FREE(node);
}

/**
 * Deinit function that simply unsets the struct pointer to NULL
 */
void ui_712_deinit(void) {
    if (ui_ctx != NULL) {
        s_ui_712_pair *pair = ui_ctx->ui_pairs;

        while (pair != NULL) {
            s_ui_712_pair *next = pair->next;

            APP_MEM_FREE((void *) pair->raw_key);
            APP_MEM_FREE((void *) pair->key);
            APP_MEM_FREE((void *) pair->value);
            APP_MEM_FREE(pair);
            pair = next;
        }
        flist_clear((flist_node_t **) &ui_ctx->calldata_info,
                    (f_list_node_del) &delete_calldata_info);
        gcs_cleanup();
        ui_712_nbgl_cleanup();
        APP_MEM_FREE_AND_NULL((void **) &ui_ctx);
    }
}

/**
 * Approve button handling, calls the common handler function then
 * deinitializes the TIP712 context altogether.
 * @param[in] e unused here, just needed to match the UI function signature
 * @return unused here, just needed to match the UI function signature
 */
unsigned int ui_712_approve(bool display_menu) {
    ui_712_approve_cb(display_menu);
    tip712_context_deinit();
    return 0;
}

/**
 * Reject button handling, calls the common handler function then
 * deinitializes the TIP712 context altogether.

 * @param[in] e unused here, just needed to match the UI function signature
 * @return unused here, just needed to match the UI function signature
 */
unsigned int ui_712_reject(bool display_menu) {
    ui_712_reject_cb(display_menu);
    tip712_context_deinit();
    return 0;
}

/**
 * Set a structure field's UI flags
 *
 * @param[in] show if this field should be shown on the device
 * @param[in] name_provided if a substitution name has been provided
 * @param[in] token_join if this field is part of a token join
 * @param[in] datetime if this field should be shown and formatted as a date/time
 * @param[in] trusted_name if this field should be shown as a trusted contract name
 */
void ui_712_flag_field(bool show,
                       bool name_provided,
                       bool token_join,
                       bool datetime,
                       bool trusted_name,
                       bool calldata) {
    if (show) {
        ui_ctx->field_flags |= UI_712_FIELD_SHOWN;
    }
    if (name_provided) {
        ui_ctx->field_flags |= UI_712_FIELD_NAME_PROVIDED;
    }
    if (token_join) {
        ui_ctx->field_flags |= UI_712_AMOUNT_JOIN;
    }
    if (datetime) {
        ui_ctx->field_flags |= UI_712_DATETIME;
    }
    if (trusted_name) {
        ui_ctx->field_flags |= UI_712_TRUSTED_NAME;
    }
    if (calldata) {
        ui_ctx->field_flags |= UI_712_CALLDATA;
    }
}

/**
 * Set the UI filtering mode
 *
 * @param[in] the new filtering mode
 */
void ui_712_set_filtering_mode(e_tip712_filtering_mode mode) {
    ui_ctx->filtering_mode = mode;
}

/**
 * Get the UI filtering mode
 *
 * @return current filtering mode
 */
e_tip712_filtering_mode ui_712_get_filtering_mode(void) {
    return ui_ctx->filtering_mode;
}

/**
 * Set the number of filters this message should process
 *
 * @param[in] count number of filters
 */
void ui_712_set_filters_count(uint8_t count) {
    ui_ctx->filters_to_process = count;
}

/**
 * Get the number of filters left to process
 *
 * @return number of filters
 */
uint8_t ui_712_remaining_filters(void) {
    return ui_ctx->filters_to_process - ui_ctx->filters_received;
}

/**
 * Reset all the UI struct field flags
 */
void ui_712_field_flags_reset(void) {
    ui_ctx->field_flags = 0;
}

/**
 * Add a struct to the UI review queue
 *
 * Makes it so the user will have to go through a "Review struct" screen
 */
void ui_712_queue_struct_to_review(void) {
#ifdef SCREEN_SIZE_WALLET
    if (true) {
#else
    if (HAS_SETTING(S_VERBOSE_TIP712)) {
#endif
        if ((ui_ctx != NULL) && (ui_ctx->structs_to_review < MAX_PATH_DEPTH)) {
            ui_ctx->structs_to_review += 1;
        }
    }
}

/**
 * Prepare a token join address check
 */
void ui_712_token_join_prepare_addr_check(uint8_t index) {
    if ((ui_ctx == NULL) || (index >= MAX_ASSETS)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return;
    }
    ui_ctx->amount.idx = index;
    ui_ctx->amount.state = AMOUNT_JOIN_STATE_TOKEN;
}

void ui_712_token_join_prepare_amount(uint8_t index, const char *name, uint8_t name_length) {
    uint8_t cpy_len;

    if ((ui_ctx == NULL) || (name == NULL) || (index >= MAX_ASSETS)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return;
    }
    cpy_len = MIN(sizeof(ui_ctx->amount.joins[index].name), name_length);

    ui_ctx->amount.idx = index;
    ui_ctx->amount.state = AMOUNT_JOIN_STATE_VALUE;
    memcpy(ui_ctx->amount.joins[index].name, name, cpy_len);
    ui_ctx->amount.joins[index].name_length = cpy_len;
}

/**
 * Set UI pair key to the raw JSON key
 *
 * @param[in] field_ptr pointer to the field
 * @return whether it was successful or not
 */
bool ui_712_show_raw_key(const void *field_ptr) {
    const char *key;
    uint8_t key_len;

    if ((key = get_struct_field_keyname(field_ptr, &key_len)) == NULL) {
        return false;
    }

    if (ui_712_field_shown() && !(ui_ctx->field_flags & UI_712_FIELD_NAME_PROVIDED)) {
        ui_712_set_title(key, key_len);
    }
    return true;
}

/**
 * Push a new filter path
 *
 * @param[in] path_crc CRC of the filter path
 * @return whether it was successful or not
 */
bool ui_712_push_new_filter_path(uint32_t path_crc) {
    uint8_t filter_count = 0;

    if (ui_ctx == NULL) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    // check if already present
    for (int i = 0; i < ui_ctx->filters_received; ++i) {
        if (ui_ctx->filters_crc[i] == path_crc) {
            PRINTF("TIP-712 path CRC (%x) already found!\n", path_crc);
            return true;
        }
        filter_count += 1;
    }
    if ((filter_count >= ui_ctx->filters_to_process) || (filter_count >= MAX_FILTERS)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    PRINTF("Pushing new TIP-712 path CRC (%x) at index %u\n", path_crc, filter_count);
    ui_ctx->filters_crc[filter_count] = path_crc;
    ui_ctx->filters_received = filter_count + 1;
    return true;
}

/**
 * Set a discarded filter path
 *
 * @param[in] path the given filter path
 * @param[in] length the path length
 */
void ui_712_set_discarded_path(const char *path, uint8_t length) {
    if ((ui_ctx == NULL) || (path == NULL) || (length >= sizeof(ui_ctx->discarded_path))) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return;
    }
    memcpy(ui_ctx->discarded_path, path, length);
    ui_ctx->discarded_path[length] = '\0';
    ui_ctx->discarded_path_length = length;
}

/**
 * Get the discarded filter path
 *
 * @param[out] length the path length
 * @return filter path
 */
const char *ui_712_get_discarded_path(uint8_t *length) {
    if ((ui_ctx == NULL) || (length == NULL)) {
        return NULL;
    }
    *length = ui_ctx->discarded_path_length;
    return ui_ctx->discarded_path;
}

void ui_712_set_trusted_name_requirements(uint8_t type_count,
                                          const e_name_type *types,
                                          uint8_t source_count,
                                          const e_name_source *sources) {
    if ((ui_ctx == NULL) || (type_count > TN_TYPE_COUNT) || (source_count > TN_SOURCE_COUNT) ||
        ((type_count > 0) && (types == NULL)) || ((source_count > 0) && (sources == NULL))) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return;
    }
    ui_ctx->tn_type_count = type_count;
    memcpy(ui_ctx->tn_types, types, type_count * sizeof(*types));
    ui_ctx->tn_source_count = source_count;
    memcpy(ui_ctx->tn_sources, sources, source_count * sizeof(*sources));
}

uint16_t ui_712_pairs_count(void) {
    if (ui_ctx == NULL) {
        return 0;
    }
    return ui_ctx->ui_pairs_count;
}

bool ui_712_get_pair(uint16_t index, const char **item, const char **value) {
    s_ui_712_pair *pair;
    uint16_t i;

    if ((ui_ctx == NULL) || (item == NULL) || (value == NULL)) {
        return false;
    }

    pair = ui_ctx->ui_pairs;
    for (i = 0; (pair != NULL) && (i < index); i++) {
        pair = pair->next;
    }

    if ((pair == NULL) || (pair->key == NULL) || (pair->value == NULL)) {
        return false;
    }

    *item = pair->key;
    *value = pair->value;
    return true;
}

void add_calldata_info(s_tip712_calldata_info *node) {
    if ((ui_ctx == NULL) || (node == NULL)) {
        return;
    }
    flist_push_back((flist_node_t **) &ui_ctx->calldata_info, (flist_node_t *) node);
}

s_tip712_calldata_info *get_calldata_info(uint8_t index) {
    if (ui_ctx == NULL) {
        return NULL;
    }
    for (s_tip712_calldata_info *tmp = ui_ctx->calldata_info; tmp != NULL;
         tmp = (s_tip712_calldata_info *) ((flist_node_t *) tmp)->next) {
        if (index == tmp->index) {
            return tmp;
        }
    }
    return NULL;
}

s_tip712_calldata_info *get_current_calldata_info(void) {
    if (ui_ctx == NULL) {
        return NULL;
    }
    return get_calldata_info(ui_ctx->calldata_index);
}

bool all_calldata_info_processed(void) {
    if (ui_ctx == NULL) {
        return false;
    }
    for (const s_tip712_calldata_info *tmp = ui_ctx->calldata_info; tmp != NULL;
         tmp = (const s_tip712_calldata_info *) ((const flist_node_t *) tmp)->next) {
        if (!tmp->processed) return false;
    }
    return true;
}

void calldata_info_set_state(uint8_t index, e_eip712_calldata_state state) {
    s_tip712_calldata_info *calldata_info = get_calldata_info(index);

    if (ui_ctx == NULL) {
        return;
    }
    ui_ctx->calldata_index = index;
    if (calldata_info != NULL) {
        calldata_info->state = state;
    }
}

bool calldata_info_all_received(const s_tip712_calldata_info *calldata_info) {
    if (calldata_info == NULL) return false;
    if (calldata_info->value_state != CALLDATA_INFO_PARAM_SET) return false;
    if (calldata_info->callee_state != CALLDATA_INFO_PARAM_SET) return false;
    switch (calldata_info->chain_id_state) {
        case CALLDATA_INFO_PARAM_NONE:
        case CALLDATA_INFO_PARAM_SET:
            break;
        default:
            return false;
    }
    switch (calldata_info->selector_state) {
        case CALLDATA_INFO_PARAM_NONE:
        case CALLDATA_INFO_PARAM_SET:
            break;
        default:
            return false;
    }
    switch (calldata_info->amount_state) {
        case CALLDATA_INFO_PARAM_NONE:
        case CALLDATA_INFO_PARAM_SET:
            break;
        default:
            return false;
    }
    switch (calldata_info->spender_state) {
        case CALLDATA_INFO_PARAM_NONE:
        case CALLDATA_INFO_PARAM_SET:
            break;
        default:
            return false;
    }
    return true;
}
