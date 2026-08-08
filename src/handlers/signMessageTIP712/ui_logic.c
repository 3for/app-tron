#include "ui_logic.h"
#include "app_mem_utils.h"
#include "os_io.h"
#include "shared_context.h"  // appState, txContext, strings, tmpCtx, chainConfig
#include "common_utils.h"
#include "common_712.h"
#include "context_712.h"  // tip712_context
#include "path.h"         // path_get_root_type
#include "app_errors.h"   // SWO_* status words
#include "typed_data.h"
#include "commands_712.h"
#include "settings.h"  // N_storage
#include "filtering.h"
#include "trusted_name.h"
#include "network.h"
#include "time_format.h"
#include "lists.h"
#include "ui_globals.h"  // ui_error_blind_signing
#include "ui_utils.h"    // g_pairs, g_pairsList, ui_pairs_init
#include "utils.h"       // ethToTronBase58
#include "tx_ctx.h"      // tx_ctx_init, validate_instruction_hash
#include "read.h"        // read_u64_be
#include "parse.h"       // asset_slot_is_kind
#include "tip712_limits.h"
#include "gcs_limits.h"
#include "gcs_memory.h"
#include "encode_field.h"
#include <string.h>
#include <time.h>
#include <limits.h>

#define N_OF_M_LENGTH 10  // enough to hold "nn of mm"

#define AMOUNT_JOIN_FLAG_TOKEN  (1 << 0)
#define AMOUNT_JOIN_FLAG_VALUE  (1 << 1)
#define AMOUNT_JOIN_NAME_LENGTH TIP712_MAX_AMOUNT_LABEL_LENGTH

typedef struct amount_join {
    flist_node_t _list;
    // display name, NULL-terminated
    char name[AMOUNT_JOIN_NAME_LENGTH + 1];
    // indicates the steps the token join has gone through
    uint8_t flags;
    uint8_t token_idx;
    uint8_t value_length;
    uint8_t value[INT256_LENGTH];
    /* Copy metadata only after the signed address has matched it. Asset slots
     * are circular and may be overwritten while the TIP-712 message streams. */
    tokenDefinition_t token_snapshot;
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
    s_amount_join *joins;
    uint8_t idx;
    e_amount_join_state state;
} s_amount_context;

typedef struct filter_crc {
    flist_node_t _list;
    uint32_t value;
} s_filter_crc;

typedef struct {
    bool end_reached;
    e_tip712_filtering_mode filtering_mode;
    uint8_t filters_to_process;
    bool message_info_received;
    uint8_t field_flags;
    uint8_t structs_to_review;
    s_amount_context amount;
    s_filter_crc *filters_crc;
    char *discarded_path;
    uint8_t tn_type_count;
    uint8_t tn_source_count;
    e_name_type tn_types[TN_TYPE_COUNT];
    e_name_source tn_sources[TN_SOURCE_COUNT];
    s_ui_712_pair *ui_pairs;
    uint16_t ui_pairs_dup_count;  // TRON: length of the current identical-page run
    uint16_t dynamic_value_remaining;
    uint16_t dynamic_value_written;
    size_t dynamic_display_bytes;
    s_eip712_calldata_info *calldata_info;
    uint8_t calldata_index;
} t_ui_context;

static t_ui_context *ui_ctx = NULL;

// to be used as a \ref f_list_node_del
static void delete_filter_crc(s_filter_crc *fcrc) {
    gcs_mem_free(fcrc);
}

// to be used as a \ref f_list_node_del
static void delete_ui_pair(s_ui_712_pair *pair) {
    gcs_mem_free(pair->key);
    gcs_mem_free(pair->raw_key);
    gcs_mem_free(pair->value);
    gcs_mem_free(pair);
}

/**
 * TRON: allocate a copy of @p key, optionally suffixed with "-<suffix>".
 *
 * @param[in] key the base (un-numbered) key
 * @param[in] suffix the run index (0 means no suffix)
 * @return the newly allocated string, or NULL on failure
 */
static char *ui_712_alloc_numbered_key(const char *key, uint16_t suffix) {
    size_t key_len = strlen(key);
    char suffix_buf[8];  // '-' + up to 5 digits (uint16_t) + '\0'
    int suffix_len;
    char *dst;

    if (suffix == 0) {
        if ((dst = gcs_mem_alloc(key_len + 1U, GCS_MEM_UI)) == NULL) {
            return NULL;
        }
        memcpy(dst, key, key_len + 1);
        return dst;
    }
    suffix_len = snprintf(suffix_buf, sizeof(suffix_buf), "-%u", suffix);
    if ((suffix_len <= 0) || ((size_t) suffix_len >= sizeof(suffix_buf))) {
        return NULL;
    }
    if ((dst = gcs_mem_alloc(key_len + (size_t) suffix_len + 1U,
                             GCS_MEM_UI)) == NULL) {
        return NULL;
    }
    memcpy(dst, key, key_len);
    memcpy(dst + key_len, suffix_buf, (size_t) suffix_len + 1);  // includes '\0'
    return dst;
}

/**
 * TRON: rename consecutive pages that share the same key and value into a
 * numbered run ("trcTokenArr-1", "trcTokenArr-2", ...), so identical adjacent
 * entries are distinguishable on screen. @p cur is the freshly completed tail
 * page and @p prev the page before it.
 */
static bool ui_712_number_duplicate_pair(s_ui_712_pair *prev, s_ui_712_pair *cur) {
    char *renamed_prev = NULL;
    char *renamed_cur = NULL;
    uint16_t next_count;

    if ((prev == NULL) || (prev->raw_key == NULL) || (prev->value == NULL) ||
        (cur->raw_key == NULL) || (cur->value == NULL) ||
        (strcmp(prev->raw_key, cur->raw_key) != 0) || (strcmp(prev->value, cur->value) != 0)) {
        ui_ctx->ui_pairs_dup_count = 1;
        return true;
    }
    if (ui_ctx->ui_pairs_dup_count == 1) {
        // Start of a run: retroactively number the previous page "<key>-1"
        renamed_prev = ui_712_alloc_numbered_key(prev->raw_key, 1);
        if (renamed_prev == NULL) {
            goto error;
        }
    }
    next_count = ui_ctx->ui_pairs_dup_count + 1U;
    renamed_cur = ui_712_alloc_numbered_key(cur->raw_key, next_count);
    if (renamed_cur == NULL) {
        goto error;
    }
    if (renamed_prev != NULL) {
        gcs_mem_free(prev->key);
        prev->key = renamed_prev;
    }
    ui_ctx->ui_pairs_dup_count = next_count;
    gcs_mem_free(cur->key);
    cur->key = renamed_cur;
    return true;
error:
    gcs_mem_free(renamed_prev);
    gcs_mem_free(renamed_cur);
    apdu_response_code = SWO_INSUFFICIENT_MEMORY;
    return false;
}

// to be used as a \ref f_list_node_del
static void delete_amount_join(s_amount_join *join) {
    gcs_mem_free(join);
}

static bool ui_712_current_pair(s_ui_712_pair **prev, s_ui_712_pair **cur) {
    s_ui_712_pair *tmp;

    if ((ui_ctx == NULL) || (prev == NULL) || (cur == NULL)) {
        return false;
    }
    tmp = ui_ctx->ui_pairs;
    if (tmp == NULL) {
        return false;
    }
    *prev = NULL;
    while (((flist_node_t *) tmp)->next != NULL) {
        *prev = tmp;
        tmp = (s_ui_712_pair *) ((flist_node_t *) tmp)->next;
    }
    *cur = tmp;
    return true;
}

static bool ui_712_can_add_pair(void) {
    if ((ui_ctx == NULL) ||
        (flist_size((flist_node_t **) &ui_ctx->ui_pairs) >=
         TIP712_MAX_UI_PAIRS)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    return true;
}

static bool ui_712_reserve_dynamic_display(size_t bytes) {
    if ((ui_ctx == NULL) || (bytes > TIP712_MAX_DYNAMIC_DISPLAY_BYTES) ||
        (ui_ctx->dynamic_display_bytes >
         (TIP712_MAX_DYNAMIC_DISPLAY_BYTES - bytes))) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    ui_ctx->dynamic_display_bytes += bytes;
    return true;
}

static bool ui_712_finalize_pair(s_ui_712_pair *prev, s_ui_712_pair *cur) {
    ui_ctx->dynamic_value_remaining = 0;
    ui_ctx->dynamic_value_written = 0;
    // TRON: number consecutive pages sharing the same key/value into a run
    if (!ui_712_number_duplicate_pair(prev, cur)) {
        return false;
    }
    cur->end_intent = validate_instruction_hash();
    if (cur->end_intent) {
        PRINTF("[Intent] End\n");
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
static bool ui_712_next_field(void) {
    bool ret = false;

    if (ui_ctx == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
    } else {
        if (ui_ctx->structs_to_review > 0) {
            ret = ui_712_review_struct(path_get_nth_field_to_last(ui_ctx->structs_to_review));
            ui_ctx->structs_to_review -= 1;
        } else if (!ui_ctx->end_reached) {
            handle_tip712_return_code(true);
            // So that later when we append to them, we start from an empty string
            explicit_bzero(&strings, sizeof(strings));
            ret = true;
        }
    }
    return ret;
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
        ret = true;
#else
        if (N_storage.verbose_tip712 || (path_get_root_type() == ROOT_DOMAIN)) {
            ret = true;
        }
#endif
    } else {  // TIP712_FILTERING_FULL
        /* The CAL signature context does not bind the complete domain
         * separator. Always review every domain field so a descriptor cannot
         * be replayed across domains without changing the trusted display. */
        if ((path_get_root_type() == ROOT_DOMAIN) ||
            (ui_ctx->field_flags & UI_712_FIELD_SHOWN)) {
            ret = true;
        }
    }
    return ret;
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
 * Set a new intent for the TIP-712 batch transaction
 *
 */
bool ui_712_set_intent(void) {
    s_ui_712_pair *new_pair = NULL;
    const char *title = "Review transaction";
    size_t title_length = strlen(title);

    if (!ui_712_can_add_pair()) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    // Allocate memory for the new pair
    new_pair = gcs_mem_calloc(sizeof(*new_pair), GCS_MEM_UI);
    if (new_pair == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    // Allocate and copy the title
    new_pair->key = gcs_mem_calloc(title_length + 1U, GCS_MEM_UI);
    if (new_pair->key == NULL) goto error;
    memcpy(new_pair->key, title, title_length);

    // Allocate and clear the intent buffer
    new_pair->value = gcs_mem_calloc(N_OF_M_LENGTH, GCS_MEM_UI);
    if (new_pair->value == NULL) goto error;

    // Mark it as an intent
    new_pair->start_intent = true;
    flist_push_back((flist_node_t **) &ui_ctx->ui_pairs, (flist_node_t *) new_pair);
    return true;
error:
    apdu_response_code = SWO_INSUFFICIENT_MEMORY;
    delete_ui_pair(new_pair);
    return false;
}

/**
 * Set a new title for the TIP-712 generic UX_STEP
 *
 * @param[in] str the new title
 * @param[in] length its length
 */
bool ui_712_set_title(const char *str, size_t length) {
    s_ui_712_pair *new_pair = NULL;

    if ((str == NULL) || !ui_712_can_add_pair()) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    new_pair = gcs_mem_calloc(sizeof(*new_pair), GCS_MEM_UI);
    if (new_pair == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    new_pair->key = gcs_mem_calloc(length + 1U, GCS_MEM_UI);
    if (new_pair->key == NULL) goto error;
    memcpy(new_pair->key, str, length);
    // TRON: keep an un-numbered copy of the key for duplicate-run detection
    new_pair->raw_key = gcs_mem_calloc(length + 1U, GCS_MEM_UI);
    if (new_pair->raw_key == NULL) goto error;
    memcpy(new_pair->raw_key, str, length);
    flist_push_back((flist_node_t **) &ui_ctx->ui_pairs, (flist_node_t *) new_pair);
    return true;
error:
    apdu_response_code = SWO_INSUFFICIENT_MEMORY;
    delete_ui_pair(new_pair);
    return false;
}

/**
 * Set a new value for the TIP-712 generic UX_STEP
 *
 * @note The parameters may be NULL if the value is already formatted into strings.tmp.tmp
 *
 * @param[in] str the new value
 * @param[in] length its length
 */
bool ui_712_set_value(const char *str, size_t length) {
    s_ui_712_pair *prev = NULL;
    s_ui_712_pair *tmp = NULL;

    if (!ui_712_current_pair(&prev, &tmp)) {
        // No pairs created yet
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (tmp->value != NULL) {
        PRINTF("Value already exist for tag %s: %s\n", tmp->key, tmp->value);
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if ((str != NULL) && (length > 0)) {
        // buffer is directly provided with parameters
        tmp->value = gcs_mem_calloc(length + 1U, GCS_MEM_UI);
        if (tmp->value == NULL) {
            apdu_response_code = SWO_INSUFFICIENT_MEMORY;
            return false;
        }
        memcpy(tmp->value, str, length);
    } else {
        // Add the value from the global variable strings.tmp.tmp
        if ((tmp->value = gcs_mem_strdup(strings.tmp.tmp, GCS_MEM_UI)) == NULL) {
            apdu_response_code = SWO_INSUFFICIENT_MEMORY;
            return false;
        }
    }
    return ui_712_finalize_pair(prev, tmp);
}

/**
 * Redraw the dynamic UI step that shows TIP712 information
 *
 * @return whether it was successful or not
 */
bool ui_712_redraw_generic_step(void) {
    if (appState != APP_STATE_SIGNING_EIP712) {  // Initialize if it is not already
        if ((ui_ctx->filtering_mode == TIP712_FILTERING_BASIC) && !N_storage.signByHash &&
            !N_storage.verbose_tip712) {
            // Both settings not enabled => Error
            ui_error_blind_signing();
            apdu_response_code = SWO_INCORRECT_DATA;
            tip712_context->go_home_on_failure = false;
            return false;
        }
        apdu_response_code = ui_712_start(ui_ctx->filtering_mode);
        if (apdu_response_code != SWO_SUCCESS) {
            return false;
        }
        handle_tip712_return_code(true);
    } else {
        if (ui_712_next_field() == false) {
            apdu_response_code = ui_sign_712(ui_ctx->filtering_mode);
            if (apdu_response_code != SWO_SUCCESS) {
                return false;
            }
        }
    }
    return true;
}

/**
 * Used to notify of a new struct to review
 *
 * @param[in] struct_ptr pointer to the structure to be shown
 * @return whether it was successful or not
 */
bool ui_712_review_struct(const s_struct_712 *struct_ptr) {
    const char *struct_name;
    const char *title = "Review struct";

    if (ui_ctx == NULL) {
        return false;
    }

    if (!ui_712_set_title(title, strlen(title))) {
        return false;
    }
    if ((struct_name = struct_ptr->name) != NULL) {
        if (!ui_712_set_value(struct_name, strlen(struct_name))) {
            return false;
        }
    }
    return ui_712_redraw_generic_step();
}

bool ui_712_review_network(const uint64_t *chain_id) {
    const char *title = "Network";
    const char *buf;

    if (*chain_id == chainConfig->chainId) {
        return true;
    }
    if (!ui_712_set_title(title, strlen(title))) {
        return false;
    }
    if ((buf = get_network_name_from_chain_id(chain_id)) == NULL) {
        if (!u64_to_string(*chain_id, strings.tmp.tmp, NETWORK_STRING_MAX_SIZE)) {
            return false;
        }
        buf = strings.tmp.tmp;
    }
    if (!ui_712_set_value(buf, strlen(buf))) {
        return false;
    }
    return ui_712_redraw_generic_step();
}

/**
 * Show the hash of the message on the generic UI step
 */
bool ui_712_message_hash(void) {
    const char *title = "Message hash";

    if (!ui_712_set_title(title, strlen(title))) {
        return false;
    }
    array_bytes_string(strings.tmp.tmp,
                       sizeof(strings.tmp.tmp),
                       tmpCtx.messageSigningContext712.messageHash,
                       KECCAK256_HASH_BYTESIZE);
    if (!ui_712_set_value(NULL, 0)) {
        return false;
    }
    ui_ctx->end_reached = true;
    return ui_712_redraw_generic_step();
}

static bool ui_712_append_str(const uint8_t *data,
                              uint8_t length,
                              const uint16_t *complete_length,
                              bool last) {
    s_ui_712_pair *prev = NULL;
    s_ui_712_pair *pair = NULL;
    if (!ui_712_current_pair(&prev, &pair)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if (complete_length != NULL) {
        const size_t allocation_size = ((size_t) *complete_length) + 1U;
        if (pair->value != NULL) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        if (!ui_712_reserve_dynamic_display(allocation_size)) {
            return false;
        }
        pair->value = gcs_mem_calloc(allocation_size, GCS_MEM_UI);
        if (pair->value == NULL) {
            ui_ctx->dynamic_display_bytes -= allocation_size;
            apdu_response_code = SWO_INSUFFICIENT_MEMORY;
            return false;
        }
        ui_ctx->dynamic_value_remaining = *complete_length;
        ui_ctx->dynamic_value_written = 0;
    } else if (pair->value == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if ((length > ui_ctx->dynamic_value_remaining) ||
        ((length > 0) && (memchr(data, '\0', length) != NULL))) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    memcpy(pair->value + ui_ctx->dynamic_value_written, data, length);
    ui_ctx->dynamic_value_written += length;
    pair->value[ui_ctx->dynamic_value_written] = '\0';
    ui_ctx->dynamic_value_remaining -= length;

    if (last) {
        if (ui_ctx->dynamic_value_remaining != 0) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        if (!ui_712_finalize_pair(prev, pair)) {
            return false;
        }
    }
    return true;
}

/**
 * Format the given address into a Tron base58 string in strings.tmp.tmp
 *
 * @param[in] addr the address to format
 * @return whether it was successful or not
 */
static bool ui_712_set_displayable_address(const uint8_t addr[ADDRESS_LENGTH]) {
    // Display EIP-712 `address` values in TRON Base58 ("T...") rather than 0x-hex.
    return tronBase58FromBinary(addr, strings.tmp.tmp, sizeof(strings.tmp.tmp));
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
        return false;
    }
    if (length != ADDRESS_LENGTH) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (!ui_712_set_displayable_address(data)) {
        apdu_response_code = SWO_PARAMETER_ERROR_NO_INFO;
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

    // no reason for a boolean to be received over multiple chunks
    if (!first) {
        return false;
    }
    if ((length != 1) || (data[0] > 1U)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    str = *data ? true_str : false_str;
    size_t str_len = MIN(max_len, strlen(str));
    memcpy(strings.tmp.tmp, str, str_len);
    strings.tmp.tmp[str_len] = '\0';
    return true;
}

/**
 * Format given data as a "0x"-prefixed hex string of bytes.
 *
 * Unlike a fixed scratch buffer, this streams the whole value into a
 * per-field heap buffer (mirroring ui_712_append_str for strings) so the full
 * byte string is shown across pages instead of being truncated with "...".
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] complete_length total byte length on the first chunk (else NULL)
 * @param[in] last if this is the last chunk
 * @return if the formatting was successful
 */
static bool ui_712_format_bytes(const uint8_t *data,
                                uint8_t length,
                                const uint16_t *complete_length,
                                bool last) {
    s_ui_712_pair *prev = NULL;
    s_ui_712_pair *pair = NULL;
    size_t cur_len;

    if (!ui_712_current_pair(&prev, &pair)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if (complete_length != NULL) {
        const size_t allocation_size = 2U + ((size_t) *complete_length) * 2U + 1U;
        // First chunk: allocate "0x" + 2 hex chars per byte + '\0'.
        if (pair->value != NULL) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        if (!ui_712_reserve_dynamic_display(allocation_size)) {
            return false;
        }
        pair->value = gcs_mem_calloc(allocation_size, GCS_MEM_UI);
        if (pair->value == NULL) {
            ui_ctx->dynamic_display_bytes -= allocation_size;
            apdu_response_code = SWO_INSUFFICIENT_MEMORY;
            return false;
        }
        memcpy(pair->value, "0x", 2);
        ui_ctx->dynamic_value_remaining = *complete_length;
    } else if (pair->value == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if (length > ui_ctx->dynamic_value_remaining) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    // From cur_len onward the buffer holds exactly (2 * remaining bytes + 1).
    cur_len = strlen(pair->value);
    if (format_hex(data,
                   length,
                   pair->value + cur_len,
                   ((size_t) ui_ctx->dynamic_value_remaining) * 2U + 1U) < 0) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    ui_ctx->dynamic_value_remaining -= length;

    if (last) {
        if (ui_ctx->dynamic_value_remaining != 0) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        if (!ui_712_finalize_pair(prev, pair)) {
            return false;
        }
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
                              const s_struct_712_field *field_ptr) {
    // no reason for an integer to be received over multiple chunks
    if (!first || (length == 0) || (length > INT256_LENGTH)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    const uint8_t effective_size = field_ptr->type_has_size
                                       ? field_ptr->type_size
                                       : INT256_LENGTH;
    if (!tip712_format_signed_int_value(data,
                                        length,
                                        effective_size,
                                        strings.tmp.tmp,
                                        sizeof(strings.tmp.tmp))) {
        apdu_response_code = SWO_INCORRECT_DATA;
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
    if (!first || (length == 0) || (length > sizeof(value256))) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    convertUint256BE(data, length, &value256);
    tostring256(&value256, 10, strings.tmp.tmp, sizeof(strings.tmp.tmp));
    return true;
}

static s_amount_join *get_amount_join(uint8_t token_idx) {
    s_amount_join *tmp;
    s_amount_join *new;

    for (tmp = ui_ctx->amount.joins; tmp != NULL;
         tmp = (s_amount_join *) ((flist_node_t *) tmp)->next) {
        if (tmp->token_idx == token_idx) break;
    }
    if (tmp != NULL) return tmp;

    // does not exist, create it
    new = gcs_mem_calloc(sizeof(*new), GCS_MEM_UI);
    if (new == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return NULL;
    }
    new->token_idx = token_idx;

    flist_push_back((flist_node_t **) &ui_ctx->amount.joins, (flist_node_t *) new);
    return new;
}

/**
 * Format given data as an amount with its ticker and value with correct decimals
 *
 * @return whether it was successful or not
 */
static bool ui_712_format_amount_join(void) {
    s_amount_join *amount_join;

    if ((amount_join = get_amount_join(ui_ctx->amount.idx)) == NULL) {
        return false;
    }
    if ((amount_join->flags & AMOUNT_JOIN_FLAG_TOKEN) == 0U) {
        apdu_response_code = SWO_REFERENCED_DATA_NOT_FOUND;
        return false;
    }
    if ((amount_join->value_length == INT256_LENGTH) &&
        ismaxint(amount_join->value, amount_join->value_length)) {
        strlcpy(strings.tmp.tmp, "Unlimited ", sizeof(strings.tmp.tmp));
        strlcat(strings.tmp.tmp,
                amount_join->token_snapshot.ticker,
                sizeof(strings.tmp.tmp));
    } else {
        if (!amountToString(amount_join->value,
                            amount_join->value_length,
                            amount_join->token_snapshot.decimals,
                            amount_join->token_snapshot.ticker,
                            strings.tmp.tmp,
                            sizeof(strings.tmp.tmp))) {
            return false;
        }
    }
    ui_ctx->field_flags |= UI_712_FIELD_SHOWN;
    if (!ui_712_set_title(amount_join->name, strlen(amount_join->name))) {
        return false;
    }
    flist_remove((flist_node_t **) &ui_ctx->amount.joins,
                 (flist_node_t *) amount_join,
                 (f_list_node_del) delete_amount_join);
    return true;
}

static bool amount_join_snapshot_token(s_amount_join *amount_join,
                                       const uint8_t *expected_address) {
    const tokenDefinition_t *token;

    if (amount_join == NULL) {
        return false;
    }
    if ((amount_join->flags & AMOUNT_JOIN_FLAG_TOKEN) != 0U) {
        if ((expected_address != NULL) &&
            (memcmp(expected_address,
                    amount_join->token_snapshot.address,
                    ADDRESS_LENGTH) != 0)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        return true;
    }
    if (!asset_slot_is_kind(amount_join->token_idx, ASSET_KIND_TOKEN)) {
        apdu_response_code = SWO_REFERENCED_DATA_NOT_FOUND;
        return false;
    }
    token = &tmpCtx.transactionContext.extraInfo[amount_join->token_idx].token;
    if ((expected_address != NULL) &&
        (memcmp(expected_address, token->address, ADDRESS_LENGTH) != 0)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    memcpy(&amount_join->token_snapshot, token, sizeof(amount_join->token_snapshot));
    amount_join->flags |= AMOUNT_JOIN_FLAG_TOKEN;
    return true;
}

/**
 * Simply mark the current amount-join's token address as received
 */
bool amount_join_set_token_received(void) {
    s_amount_join *amount_join = get_amount_join(ui_ctx->amount.idx);

    return amount_join_snapshot_token(amount_join, NULL);
}

/**
 * Update the state of the amount-join
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @return whether it was successful or not
 */
static bool update_amount_join(const uint8_t *data, uint8_t length) {
    s_amount_join *amount_join;

    switch (ui_ctx->amount.state) {
        case AMOUNT_JOIN_STATE_TOKEN:
            if (length != ADDRESS_LENGTH) {
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
            }
            if ((amount_join = get_amount_join(ui_ctx->amount.idx)) == NULL ||
                !amount_join_snapshot_token(amount_join, data)) {
                return false;
            }
            break;

        case AMOUNT_JOIN_STATE_VALUE:
            if ((amount_join = get_amount_join(ui_ctx->amount.idx)) == NULL) {
                return false;
            }
            if (length > sizeof(amount_join->value)) {
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
            }
            memcpy(amount_join->value, data, length);
            amount_join->value_length = length;
            amount_join->flags |= AMOUNT_JOIN_FLAG_VALUE;
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
    if ((trusted_name = get_trusted_name(ui_ctx->tn_type_count,
                                         ui_ctx->tn_types,
                                         ui_ctx->tn_source_count,
                                         ui_ctx->tn_sources,
                                         &tip712_context->chain_id,
                                         data)) != NULL) {
        strlcpy(strings.tmp.tmp, trusted_name->name, sizeof(strings.tmp.tmp));
    }
    return true;
}

bool tip712_u64_from_zero_extended(const uint8_t *data,
                                   size_t length,
                                   uint64_t *value) {
    if ((data == NULL) || (value == NULL) || (length == 0U)) {
        return false;
    }
    while ((length > 1U) && (*data == 0U)) {
        data++;
        length--;
    }
    if (length > sizeof(*value)) {
        return false;
    }
    *value = u64_from_BE(data, length);
    return true;
}

bool tip712_is_full_width_max_value(const uint8_t *data,
                                    size_t length,
                                    size_t effective_size) {
    return (data != NULL) && (effective_size != 0U) &&
           (length == effective_size) && ismaxint((uint8_t *) data, length);
}

bool tip712_format_signed_int_value(const uint8_t *data,
                                    size_t length,
                                    uint8_t effective_size,
                                    char *out,
                                    size_t out_size) {
    uint8_t encoded[INT256_LENGTH];
    uint256_t value256;
    bool formatted;

    if ((data == NULL) || (length == 0U) || (length > effective_size) ||
        (effective_size == 0U) || (effective_size > sizeof(encoded)) ||
        (out == NULL) || (out_size == 0U) ||
        !encode_int(data, (uint8_t) length, effective_size, encoded)) {
        return false;
    }
    convertUint256BE(encoded, sizeof(encoded), &value256);
    formatted = tostring256_signed(&value256, 10, out, out_size);
    explicit_bzero(encoded, sizeof(encoded));
    explicit_bzero(&value256, sizeof(value256));
    return formatted;
}

/**
 * Format given data as a human-readable date/time representation
 *
 * @param[in] data the data that needs formatting
 * @param[in] length its length
 * @param[in] field_ptr pointer to the new struct field
 * @return whether it was successful or not
 */
static bool ui_712_format_datetime(const uint8_t *data,
                                   uint8_t length,
                                   const s_struct_712_field *field_ptr,
                                   bool first,
                                   bool last,
                                   const uint16_t *complete_length) {
    uint64_t timestamp_u64;
    time_t timestamp;

    if ((data == NULL) || (length == 0U) || !first || !last ||
        (complete_length == NULL) || (*complete_length != length)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    const uint8_t effective_size = field_ptr->type_has_size
                                       ? field_ptr->type_size
                                       : INT256_LENGTH;
    if (tip712_is_full_width_max_value(data, length, effective_size)) {
        snprintf(strings.tmp.tmp, sizeof(strings.tmp.tmp), "Unlimited");
        return true;
    }

    /* Standard uint256 timestamps are left-padded to 32 bytes. u64_from_BE()
     * reads from the start of its input, so strip only zero extension and reject
     * a value whose significant part cannot be represented by the UI metadata
     * type. */
    if (!tip712_u64_from_zero_extended(data, length, &timestamp_u64)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (timestamp_u64 > (uint64_t) INT64_MAX) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    timestamp = (time_t) timestamp_u64;
    return time_format_to_utc(&timestamp, strings.tmp.tmp, sizeof(strings.tmp.tmp));
}

static bool ui_712_set_intent_field(const char *value) {
    const char key[] = "Transaction type";

    return ui_712_set_title(key, strlen(key)) && ui_712_set_value(value, strlen(value));
}

static bool handle_fallback_empty_calldata(const s_eip712_calldata_info *calldata_info) {
    char *buf = strings.tmp.tmp;
    size_t buf_size = sizeof(strings.tmp.tmp);
    uint64_t chain_id;
    const char *ticker;

    if (calldata_info->amount_state == CALLDATA_INFO_PARAM_SET) {
        if (!ui_712_set_intent_field("Send")) return false;

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
        if (!ui_712_set_title("Amount", 6) || !ui_712_set_value(buf, strlen(buf))) return false;
    } else {
        if (!ui_712_set_intent_field("Empty transaction")) return false;
    }

    e_name_type types[] = {TN_TYPE_ACCOUNT};
    e_name_source sources[] = {TN_SOURCE_ENS, TN_SOURCE_LAB, TN_SOURCE_MAB};
    const s_trusted_name *trusted_name;

    if (!ui_712_set_title("To", 2)) return false;
    if ((trusted_name = get_trusted_name(ARRAYLEN(types),
                                         types,
                                         ARRAYLEN(sources),
                                         sources,
                                         &calldata_info->chain_id,
                                         calldata_info->callee)) != NULL) {
        if (!ui_712_set_value(trusted_name->name, strlen(trusted_name->name))) return false;
    } else {
        if (!ui_712_set_displayable_address(calldata_info->callee)) {
            return false;
        }
        if (!ui_712_set_value(buf, strlen(buf))) return false;
    }
    return true;
}

static bool update_calldata_value(const uint8_t *data,
                                  uint8_t length,
                                  const uint16_t *complete_length,
                                  bool last,
                                  s_eip712_calldata_info *calldata_info) {
    const uint8_t *selector = NULL;
    size_t calldata_size;

    if (calldata_info->value_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (complete_length != NULL) {
        calldata_size = *complete_length;
        if (calldata_info->pending_calldata != NULL) return false;

        if (calldata_info->selector_state == CALLDATA_INFO_PARAM_NONE) {
            // No embedded or separately filtered selector with an empty value
            // is a real empty transaction, not a zero-argument contract call.
            if (calldata_size != 0U) {
                if ((length < CALLDATA_SELECTOR_SIZE) ||
                    (calldata_size < CALLDATA_SELECTOR_SIZE)) {
                    return false;
                }
                selector = data;
                data += CALLDATA_SELECTOR_SIZE;
                length -= CALLDATA_SELECTOR_SIZE;
                calldata_size -= CALLDATA_SELECTOR_SIZE;
            }
        } else {
            // A separately filtered selector may arrive before or after the
            // value. A zero selector is only a temporary placeholder while
            // selector_state is UNSET; the TX context cannot be published
            // until the real selector has been received.
            selector = calldata_info->selector;
        }

        if (selector != NULL) {
            if (calldata_size > GCS_MAX_NESTED_CALLDATA_SIZE) {
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
            }
            calldata_info->pending_calldata = calldata_init_nested(calldata_size, selector);
            if (calldata_info->pending_calldata == NULL) {
                apdu_response_code = SWO_INSUFFICIENT_MEMORY;
                return false;
            }
        }
    }

    if (calldata_info->pending_calldata != NULL) {
        if (!calldata_append(calldata_info->pending_calldata, data, length)) {
            return false;
        }
    }
    if (last) calldata_info->value_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_callee(const uint8_t *data,
                                   uint8_t length,
                                   bool last,
                                   s_eip712_calldata_info *calldata_info) {
    if (calldata_info->callee_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last || (length != ADDRESS_LENGTH)) return false;
    buf_shrink_expand(data, length, calldata_info->callee, sizeof(calldata_info->callee));
    calldata_info->callee_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_chain_id(const uint8_t *data,
                                     uint8_t length,
                                     bool last,
                                     s_eip712_calldata_info *calldata_info) {
    if (calldata_info->chain_id_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last || (data == NULL) || (length == 0U)) return false;

    /* Accept legacy 8/24/32-byte zero-extended values, but never silently use
     * the low 64 bits when the signed chainId has non-zero high bits. */
    if (!tip712_u64_from_zero_extended(data,
                                       length,
                                       &calldata_info->chain_id)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    calldata_info->chain_id_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_selector(const uint8_t *data,
                                     uint8_t length,
                                     bool last,
                                     s_eip712_calldata_info *calldata_info) {
    if (calldata_info->selector_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last || (length != CALLDATA_SELECTOR_SIZE)) return false;
    buf_shrink_expand(data, length, calldata_info->selector, sizeof(calldata_info->selector));
    calldata_info->selector_state = CALLDATA_INFO_PARAM_SET;
    if (calldata_info->value_state == CALLDATA_INFO_PARAM_SET) {
        if (calldata_info->pending_calldata == NULL) {
            calldata_info->pending_calldata =
                calldata_init_nested(0U, calldata_info->selector);
            if (calldata_info->pending_calldata == NULL) {
                apdu_response_code = SWO_INSUFFICIENT_MEMORY;
                return false;
            }
        } else if (!calldata_set_selector(calldata_info->pending_calldata,
                                          calldata_info->selector)) {
            return false;
        }
    }
    return true;
}

static bool update_calldata_amount(const uint8_t *data,
                                   uint8_t length,
                                   bool last,
                                   s_eip712_calldata_info *calldata_info) {
    if (calldata_info->amount_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last || (length == 0U) || (length > sizeof(calldata_info->amount))) return false;
    buf_shrink_expand(data, length, calldata_info->amount, sizeof(calldata_info->amount));
    calldata_info->amount_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata_spender(const uint8_t *data,
                                    uint8_t length,
                                    bool last,
                                    s_eip712_calldata_info *calldata_info) {
    if (calldata_info->spender_state != CALLDATA_INFO_PARAM_UNSET) return false;
    if (!last || (length != ADDRESS_LENGTH)) return false;
    buf_shrink_expand(data, length, calldata_info->spender, sizeof(calldata_info->spender));
    calldata_info->spender_state = CALLDATA_INFO_PARAM_SET;
    return true;
}

static bool update_calldata(const uint8_t *data,
                            uint8_t length,
                            const uint16_t *complete_length,
                            bool last) {
    s_eip712_calldata_info *calldata_info = get_calldata_info(ui_ctx->calldata_index);

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
        if (calldata_info->processed) return false;
        if (calldata_info->pending_calldata == NULL) {
            if (!handle_fallback_empty_calldata(calldata_info)) return false;
            calldata_info->processed = true;
        } else {
            if (!tx_ctx_init(calldata_info->pending_calldata,
                             calldata_info->spender,
                             calldata_info->callee,
                             calldata_info->amount,
                             &calldata_info->chain_id)) {
                calldata_delete(calldata_info->pending_calldata);
                calldata_info->pending_calldata = NULL;
                return false;
            }
            calldata_info->pending_calldata = NULL;
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
bool ui_712_feed_to_display(const s_struct_712_field *field_ptr,
                            const uint8_t *data,
                            uint8_t length,
                            const uint16_t *complete_length,
                            bool last) {
    bool first = complete_length != NULL;

    if (ui_ctx == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if (first && (strlen(strings.tmp.tmp) > 0)) {
        return false;
    }
    // Value
    if (ui_712_field_shown()) {
        switch (field_ptr->type) {
            case TYPE_SOL_STRING:
                if (!ui_712_append_str(data, length, complete_length, last)) {
                    return false;
                }
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
                if (ui_712_format_bytes(data, length, complete_length, last) == false) {
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

        s_amount_join *amount_join = get_amount_join(ui_ctx->amount.idx);
        if (amount_join == NULL) {
            return false;
        }
        if (amount_join->flags == (AMOUNT_JOIN_FLAG_TOKEN | AMOUNT_JOIN_FLAG_VALUE)) {
            if (!ui_712_format_amount_join()) {
                return false;
            }
        }
    }

    if (ui_ctx->field_flags & UI_712_DATETIME) {
        if (!ui_712_format_datetime(data,
                                    length,
                                    field_ptr,
                                    first,
                                    last,
                                    complete_length)) {
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
        // This is the last chunk, we can now set the value. String and bytes
        // stream straight into pair->value and finalize themselves, so only the
        // fixed-buffer types need committing from strings.tmp.tmp here.
        if ((field_ptr->type != TYPE_SOL_STRING) && (field_ptr->type != TYPE_SOL_BYTES_FIX) &&
            (field_ptr->type != TYPE_SOL_BYTES_DYN)) {
            if (!ui_712_set_value(NULL, 0)) {
                return false;
            }
        }

        return ui_712_redraw_generic_step();
    }
    return true;
}

/**
 * Used to signal that we are done with reviewing the structs and we can now have
 * the option to approve or reject the signature
 */
bool ui_712_end_sign(void) {
    if (ui_ctx == NULL) {
        apdu_response_code = SWO_COMMAND_NOT_ALLOWED;
        return false;
    }

#ifdef SCREEN_SIZE_WALLET
    if (true) {
#else
    if (N_storage.verbose_tip712 || (ui_ctx->filtering_mode == TIP712_FILTERING_FULL)) {
#endif
        ui_ctx->end_reached = true;
        apdu_response_code = ui_sign_712(ui_ctx->filtering_mode);
        return apdu_response_code == SWO_SUCCESS;
    }
    return true;
}

/**
 * Initializes the UI context structure in memory
 */
bool ui_712_init(void) {
    if (ui_ctx != NULL) {
        ui_712_deinit();
        return false;
    }

    ui_ctx = gcs_mem_calloc(sizeof(*ui_ctx), GCS_MEM_UI);
    if (ui_ctx == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
    } else {
        ui_712_set_filtering_mode(TIP712_FILTERING_BASIC);
        explicit_bzero(&strings, sizeof(strings));
    }
    return ui_ctx != NULL;
}

static void delete_calldata_info(s_eip712_calldata_info *node) {
    if (node->pending_calldata != NULL) {
        calldata_delete(node->pending_calldata);
        node->pending_calldata = NULL;
    }
    gcs_mem_free(node);
}

/**
 * Deinit function that simply unsets the struct pointer to NULL
 */
void ui_712_deinit(void) {
    if (ui_ctx != NULL) {
        if (ui_ctx->filters_crc != NULL) {
            flist_clear((flist_node_t **) &ui_ctx->filters_crc,
                        (f_list_node_del) &delete_filter_crc);
        }
        if (ui_ctx->ui_pairs != NULL) {
            flist_clear((flist_node_t **) &ui_ctx->ui_pairs, (f_list_node_del) &delete_ui_pair);
        }
        if (ui_ctx->amount.joins != NULL) {
            flist_clear((flist_node_t **) &ui_ctx->amount.joins,
                        (f_list_node_del) &delete_amount_join);
        }
        if (ui_ctx->calldata_info != NULL) {
            flist_clear((flist_node_t **) &ui_ctx->calldata_info,
                        (f_list_node_del) &delete_calldata_info);
            gcs_cleanup();
        }
        ui_712_clear_discarded_path();
        gcs_mem_free_and_null((void **) &ui_ctx);
    }
}

/**
 * Approve button handling. The common callback sends the response and resets
 * the complete application context.
 */
void ui_712_approve(void) {
    ui_712_approve_cb(true);
}

/**
 * Reject button handling. The common callback sends the response and resets
 * the complete application context.
 */
void ui_712_reject(void) {
    ui_712_reject_cb(true);
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
    ui_ctx->message_info_received = true;
}

/**
 * Get the number of filters left to process
 *
 * @return number of filters
 */
uint8_t ui_712_remaining_filters(void) {
    return ui_ctx->filters_to_process - flist_size((flist_node_t **) &ui_ctx->filters_crc);
}

bool ui_712_message_info_received(void) {
    return ui_ctx->message_info_received;
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
    if (N_storage.verbose_tip712) {
#endif
        ui_ctx->structs_to_review += 1;
    }
}

void ui_712_token_join_prepare_addr_check(uint8_t index) {
    ui_ctx->amount.idx = index;
    ui_ctx->amount.state = AMOUNT_JOIN_STATE_TOKEN;
}

bool ui_712_token_join_prepare_amount(uint8_t index, const char *name, uint8_t name_length) {
    s_amount_join *amount_join = get_amount_join(index);
    if ((amount_join == NULL) || (name == NULL) || (name_length == 0U) ||
        (name_length > AMOUNT_JOIN_NAME_LENGTH)) {
        return false;
    }
    ui_ctx->amount.idx = index;
    ui_ctx->amount.state = AMOUNT_JOIN_STATE_VALUE;
    memcpy(amount_join->name, name, name_length);
    amount_join->name[name_length] = '\0';
    return true;
}

/**
 * Set UI pair key to the raw JSON key
 *
 * @param[in] field_ptr pointer to the field
 * @return whether it was successful or not
 */
bool ui_712_show_raw_key(const s_struct_712_field *field_ptr) {
    const char *key;

    if ((key = field_ptr->key_name) == NULL) {
        return false;
    }

    if (ui_712_field_shown() && !(ui_ctx->field_flags & UI_712_FIELD_NAME_PROVIDED)) {
        if (!ui_712_set_title(key, strlen(key))) {
            return false;
        }
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
    s_filter_crc *tmp;
    s_filter_crc *new_crc;
    uint8_t filter_count = 0;

    // check if already present
    for (tmp = ui_ctx->filters_crc; tmp != NULL;
         tmp = (s_filter_crc *) ((flist_node_t *) tmp)->next) {
        if (tmp->value == path_crc) {
            PRINTF("TIP-712 path CRC (%x) already found!\n", path_crc);
            return true;
        }
        filter_count += 1;
    }

    if (filter_count >= ui_ctx->filters_to_process) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    // allocate it
    new_crc = gcs_mem_calloc(sizeof(*new_crc), GCS_MEM_GENERIC);
    if (new_crc == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    new_crc->value = path_crc;

    PRINTF("Pushing new TIP-712 path CRC (%x)\n", path_crc);
    flist_push_back((flist_node_t **) &ui_ctx->filters_crc, (flist_node_t *) new_crc);
    return true;
}

/**
 * Set a discarded filter path
 *
 * @param[in] path the given filter path
 * @param[in] length the path length
 * @return whether it was successful or not
 */
bool ui_712_set_discarded_path(const char *path, uint8_t length) {
    if (ui_ctx->discarded_path != NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if ((ui_ctx->discarded_path = gcs_mem_alloc(length + 1U,
                                                GCS_MEM_GENERIC)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    memcpy(ui_ctx->discarded_path, path, length);
    ui_ctx->discarded_path[length] = '\0';
    return true;
}

/**
 * Get the discarded filter path
 *
 * @return filter path
 */
const char *ui_712_get_discarded_path(void) {
    return ui_ctx->discarded_path;
}

void ui_712_clear_discarded_path(void) {
    gcs_mem_free_and_null((void **) &ui_ctx->discarded_path);
}

void ui_712_set_trusted_name_requirements(uint8_t type_count,
                                          const e_name_type *types,
                                          uint8_t source_count,
                                          const e_name_source *sources) {
    ui_ctx->tn_type_count = type_count;
    memcpy(ui_ctx->tn_types, types, type_count);
    ui_ctx->tn_source_count = source_count;
    memcpy(ui_ctx->tn_sources, sources, source_count);
}

/**
 * Set the tag/value pairs for the review
 *
 */
bool ui_712_push_pairs(void) {
    uint8_t nbPairs = 0;
    uint8_t pair = 0;
    size_t pair_count;
    s_ui_712_pair *tmp = NULL;
    uint8_t tx_idx = 0;

    // Initialize the pairs list
    if (ui_ctx == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    pair_count = flist_size((flist_node_t **) &ui_ctx->ui_pairs);
    if (N_storage.displayHash) {
        // Two extra pages for the domain hash + message hash (the "Transaction
        // hash" / displayHash setting). Mirrors app-ethereum's ui_712_push_pairs.
        pair_count += 2;
    }
    if ((pair_count == 0) || (pair_count > TIP712_MAX_UI_PAIRS) ||
        (pair_count > UINT8_MAX)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    nbPairs = (uint8_t) pair_count;

    if (!ui_pairs_init(nbPairs)) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    // Initialize the tag/value pairs from the chain list
    tmp = ui_ctx->ui_pairs;
    while (tmp != NULL) {
        if ((g_pairs == NULL) || (g_pairsList == NULL) || (pair >= g_pairsList->nbPairs)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        if (tmp->start_intent) {
            // Batch intermediate page
            tx_idx++;
            // Replace "nn of mm" placeholder, initialized in ui_712_set_intent()
            snprintf(tmp->value, N_OF_M_LENGTH, "%d of %d", tx_idx, txContext.batch_nb_tx);
            g_pairs[pair].centeredInfo = true;
        }
        g_pairs[pair].item = tmp->key;
        g_pairs[pair].value = tmp->value;
        pair++;
        if ((tmp->end_intent) && (txContext.batch_nb_tx > 1) &&
            (pair < g_pairsList->nbPairs)) {
            // End of batch transaction : start next info on full page
            g_pairs[pair].forcePageStart = true;
        }
        tmp = (s_ui_712_pair *) ((flist_node_t *) tmp)->next;
    }

    if (N_storage.displayHash) {
        // Append the Domain hash + Message hash pages, mirroring app-ethereum.
        // tip712_format_hash() writes the two hex strings into non-overlapping
        // offsets of strings.tmp.tmp, so both values stay valid simultaneously.
        if ((g_pairs == NULL) || (g_pairsList == NULL) ||
            (((size_t) pair + 1U) >= g_pairsList->nbPairs)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        tip712_format_hash(0, &g_pairs[pair].item, &g_pairs[pair].value);
        g_pairs[pair].forcePageStart = true;
        tip712_format_hash(1, &g_pairs[pair + 1].item, &g_pairs[pair + 1].value);
    }
    return true;
}

void add_calldata_info(s_eip712_calldata_info *node) {
    flist_push_back((flist_node_t **) &ui_ctx->calldata_info, (flist_node_t *) node);
}

size_t ui_712_calldata_info_count(void) {
    return (ui_ctx == NULL)
               ? 0U
               : flist_size((flist_node_t **) &ui_ctx->calldata_info);
}

s_eip712_calldata_info *get_calldata_info(uint8_t index) {
    for (s_eip712_calldata_info *tmp = ui_ctx->calldata_info; tmp != NULL;
         tmp = (s_eip712_calldata_info *) ((flist_node_t *) tmp)->next) {
        if (index == tmp->index) {
            return tmp;
        }
    }
    return NULL;
}

s_eip712_calldata_info *get_current_calldata_info(void) {
    return get_calldata_info(ui_ctx->calldata_index);
}

bool all_calldata_info_processed(void) {
    for (const s_eip712_calldata_info *tmp = ui_ctx->calldata_info; tmp != NULL;
         tmp = (const s_eip712_calldata_info *) ((const flist_node_t *) tmp)->next) {
        if (!tmp->processed || !calldata_info_all_received(tmp) ||
            (tmp->pending_calldata != NULL)) {
            return false;
        }
    }
    return true;
}

void calldata_info_set_state(uint8_t index, e_eip712_calldata_state state) {
    s_eip712_calldata_info *calldata_info = get_calldata_info(index);

    ui_ctx->calldata_index = index;
    if (calldata_info != NULL) {
        calldata_info->state = state;
    }
}

bool calldata_info_all_received(const s_eip712_calldata_info *calldata_info) {
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
