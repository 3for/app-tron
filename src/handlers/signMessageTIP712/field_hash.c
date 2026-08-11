#include <stdlib.h>
#include "field_hash.h"
#include "encode_field.h"
#include "path.h"
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "ui_logic.h"
#include "context_712.h"   // contract_addr
#include "common_utils.h"  // u64_from_BE
#include "typed_data.h"
#include "commands_712.h"
#include "hash_bytes.h"
#include "app_errors.h"
#include "parse.h"
#include "ui_globals.h"
#include "gcs_memory.h"
#include "utils.h"

static s_field_hashing *fh = NULL;

static uint8_t field_effective_size(const s_struct_712_field *field_ptr);

/**
 * Initialize the field hash context
 *
 * @return whether the initialization was successful or not
 */
bool field_hash_init(void) {
    if (fh != NULL) {
        field_hash_deinit();
        return false;
    }

    fh = gcs_mem_calloc(sizeof(*fh), GCS_MEM_GENERIC);
    if (fh == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    fh->state = FHS_IDLE;
    return true;
}

/**
 * Deinitialize the field hash context
 */
void field_hash_deinit(void) {
    gcs_mem_free_and_null((void **) &fh);
}

/**
 * Special handling of the first chunk received from a field value
 *
 * @param[in] field_ptr pointer to the struct field definition
 * @param[in] data the field value
 * @param[in,out] data_length the value length
 * @return the data pointer
 */
static const uint8_t *field_hash_prepare(const s_struct_712_field *field_ptr,
                                         const uint8_t *data,
                                         uint8_t *data_length) {
    fh->remaining_size = ((uint16_t) data[0] << 8) | data[1];
    data += sizeof(uint16_t);
    *data_length -= sizeof(uint16_t);
    fh->state = FHS_WAITING_FOR_MORE;
    if (IS_DYN(field_ptr->type)) {
        if (cx_keccak_init_no_throw(&global_sha3, 256) != CX_OK) {
            return NULL;
        }
    }
    return data;
}

/**
 * Finalize static field hash
 *
 * Encode the field data depending on its type
 *
 * @param[in] field_ptr pointer to the struct field definition
 * @param[in] data the field value
 * @param[in] data_length the value length
 * @return pointer to the encoded value
 */
static bool field_hash_finalize_static(const s_struct_712_field *field_ptr,
                                       const uint8_t *data,
                                       uint8_t data_length,
                                       uint8_t value[TIP_712_ENCODED_FIELD_LENGTH]) {
    switch (field_ptr->type) {
        case TYPE_SOL_INT:
            return encode_int(data,
                              data_length,
                              field_effective_size(field_ptr),
                              value);
        case TYPE_SOL_UINT:
            return encode_uint(data, data_length, value);
        case TYPE_SOL_BYTES_FIX:
            return encode_bytes(data, data_length, value);
        case TYPE_SOL_ADDRESS:
            return encode_address(data, data_length, value);
        case TYPE_SOL_BOOL:
            return encode_boolean(data, data_length, value);
        case TYPE_SOL_TRCTOKEN:  // trcToken is equal to uint256
            return encode_uint(data, data_length, value);
        case TYPE_CUSTOM:
        default:
            apdu_response_code = SWO_INCORRECT_DATA;
            PRINTF("Unknown solidity type!\n");
            return false;
    }
}

static uint8_t field_effective_size(const s_struct_712_field *field_ptr) {
    if (field_ptr == NULL) {
        return 0U;
    }
    switch (field_ptr->type) {
        case TYPE_SOL_INT:
        case TYPE_SOL_UINT:
            return field_ptr->type_has_size ? field_ptr->type_size
                                            : TIP_712_ENCODED_FIELD_LENGTH;
        case TYPE_SOL_TRCTOKEN:
            return TIP_712_ENCODED_FIELD_LENGTH;
        case TYPE_SOL_BYTES_FIX:
            return field_ptr->type_size;
        case TYPE_SOL_ADDRESS:
            return ADDRESS_LENGTH;
        case TYPE_SOL_BOOL:
            return 1U;
        default:
            return 0U;
    }
}

static bool validate_static_field_value(const s_struct_712_field *field_ptr,
                                        const uint8_t *data,
                                        uint8_t data_length) {
    uint8_t effective_size = field_effective_size(field_ptr);

    if ((field_ptr == NULL) || (data == NULL) || (effective_size == 0U)) {
        return false;
    }
    switch (field_ptr->type) {
        case TYPE_SOL_INT:
        case TYPE_SOL_UINT:
        case TYPE_SOL_TRCTOKEN:
            return (data_length > 0U) && (data_length <= effective_size);
        case TYPE_SOL_BYTES_FIX:
        case TYPE_SOL_ADDRESS:
            return data_length == effective_size;
        case TYPE_SOL_BOOL:
            return (data_length == 1U) && (data[0] <= 1U);
        default:
            return false;
    }
}

/**
 * Finalize dynamic field hash
 *
 * Allocate and hash the data
 *
 * @return pointer to the hash, \ref NULL if it failed
 */
static bool field_hash_finalize_dynamic(uint8_t value[KECCAK256_HASH_BYTESIZE]) {
    return finalize_hash((cx_hash_t *) &global_sha3,
                         value,
                         KECCAK256_HASH_BYTESIZE);
}

/**
 * Feed the newly created field hash into the parent struct's progressive hash
 *
 * @param[in] field_type the struct field's type
 * @param[in] hash the field hash
 */
static bool field_hash_feed_parent(e_type field_type, const uint8_t *hash) {
    uint8_t len;

    if (IS_DYN(field_type)) {
        len = KECCAK256_HASH_BYTESIZE;
    } else {
        len = TIP_712_ENCODED_FIELD_LENGTH;
    }

    // last thing in mem is the hash of the previous field
    // and just before it is the current hash context
    s_hash_ctx *hash_ctx = get_last_hash_ctx();
    if (hash_ctx == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (cx_hash_no_throw((cx_hash_t *) &hash_ctx->hash,
                         0,
                         hash,
                         len,
                         NULL,
                         0) != CX_OK) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    hash_ctx->has_data = true;
    return true;
}

/**
 * Special domain fields handling
 *
 * Do something special for certain EIP712Domain fields
 *
 * @param[in] field_ptr pointer to the struct field definition
 * @param[in] data the field value
 * @param[in] data_length the value length
 * @return whether an error occurred or not
 */
static bool field_hash_domain_special_fields(const s_struct_712_field *field_ptr,
                                             const uint8_t *data,
                                             uint8_t data_length) {
    const char *key;
    key = field_ptr->key_name;
    // copy contract address into context
    if (strcmp(key, "verifyingContract") == 0) {
        if (field_ptr->type_is_array || (field_ptr->type != TYPE_SOL_ADDRESS) ||
            (data_length != sizeof(tip712_context->contract_addr))) {
            apdu_response_code = SWO_INCORRECT_DATA;
            PRINTF("Error: non-canonical verifyingContract\n");
            return false;
        }
        memcpy(tip712_context->contract_addr, data, data_length);
    } else if (strcmp(key, "chainId") == 0) {
        if (field_ptr->type_is_array || (field_ptr->type != TYPE_SOL_UINT) ||
            (data_length == 0U)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }

        tip712_context->chain_id_seen = true;
        // TIP-712 hashes chainId as the declared Solidity integer (up to
        // uint256), but filtering certificates and network metadata use a
        // uint64_t chain ID. Strip harmless leading zeroes and never silently
        // truncate a genuinely larger value into that metadata context.
        while ((data_length > 1) && (*data == 0)) {
            data++;
            data_length--;
        }
        if (data_length > sizeof(tip712_context->chain_id)) {
            tip712_context->chain_id = 0;
            tip712_context->chain_id_fits_u64 = false;
            if (ui_712_get_filtering_mode() == TIP712_FILTERING_FULL) {
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
            }
            return true;
        }

        tip712_context->chain_id = u64_from_BE(data, data_length);
        tip712_context->chain_id_fits_u64 = true;
    }
    return true;
}

/**
 * Finalize the data hashing
 *
 * @param[in] field_ptr pointer to the struct field definition
 * @param[in] data the field value
 * @param[in] data_length the value length
 * @return whether an error occurred or not
 */
static bool field_hash_finalize(const s_struct_712_field *field_ptr,
                                const uint8_t *data,
                                uint8_t data_length) {
    uint8_t value[TIP_712_ENCODED_FIELD_LENGTH];
    bool encoded;

    if (!IS_DYN(field_ptr->type)) {
        encoded = field_hash_finalize_static(field_ptr,
                                             data,
                                             data_length,
                                             value);
    } else {
        encoded = field_hash_finalize_dynamic(value);
    }
    if (!encoded) {
        explicit_bzero(value, sizeof(value));
        return false;
    }

    if (!field_hash_feed_parent(field_ptr->type, value)) {
        explicit_bzero(value, sizeof(value));
        return false;
    }
    explicit_bzero(value, sizeof(value));

    if (path_get_root_type() == ROOT_DOMAIN) {
        if (field_hash_domain_special_fields(field_ptr, data, data_length) == false) {
            return false;
        }
    }
    if (!path_advance(true)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    fh->state = FHS_IDLE;
    ui_712_finalize_field();
    return true;
}

/**
 * Hash a field value
 *
 * @param[in] data the field value
 * @param[in] data_length the value length
 * @param[in] partial whether there is more of that data coming later or not
 * @return whether the data hashing was successful or not
 */
bool field_hash(const uint8_t *data, uint8_t data_length, bool partial) {
    const s_struct_712_field *field_ptr;
    bool first;
    uint16_t total_length = 0;

    if ((fh == NULL) || ((field_ptr = path_get_field()) == NULL)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    first = fh->state == FHS_IDLE;

    // first packet for this frame
    if (first) {
        if (!ui_712_show_raw_key(field_ptr)) {
            return false;
        }
        if (data_length < 2) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }

        data = field_hash_prepare(field_ptr, data, &data_length);
        if (data == NULL) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        total_length = fh->remaining_size;
    }
    /* Once a dynamic field is waiting for bytes, an empty continuation makes
     * no progress and could otherwise keep the build session alive forever. */
    if (!first && IS_DYN(field_ptr->type) && (fh->remaining_size > 0U) &&
        (data_length == 0U)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (data_length > fh->remaining_size) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    fh->remaining_size -= data_length;
    if ((field_ptr->type == TYPE_SOL_STRING) &&
        !is_printable((const char *) data, data_length)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (!IS_DYN(field_ptr->type) &&
        !validate_static_field_value(field_ptr, data, data_length)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    // if a dynamic type -> continue progressive hash
    if (IS_DYN(field_ptr->type)) {
        if (!hash_nbytes_no_throw(data,
                                  data_length,
                                  (cx_hash_t *) &global_sha3)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
    }
    if (!ui_712_feed_to_display(field_ptr,
                                data,
                                data_length,
                                first ? &total_length : NULL,
                                fh->remaining_size == 0)) {
        return false;
    }
    if (fh->remaining_size == 0) {
        if (partial)  // only makes sense if marked as complete
        {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        if (field_hash_finalize(field_ptr, data, data_length) == false) {
            return false;
        }
    } else {
        if (!partial || !IS_DYN(field_ptr->type))  // only makes sense if marked as partial
        {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        handle_tip712_return_code(true);
    }
    return true;
}
