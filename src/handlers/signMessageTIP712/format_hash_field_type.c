#include "format_hash_field_type.h"
#include <stdio.h>
#include <string.h>
#include "commands_712.h"
#include "hash_bytes.h"
#include "app_errors.h"  // APDU response codes
#include "parse.h"       // apdu_response_code
#include "typed_data.h"

/**
 * Format & hash a struct field typesize
 *
 * @param[in] field_ptr pointer to the struct field
 * @param[in] hash_ctx pointer to the hashing context
 * @return whether the formatting & hashing were successful or not
 */
static bool format_hash_field_type_size(const s_struct_712_field *field_ptr, cx_hash_t *hash_ctx) {
    uint16_t field_size;
    char uint_str[sizeof("4294967295")];

    field_size = field_ptr->type_size;
    switch (field_ptr->type) {
        case TYPE_SOL_INT:
        case TYPE_SOL_UINT:
        case TYPE_SOL_TRCTOKEN:
            field_size *= 8;  // bytes -> bits
            break;
        case TYPE_SOL_BYTES_FIX:
            break;
        default:
            // should not be in here :^)
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
    }
    int written = snprintf(uint_str,
                           sizeof(uint_str),
                           "%u",
                           (unsigned int) field_size);
    if ((written < 0) || ((size_t) written >= sizeof(uint_str)) ||
        !hash_nbytes_no_throw((const uint8_t *) uint_str,
                              (size_t) written,
                              hash_ctx)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    return true;
}

/**
 * Format & hash a struct field array levels
 *
 * @param[in] field_ptr pointer to the struct field
 * @param[in] hash_ctx pointer to the hashing context
 * @return whether the formatting & hashing were successful or not
 */
static bool format_hash_field_type_array_levels(const s_struct_712_field *field_ptr,
                                                cx_hash_t *hash_ctx) {
    char uint_str[sizeof("255")];

    for (int i = 0; i < field_ptr->array_level_count; ++i) {
        if (!hash_byte_no_throw('[', hash_ctx)) {
            return false;
        }

        switch (field_ptr->array_levels[i].type) {
            case ARRAY_DYNAMIC:
                break;
            case ARRAY_FIXED_SIZE: {
                int written = snprintf(uint_str,
                                       sizeof(uint_str),
                                       "%u",
                                       (unsigned int) field_ptr->array_levels[i].size);
                if ((written < 0) || ((size_t) written >= sizeof(uint_str)) ||
                    !hash_nbytes_no_throw((const uint8_t *) uint_str,
                                          (size_t) written,
                                          hash_ctx)) {
                    apdu_response_code = SWO_INCORRECT_DATA;
                    return false;
                }
                break;
            }
            default:
                // should not be in here :^)
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
        }
        if (!hash_byte_no_throw(']', hash_ctx)) {
            return false;
        }
    }
    return true;
}

/**
 * Format & hash a struct field type
 *
 * @param[in] field_ptr pointer to the struct field
 * @param[in] hash_ctx pointer to the hashing context
 * @return whether the formatting & hashing were successful or not
 */
bool format_hash_field_type(const s_struct_712_field *field_ptr, cx_hash_t *hash_ctx) {
    const char *name;

    // field type name
    name = get_struct_field_typename(field_ptr);
    if (name == NULL) {
        return false;
    }
    if (!hash_nbytes_no_throw((const uint8_t *) name, strlen(name), hash_ctx)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    // field type size
    if (field_ptr->type_has_size) {
        if (!format_hash_field_type_size(field_ptr, hash_ctx)) {
            return false;
        }
    }

    // field type array levels
    if (field_ptr->type_is_array) {
        if (!format_hash_field_type_array_levels(field_ptr, hash_ctx)) {
            return false;
        }
    }
    return true;
}
