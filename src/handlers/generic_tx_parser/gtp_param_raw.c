#include <inttypes.h>
#include "os_print.h"
#include "gtp_param_raw.h"
#include "gtp_field.h"
#include "uint256.h"
#include "read.h"
#include "gtp_field_table.h"
#include "utils.h"
#include "shared_context.h"
#include "tlv_library.h"
#include "tlv_apdu.h"

#define PARAM_RAW_TAGS(X)                                    \
    X(0x00, TAG_VERSION, handle_version, ENFORCE_UNIQUE_TAG) \
    X(0x01, TAG_VALUE, handle_value, ENFORCE_UNIQUE_TAG)

static bool handle_version(const tlv_data_t *data, s_param_raw_context *context) {
    return tlv_get_uint8_range(data, &context->param->version, 0, UINT8_MAX);
}

static bool handle_value(const tlv_data_t *data, s_param_raw_context *context) {
    s_value_context ctx = {0};

    ctx.value = &context->param->value;
    explicit_bzero(ctx.value, sizeof(*ctx.value));
    return handle_value_struct(&data->value, &ctx);
}

DEFINE_TLV_PARSER(PARAM_RAW_TAGS, NULL, param_raw_tlv_parser)

bool handle_param_raw_struct(const buffer_t *buf, s_param_raw_context *context) {
    TLV_reception_t received_tags = {0};
    return param_raw_tlv_parser(buf, context, &received_tags) &&
           TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_VERSION, TAG_VALUE) &&
           (context->param->version == 1U);
}

/**
 * @brief Apply visibility constraint logic
 *
 * @param field Field with visibility setting
 * @param to_be_displayed Output: whether field should be displayed
 * @param constraint_matched Whether value matched a constraint
 * @param value_type Type name for error messages
 * @return false if TX should be rejected (MUST_BE not matched), true otherwise
 */
static bool apply_visibility_constraint(const s_field *field,
                                        bool *to_be_displayed,
                                        bool constraint_matched) {
    *to_be_displayed = false;

    switch (field->visibility) {
        case PARAM_VISIBILITY_MUST_BE:
            if (!constraint_matched) {
                PRINTF("Error: RAW value does not match any MUST_BE constraint!\n");
                // Reject the TX
                return false;
            }
            break;
        case PARAM_VISIBILITY_IF_NOT_IN:
            if (constraint_matched) {
                PRINTF("Warning: RAW value does match a IF_NOT_IN constraint!\n");
                // Skip displaying the field
                break;
            }
            *to_be_displayed = true;
            break;
        default:  // PARAM_VISIBILITY_ALWAYS
            *to_be_displayed = true;
            break;
    }

    return true;
}

/**
 * @brief Check if a uint256 value matches any of the field's constraints
 *
 * @param field Field containing the constraints to check
 * @param value256 Value to check against constraints
 * @return true if value matches a constraint, false otherwise
 */
static bool check_uint_constraint(const s_field *field, const uint256_t *value256) {
    uint256_t constraint = {0};
    uint8_t encoded[INT256_LENGTH];

    for (s_field_constraint *c_node = field->constraints; c_node != NULL;
         c_node = (s_field_constraint *) c_node->node.next) {
        s_parsed_value parsed = {.ptr = c_node->value, .length = c_node->size};
        if (!parsed_value_to_uint_be(&parsed, encoded, sizeof(encoded))) continue;
        convertUint256BE(encoded, sizeof(encoded), &constraint);
        if (equal256(value256, &constraint)) {
            return true;
        }
    }
    return false;
}

bool format_uint(const s_field *field,
                 bool *to_be_displayed,
                 s_parsed_value *value,
                 char *buf,
                 size_t buf_size) {
    uint256_t value256 = {0};
    uint8_t encoded[INT256_LENGTH] = {0};

    if ((field == NULL) || (to_be_displayed == NULL) ||
        (buf == NULL) || (buf_size == 0U) ||
        !parsed_value_to_typed_uint_be(&field->param_raw.value,
                                       value,
                                       encoded,
                                       sizeof(encoded))) {
        return false;
    }
    convertUint256BE(encoded, sizeof(encoded), &value256);

    if (!apply_visibility_constraint(field,
                                     to_be_displayed,
                                     check_uint_constraint(field, &value256))) {
        return false;
    }

    return *to_be_displayed ? tostring256(&value256, 10, buf, buf_size) : true;
}

bool format_int(const s_value *def, const s_parsed_value *value, char *buf, size_t buf_size) {
    uint8_t tmp[INT256_LENGTH] = {0};
    const uint8_t *encoded;
    size_t encoded_length;
    size_t ignored_prefix = 0U;
    uint8_t padding;
    bool ret;
    int written;
    union {
        uint256_t value256;
        uint128_t value128;
        int64_t value64;
        int32_t value32;
        int16_t value16;
        int8_t value8;
    } uv;

    if ((def == NULL) || (value == NULL) || (value->ptr == NULL) ||
        (value->length == 0U) || (value->length > INT256_LENGTH) ||
        (def->type_size == 0U) || (def->type_size > INT256_LENGTH) ||
        (buf == NULL) || (buf_size == 0U)) {
        return false;
    }
    encoded = value->ptr;
    encoded_length = value->length;
    if (encoded_length > def->type_size) {
        ignored_prefix = encoded_length - def->type_size;
        encoded += ignored_prefix;
        encoded_length = def->type_size;
    }
    padding = (encoded[0] & 0x80U) ? 0xffU : 0x00U;
    for (size_t i = 0U; i < ignored_prefix; ++i) {
        if (value->ptr[i] != padding) {
            return false;
        }
    }
    memset(tmp, padding, def->type_size);
    memcpy(tmp + def->type_size - encoded_length, encoded, encoded_length);
    switch (def->type_size * 8) {
        case 256:
            convertUint256BE(tmp, def->type_size, &uv.value256);
            ret = tostring256_signed(&uv.value256, 10, buf, buf_size);
            break;
        case 128:
            convertUint128BE(tmp, def->type_size, &uv.value128);
            ret = tostring128_signed(&uv.value128, 10, buf, buf_size);
            break;
        case 64:
            uv.value64 = (int64_t) read_u64_be(tmp, 0);
            written = snprintf(buf, buf_size, "%" PRId64, uv.value64);
            ret = (written >= 0) && ((size_t) written < buf_size);
            break;
        case 32:
            uv.value32 = (int32_t) read_u32_be(tmp, 0);
            written = snprintf(buf, buf_size, "%" PRId32, uv.value32);
            ret = (written >= 0) && ((size_t) written < buf_size);
            break;
        case 16:
            uv.value16 = (int16_t) read_u16_be(tmp, 0);
            written = snprintf(buf, buf_size, "%" PRId16, uv.value16);
            ret = (written >= 0) && ((size_t) written < buf_size);
            break;
        case 8:
            uv.value8 = (int8_t) tmp[0];
            written = snprintf(buf, buf_size, "%" PRId8, uv.value8);
            ret = (written >= 0) && ((size_t) written < buf_size);
            break;
        default:
            ret = false;
    }
    return ret;
}

/**
 * @brief Check if an address matches any of the field's constraints
 *
 * @param field Field containing the constraints to check
 * @param addr Address to check against constraints
 * @return true if address matches a constraint, false otherwise
 */
static bool check_address_constraint(const s_field *field, const uint8_t *addr) {
    uint8_t constraint[ADDRESS_LENGTH] = {0};

    for (s_field_constraint *c_node = field->constraints; c_node != NULL;
         c_node = (s_field_constraint *) c_node->node.next) {
        s_parsed_value parsed = {.ptr = c_node->value, .length = c_node->size};
        if (!parsed_value_to_address(&parsed, constraint)) continue;
        if (memcmp(addr, constraint, ADDRESS_LENGTH) == 0) {
            return true;
        }
    }
    return false;
}

static bool format_addr(const s_field *field,
                        bool *to_be_displayed,
                        const s_parsed_value *value,
                        char *buf,
                        size_t buf_size) {
    uint8_t tmp[ADDRESS_LENGTH] = {0};

    if ((field == NULL) || (to_be_displayed == NULL) ||
        (buf == NULL) || (buf_size == 0U) ||
        !parsed_value_to_address(value, tmp)) {
        return false;
    }

    if (!apply_visibility_constraint(field,
                                     to_be_displayed,
                                     check_address_constraint(field, tmp))) {
        return false;
    }

    return *to_be_displayed ? tronBase58FromBinary(tmp, buf, buf_size)
                            : true;
}

static bool format_bool(const s_value *def,
                        const s_parsed_value *value,
                        char *buf,
                        size_t buf_size) {
    uint8_t tmp = 0U;

    (void) def;
    if ((value == NULL) || (value->ptr == NULL) || (buf == NULL) ||
        (buf_size == 0U) ||
        ((value->length != 1U) && (value->length != INT256_LENGTH))) {
        return false;
    }
    if (value->length == INT256_LENGTH) {
        for (size_t i = 0U; i < (INT256_LENGTH - 1U); ++i) {
            if (value->ptr[i] != 0U) {
                return false;
            }
        }
    }
    tmp = value->ptr[value->length - 1U];
    if (tmp > 1U) {
        return false;
    }
    int written = snprintf(buf, buf_size, "%s", tmp ? "true" : "false");
    return (written >= 0) && ((size_t) written < buf_size);
}

/**
 * @brief Check if a bytes value matches any of the field's constraints
 *
 * @param field Field containing the constraints to check
 * @param value Value being formatted
 * @param formatted_buf Formatted buffer containing the hex string to check
 * @return true if value matches a constraint, false otherwise
 */
static bool check_bytes_constraint(const s_field *field,
                                   const s_parsed_value *value) {
    for (s_field_constraint *c_node = field->constraints; c_node != NULL;
         c_node = (s_field_constraint *) c_node->node.next) {
        /* Compare the complete signed value, not two potentially truncated
         * display strings that happen to share the same prefix. */
        if ((c_node->size == value->length) &&
            (memcmp(c_node->value, value->ptr, value->length) == 0)) {
            return true;
        }
    }
    return false;
}

static bool format_bytes(const s_field *field,
                         bool *to_be_displayed,
                         const s_parsed_value *value,
                         char *buf,
                         size_t buf_size) {
    size_t rendered_size;

    LEDGER_ASSERT(sizeof(strings.tmp.tmp) == buf_size, "Buffer too small for bytes formatting");
    if ((field == NULL) || (to_be_displayed == NULL) ||
        (value == NULL) || ((value->length != 0U) && (value->ptr == NULL)) ||
        (buf == NULL) || (buf_size == 0U) ||
        __builtin_mul_overflow((size_t) value->length, 2U, &rendered_size) ||
        __builtin_add_overflow(rendered_size, 3U, &rendered_size)) {
        return false;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
    snprintf(buf, buf_size, "0x%.*h", value->length, value->ptr);
#pragma GCC diagnostic pop

    if (!apply_visibility_constraint(field,
                                     to_be_displayed,
                                     check_bytes_constraint(field, value))) {
        return false;
    }

    if (!*to_be_displayed) {
        return true;
    }

    // Truncate if needed for display
    if (rendered_size > buf_size) {
        memmove(&buf[buf_size - 1 - 3], "...", 3);
    }
    return true;
}

static bool format_string(const s_value *def,
                          const s_parsed_value *value,
                          char *buf,
                          size_t buf_size) {
    (void) def;
    if ((value == NULL) || (buf == NULL) || (buf_size == 0U) ||
        (value->length >= buf_size) ||
        ((value->length != 0U) && (value->ptr == NULL)) ||
        !is_printable((const char *) value->ptr, value->length)) {
        return false;
    }
    if (value->length != 0U) {
        memcpy(buf, value->ptr, value->length);
    }
    buf[value->length] = '\0';
    return true;
}

bool format_param_raw(const s_field *field) {
    bool ret = false;
    s_parsed_value_collection collec = {0};
    char *buf = strings.tmp.tmp;
    size_t buf_size = sizeof(strings.tmp.tmp);
    bool to_be_displayed = true;

    ret = value_get(&field->param_raw.value, &collec);
    if (ret) {
        for (int i = 0; i < collec.size && ret == true; ++i) {
            switch (field->param_raw.value.type_family) {
                case TF_UINT:
                // TVM trcToken is a uint256 token id; format it like a uint.
                case TF_TRC_TOKEN:
                    ret = format_uint(field, &to_be_displayed, &collec.value[i], buf, buf_size);
                    break;
                case TF_INT:
                    ret = format_int(&field->param_raw.value, &collec.value[i], buf, buf_size);
                    break;
                case TF_ADDRESS:
                    ret = format_addr(field, &to_be_displayed, &collec.value[i], buf, buf_size);
                    break;
                case TF_BOOL:
                    ret = format_bool(&field->param_raw.value, &collec.value[i], buf, buf_size);
                    break;
                case TF_BYTES:
                    ret = format_bytes(field, &to_be_displayed, &collec.value[i], buf, buf_size);
                    break;
                case TF_STRING:
                    ret = format_string(&field->param_raw.value, &collec.value[i], buf, buf_size);
                    break;
                case TF_UFIXED:
                case TF_FIXED:
                default:
                    ret = false;
            }
            // Add to field table only if required to be displayed
            if (ret && to_be_displayed) {
                ret = add_to_field_table(PARAM_TYPE_RAW, field->name, buf, NULL);
            }
        }
    }
    value_cleanup(&field->param_raw.value, &collec);
    return ret;
}
