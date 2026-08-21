#include "exchange_serialization.h"

#include <string.h>

_Static_assert(sizeof(EXCHANGE_SIGNATURE_DOMAIN) - 1u == EXCHANGE_SIGNATURE_DOMAIN_LENGTH,
               "exchange signature domain length mismatch");

static bool is_ascii_letter(uint8_t value) {
    return ((value >= 'A') && (value <= 'Z')) || ((value >= 'a') && (value <= 'z'));
}

static bool is_valid_token_id(const char *token_id, size_t *token_id_length) {
    size_t length = strlen(token_id);

    if ((length == 1u) && (token_id[0] == '_')) {
        *token_id_length = length;
        return true;
    }
    if (length != EXCHANGE_TOKEN_ID_SIZE) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        if ((token_id[i] < '0') || (token_id[i] > '9')) {
            return false;
        }
    }
    *token_id_length = length;
    return true;
}

static bool is_valid_token_name(const char *token_name,
                                bool require_leading_letter,
                                size_t *token_name_length) {
    size_t length = strlen(token_name);

    if ((length == 0u) || (length > EXCHANGE_MAX_TOKEN_NAME_LENGTH) ||
        (require_leading_letter && !is_ascii_letter((uint8_t) token_name[0]))) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        uint8_t value = (uint8_t) token_name[i];
        if ((value < 0x20u) || (value > 0x7eu)) {
            return false;
        }
    }
    *token_name_length = length;
    return true;
}

static size_t write_uint64_decimal(uint8_t *out, uint64_t value) {
    uint8_t reverse[EXCHANGE_UINT64_DECIMAL_LENGTH];
    size_t length = 0;

    do {
        reverse[length++] = (uint8_t) ('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u);

    for (size_t i = 0; i < length; i++) {
        out[i] = reverse[length - i - 1u];
    }
    return length;
}

static void append_bytes(uint8_t *out, size_t *offset, const void *value, size_t value_size) {
    memcpy(out + *offset, value, value_size);
    *offset += value_size;
}

static bool validate_arguments(uint8_t *out,
                               size_t *payload_size,
                               const char *token1_id,
                               const char *token1_name,
                               const char *token2_id,
                               const char *token2_name) {
    if ((out == NULL) || (payload_size == NULL) || (token1_id == NULL) || (token1_name == NULL) ||
        (token2_id == NULL) || (token2_name == NULL)) {
        return false;
    }
    *payload_size = 0;
    return true;
}

static bool validate_exchange_fields(const char *token1_id,
                                     const char *token1_name,
                                     uint32_t token1_precision,
                                     const char *token2_id,
                                     const char *token2_name,
                                     uint32_t token2_precision,
                                     bool require_leading_letter,
                                     size_t *token1_id_length,
                                     size_t *token1_name_length,
                                     size_t *token2_id_length,
                                     size_t *token2_name_length) {
    return is_valid_token_id(token1_id, token1_id_length) &&
           is_valid_token_name(token1_name, require_leading_letter, token1_name_length) &&
           is_valid_token_id(token2_id, token2_id_length) &&
           is_valid_token_name(token2_name, require_leading_letter, token2_name_length) &&
           (token1_precision <= EXCHANGE_MAX_TOKEN_PRECISION) &&
           (token2_precision <= EXCHANGE_MAX_TOKEN_PRECISION);
}

bool serialize_legacy_exchange_signature_payload(uint8_t *out,
                                                 size_t out_size,
                                                 size_t *payload_size,
                                                 uint64_t exchange_id,
                                                 const char *token1_id,
                                                 const char *token1_name,
                                                 uint32_t token1_precision,
                                                 const char *token2_id,
                                                 const char *token2_name,
                                                 uint32_t token2_precision) {
    size_t token1_id_length;
    size_t token1_name_length;
    size_t token2_id_length;
    size_t token2_name_length;

    if (!validate_arguments(out, payload_size, token1_id, token1_name, token2_id, token2_name)) {
        return false;
    }
    if (!validate_exchange_fields(token1_id,
                                  token1_name,
                                  token1_precision,
                                  token2_id,
                                  token2_name,
                                  token2_precision,
                                  true,
                                  &token1_id_length,
                                  &token1_name_length,
                                  &token2_id_length,
                                  &token2_name_length)) {
        return false;
    }

    size_t required_size = EXCHANGE_UINT64_DECIMAL_LENGTH + token1_id_length + token1_name_length +
                           1u + token2_id_length + token2_name_length + 1u;
    if (required_size > out_size) {
        return false;
    }

    size_t offset = write_uint64_decimal(out, exchange_id);
    append_bytes(out, &offset, token1_id, token1_id_length);
    append_bytes(out, &offset, token1_name, token1_name_length);
    out[offset++] = (uint8_t) token1_precision;
    append_bytes(out, &offset, token2_id, token2_id_length);
    append_bytes(out, &offset, token2_name, token2_name_length);
    out[offset++] = (uint8_t) token2_precision;

    *payload_size = offset;
    return true;
}

bool serialize_exchange_signature_payload(uint8_t *out,
                                          size_t out_size,
                                          size_t *payload_size,
                                          uint64_t exchange_id,
                                          const char *token1_id,
                                          const char *token1_name,
                                          uint32_t token1_precision,
                                          const char *token2_id,
                                          const char *token2_name,
                                          uint32_t token2_precision) {
    size_t token1_id_length;
    size_t token1_name_length;
    size_t token2_id_length;
    size_t token2_name_length;

    if (!validate_arguments(out, payload_size, token1_id, token1_name, token2_id, token2_name)) {
        return false;
    }
    if (!validate_exchange_fields(token1_id,
                                  token1_name,
                                  token1_precision,
                                  token2_id,
                                  token2_name,
                                  token2_precision,
                                  false,
                                  &token1_id_length,
                                  &token1_name_length,
                                  &token2_id_length,
                                  &token2_name_length)) {
        return false;
    }

    size_t required_size = EXCHANGE_SIGNATURE_DOMAIN_LENGTH + 1u + 8u + 4u + token1_id_length +
                           token1_name_length + token2_id_length + token2_name_length + 2u;
    if (required_size > out_size) {
        return false;
    }

    size_t offset = 0;
    append_bytes(out, &offset, EXCHANGE_SIGNATURE_DOMAIN, EXCHANGE_SIGNATURE_DOMAIN_LENGTH);
    out[offset++] = EXCHANGE_SIGNATURE_FORMAT_V1;
    for (size_t i = 0; i < 8u; i++) {
        out[offset++] = (uint8_t) (exchange_id >> (56u - (8u * i)));
    }
    out[offset++] = (uint8_t) token1_id_length;
    append_bytes(out, &offset, token1_id, token1_id_length);
    out[offset++] = (uint8_t) token1_name_length;
    append_bytes(out, &offset, token1_name, token1_name_length);
    out[offset++] = (uint8_t) token1_precision;
    out[offset++] = (uint8_t) token2_id_length;
    append_bytes(out, &offset, token2_id, token2_id_length);
    out[offset++] = (uint8_t) token2_name_length;
    append_bytes(out, &offset, token2_name, token2_name_length);
    out[offset++] = (uint8_t) token2_precision;

    *payload_size = offset;
    return true;
}
