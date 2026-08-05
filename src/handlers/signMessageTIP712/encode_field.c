#include <string.h>
#include "encode_field.h"
#include "parse.h"
#include "app_errors.h"

typedef enum { MSB, LSB } e_padding_type;

/**
 * Encode a field value to 32 bytes (padded)
 *
 * @param[in] value field value to encode
 * @param[in] length field length before encoding
 * @param[in] ptype padding direction (LSB vs MSB)
 * @param[in] pval value used for padding
 * @return encoded field value
 */
static bool field_encode(const uint8_t *value,
                         uint8_t length,
                         e_padding_type ptype,
                         uint8_t pval,
                         uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]) {
    uint8_t start_idx;

    if ((value == NULL) || (out == NULL) ||
        (length > TIP_712_ENCODED_FIELD_LENGTH)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    switch (ptype) {
        case MSB:
            memset(out, pval, TIP_712_ENCODED_FIELD_LENGTH - length);
            start_idx = TIP_712_ENCODED_FIELD_LENGTH - length;
            break;
        case LSB:
            explicit_bzero(out, TIP_712_ENCODED_FIELD_LENGTH);
            start_idx = 0;
            break;
        default:
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
    }
    memcpy(&out[start_idx], value, length);
    return true;
}

/**
 * Encode an unsigned integer
 *
 * @param[in] value pointer to the "packed" integer received
 * @param[in] length its byte-length
 * @return the encoded value
 */
bool encode_uint(const uint8_t *value,
                 uint8_t length,
                 uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]) {
    return field_encode(value, length, MSB, 0x00, out);
}

/**
 * Encode a signed integer
 *
 * @param[in] value pointer to the "packed" integer received
 * @param[in] length its byte-length
 * @param[in] typesize the type size in bytes
 * @return the encoded value
 */
bool encode_int(const uint8_t *value,
                uint8_t length,
                uint8_t typesize,
                uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]) {
    uint8_t padding_value;

    if (length < 1) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if ((length == typesize) && (value[0] & (1 << 7)))  // negative number
    {
        padding_value = 0xFF;
    } else {
        padding_value = 0x00;
    }
    // no length check here since it will be checked by field_encode
    return field_encode(value, length, MSB, padding_value, out);
}

/**
 * Encode a fixed-size byte array
 *
 * @param[in] value pointer to the "packed" bytes array
 * @param[in] length its byte-length
 * @return the encoded value
 */
bool encode_bytes(const uint8_t *value,
                  uint8_t length,
                  uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]) {
    return field_encode(value, length, LSB, 0x00, out);
}

/**
 * Encode a boolean
 *
 * @param[in] value pointer to the boolean received
 * @param[in] length its byte-length
 * @return the encoded value
 */
bool encode_boolean(const uint8_t *value,
                    uint8_t length,
                    uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]) {
    if ((value == NULL) || (length != 1) || (value[0] > 1U))
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    return encode_uint(value, length, out);
}

/**
 * Encode an address
 *
 * @param[in] value pointer to the address received
 * @param[in] length its byte-length
 * @return the encoded value
 */
bool encode_address(const uint8_t *value,
                    uint8_t length,
                    uint8_t out[TIP_712_ENCODED_FIELD_LENGTH]) {
    if (length != ADDRESS_LENGTH)  // sanity check
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    return encode_uint(value, length, out);
}
