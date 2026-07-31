#include "der_signature.h"

#include <string.h>

#define DER_SEQUENCE_TAG 0x30U
#define DER_INTEGER_TAG  0x02U
#define DER_MAX_INTEGER_SIZE 33U
#define DER_MIN_SIGNATURE_SIZE 8U
#define DER_MAX_SIGNATURE_SIZE 72U

typedef struct {
    const uint8_t *value;
    size_t length;
} der_integer_t;

static bool parse_der_integer(const uint8_t *signature,
                              size_t signature_length,
                              size_t *offset,
                              der_integer_t *integer) {
    if (signature == NULL || offset == NULL || integer == NULL ||
        *offset > signature_length || signature_length - *offset < 2U ||
        signature[*offset] != DER_INTEGER_TAG) {
        return false;
    }

    (*offset)++;
    const size_t encoded_length = signature[*offset];
    (*offset)++;
    if (encoded_length == 0U || encoded_length > DER_MAX_INTEGER_SIZE ||
        encoded_length > signature_length - *offset) {
        return false;
    }

    const uint8_t *value = signature + *offset;
    if ((value[0] & 0x80U) != 0U) {
        // Negative INTEGER: positive r/s values require a leading 0x00.
        return false;
    }
    if (encoded_length > 1U && value[0] == 0U &&
        (value[1] & 0x80U) == 0U) {
        // Redundant sign-protection byte is not canonical DER.
        return false;
    }
    if (encoded_length == DER_MAX_INTEGER_SIZE && value[0] != 0U) {
        return false;
    }

    integer->value = value;
    integer->length = encoded_length;
    *offset += encoded_length;
    return true;
}

bool ecdsa_der_to_rs(const uint8_t *signature,
                     size_t signature_length,
                     uint8_t out[ECDSA_RS_SIGNATURE_SIZE]) {
    if (signature == NULL || out == NULL ||
        signature_length < DER_MIN_SIGNATURE_SIZE ||
        signature_length > DER_MAX_SIGNATURE_SIZE ||
        signature[0] != DER_SEQUENCE_TAG ||
        signature[1] != signature_length - 2U) {
        return false;
    }

    size_t offset = 2U;
    der_integer_t r = {0};
    der_integer_t s = {0};
    if (!parse_der_integer(signature, signature_length, &offset, &r) ||
        !parse_der_integer(signature, signature_length, &offset, &s) ||
        offset != signature_length) {
        return false;
    }

    if (r.length == DER_MAX_INTEGER_SIZE) {
        r.value++;
        r.length--;
    }
    if (s.length == DER_MAX_INTEGER_SIZE) {
        s.value++;
        s.length--;
    }

    memset(out, 0, ECDSA_RS_SIGNATURE_SIZE);
    memcpy(out + 32U - r.length, r.value, r.length);
    memcpy(out + 64U - s.length, s.value, s.length);
    return true;
}
