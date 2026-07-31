#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ECDSA_RS_SIGNATURE_SIZE 64U

/**
 * Convert a canonical ASN.1 DER ECDSA signature into fixed-width r || s.
 *
 * Both INTEGERs must be positive, minimally encoded, and at most 32 bytes
 * after removal of the optional sign-protection byte.
 */
bool ecdsa_der_to_rs(const uint8_t *signature,
                     size_t signature_length,
                     uint8_t out[ECDSA_RS_SIGNATURE_SIZE]);
