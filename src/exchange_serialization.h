#ifndef EXCHANGE_SERIALIZATION_H
#define EXCHANGE_SERIALIZATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LEGACY_TOKEN_ID_SIZE           7u
#define TOKEN_ID_MAX_LENGTH            19u
#define EXCHANGE_MAX_TOKEN_NAME_LENGTH 31u
#define EXCHANGE_MAX_TOKEN_PRECISION   6u
#define EXCHANGE_UINT64_DECIMAL_LENGTH 20u

#define EXCHANGE_SIGNATURE_FORMAT_V1     1u
#define EXCHANGE_SIGNATURE_DOMAIN        "TRON-EXCHANGE-DETAILS"
#define EXCHANGE_SIGNATURE_DOMAIN_LENGTH 21u

#define TOKEN_SIGNATURE_FORMAT_V1     1u
#define TOKEN_SIGNATURE_DOMAIN        "TRON-TOKEN-DETAILS"
#define TOKEN_SIGNATURE_DOMAIN_LENGTH 18u

#define EXCHANGE_TOKEN_LABEL_MAX_LENGTH \
    (EXCHANGE_MAX_TOKEN_NAME_LENGTH + TOKEN_ID_MAX_LENGTH + 2u)
#define EXCHANGE_PAIR_SEPARATOR        " -> "
#define EXCHANGE_PAIR_SEPARATOR_LENGTH 4u
#define EXCHANGE_PAIR_REVIEW_MAX_SIZE                                      \
    ((2u * EXCHANGE_TOKEN_LABEL_MAX_LENGTH) + EXCHANGE_PAIR_SEPARATOR_LENGTH + 1u)

#define EXCHANGE_LEGACY_SIGNATURE_PAYLOAD_MAX_SIZE                    \
    (EXCHANGE_UINT64_DECIMAL_LENGTH + (2u * LEGACY_TOKEN_ID_SIZE) +   \
     (2u * EXCHANGE_MAX_TOKEN_NAME_LENGTH) + 2u)

#define EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE                                            \
    (EXCHANGE_SIGNATURE_DOMAIN_LENGTH + 1u + 8u + 4u + (2u * TOKEN_ID_MAX_LENGTH) +    \
     (2u * EXCHANGE_MAX_TOKEN_NAME_LENGTH) + 2u)

#define TOKEN_LEGACY_SIGNATURE_PAYLOAD_MAX_SIZE \
    (LEGACY_TOKEN_ID_SIZE + EXCHANGE_MAX_TOKEN_NAME_LENGTH + 1u)

#define TOKEN_SIGNATURE_PAYLOAD_MAX_SIZE                                             \
    (TOKEN_SIGNATURE_DOMAIN_LENGTH + 1u + 2u + TOKEN_ID_MAX_LENGTH +                \
     EXCHANGE_MAX_TOKEN_NAME_LENGTH + 1u)

/**
 * Construct the canonical, domain-separated TokenDetails v1 payload:
 *
 *   domain || version || id length || id || name length || name || precision
 */
bool serialize_token_signature_payload(uint8_t *out,
                                       size_t out_size,
                                       size_t *payload_size,
                                       const char *token_id,
                                       const char *token_name,
                                       uint32_t token_precision);

/**
 * Reconstruct the existing TokenDetails signature payload for published
 * metadata. Its restricted grammar keeps it disjoint from every accepted
 * legacy ExchangeDetails payload.
 */
bool serialize_legacy_token_signature_payload(uint8_t *out,
                                              size_t out_size,
                                              size_t *payload_size,
                                              const char *token_id,
                                              const char *token_name,
                                              uint32_t token_precision);

/**
 * Reconstruct the legacy ExchangeDetails signature payload.
 *
 * The legacy wire format has no explicit field lengths. To make it
 * unambiguous while retaining compatibility with existing signed records,
 * this function accepts only the grammar used by the published list:
 *
 *   decimal uint64 exchange ID
 *   ("_" or seven decimal digits)
 *   non-empty printable ASCII name beginning with a letter
 *   precision byte in [0, 6]
 *   ("_" or seven decimal digits)
 *   non-empty printable ASCII name beginning with a letter
 *   precision byte in [0, 6]
 */
bool serialize_legacy_exchange_signature_payload(uint8_t *out,
                                                 size_t out_size,
                                                 size_t *payload_size,
                                                 uint64_t exchange_id,
                                                 const char *token1_id,
                                                 const char *token1_name,
                                                 uint32_t token1_precision,
                                                 const char *token2_id,
                                                 const char *token2_name,
                                                 uint32_t token2_precision);

/**
 * Construct the canonical, domain-separated ExchangeDetails v1 payload.
 * Integer widths and string lengths are explicit, so every accepted semantic
 * record has exactly one authenticated representation.
 */
bool serialize_exchange_signature_payload(uint8_t *out,
                                          size_t out_size,
                                          size_t *payload_size,
                                          uint64_t exchange_id,
                                          const char *token1_id,
                                          const char *token1_name,
                                          uint32_t token1_precision,
                                          const char *token2_id,
                                          const char *token2_name,
                                          uint32_t token2_precision);

/**
 * Build the security-critical exchange pair shown during review without
 * truncating either authenticated token label.
 */
bool format_exchange_pair_for_review(char *out,
                                     size_t out_size,
                                     const char *token1_label,
                                     size_t token1_length,
                                     const char *token2_label,
                                     size_t token2_length);

#endif
