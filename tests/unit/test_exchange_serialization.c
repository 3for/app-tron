#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "exchange_serialization.h"

static bool serialize_legacy(uint8_t *out,
                             size_t *out_size,
                             uint64_t exchange_id,
                             const char *token1_id,
                             const char *token1_name,
                             uint32_t token1_precision,
                             const char *token2_id,
                             const char *token2_name,
                             uint32_t token2_precision) {
    return serialize_legacy_exchange_signature_payload(out,
                                                       EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE,
                                                       out_size,
                                                       exchange_id,
                                                       token1_id,
                                                       token1_name,
                                                       token1_precision,
                                                       token2_id,
                                                       token2_name,
                                                       token2_precision);
}

static bool serialize_v1(uint8_t *out,
                         size_t *out_size,
                         uint64_t exchange_id,
                         const char *token1_id,
                         const char *token1_name,
                         uint32_t token1_precision,
                         const char *token2_id,
                         const char *token2_name,
                         uint32_t token2_precision) {
    return serialize_exchange_signature_payload(out,
                                                EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE,
                                                out_size,
                                                exchange_id,
                                                token1_id,
                                                token1_name,
                                                token1_precision,
                                                token2_id,
                                                token2_name,
                                                token2_precision);
}

static bool serialize_token(uint8_t *out,
                            size_t *out_size,
                            const char *token_id,
                            const char *token_name,
                            uint32_t token_precision) {
    return serialize_token_signature_payload(out,
                                             EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE,
                                             out_size,
                                             token_id,
                                             token_name,
                                             token_precision);
}

static bool serialize_legacy_token(uint8_t *out,
                                   size_t *out_size,
                                   const char *token_id,
                                   const char *token_name,
                                   uint32_t token_precision) {
    return serialize_legacy_token_signature_payload(out,
                                                    EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE,
                                                    out_size,
                                                    token_id,
                                                    token_name,
                                                    token_precision);
}

int main(void) {
    uint8_t payload[EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE];
    size_t payload_size;

    const uint8_t legacy_expected[] = "1661002000BitTorrent\x06_TRX\x06";
    assert(
        serialize_legacy(payload, &payload_size, 166, "1002000", "BitTorrent", 6, "_", "TRX", 6));
    assert(payload_size == sizeof(legacy_expected) - 1u);
    assert(memcmp(payload, legacy_expected, payload_size) == 0);

    const uint8_t token_expected[] = "1002000BitTorrent\x06";
    assert(serialize_legacy_token(payload, &payload_size, "1002000", "BitTorrent", 6));
    assert(payload_size == sizeof(token_expected) - 1u);
    assert(memcmp(payload, token_expected, payload_size) == 0);

    assert(serialize_legacy_token(payload, &payload_size, "TRX", "TRX", 6));
    assert(payload_size == sizeof("TRXTRX\x06") - 1u);
    assert(memcmp(payload, "TRXTRX\x06", payload_size) == 0);

    const uint8_t token_v1_expected[] = TOKEN_SIGNATURE_DOMAIN
        "\x01\x07"
        "1002000"
        "\x0a"
        "BitTorrent"
        "\x06";
    assert(serialize_token(payload, &payload_size, "1002000", "BitTorrent", 6));
    assert(payload_size == sizeof(token_v1_expected) - 1u);
    assert(memcmp(payload, token_v1_expected, payload_size) == 0);

    assert(serialize_token(payload, &payload_size, "10000000", "Future", 6));
    assert(!serialize_legacy_token(payload, &payload_size, "10000000", "Future", 6));
    assert(!serialize_token(payload, &payload_size, "01000000", "Future", 6));
    assert(!serialize_token(payload, &payload_size, "12345678901234567890", "Future", 6));

    // Legacy exchange 166 is byte-identical to this invalid TokenDetails
    // repartition. Its embedded precision byte must keep it out of the token
    // signature grammar.
    assert(!serialize_legacy_token(payload,
                                   &payload_size,
                                   "1661002",
                                   "000BitTorrent\x06_TRX",
                                   6));
    assert(!serialize_legacy_token(payload, &payload_size, "10020A0", "BitTorrent", 6));
    assert(!serialize_legacy_token(payload, &payload_size, "1002000", "Bit\tTorrent", 6));
    assert(!serialize_legacy_token(payload, &payload_size, "1002000", "BitTorrent", 7));

    const uint8_t v1_expected[] = EXCHANGE_SIGNATURE_DOMAIN
        "\x01\x00\x00\x00\x00\x00\x00\x00\xa6"
        "\x07"
        "1002000"
        "\x0a"
        "BitTorrent"
        "\x06\x01"
        "_"
        "\x03"
        "TRX"
        "\x06";
    assert(serialize_v1(payload, &payload_size, 166, "1002000", "BitTorrent", 6, "_", "TRX", 6));
    assert(payload_size == sizeof(v1_expected) - 1u);
    assert(memcmp(payload, v1_expected, payload_size) == 0);
    assert(memcmp(payload, legacy_expected, sizeof(legacy_expected) - 1u) != 0);

    assert(serialize_v1(payload, &payload_size, 166, "10000000", "Future", 6, "_", "TRX", 6));
    assert(!serialize_legacy(payload,
                             &payload_size,
                             166,
                             "10000000",
                             "Future",
                             6,
                             "_",
                             "TRX",
                             6));

    const uint8_t high_id_expected[] = "42949674621002000BitTorrent\x06_TRX\x06";
    assert(serialize_legacy(payload,
                            &payload_size,
                            UINT64_C(4294967462),
                            "1002000",
                            "BitTorrent",
                            6,
                            "_",
                            "TRX",
                            6));
    assert(payload_size == sizeof(high_id_expected) - 1u);
    assert(memcmp(payload, high_id_expected, payload_size) == 0);
    assert(memcmp(payload, legacy_expected, sizeof(legacy_expected) - 1u) != 0);

    assert(serialize_v1(payload,
                        &payload_size,
                        UINT64_MAX,
                        "1002000",
                        "BitTorrent",
                        6,
                        "_",
                        "TRX",
                        6));
    assert(memcmp(payload, EXCHANGE_SIGNATURE_DOMAIN, EXCHANGE_SIGNATURE_DOMAIN_LENGTH) == 0);
    for (size_t i = 0; i < 8u; i++) {
        assert(payload[EXCHANGE_SIGNATURE_DOMAIN_LENGTH + 1u + i] == 0xffu);
    }

    assert(!serialize_legacy(payload,
                             &payload_size,
                             166,
                             "1002000",
                             "BitTorrent\x06",
                             95,
                             "T",
                             "RX",
                             6));
    assert(
        !serialize_legacy(payload, &payload_size, 166, "1002000", "1BitTorrent", 6, "_", "TRX", 6));
    assert(serialize_v1(payload, &payload_size, 166, "1002000", "1BitTorrent", 6, "_", "TRX", 6));
    assert(!serialize_v1(payload, &payload_size, 166, "10020A0", "BitTorrent", 6, "_", "TRX", 6));
    assert(!serialize_v1(payload, &payload_size, 166, "1002000", "Bit\tTorrent", 6, "_", "TRX", 6));
    assert(!serialize_v1(payload, &payload_size, 166, "1002000", "BitTorrent", 7, "_", "TRX", 6));

    const char maximum_label1[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[1234567890123456789]";
    const char maximum_label2[] = "AAAAAAAAAAAAAAAAAAAAAABBBBBBBBB[9876543210987654321]";
    char pair[EXCHANGE_PAIR_REVIEW_MAX_SIZE];
    assert(strlen(maximum_label1) == EXCHANGE_TOKEN_LABEL_MAX_LENGTH);
    assert(strlen(maximum_label2) == EXCHANGE_TOKEN_LABEL_MAX_LENGTH);
    assert(format_exchange_pair_for_review(pair,
                                           sizeof(pair),
                                           maximum_label1,
                                           strlen(maximum_label1),
                                           maximum_label2,
                                           strlen(maximum_label2)));
    assert(strlen(pair) == EXCHANGE_PAIR_REVIEW_MAX_SIZE - 1u);
    assert(strstr(pair, "[1234567890123456789] -> ") != NULL);
    assert(strstr(pair, "BBBBBBBBB[9876543210987654321]") != NULL);

    char truncated_pair[EXCHANGE_PAIR_REVIEW_MAX_SIZE - 1u];
    assert(!format_exchange_pair_for_review(truncated_pair,
                                            sizeof(truncated_pair),
                                            maximum_label1,
                                            strlen(maximum_label1),
                                            maximum_label2,
                                            strlen(maximum_label2)));
    assert(truncated_pair[0] == '\0');

    assert(format_exchange_pair_for_review(pair,
                                           sizeof(pair),
                                           "1002000",
                                           strlen("1002000"),
                                           "TRX",
                                           strlen("TRX")));
    assert(strcmp(pair, "1002000 -> TRX") == 0);

    return 0;
}
