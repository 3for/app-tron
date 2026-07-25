#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu_constants.h"
#include "cmd_enum_value.h"
#include "cmd_proxy_info.h"
#include "cmd_trusted_name.h"
#include "enum_value.h"
#include "proxy_info.h"
#include "trusted_name.h"
#include "tlv_apdu.h"

void fuzz_external_metadata_set_certificate_status(uint8_t control);

/*
 * Byte stream format:
 *   certificate status (1 byte), followed by zero or more APDU records:
 *   ins (1), p1 (1), p2 (1), payload length (1), payload (length).
 *
 * First chunks contain the production two-byte total TLV length prefix. The
 * fuzzer controls instruction interleaving and p1, so complete, fragmented,
 * restarted, oversized and truncated metadata streams all share one harness.
 */
static void fuzz_external_metadata_apdu_stream(const uint8_t *data, size_t size) {
    uint8_t payload[UINT8_MAX];

    while (size >= 4U) {
        const uint8_t ins = data[0];
        const uint8_t p1 = data[1];
        const uint8_t p2 = data[2];
        size_t payload_len = data[3];
        data += 4U;
        size -= 4U;

        if (payload_len > size) {
            payload_len = size;
        }
        if (payload_len != 0U) {
            memcpy(payload, data, payload_len);
        }

        switch (ins) {
            case INS_PROVIDE_TRUSTED_NAME:
                (void) handle_trusted_name(p1, p2, payload, (uint8_t) payload_len);
                break;
            case INS_PROVIDE_PROXY_INFO:
                (void) handle_proxy_info(p1, p2, (uint8_t) payload_len, payload);
                break;
            case INS_PROVIDE_ENUM_VALUE:
                (void) handle_enum_value(p1, p2, (uint8_t) payload_len, payload);
                break;
            default:
                break;
        }

        data += payload_len;
        size -= payload_len;
    }
}

static void reset_external_metadata_context(void) {
    tlv_apdu_reset();
    trusted_name_cleanup();
    proxy_cleanup();
    enum_value_cleanup();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    reset_external_metadata_context();
    if (size != 0U) {
        fuzz_external_metadata_set_certificate_status(*data++);
        size--;
        fuzz_external_metadata_apdu_stream(data, size);
    }
    reset_external_metadata_context();
    return 0;
}
