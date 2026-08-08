#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "apdu_constants.h"

void fuzz_personal_message_init(uint8_t control);

/*
 * Byte stream format:
 *   control (1 byte: bit 0 fails public-key setup, bit 1 enables legacy
 *   hash-only signing), followed by zero or more APDU records:
 *   ins (1), p1 (1), p2 (1), payload length (1), payload (length).
 *
 * Both TIP-191 instructions share this stream so the fuzzer can exercise the
 * legacy hash-display flow, the full-message display flow, instruction
 * interleaving, restarts, invalid continuations and truncated APDUs.
 */
static void fuzz_personal_message_apdu_stream(const uint8_t *data, size_t size) {
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

        /*
         * Use an exact-sized allocation so sanitizers can detect production
         * handlers reading beyond the APDU length. Keep a valid pointer for
         * zero-length records because the handlers accept a buffer pointer.
         */
        const size_t allocation_len = (payload_len == 0U) ? 1U : payload_len;
        uint8_t *payload = malloc(allocation_len);
        if (payload == NULL) {
            return;
        }
        memset(payload, 0, allocation_len);
        if (payload_len != 0U) {
            memcpy(payload, data, payload_len);
        }

        bool was_reviewing = personal_message_review_in_progress();
        switch (ins) {
            case INS_SIGN_PERSONAL_MESSAGE:
                (void) handleSignPersonalMessage(p1, p2, payload, (uint16_t) payload_len);
                break;
            case INS_SIGN_PERSONAL_MESSAGE_FULL_DISPLAY:
                (void) handleSignPersonalMessageFullDisplay(p1,
                                                            p2,
                                                            payload,
                                                            (uint16_t) payload_len);
                break;
            default:
                break;
        }
        if (was_reviewing && !personal_message_review_in_progress()) {
            __builtin_trap();
        }

        free(payload);
        data += payload_len;
        size -= payload_len;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t control = 0U;

    if (size != 0U) {
        control = *data++;
        size--;
    }
    fuzz_personal_message_init(control);
    fuzz_personal_message_apdu_stream(data, size);
    reset_app_context();
    return 0;
}
