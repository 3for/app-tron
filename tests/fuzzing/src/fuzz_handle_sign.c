#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu_constants.h"
#include "settings.h"

void init_tip712_fuzz_environment(void);
void fuzz_set_settings(uint8_t value);
void sign_cleanup(void);

/*
 * Byte stream format:
 *   settings (1 byte), followed by zero or more APDU records:
 *   p1 (1), p2 (1), payload length, little endian (2), payload (length).
 *
 * Keeping p1/p2 under fuzzer control covers valid multi-frame signing as well
 * as restarts, out-of-order continuation frames, TRC10 metadata frames and
 * invalid parameter combinations.  Length is capped to the actual remaining
 * input, so truncated records are replayed as truncated APDUs too.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t frame[UINT16_MAX];

    init_tip712_fuzz_environment();
    if (size == 0U) {
        sign_cleanup();
        return 0;
    }

    fuzz_set_settings(*data++);
    size--;

    while (size >= 4U) {
        const uint8_t p1 = data[0];
        const uint8_t p2 = data[1];
        size_t frame_len = (size_t) data[2] | ((size_t) data[3] << 8U);
        data += 4U;
        size -= 4U;

        if (frame_len > size) {
            frame_len = size;
        }

        /* handleSign mutates/advances its work buffer in some paths. */
        if (frame_len != 0U) {
            memcpy(frame, data, frame_len);
        }
        (void) handleSign(p1, p2, frame, (uint16_t) frame_len);

        data += frame_len;
        size -= frame_len;
    }

    sign_cleanup();
    return 0;
}
