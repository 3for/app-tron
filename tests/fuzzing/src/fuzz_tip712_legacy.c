#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "settings.h"

extern void init_tip712_fuzz_environment(void);
extern uint16_t handleSignTIP712Message(uint8_t p1,
                                        const uint8_t *workBuffer,
                                        uint8_t dataLength);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *work_buffer;
    size_t payload_size;

    if ((data == NULL) || (size < 4U)) {
        return 0;
    }

    init_tip712_fuzz_environment();

    fuzz_set_settings(data[0]);
    appState = data[1] % (APP_STATE_SIGNING_TIP712 + 1U);

    payload_size = size - 4U;
    if (payload_size > UINT16_MAX) {
        payload_size = UINT16_MAX;
    }

    work_buffer = NULL;
    if (payload_size > 0U) {
        work_buffer = malloc(payload_size);
        if (work_buffer == NULL) {
            return 0;
        }
        memcpy(work_buffer, data + 4U, payload_size);
    }

    (void) handleSignTIP712Message(data[2], work_buffer, (uint8_t) payload_size);

    free(work_buffer);
    return 0;
}
