#include <stddef.h>
#include <stdint.h>

#include "apdu_constants.h"

void init_external_plugin_fuzz_environment(const uint8_t *config, size_t config_len);
void reset_app_context(void);

enum {
    EXTERNAL_PLUGIN_FUZZ_CONFIG_SIZE = 16,
    OP_RESET = 0,
    OP_SET_EXTERNAL_PLUGIN = 1,
    OP_SIGN_EXTERNAL_PLUGIN = 2,
    OP_SET_SETTINGS = 3,
};

extern uint8_t g_fuzz_settings;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *stream = data;
    size_t remaining = size;

    if ((data == NULL) || (size == 0U)) {
        return 0;
    }

    init_external_plugin_fuzz_environment(data,
                                          (size < EXTERNAL_PLUGIN_FUZZ_CONFIG_SIZE)
                                              ? size
                                              : EXTERNAL_PLUGIN_FUZZ_CONFIG_SIZE);

    if (remaining > EXTERNAL_PLUGIN_FUZZ_CONFIG_SIZE) {
        stream += EXTERNAL_PLUGIN_FUZZ_CONFIG_SIZE;
        remaining -= EXTERNAL_PLUGIN_FUZZ_CONFIG_SIZE;
    } else {
        stream += remaining;
        remaining = 0U;
    }

    while (remaining > 0U) {
        const uint8_t op = *stream++;

        remaining--;

        if (op == OP_RESET) {
            reset_app_context();
            continue;
        }
        if (op == OP_SET_SETTINGS) {
            if (remaining == 0U) {
                break;
            }
            g_fuzz_settings = *stream++;
            remaining--;
            continue;
        }
        if (remaining < 3U) {
            break;
        }

        {
            const uint8_t p1 = *stream++;
            const uint8_t p2 = *stream++;
            const uint8_t len = *stream++;

            remaining -= 3U;

            if (remaining < len) {
                break;
            }

            switch (op) {
                case OP_SET_EXTERNAL_PLUGIN:
                    (void) handleSetExternalPlugin(p1, p2, (uint8_t *) stream, len);
                    break;
                case OP_SIGN_EXTERNAL_PLUGIN:
                    (void) handleSignExternalPlugin(p1, p2, (uint8_t *) stream, len);
                    break;
                default:
                    break;
            }

            stream += len;
            remaining -= len;
        }
    }

    return 0;
}
