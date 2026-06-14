#include <stddef.h>
#include <stdint.h>

#include "commands_712.h"
#include "context_712.h"
#include "settings.h"

void init_tip712_fuzz_environment(void);

enum {
    OP_STRUCT_DEF = 0,
    OP_FILTERING = 1,
    OP_STRUCT_IMPL = 2,
    OP_SIGN = 3,
    OP_RESET = 4,
    OP_SET_SETTINGS = 5,
};

static void fuzz_tip712_apdu_stream(const uint8_t *data, size_t size) {
    while (size > 0U) {
        const uint8_t op = *data++;
        size--;

        if (op == OP_RESET) {
            if (tip712_context != NULL) {
                tip712_context_deinit();
            }
            continue;
        }
        if (op == OP_SET_SETTINGS) {
            if (size < 1U) {
                break;
            }
            fuzz_set_settings(*data++ & ((1U << S_SIGN_BY_HASH) | (1U << S_VERBOSE_TIP712)));
            size--;
            continue;
        }

        if (size < 3U) {
            break;
        }

        const uint8_t p1 = *data++;
        const uint8_t p2 = *data++;
        const uint8_t len = *data++;
        size -= 3U;

        if (size < len) {
            break;
        }

        switch (op % 4U) {
            case OP_STRUCT_DEF:
                handleTIP712StructDef(p2, (uint8_t *) data, len);
                break;
            case OP_FILTERING:
                handleTIP712Filtering(p1, p2, (uint8_t *) data, len);
                break;
            case OP_STRUCT_IMPL:
                handleTIP712StructImpl(p1, p2, (uint8_t *) data, len);
                break;
            case OP_SIGN:
                handleTIP712Sign((uint8_t *) data, len);
                break;
        }

        data += len;
        size -= len;
    }

    if (tip712_context != NULL) {
        tip712_context_deinit();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_tip712_fuzz_environment();
    fuzz_tip712_apdu_stream(data, size);
    return 0;
}
