#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "commands_712.h"
#include "context_712.h"
#include "settings.h"
#include "app_errors.h"
#include "ui_logic.h"
#include "shared_context.h"
#include "gcs_memory.h"
#include "tip712_limits.h"

void init_tip712_fuzz_environment(void);

enum {
    OP_STRUCT_DEF = 0,
    OP_FILTERING = 1,
    OP_STRUCT_IMPL = 2,
    OP_SIGN = 3,
    OP_RESET = 4,
    OP_SET_SETTINGS = 5,
};

static const uint8_t default_path[] = {1U, 0x80U, 0x00U, 0x00U, 0x2cU};

static void check_zero_extended_u64_boundaries(void) {
    const uint64_t expected = UINT64_C(0x0102030405060708);
    uint8_t value8[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t value24[24] = {0};
    uint8_t value32[32] = {0};
    uint64_t parsed = 0;

    memcpy(value24 + sizeof(value24) - sizeof(value8), value8, sizeof(value8));
    memcpy(value32 + sizeof(value32) - sizeof(value8), value8, sizeof(value8));
    if (!tip712_u64_from_zero_extended(value8, sizeof(value8), &parsed) ||
        (parsed != expected) ||
        !tip712_u64_from_zero_extended(value24, sizeof(value24), &parsed) ||
        (parsed != expected) ||
        !tip712_u64_from_zero_extended(value32, sizeof(value32), &parsed) ||
        (parsed != expected)) {
        __builtin_trap();
    }
    value32[0] = 1U;
    if (tip712_u64_from_zero_extended(value32, sizeof(value32), &parsed)) {
        __builtin_trap();
    }
}

static void check_display_boundaries(void) {
    const uint8_t compact_ff[] = {0xff};
    uint8_t full_ff[INT256_LENGTH];
    char output[80];

    memset(full_ff, 0xff, sizeof(full_ff));
    if (tip712_is_full_width_max_value(compact_ff,
                                       sizeof(compact_ff),
                                       INT256_LENGTH) ||
        !tip712_is_full_width_max_value(full_ff,
                                        sizeof(full_ff),
                                        INT256_LENGTH) ||
        !tip712_is_full_width_max_value(compact_ff,
                                        sizeof(compact_ff),
                                        sizeof(compact_ff))) {
        __builtin_trap();
    }

    /* Every Solidity int width is a multiple of eight bits.  A full-width
     * all-ones value is -1, while compact 0xff remains +255 unless the
     * declared type itself is int8. */
    for (uint8_t width = 1U; width <= INT256_LENGTH; width++) {
        if (!tip712_format_signed_int_value(full_ff,
                                            width,
                                            width,
                                            output,
                                            sizeof(output)) ||
            (strcmp(output, "-1") != 0)) {
            __builtin_trap();
        }
        if ((width > 1U) &&
            (!tip712_format_signed_int_value(compact_ff,
                                             sizeof(compact_ff),
                                             width,
                                             output,
                                             sizeof(output)) ||
             (strcmp(output, "255") != 0))) {
            __builtin_trap();
        }
    }
}

static void check_tip712_phase_boundaries(void) {
    appState = APP_STATE_SIGNING;
    if (tip712_context_init() || (tip712_context != NULL) ||
        (tip712_get_phase() != TIP712_PHASE_NONE)) {
        __builtin_trap();
    }

    appState = APP_STATE_IDLE;
    if (!tip712_mark_legacy_reviewing() || !tip712_review_in_progress() ||
        tip712_context_init()) {
        __builtin_trap();
    }
    tip712_context_cleanup();

    if (!tip712_context_init() || !tip712_full_session_in_progress() ||
        (tip712_context->build_apdu_count != 1U) ||
        tip712_mark_legacy_reviewing() ||
        !tip712_lock_signing_path(default_path, sizeof(default_path)) ||
        (tip712_get_signing_path() == NULL) ||
        (tip712_get_signing_path()->length != 1U) ||
        (tip712_get_signing_path()->indices[0] != UINT32_C(0x8000002c)) ||
        tip712_lock_signing_path(default_path, sizeof(default_path))) {
        __builtin_trap();
    }
    tip712_context->build_apdu_count = TIP712_MAX_BUILD_APDUS - 1U;
    if (!tip712_note_build_apdu() || tip712_note_build_apdu()) {
        __builtin_trap();
    }
    tip712_context_deinit();
    if (gcs_budget_is_active() || (gcs_mem_session_live_bytes() != 0U) ||
        gcs_mem_invariant_failed()) {
        __builtin_trap();
    }
    appState = APP_STATE_IDLE;
}

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

        uint32_t flags = 0;
        switch (op % 4U) {
            case OP_STRUCT_DEF:
                {
                    if (tip712_context == NULL) {
                        (void) handleTIP712Init(default_path,
                                                sizeof(default_path));
                    }
                    bool schema_was_locked =
                        (tip712_context != NULL) && tip712_context->schema_locked;
                    uint16_t sw = handleTIP712StructDef(p2, (uint8_t *) data, len);
                    if (schema_was_locked && (sw == SWO_SUCCESS)) {
                        __builtin_trap();
                    }
                }
                break;
            case OP_FILTERING:
                handleTIP712Filtering(p1, p2, (uint8_t *) data, len, &flags);
                break;
            case OP_STRUCT_IMPL:
                handleTIP712StructImpl(p1, p2, (uint8_t *) data, len, &flags);
                break;
            case OP_SIGN:
                handleTIP712Sign((uint8_t *) data, len, &flags);
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
    check_zero_extended_u64_boundaries();
    check_display_boundaries();
    check_tip712_phase_boundaries();
    init_tip712_fuzz_environment();
    fuzz_tip712_apdu_stream(data, size);
    if (gcs_budget_is_active() || (gcs_mem_session_live_bytes() != 0U) ||
        gcs_mem_invariant_failed()) {
        __builtin_trap();
    }
    return 0;
}
