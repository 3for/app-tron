#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "gcs_limits.h"
#include "gcs_memory.h"

#define GCS_MEMORY_FUZZ_SLOT_COUNT 32U
#define GCS_MEMORY_FUZZ_HEADER_SIZE 8U
#define GCS_MEMORY_FUZZ_STR_MAX    64U

#define GCS_ALLOC_ACCOUNTED_MASK   UINT32_C(0x80000000)
#define GCS_ALLOC_CATEGORY_SHIFT   28U
#define GCS_ALLOC_CATEGORY_MASK    UINT32_C(0x70000000)
#define GCS_ALLOC_GENERATION_MASK  UINT32_C(0x0fffffff)

typedef union {
    struct {
        uint32_t charged_size;
        uint32_t accounting_tag;
    } fields;
    uint64_t alignment;
} gcs_memory_fuzz_header_t;

typedef enum {
    GCS_MEMORY_FUZZ_ALLOC,
    GCS_MEMORY_FUZZ_CALLOC,
    GCS_MEMORY_FUZZ_CALLOC_INTO,
} gcs_memory_fuzz_alloc_kind_t;

typedef struct {
    void *ptr;
    size_t charged_size;
    gcs_mem_category_t category;
    bool charged_session;
} gcs_memory_fuzz_slot_t;

typedef struct {
    bool active;
    bool invariant_failed;
    size_t tracked_live_bytes;
    size_t session_live_bytes;
    size_t category_live_bytes[GCS_MEM_CATEGORY_COUNT];
    size_t phase_tracked_peak_bytes;
    size_t phase_category_peak_bytes[GCS_MEM_CATEGORY_COUNT];
} gcs_memory_fuzz_model_t;

static gcs_memory_fuzz_slot_t g_slots[GCS_MEMORY_FUZZ_SLOT_COUNT];
static gcs_memory_fuzz_model_t g_model;

void gcs_mem_fuzz_reset_state(void);

static void fuzz_trap(void) {
    __builtin_trap();
}

static size_t add_charged_size(size_t size, bool *ok) {
    size_t charged_size;

    if ((ok == NULL) || !(*ok)) {
        return 0U;
    }
    if (__builtin_add_overflow(size, (size_t) GCS_MEMORY_FUZZ_HEADER_SIZE, &charged_size) ||
        (charged_size > UINT32_MAX)) {
        *ok = false;
        return 0U;
    }
    return charged_size;
}

static void model_sync_phase_peaks(void) {
    g_model.phase_tracked_peak_bytes = g_model.tracked_live_bytes;
    for (size_t i = 0U; i < GCS_MEM_CATEGORY_COUNT; i++) {
        g_model.phase_category_peak_bytes[i] = g_model.category_live_bytes[i];
    }
}

static void model_begin(void) {
    g_model.active = true;
    memset(g_model.category_live_bytes, 0, sizeof(g_model.category_live_bytes));
    model_sync_phase_peaks();
}

static void model_end(void) {
    g_model.active = false;
}

static void model_reset_phase_peaks(void) {
    model_sync_phase_peaks();
}

static bool allocation_would_fit(size_t size, gcs_mem_category_t category) {
    bool ok = true;
    size_t charged_size;
    size_t next_tracked;
    size_t next_session;
    size_t next_category;

    if ((size == 0U) || (category >= GCS_MEM_CATEGORY_COUNT)) {
        return false;
    }

    charged_size = add_charged_size(size, &ok);
    if (!ok) {
        return false;
    }
    if (!__builtin_add_overflow(g_model.tracked_live_bytes, charged_size, &next_tracked)) {
        if (!g_model.active) {
            return true;
        }
        if (__builtin_add_overflow(g_model.session_live_bytes, charged_size, &next_session) ||
            __builtin_add_overflow(g_model.category_live_bytes[category],
                                   charged_size,
                                   &next_category)) {
            return false;
        }
        if ((next_tracked > GCS_MAX_TRACKED_LIVE_BYTES) ||
            ((category == GCS_MEM_CALLDATA) &&
             (next_category > GCS_MAX_CALLDATA_FOOTPRINT_BYTES))) {
            return false;
        }
        (void) next_session;
        return true;
    }
    return false;
}

static bool begin_would_fit(void) {
    return !g_model.invariant_failed && !g_model.active &&
           (g_model.session_live_bytes == 0U) &&
           (g_model.tracked_live_bytes <= GCS_MAX_TRACKED_LIVE_BYTES);
}

static void model_alloc_update(size_t charged_size, gcs_mem_category_t category) {
    g_model.tracked_live_bytes += charged_size;
    if (g_model.active) {
        g_model.session_live_bytes += charged_size;
        g_model.category_live_bytes[category] += charged_size;
        if (g_model.tracked_live_bytes > g_model.phase_tracked_peak_bytes) {
            g_model.phase_tracked_peak_bytes = g_model.tracked_live_bytes;
        }
        if (g_model.category_live_bytes[category] >
            g_model.phase_category_peak_bytes[category]) {
            g_model.phase_category_peak_bytes[category] =
                g_model.category_live_bytes[category];
        }
    }
}

static void model_free_update(size_t charged_size,
                              gcs_mem_category_t category,
                              bool charged_session) {
    g_model.tracked_live_bytes -= charged_size;
    if (charged_session) {
        g_model.session_live_bytes -= charged_size;
        g_model.category_live_bytes[category] -= charged_size;
    }
}

static void verify_model_state(void) {
    if (gcs_mem_invariant_failed() != g_model.invariant_failed) {
        fuzz_trap();
    }
    if (gcs_budget_is_active() != g_model.active) {
        fuzz_trap();
    }
    if (gcs_mem_tracked_live_bytes() != g_model.tracked_live_bytes) {
        fuzz_trap();
    }
    if (gcs_mem_session_live_bytes() != g_model.session_live_bytes) {
        fuzz_trap();
    }
    for (size_t i = 0U; i < GCS_MEM_CATEGORY_COUNT; i++) {
        if (gcs_mem_category_live_bytes((gcs_mem_category_t) i) !=
            g_model.category_live_bytes[i]) {
            fuzz_trap();
        }
        if (gcs_mem_phase_category_peak_bytes((gcs_mem_category_t) i) !=
            g_model.phase_category_peak_bytes[i]) {
            fuzz_trap();
        }
    }
    if (gcs_mem_phase_tracked_peak_bytes() != g_model.phase_tracked_peak_bytes) {
        fuzz_trap();
    }
}

static void start_input(void) {
    if (!gcs_budget_end()) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    if (gcs_mem_invariant_failed()) {
        fuzz_trap();
    }
    if ((gcs_mem_tracked_live_bytes() != 0U) || (gcs_mem_session_live_bytes() != 0U)) {
        fuzz_trap();
    }

    memset(g_slots, 0, sizeof(g_slots));
    memset(&g_model, 0, sizeof(g_model));
    g_model.phase_tracked_peak_bytes = gcs_mem_phase_tracked_peak_bytes();
    for (size_t i = 0U; i < GCS_MEM_CATEGORY_COUNT; i++) {
        g_model.phase_category_peak_bytes[i] =
            gcs_mem_phase_category_peak_bytes((gcs_mem_category_t) i);
    }
    verify_model_state();
}

static void finish_input(void) {
    if (g_model.invariant_failed) {
        for (size_t i = 0U; i < GCS_MEMORY_FUZZ_SLOT_COUNT; i++) {
            if (g_slots[i].ptr != NULL) {
                gcs_mem_free(g_slots[i].ptr);
                g_slots[i].ptr = NULL;
            }
        }
        gcs_mem_fuzz_reset_state();
        memset(g_slots, 0, sizeof(g_slots));
        memset(&g_model, 0, sizeof(g_model));
        verify_model_state();
        return;
    }

    for (size_t i = 0U; i < GCS_MEMORY_FUZZ_SLOT_COUNT; i++) {
        if (g_slots[i].ptr != NULL) {
            gcs_mem_free(g_slots[i].ptr);
            model_free_update(g_slots[i].charged_size,
                              g_slots[i].category,
                              g_slots[i].charged_session);
            g_slots[i].ptr = NULL;
        }
    }
    if (g_model.active) {
        if (!gcs_budget_end()) {
            fuzz_trap();
        }
        model_end();
    } else if (!gcs_budget_end()) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure() || gcs_mem_invariant_failed()) {
        fuzz_trap();
    }
    verify_model_state();
    if ((gcs_mem_tracked_live_bytes() != 0U) || (gcs_mem_session_live_bytes() != 0U)) {
        fuzz_trap();
    }
}

static void free_slot(size_t slot_idx) {
    gcs_memory_fuzz_slot_t *slot = &g_slots[slot_idx];

    if (slot->ptr == NULL) {
        return;
    }
    gcs_mem_free(slot->ptr);
    model_free_update(slot->charged_size, slot->category, slot->charged_session);
    slot->ptr = NULL;
    slot->charged_size = 0U;
    slot->charged_session = false;
}

static void free_and_null_slot(size_t slot_idx) {
    gcs_memory_fuzz_slot_t *slot = &g_slots[slot_idx];

    if (slot->ptr == NULL) {
        gcs_mem_free_and_null(NULL);
        return;
    }
    gcs_mem_free_and_null(&slot->ptr);
    if (slot->ptr != NULL) {
        fuzz_trap();
    }
    model_free_update(slot->charged_size, slot->category, slot->charged_session);
    slot->charged_size = 0U;
    slot->charged_session = false;
}

static void verify_zeroed(const void *ptr, size_t size) {
    const uint8_t *bytes = (const uint8_t *) ptr;

    for (size_t i = 0U; i < size; i++) {
        if (bytes[i] != 0U) {
            fuzz_trap();
        }
    }
}

static void alloc_into_slot(const uint8_t *data,
                            size_t size,
                            size_t *offset,
                            gcs_memory_fuzz_alloc_kind_t kind) {
    size_t slot_idx;
    size_t raw_size;
    size_t alloc_size;
    uint8_t category_raw;
    gcs_mem_category_t category;
    bool would_fit;
    void *ptr;
    void *out = (void *) UINTPTR_MAX;

    if (*offset + 4U > size) {
        return;
    }

    slot_idx = data[(*offset)++] % GCS_MEMORY_FUZZ_SLOT_COUNT;
    free_slot(slot_idx);

    raw_size = (size_t) data[(*offset)++] | ((size_t) data[(*offset)++] << 8U);
    alloc_size = raw_size % (GCS_MAX_TRACKED_LIVE_BYTES + 1U);
    category_raw = data[(*offset)++];
    category = (gcs_mem_category_t) (category_raw % (GCS_MEM_CATEGORY_COUNT + 2U));

    would_fit = allocation_would_fit(alloc_size, category);
    switch (kind) {
        case GCS_MEMORY_FUZZ_CALLOC:
            ptr = gcs_mem_calloc(alloc_size, category);
            break;
        case GCS_MEMORY_FUZZ_CALLOC_INTO:
            if (gcs_mem_calloc_into(&out, alloc_size, category) != would_fit) {
                fuzz_trap();
            }
            ptr = out;
            break;
        case GCS_MEMORY_FUZZ_ALLOC:
        default:
            ptr = gcs_mem_alloc(alloc_size, category);
            break;
    }
    if (ptr == NULL) {
        if (gcs_mem_take_allocation_failure() != !would_fit) {
            fuzz_trap();
        }
        verify_model_state();
        return;
    }
    if (!would_fit) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    g_slots[slot_idx].ptr = ptr;
    g_slots[slot_idx].charged_size = alloc_size + GCS_MEMORY_FUZZ_HEADER_SIZE;
    g_slots[slot_idx].category = category;
    g_slots[slot_idx].charged_session = g_model.active;
    model_alloc_update(g_slots[slot_idx].charged_size, category);
    if (kind != GCS_MEMORY_FUZZ_ALLOC) {
        verify_zeroed(ptr, alloc_size);
    }
    verify_model_state();
}

static void strdup_into_slot(const uint8_t *data, size_t size, size_t *offset) {
    size_t slot_idx;
    size_t raw_len;
    size_t str_len;
    size_t payload_size;
    uint8_t category_raw;
    gcs_mem_category_t category;
    char input[GCS_MEMORY_FUZZ_STR_MAX + 1U];
    bool would_fit;
    char *ptr;

    if (*offset + 3U > size) {
        return;
    }

    slot_idx = data[(*offset)++] % GCS_MEMORY_FUZZ_SLOT_COUNT;

    raw_len = data[(*offset)++];
    str_len = raw_len % (GCS_MEMORY_FUZZ_STR_MAX + 1U);
    if (*offset + str_len + 1U > size) {
        return;
    }
    memcpy(input, &data[*offset], str_len);
    *offset += str_len;
    input[str_len] = '\0';
    category_raw = data[(*offset)++];
    category = (gcs_mem_category_t) (category_raw % (GCS_MEM_CATEGORY_COUNT + 2U));

    free_slot(slot_idx);

    payload_size = strlen(input) + 1U;
    would_fit = allocation_would_fit(payload_size, category);
    ptr = gcs_mem_strdup(input, category);
    if (ptr == NULL) {
        if (gcs_mem_take_allocation_failure() != !would_fit) {
            fuzz_trap();
        }
        verify_model_state();
        return;
    }
    if (!would_fit || (strcmp(ptr, input) != 0)) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    g_slots[slot_idx].ptr = ptr;
    g_slots[slot_idx].charged_size = payload_size + GCS_MEMORY_FUZZ_HEADER_SIZE;
    g_slots[slot_idx].category = category;
    g_slots[slot_idx].charged_session = g_model.active;
    model_alloc_update(g_slots[slot_idx].charged_size, category);
    verify_model_state();
}

static void strdup_empty_into_slot(void) {
    const size_t slot_idx = 0U;
    const size_t payload_size = 1U;
    const gcs_mem_category_t category = GCS_MEM_GENERIC;
    bool would_fit;
    char *ptr;

    free_slot(slot_idx);
    would_fit = allocation_would_fit(payload_size, category);
    ptr = gcs_mem_strdup("", category);
    if (ptr == NULL) {
        if (gcs_mem_take_allocation_failure() != !would_fit) {
            fuzz_trap();
        }
        verify_model_state();
        return;
    }
    if (!would_fit || (ptr[0] != '\0')) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    g_slots[slot_idx].ptr = ptr;
    g_slots[slot_idx].charged_size = payload_size + GCS_MEMORY_FUZZ_HEADER_SIZE;
    g_slots[slot_idx].category = category;
    g_slots[slot_idx].charged_session = g_model.active;
    model_alloc_update(g_slots[slot_idx].charged_size, category);
    verify_model_state();
}

static void calloc_into_null_out(void) {
    if (gcs_mem_calloc_into(NULL, 1U, GCS_MEM_GENERIC)) {
        fuzz_trap();
    }
    if (!gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    verify_model_state();
}

static void strdup_null_input(void) {
    if (gcs_mem_strdup(NULL, GCS_MEM_GENERIC) != NULL) {
        fuzz_trap();
    }
    if (!gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    verify_model_state();
}

static gcs_memory_fuzz_header_t *slot_header(size_t slot_idx) {
    return ((gcs_memory_fuzz_header_t *) g_slots[slot_idx].ptr) - 1;
}

static void free_all_slots(void) {
    for (size_t i = 0U; i < GCS_MEMORY_FUZZ_SLOT_COUNT; i++) {
        free_slot(i);
    }
}

static void normalize_to_inactive_session(void) {
    free_all_slots();
    if (g_model.active) {
        if (!gcs_budget_end()) {
            fuzz_trap();
        }
        model_end();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    verify_model_state();
}

static void begin_session_with_live_slot_zero(void) {
    const size_t slot_idx = 0U;
    const size_t payload_size = 1U;
    const size_t charged_size = payload_size + GCS_MEMORY_FUZZ_HEADER_SIZE;
    const gcs_mem_category_t category = GCS_MEM_GENERIC;
    void *ptr;

    normalize_to_inactive_session();
    if (!gcs_budget_begin()) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    model_begin();

    ptr = gcs_mem_alloc(payload_size, category);
    if (ptr == NULL) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    g_slots[slot_idx].ptr = ptr;
    g_slots[slot_idx].charged_size = charged_size;
    g_slots[slot_idx].category = category;
    g_slots[slot_idx].charged_session = true;
    model_alloc_update(charged_size, category);
    verify_model_state();
}

static void verify_invariant_persistence(void) {
    if (!g_model.invariant_failed || g_model.active) {
        fuzz_trap();
    }
    if (!gcs_mem_invariant_failed()) {
        fuzz_trap();
    }
    if (gcs_budget_end()) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    verify_model_state();
}

static void expect_active_budget_end_failure(void) {
    if (!g_model.active || !gcs_budget_is_active()) {
        fuzz_trap();
    }
    if (gcs_budget_end()) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    g_model.active = false;
    g_model.invariant_failed = true;
    verify_model_state();
    verify_invariant_persistence();
}

static void end_session_with_live_allocation(void) {
    begin_session_with_live_slot_zero();
    expect_active_budget_end_failure();
}

static void free_stale_generation_allocation(void) {
    const size_t slot_idx = 0U;
    gcs_memory_fuzz_header_t *header;

    begin_session_with_live_slot_zero();
    header = slot_header(slot_idx);
    header->fields.accounting_tag =
        (header->fields.accounting_tag & ~GCS_ALLOC_GENERATION_MASK) |
        ((header->fields.accounting_tag ^ 1U) & GCS_ALLOC_GENERATION_MASK);

    gcs_mem_free(g_slots[slot_idx].ptr);
    g_model.tracked_live_bytes -= g_slots[slot_idx].charged_size;
    g_slots[slot_idx].ptr = NULL;
    g_slots[slot_idx].charged_size = 0U;
    g_slots[slot_idx].charged_session = false;
    g_model.invariant_failed = true;
    verify_model_state();
    expect_active_budget_end_failure();
}

static void free_wrong_category_allocation(void) {
    const size_t slot_idx = 0U;
    gcs_memory_fuzz_header_t *header;

    begin_session_with_live_slot_zero();
    header = slot_header(slot_idx);
    header->fields.accounting_tag =
        (header->fields.accounting_tag & ~GCS_ALLOC_CATEGORY_MASK) |
        (((uint32_t) GCS_MEM_CALLDATA << GCS_ALLOC_CATEGORY_SHIFT) &
         GCS_ALLOC_CATEGORY_MASK);

    gcs_mem_free(g_slots[slot_idx].ptr);
    g_model.tracked_live_bytes -= g_slots[slot_idx].charged_size;
    g_slots[slot_idx].ptr = NULL;
    g_slots[slot_idx].charged_size = 0U;
    g_slots[slot_idx].charged_session = false;
    g_model.invariant_failed = true;
    verify_model_state();
    expect_active_budget_end_failure();
}

static void begin_session(void) {
    bool expected_success = begin_would_fit();
    bool actual_success = gcs_budget_begin();

    if (actual_success != expected_success) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure() != !expected_success) {
        fuzz_trap();
    }
    if (actual_success) {
        model_begin();
    }
    verify_model_state();
}

static void end_session(void) {
    for (size_t i = 0U; i < GCS_MEMORY_FUZZ_SLOT_COUNT; i++) {
        if (g_slots[i].ptr != NULL && g_slots[i].charged_session) {
            free_slot(i);
        }
    }
    if (!gcs_budget_end()) {
        fuzz_trap();
    }
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    if (g_model.active) {
        model_end();
    }
    verify_model_state();
}

static void reset_peaks(void) {
    gcs_mem_reset_phase_peaks();
    model_reset_phase_peaks();
    if (gcs_mem_take_allocation_failure()) {
        fuzz_trap();
    }
    verify_model_state();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t offset = 0U;

    start_input();
    while (offset < size) {
        const uint8_t op = data[offset++];

        switch (op & 0x0fU) {
            case 0U:
                alloc_into_slot(data,
                                size,
                                &offset,
                                ((op & 0x10U) != 0U) ? GCS_MEMORY_FUZZ_CALLOC
                                                      : GCS_MEMORY_FUZZ_ALLOC);
                break;
            case 1U:
                if (offset >= size) {
                    break;
                }
                free_slot(data[offset++] % GCS_MEMORY_FUZZ_SLOT_COUNT);
                if (gcs_mem_take_allocation_failure()) {
                    fuzz_trap();
                }
                verify_model_state();
                break;
            case 2U:
                begin_session();
                break;
            case 3U:
                end_session();
                break;
            case 4U:
                reset_peaks();
                break;
            case 5U:
                if (gcs_mem_take_allocation_failure()) {
                    fuzz_trap();
                }
                verify_model_state();
                break;
            case 6U:
                alloc_into_slot(data,
                                size,
                                &offset,
                                GCS_MEMORY_FUZZ_CALLOC_INTO);
                break;
            case 7U:
                strdup_into_slot(data, size, &offset);
                break;
            case 8U:
                if (offset >= size) {
                    break;
                }
                free_and_null_slot(data[offset++] % GCS_MEMORY_FUZZ_SLOT_COUNT);
                if (gcs_mem_take_allocation_failure()) {
                    fuzz_trap();
                }
                verify_model_state();
                break;
            case 9U:
                calloc_into_null_out();
                break;
            case 10U:
                strdup_empty_into_slot();
                break;
            case 11U:
                strdup_null_input();
                break;
            case 12U:
                end_session_with_live_allocation();
                break;
            case 13U:
                free_stale_generation_allocation();
                break;
            case 14U:
                free_wrong_category_allocation();
                break;
            default:
                if (gcs_mem_take_allocation_failure()) {
                    fuzz_trap();
                }
                verify_model_state();
                break;
        }
        if (g_model.invariant_failed) {
            break;
        }
    }
    finish_input();
    return 0;
}
