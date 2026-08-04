#include "gcs_memory.h"

#include <inttypes.h>
#include <limits.h>
#include <string.h>

#include "app_mem_utils.h"
#include "gcs_limits.h"

#define GCS_ALLOC_ACCOUNTED_MASK UINT32_C(0x80000000)
#define GCS_ALLOC_CATEGORY_SHIFT 28U
#define GCS_ALLOC_CATEGORY_MASK  UINT32_C(0x70000000)
#define GCS_ALLOC_GENERATION_MASK UINT32_C(0x0fffffff)

/*
 * Keep the header exactly eight bytes. A natural struct containing size_t,
 * generation, category and flags would commonly round up to 16 bytes once it
 * is aligned for intmax_t, defeating the calldata chunk compaction.
 */
typedef union {
    struct {
        uint32_t charged_size;
        uint32_t accounting_tag;
    } fields;
    intmax_t alignment;
} gcs_alloc_header_t;

_Static_assert(sizeof(gcs_alloc_header_t) == 8U,
               "GCS allocation header must remain eight bytes");
_Static_assert(_Alignof(gcs_alloc_header_t) >= _Alignof(intmax_t),
               "GCS allocation header must preserve heap alignment");
_Static_assert(GCS_MEM_CATEGORY_COUNT <= 8U,
               "GCS allocation tag reserves three category bits");
_Static_assert((GCS_MAX_TRACKED_LIVE_BYTES + GCS_HEAP_RESERVE_BYTES) ==
                   (16U * 1024U),
               "GCS tracked budget and reserve must cover the 16 KiB app heap");

static size_t g_tracked_live_bytes;
static size_t g_session_live_bytes;
static size_t g_category_live_bytes[GCS_MEM_CATEGORY_COUNT];
static size_t g_phase_tracked_peak_bytes;
static size_t g_phase_category_peak_bytes[GCS_MEM_CATEGORY_COUNT];
static uint32_t g_generation;
static bool g_budget_active;
static bool g_allocation_failure;
static bool g_invariant_failure;

static bool checked_add(size_t left, size_t right, size_t *out) {
    return (out != NULL) && !__builtin_add_overflow(left, right, out);
}

static uint32_t make_accounting_tag(gcs_mem_category_t category) {
    uint32_t tag = ((uint32_t) category << GCS_ALLOC_CATEGORY_SHIFT) &
                   GCS_ALLOC_CATEGORY_MASK;

    if (g_budget_active) {
        tag |= GCS_ALLOC_ACCOUNTED_MASK | (g_generation & GCS_ALLOC_GENERATION_MASK);
    }
    return tag;
}

static gcs_mem_category_t tag_category(uint32_t tag) {
    return (gcs_mem_category_t) ((tag & GCS_ALLOC_CATEGORY_MASK) >>
                                GCS_ALLOC_CATEGORY_SHIFT);
}

static bool allocation_fits_budget(size_t charged_size,
                                   gcs_mem_category_t category) {
    size_t next_tracked;
    size_t next_session;
    size_t next_category;

    if (!checked_add(g_tracked_live_bytes, charged_size, &next_tracked)) {
        return false;
    }
    if (!g_budget_active) {
        return true;
    }
    if (!checked_add(g_session_live_bytes, charged_size, &next_session) ||
        !checked_add(g_category_live_bytes[category], charged_size, &next_category) ||
        (next_tracked > GCS_MAX_TRACKED_LIVE_BYTES)) {
        return false;
    }
    if ((category == GCS_MEM_CALLDATA) &&
        (next_category > GCS_MAX_CALLDATA_FOOTPRINT_BYTES)) {
        return false;
    }
    return true;
}

void *gcs_mem_alloc(size_t size, gcs_mem_category_t category) {
    gcs_alloc_header_t *header;
    size_t charged_size;

    if ((size == 0U) || (category >= GCS_MEM_CATEGORY_COUNT) ||
        !checked_add(sizeof(*header), size, &charged_size) ||
        (charged_size > UINT32_MAX) ||
        !allocation_fits_budget(charged_size, category)) {
        g_allocation_failure = true;
        return NULL;
    }
    header = APP_MEM_ALLOC(charged_size);
    if (header == NULL) {
        g_allocation_failure = true;
        return NULL;
    }
    header->fields.charged_size = (uint32_t) charged_size;
    header->fields.accounting_tag = make_accounting_tag(category);
    g_tracked_live_bytes += charged_size;
    if (g_budget_active) {
        g_session_live_bytes += charged_size;
        g_category_live_bytes[category] += charged_size;
        if (g_tracked_live_bytes > g_phase_tracked_peak_bytes) {
            g_phase_tracked_peak_bytes = g_tracked_live_bytes;
        }
        if (g_category_live_bytes[category] >
            g_phase_category_peak_bytes[category]) {
            g_phase_category_peak_bytes[category] =
                g_category_live_bytes[category];
        }
    }
    return header + 1;
}

void *gcs_mem_calloc(size_t size, gcs_mem_category_t category) {
    void *ptr = gcs_mem_alloc(size, category);

    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    return ptr;
}

bool gcs_mem_calloc_into(void **out, size_t size, gcs_mem_category_t category) {
    if (out == NULL) {
        g_allocation_failure = true;
        return false;
    }
    *out = gcs_mem_calloc(size, category);
    return *out != NULL;
}

char *gcs_mem_strdup(const char *str, gcs_mem_category_t category) {
    size_t size;
    char *copy;

    if ((str == NULL) || __builtin_add_overflow(strlen(str), 1U, &size)) {
        g_allocation_failure = true;
        return NULL;
    }
    copy = gcs_mem_alloc(size, category);
    if (copy != NULL) {
        memcpy(copy, str, size);
    }
    return copy;
}

void gcs_mem_free(void *ptr) {
    gcs_alloc_header_t *header;
    size_t charged_size;
    uint32_t tag;
    gcs_mem_category_t category;
    bool accounted;

    if (ptr == NULL) {
        return;
    }
    header = ((gcs_alloc_header_t *) ptr) - 1;
    charged_size = header->fields.charged_size;
    tag = header->fields.accounting_tag;
    category = tag_category(tag);
    accounted = (tag & GCS_ALLOC_ACCOUNTED_MASK) != 0U;

    if ((charged_size < sizeof(*header)) ||
        (charged_size > g_tracked_live_bytes) ||
        (category >= GCS_MEM_CATEGORY_COUNT)) {
        g_invariant_failure = true;
    } else {
        g_tracked_live_bytes -= charged_size;
        if (accounted) {
            if (((tag & GCS_ALLOC_GENERATION_MASK) != g_generation) ||
                (charged_size > g_session_live_bytes) ||
                (charged_size > g_category_live_bytes[category])) {
                /* Never refund a stale allocation into the current session. */
                g_invariant_failure = true;
            } else {
                g_session_live_bytes -= charged_size;
                g_category_live_bytes[category] -= charged_size;
            }
        }
    }
    memset(header, 0, sizeof(*header));
    APP_MEM_FREE(header);
}

void gcs_mem_free_and_null(void **ptr) {
    if ((ptr != NULL) && (*ptr != NULL)) {
        gcs_mem_free(*ptr);
        *ptr = NULL;
    }
}

bool gcs_budget_begin(void) {
    if (g_budget_active || g_invariant_failure || (g_session_live_bytes != 0U) ||
        (g_tracked_live_bytes > GCS_MAX_TRACKED_LIVE_BYTES)) {
        g_allocation_failure = true;
        return false;
    }
    g_generation = (g_generation + 1U) & GCS_ALLOC_GENERATION_MASK;
    if (g_generation == 0U) {
        g_generation = 1U;
    }
    memset(g_category_live_bytes, 0, sizeof(g_category_live_bytes));
    g_budget_active = true;
    g_allocation_failure = false;
    gcs_mem_reset_phase_peaks();
    return true;
}

bool gcs_budget_end(void) {
    if (!g_budget_active) {
        /* Ending/resetting a non-GCS flow is still a session boundary. Do not
         * let an allocation failure raised by a failed metadata/TIP-712 parse
         * leak into the status mapping of the next APDU. */
        g_allocation_failure = false;
        return !g_invariant_failure;
    }
    if ((g_session_live_bytes != 0U) || g_invariant_failure) {
        g_invariant_failure = true;
        g_budget_active = false;
        g_allocation_failure = false;
        return false;
    }
    for (size_t i = 0U; i < GCS_MEM_CATEGORY_COUNT; i++) {
        if (g_category_live_bytes[i] != 0U) {
            g_invariant_failure = true;
            g_budget_active = false;
            g_allocation_failure = false;
            return false;
        }
    }
    g_budget_active = false;
    g_allocation_failure = false;
    return true;
}

bool gcs_budget_is_active(void) {
    return g_budget_active;
}

bool gcs_mem_take_allocation_failure(void) {
    bool failed = g_allocation_failure;
    g_allocation_failure = false;
    return failed;
}

size_t gcs_mem_tracked_live_bytes(void) {
    return g_tracked_live_bytes;
}

size_t gcs_mem_session_live_bytes(void) {
    return g_session_live_bytes;
}

size_t gcs_mem_category_live_bytes(gcs_mem_category_t category) {
    return (category < GCS_MEM_CATEGORY_COUNT) ? g_category_live_bytes[category] : 0U;
}

size_t gcs_mem_phase_tracked_peak_bytes(void) {
    return g_phase_tracked_peak_bytes;
}

size_t gcs_mem_phase_category_peak_bytes(gcs_mem_category_t category) {
    return (category < GCS_MEM_CATEGORY_COUNT)
               ? g_phase_category_peak_bytes[category]
               : 0U;
}

void gcs_mem_reset_phase_peaks(void) {
    g_phase_tracked_peak_bytes = g_tracked_live_bytes;
    for (size_t i = 0U; i < GCS_MEM_CATEGORY_COUNT; i++) {
        g_phase_category_peak_bytes[i] = g_category_live_bytes[i];
    }
}

bool gcs_mem_invariant_failed(void) {
    return g_invariant_failure;
}

#if defined(GCS_MEMORY_FUZZ_TESTING)
void gcs_mem_fuzz_reset_state(void) {
    g_tracked_live_bytes = 0U;
    g_session_live_bytes = 0U;
    memset(g_category_live_bytes, 0, sizeof(g_category_live_bytes));
    g_phase_tracked_peak_bytes = 0U;
    memset(g_phase_category_peak_bytes, 0, sizeof(g_phase_category_peak_bytes));
    g_generation = 0U;
    g_budget_active = false;
    g_allocation_failure = false;
    g_invariant_failure = false;
}
#endif
