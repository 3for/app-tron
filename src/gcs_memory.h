#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    GCS_MEM_GENERIC = 0,
    GCS_MEM_CALLDATA,
    GCS_MEM_DESCRIPTOR,
    GCS_MEM_TX_CONTEXT,
    GCS_MEM_FIELD,
    GCS_MEM_UI,
    GCS_MEM_METADATA,
    GCS_MEM_TEMPORARY,
    GCS_MEM_CATEGORY_COUNT,
} gcs_mem_category_t;

/*
 * These wrappers are also used by shared TIP-712/GCS modules while no GCS
 * budget is active. Every allocation therefore carries the same header, while
 * only allocations made during an active GCS session are charged to that
 * session's counters.
 */
void *gcs_mem_alloc(size_t size, gcs_mem_category_t category);
void *gcs_mem_calloc(size_t size, gcs_mem_category_t category);
bool gcs_mem_calloc_into(void **out, size_t size, gcs_mem_category_t category);
char *gcs_mem_strdup(const char *str, gcs_mem_category_t category);
void gcs_mem_free(void *ptr);
void gcs_mem_free_and_null(void **ptr);

bool gcs_budget_begin(void);
bool gcs_budget_end(void);
bool gcs_budget_is_active(void);

/* Consume the sticky allocation failure raised since the previous call. */
bool gcs_mem_take_allocation_failure(void);

/* Introspection used by tests and phase-boundary assertions. */
size_t gcs_mem_tracked_live_bytes(void);
size_t gcs_mem_session_live_bytes(void);
size_t gcs_mem_category_live_bytes(gcs_mem_category_t category);
size_t gcs_mem_phase_tracked_peak_bytes(void);
size_t gcs_mem_phase_category_peak_bytes(gcs_mem_category_t category);
void gcs_mem_reset_phase_peaks(void);
bool gcs_mem_invariant_failed(void);
