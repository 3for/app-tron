#include <inttypes.h>
#include <setjmp.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>

#include "gcs_limits.h"
#include "gcs_memory.h"
#include "calldata.h"
#include "shared_context.h"
#include "transaction_trigger_decode.h"

#define TRACKED_HEADER_SIZE 8U

app_state_t appState;

static void test_inactive_budget_end_clears_allocation_failure(void **state) {
    (void) state;

    assert_null(gcs_mem_alloc(0U, GCS_MEM_GENERIC));
    assert_true(gcs_budget_end());
    assert_false(gcs_mem_take_allocation_failure());
}

static void test_inactive_allocation_is_not_refunded_from_session(void **state) {
    (void) state;
    void *before = gcs_mem_alloc(32U, GCS_MEM_METADATA);

    assert_non_null(before);
    assert_int_equal(gcs_mem_tracked_live_bytes(), 32U + TRACKED_HEADER_SIZE);
    assert_true(gcs_budget_begin());
    assert_int_equal(gcs_mem_session_live_bytes(), 0U);

    gcs_mem_free(before);
    assert_int_equal(gcs_mem_tracked_live_bytes(), 0U);
    assert_int_equal(gcs_mem_session_live_bytes(), 0U);

    void *during = gcs_mem_alloc(64U, GCS_MEM_CALLDATA);
    assert_non_null(during);
    assert_int_equal(gcs_mem_session_live_bytes(), 64U + TRACKED_HEADER_SIZE);
    assert_int_equal(gcs_mem_category_live_bytes(GCS_MEM_CALLDATA),
                     64U + TRACKED_HEADER_SIZE);
    gcs_mem_free(during);
    assert_true(gcs_budget_end());
}

static void test_tracked_live_budget_is_deterministic(void **state) {
    (void) state;
    void *baseline = gcs_mem_alloc(1024U, GCS_MEM_METADATA);
    const size_t baseline_charged = 1024U + TRACKED_HEADER_SIZE;
    const size_t remaining = GCS_MAX_TRACKED_LIVE_BYTES - baseline_charged;

    assert_non_null(baseline);
    assert_true(gcs_budget_begin());
    void *maximum = gcs_mem_alloc(remaining - TRACKED_HEADER_SIZE,
                                  GCS_MEM_GENERIC);
    assert_non_null(maximum);
    assert_null(gcs_mem_alloc(1U, GCS_MEM_GENERIC));
    assert_true(gcs_mem_take_allocation_failure());

    gcs_mem_free(maximum);
    gcs_mem_free(baseline);
    assert_true(gcs_budget_end());
}

static void test_calldata_sub_budget_is_deterministic(void **state) {
    (void) state;

    assert_true(gcs_budget_begin());
    void *maximum = gcs_mem_alloc(GCS_MAX_CALLDATA_FOOTPRINT_BYTES -
                                      TRACKED_HEADER_SIZE,
                                  GCS_MEM_CALLDATA);
    assert_non_null(maximum);
    assert_null(gcs_mem_alloc(1U, GCS_MEM_CALLDATA));
    assert_true(gcs_mem_take_allocation_failure());

    gcs_mem_free(maximum);
    assert_true(gcs_budget_end());
}

static void test_returned_pointer_preserves_intmax_alignment(void **state) {
    (void) state;
    void *ptr = gcs_mem_alloc(1U, GCS_MEM_GENERIC);

    assert_non_null(ptr);
    assert_int_equal((uintptr_t) ptr % alignof(intmax_t), 0U);
    gcs_mem_free(ptr);
}

static void test_incompressible_4096_bounded_root_fits_calldata_budget(void **state) {
    (void) state;
    uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0x12, 0x34, 0x56, 0x78};
    /* 127 complete ABI words plus the selector: the largest ABI-aligned value
     * not exceeding the 4096-byte root semantic limit. */
    uint8_t args[127U * CALLDATA_CHUNK_SIZE];

    memset(args, 0xa5, sizeof(args));
    appState = APP_STATE_SIGNING_GCS_STORE;
    assert_true(gcs_budget_begin());
    void *decoder = gcs_mem_calloc(sizeof(tron_stream_decoder_t),
                                   GCS_MEM_TX_CONTEXT);
    assert_non_null(decoder);
    s_calldata *calldata = calldata_init_root(sizeof(args), selector);
    assert_non_null(calldata);
    assert_true(calldata_append(calldata, args, sizeof(args)));
    assert_true(gcs_mem_category_live_bytes(GCS_MEM_CALLDATA) <=
                GCS_MAX_CALLDATA_FOOTPRINT_BYTES);
    assert_true(gcs_mem_phase_category_peak_bytes(GCS_MEM_CALLDATA) >=
                gcs_mem_category_live_bytes(GCS_MEM_CALLDATA));
    assert_memory_equal(calldata_get_chunk(calldata, 126U),
                        &args[126U * CALLDATA_CHUNK_SIZE],
                        CALLDATA_CHUNK_SIZE);

    calldata_delete(calldata);
    gcs_mem_free(decoder);
    assert_int_equal(gcs_mem_category_live_bytes(GCS_MEM_CALLDATA), 0U);
    assert_true(gcs_budget_end());
    appState = APP_STATE_IDLE;
}

static void test_nested_calldata_limit_is_state_independent(void **state) {
    (void) state;
    uint8_t selector[CALLDATA_SELECTOR_SIZE] = {0x12, 0x34, 0x56, 0x78};

    /* A bounded constructor must not silently become unbounded merely because
     * TIP-712 has not switched appState to a GCS-specific value. */
    appState = APP_STATE_IDLE;
    s_calldata *maximum =
        calldata_init_nested(GCS_MAX_NESTED_CALLDATA_SIZE, selector);
    assert_non_null(maximum);
    calldata_delete(maximum);
    assert_null(calldata_init_nested(GCS_MAX_NESTED_CALLDATA_SIZE + 1U,
                                     selector));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_inactive_budget_end_clears_allocation_failure),
        cmocka_unit_test(test_inactive_allocation_is_not_refunded_from_session),
        cmocka_unit_test(test_tracked_live_budget_is_deterministic),
        cmocka_unit_test(test_calldata_sub_budget_is_deterministic),
        cmocka_unit_test(test_returned_pointer_preserves_intmax_alignment),
        cmocka_unit_test(test_incompressible_4096_bounded_root_fits_calldata_budget),
        cmocka_unit_test(test_nested_calldata_limit_is_state_independent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
