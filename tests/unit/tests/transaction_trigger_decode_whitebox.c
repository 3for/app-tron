#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#define static
#include "../../../src/handlers/transaction_trigger_decode.c"
#undef static

static void test_tron_current_ctx_returns_tx_when_stack_empty(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    memset(&decoder, 0, sizeof(decoder));
    assert_int_equal(tron_current_ctx(&decoder), TRON_CTX_TX);
}

static void test_tron_push_frame_rejects_overflow(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    memset(&decoder, 0, sizeof(decoder));
    decoder.depth = sizeof(decoder.frames) / sizeof(decoder.frames[0]);

    assert_false(tron_push_frame(&decoder, TRON_CTX_RAW, 1U));
}

static void test_tron_consume_byte_rejects_invalid_states(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    memset(&decoder, 0, sizeof(decoder));
    decoder.done = true;
    assert_false(tron_consume_byte(&decoder));

    memset(&decoder, 0, sizeof(decoder));
    assert_false(tron_consume_byte(&decoder));

    memset(&decoder, 0, sizeof(decoder));
    decoder.depth = 1U;
    decoder.frames[0].remaining = 0U;
    assert_false(tron_consume_byte(&decoder));
}

static void test_tron_length_action_handles_non_string_and_unknown_ctx(void **state) {
    (void) state;

    assert_int_equal(tron_length_action(TRON_CTX_TX, 1U, PB_WT_VARINT), TRON_ACT_SKIP);
    assert_int_equal(tron_length_action((tron_ctx_t) 99, 1U, PB_WT_STRING), TRON_ACT_SKIP);
}

static void test_tron_enter_submessage_rejects_invalid_action(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    memset(&decoder, 0, sizeof(decoder));
    assert_false(tron_enter_submessage(&decoder, (tron_action_t) 99, 0U));
}

static void test_tron_process_byte_handles_whitebox_error_modes(void **state) {
    (void) state;

    tron_stream_decoder_t decoder;

    memset(&decoder, 0, sizeof(decoder));
    decoder.depth = 1U;
    decoder.frames[0].ctx = TRON_CTX_TX;
    decoder.frames[0].remaining = 1U;
    decoder.mode = TRON_MODE_BYTES;
    decoder.bytes_remaining = 0U;
    assert_true(tron_process_byte(&decoder, 0x00U));
    assert_int_equal(decoder.mode, TRON_MODE_KEY);

    memset(&decoder, 0, sizeof(decoder));
    decoder.depth = 1U;
    decoder.frames[0].ctx = TRON_CTX_TX;
    decoder.frames[0].remaining = 1U;
    decoder.mode = (tron_mode_t) 99;
    assert_false(tron_process_byte(&decoder, 0x00U));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tron_current_ctx_returns_tx_when_stack_empty),
        cmocka_unit_test(test_tron_push_frame_rejects_overflow),
        cmocka_unit_test(test_tron_consume_byte_rejects_invalid_states),
        cmocka_unit_test(test_tron_length_action_handles_non_string_and_unknown_ctx),
        cmocka_unit_test(test_tron_enter_submessage_rejects_invalid_action),
        cmocka_unit_test(test_tron_process_byte_handles_whitebox_error_modes),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
