#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "transaction_trigger_decode.h"

typedef struct {
    bool fail_enabled;
    size_t fail_at_offset;
    size_t call_count;
    size_t observed_bytes;
} observer_ctx_t;

static bool fuzz_observer(void *ctx,
                          const uint8_t *chunk,
                          size_t chunk_len,
                          size_t chunk_offset,
                          size_t total_len) {
    observer_ctx_t *observer = (observer_ctx_t *) ctx;

    if (observer == NULL || chunk == NULL) {
        return false;
    }
    if (chunk_len > total_len) {
        return false;
    }
    if (chunk_offset > total_len) {
        return false;
    }
    if (chunk_len > (total_len - chunk_offset)) {
        return false;
    }

    observer->call_count++;
    observer->observed_bytes += chunk_len;

    if (observer->fail_enabled && chunk_offset == observer->fail_at_offset) {
        return false;
    }

    return true;
}

static size_t select_declared_len(size_t payload_len, uint8_t mode, uint8_t selector) {
    switch (mode & 0x03U) {
        case 0U:
            return payload_len;
        case 1U:
            if (payload_len == 0U) {
                return 0U;
            }
            return (size_t) (selector % (payload_len + 1U));
        case 2U:
            return payload_len + (size_t) (selector & 0x3FU);
        default:
            return 0U;
    }
}

static size_t select_chunk_len(size_t remaining, uint8_t seed, size_t iter) {
    size_t chunk_len;

    switch (seed & 0x03U) {
        case 0U:
            chunk_len = remaining;
            break;
        case 1U:
            chunk_len = 1U;
            break;
        case 2U:
            chunk_len = ((size_t) seed % 8U) + 1U;
            break;
        default:
            chunk_len = (((size_t) seed + iter) % 17U) + 1U;
            break;
    }

    if (chunk_len > remaining) {
        chunk_len = remaining;
    }
    return chunk_len;
}

static void validate_result(const tron_decode_result_t *result) {
    if (result == NULL) {
        return;
    }

    if (result->has_owner_address &&
        result->owner_address_len > sizeof(result->owner_address)) {
        __builtin_trap();
    }
    if (result->has_contract_address &&
        result->contract_address_len > sizeof(result->contract_address)) {
        __builtin_trap();
    }
    if (result->has_data) {
        if (result->data_prefix_len > sizeof(result->data_prefix)) {
            __builtin_trap();
        }
        if (result->data_prefix_len > result->data_len) {
            __builtin_trap();
        }
    }
    if (result->has_custom_data) {
        if (result->custom_data_prefix_len > sizeof(result->custom_data_prefix)) {
            __builtin_trap();
        }
        if (result->custom_data_prefix_len > result->custom_data_len) {
            __builtin_trap();
        }
    }
}

static void run_decoder_scenario(const uint8_t *payload,
                                 size_t payload_len,
                                 bool raw_mode,
                                 size_t declared_len,
                                 bool attach_observer,
                                 bool failing_observer,
                                 uint8_t chunk_seed,
                                 bool interleave_zero_length_feeds) {
    tron_stream_decoder_t decoder;
    tron_decode_result_t result;
    observer_ctx_t observer = {0};
    uint8_t scratch = 0;
    size_t offset = 0;
    size_t iter = 0;

    if (raw_mode) {
        tron_stream_decoder_init_raw(&decoder, declared_len);
    } else {
        tron_stream_decoder_init(&decoder, declared_len);
    }

    if (attach_observer) {
        observer.fail_enabled = failing_observer;
        observer.fail_at_offset = (payload_len == 0U) ? 0U : ((size_t) chunk_seed % payload_len);
        tron_stream_decoder_set_trigger_data_observer(&decoder, fuzz_observer, &observer);
    }

    (void) tron_stream_decoder_is_done(&decoder);
    (void) tron_stream_decoder_get_result(&decoder, &result);

    if (payload_len == 0U) {
        (void) tron_stream_decoder_feed(&decoder, &scratch, 0U);
    }

    while (offset < payload_len) {
        const size_t remaining = payload_len - offset;
        const size_t chunk_len = select_chunk_len(remaining, chunk_seed, iter);

        if (interleave_zero_length_feeds) {
            (void) tron_stream_decoder_feed(&decoder, &scratch, 0U);
        }

        if (!tron_stream_decoder_feed(&decoder, &payload[offset], chunk_len)) {
            break;
        }

        offset += chunk_len;
        iter++;

        (void) tron_stream_decoder_is_done(&decoder);
        (void) tron_stream_decoder_get_result(&decoder, &result);
    }

    if (tron_stream_decoder_is_done(&decoder) &&
        tron_stream_decoder_get_result(&decoder, &result)) {
        validate_result(&result);
    }

    if (attach_observer && observer.observed_bytes > payload_len) {
        __builtin_trap();
    }

    if (payload_len > 0U) {
        (void) tron_stream_decoder_feed(&decoder, payload, 0U);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const uint8_t *payload = data;
    size_t payload_len = size;
    uint8_t config[8] = {0};
    size_t i;

    for (i = 0; i < sizeof(config) && i < size; i++) {
        config[i] = data[i];
    }

    if (size > sizeof(config)) {
        payload = data + sizeof(config);
        payload_len = size - sizeof(config);
    }

    run_decoder_scenario(payload,
                         payload_len,
                         false,
                         select_declared_len(payload_len, config[0], config[1]),
                         (config[2] & 0x01U) != 0U,
                         false,
                         config[3],
                         (config[4] & 0x01U) != 0U);

    run_decoder_scenario(payload,
                         payload_len,
                         true,
                         select_declared_len(payload_len, config[1], config[2]),
                         true,
                         (config[3] & 0x01U) != 0U,
                         config[4],
                         (config[5] & 0x01U) != 0U);

    run_decoder_scenario(payload,
                         payload_len,
                         false,
                         payload_len,
                         true,
                         (config[6] & 0x01U) != 0U,
                         1U,
                         false);

    run_decoder_scenario(payload,
                         payload_len,
                         true,
                         payload_len,
                         false,
                         false,
                         0U,
                         true);

    return 0;
}
