#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "transaction_trigger_decode.h"

typedef enum {
    CHUNKS_WHOLE,
    CHUNKS_BYTES,
    CHUNKS_PSEUDORANDOM,
} chunk_mode_t;

typedef struct {
    bool fail_enabled;
    size_t fail_at_offset;
    bool total_seen;
    size_t total_len;
    size_t next_offset;
    size_t call_count;
    size_t observed_bytes;
    uint64_t hash;
} observer_ctx_t;

typedef struct {
    bool done;
    bool has_result;
    tron_decode_result_t result;
    size_t observer_calls;
    size_t observer_bytes;
    uint64_t observer_hash;
} decode_snapshot_t;

static void fuzz_assert(bool condition) {
    if (!condition) {
        __builtin_trap();
    }
}

static bool fuzz_observer(void *ctx,
                          const uint8_t *chunk,
                          size_t chunk_len,
                          size_t chunk_offset,
                          size_t total_len) {
    observer_ctx_t *observer = (observer_ctx_t *) ctx;

    if (observer == NULL || (chunk == NULL && chunk_len != 0U)) {
        return false;
    }
    fuzz_assert(chunk_offset == observer->next_offset);
    fuzz_assert(chunk_offset <= total_len);
    fuzz_assert(chunk_len <= total_len - chunk_offset);
    if (observer->total_seen) {
        fuzz_assert(observer->total_len == total_len);
    } else {
        observer->total_seen = true;
        observer->total_len = total_len;
    }

    observer->call_count++;
    if (observer->fail_enabled && chunk_offset == observer->fail_at_offset) {
        return false;
    }

    for (size_t i = 0; i < chunk_len; i++) {
        observer->hash ^= chunk[i];
        observer->hash *= UINT64_C(1099511628211);
    }
    observer->next_offset += chunk_len;
    observer->observed_bytes += chunk_len;
    return true;
}

static void validate_result(const tron_decode_result_t *result) {
    fuzz_assert(result != NULL);
    fuzz_assert(!result->has_owner_address ||
                result->owner_address_len <= sizeof(result->owner_address));
    fuzz_assert(!result->has_contract_address ||
                result->contract_address_len <= sizeof(result->contract_address));
    fuzz_assert(!result->has_data ||
                result->data_prefix_len <= sizeof(result->data_prefix));
    fuzz_assert(!result->has_data || result->data_prefix_len <= result->data_len);
    fuzz_assert(!result->has_custom_data ||
                result->custom_data_prefix_len <= sizeof(result->custom_data_prefix));
    fuzz_assert(!result->has_custom_data ||
                result->custom_data_prefix_len <= result->custom_data_len);
}

static size_t pseudorandom_chunk_len(size_t remaining, uint64_t *state) {
    *state ^= *state << 13U;
    *state ^= *state >> 7U;
    *state ^= *state << 17U;
    size_t len = (size_t) (*state % 31U) + 1U;
    return (len < remaining) ? len : remaining;
}

static uint64_t payload_seed(const uint8_t *data, size_t len) {
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash == 0U ? UINT64_C(0x9e3779b97f4a7c15) : hash;
}

static decode_snapshot_t run_decoder(tron_stream_decoder_t *decoder,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     bool raw_mode,
                                     size_t declared_len,
                                     chunk_mode_t chunk_mode,
                                     bool reuse_decoder) {
    decode_snapshot_t snapshot = {0};
    observer_ctx_t observer = {.hash = UINT64_C(1469598103934665603)};
    uint64_t chunk_state = payload_seed(payload, payload_len);
    uint8_t scratch = 0U;
    size_t offset = 0U;

    if (raw_mode) {
        tron_stream_decoder_init_raw(decoder, declared_len);
    } else {
        tron_stream_decoder_init(decoder, declared_len);
    }
    tron_stream_decoder_set_trigger_data_observer(decoder, fuzz_observer, &observer);

    if (!tron_stream_decoder_is_done(decoder)) {
        fuzz_assert(tron_stream_decoder_feed(decoder, &scratch, 0U));
    }

    while (offset < payload_len) {
        const size_t remaining = payload_len - offset;
        size_t chunk_len = remaining;
        if (chunk_mode == CHUNKS_BYTES) {
            chunk_len = 1U;
        } else if (chunk_mode == CHUNKS_PSEUDORANDOM) {
            chunk_len = pseudorandom_chunk_len(remaining, &chunk_state);
        }
        if (!tron_stream_decoder_feed(decoder, payload + offset, chunk_len)) {
            break;
        }
        offset += chunk_len;
    }

    snapshot.done = tron_stream_decoder_is_done(decoder);
    snapshot.has_result = tron_stream_decoder_get_result(decoder, &snapshot.result);
    /* Wire parsing may complete for a semantically incomplete Trigger contract;
     * get_result() intentionally applies the stricter policy validation. */
    fuzz_assert(!snapshot.has_result || snapshot.done);
    if (snapshot.has_result) {
        tron_decode_result_t before_extra = snapshot.result;
        validate_result(&snapshot.result);

        /* Completion is terminal: even one non-empty trailing byte is rejected
         * without changing the already available result. */
        fuzz_assert(!tron_stream_decoder_feed(decoder, &scratch, 1U));
        fuzz_assert(tron_stream_decoder_is_done(decoder));
        fuzz_assert(tron_stream_decoder_get_result(decoder, &snapshot.result));
        fuzz_assert(memcmp(&before_extra, &snapshot.result, sizeof(snapshot.result)) == 0);
    }

    fuzz_assert(observer.next_offset == observer.observed_bytes);
    if (observer.total_seen) {
        fuzz_assert(observer.observed_bytes <= observer.total_len);
    }
    snapshot.observer_calls = observer.call_count;
    snapshot.observer_bytes = observer.observed_bytes;
    snapshot.observer_hash = observer.hash;

    if (reuse_decoder) {
        /* Reinitializing the same object is the decoder's reset/reuse API. */
        const decode_snapshot_t replay = run_decoder(decoder,
                                                     payload,
                                                     payload_len,
                                                     raw_mode,
                                                     declared_len,
                                                     CHUNKS_BYTES,
                                                     false);
        fuzz_assert(snapshot.done == replay.done);
        fuzz_assert(snapshot.has_result == replay.has_result);
        fuzz_assert(snapshot.observer_bytes == replay.observer_bytes);
        fuzz_assert(snapshot.observer_hash == replay.observer_hash);
        if (snapshot.has_result) {
            fuzz_assert(memcmp(&snapshot.result, &replay.result, sizeof(snapshot.result)) == 0);
        }
    }
    return snapshot;
}

static void assert_equivalent(const decode_snapshot_t *left, const decode_snapshot_t *right) {
    fuzz_assert(left->done == right->done);
    fuzz_assert(left->has_result == right->has_result);
    fuzz_assert(left->observer_bytes == right->observer_bytes);
    fuzz_assert(left->observer_hash == right->observer_hash);
    if (left->has_result) {
        fuzz_assert(memcmp(&left->result, &right->result, sizeof(left->result)) == 0);
    }
}

static size_t encode_varint(uint8_t out[10], size_t value) {
    size_t len = 0U;
    do {
        uint8_t byte = (uint8_t) (value & 0x7FU);
        value >>= 7U;
        if (value != 0U) {
            byte |= 0x80U;
        }
        out[len++] = byte;
    } while (value != 0U);
    return len;
}

static uint8_t *wrap_raw_transaction(const uint8_t *raw,
                                     size_t raw_len,
                                     size_t *wrapped_len) {
    uint8_t length_varint[10];
    uint8_t key_varint[10];
    const size_t length_len = encode_varint(length_varint, raw_len);
    const size_t key_len = encode_varint(
        key_varint, ((size_t) protocol_Transaction_raw_data_tag << 3U) | PB_WT_STRING);

    if (raw_len > SIZE_MAX - key_len - length_len) {
        return NULL;
    }
    *wrapped_len = key_len + length_len + raw_len;
    uint8_t *wrapped = (uint8_t *) malloc(*wrapped_len == 0U ? 1U : *wrapped_len);
    if (wrapped == NULL) {
        return NULL;
    }
    memcpy(wrapped, key_varint, key_len);
    memcpy(wrapped + key_len, length_varint, length_len);
    if (raw_len != 0U) {
        memcpy(wrapped + key_len + length_len, raw, raw_len);
    }
    return wrapped;
}

static void run_observer_failure(const uint8_t *payload, size_t payload_len) {
    tron_stream_decoder_t decoder;
    observer_ctx_t observer = {
        .fail_enabled = true,
        .fail_at_offset = payload_len == 0U ? 0U : payload_seed(payload, payload_len) % payload_len,
        .hash = UINT64_C(1469598103934665603),
    };

    tron_stream_decoder_init_raw(&decoder, payload_len);
    tron_stream_decoder_set_trigger_data_observer(&decoder, fuzz_observer, &observer);
    if (payload_len != 0U) {
        (void) tron_stream_decoder_feed(&decoder, payload, payload_len);
    }
    fuzz_assert(observer.next_offset == observer.observed_bytes);
    if (observer.total_seen) {
        fuzz_assert(observer.observed_bytes <= observer.total_len);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tron_stream_decoder_t decoder;
    size_t wrapped_len = 0U;
    uint8_t *wrapped = wrap_raw_transaction(data, size, &wrapped_len);
    if (wrapped == NULL) {
        return 0;
    }

    /* Core differential oracle: the same protobuf is decoded whole, one byte
     * at a time, and in deterministic pseudo-random chunks. */
    const decode_snapshot_t raw_whole =
        run_decoder(&decoder, data, size, true, size, CHUNKS_WHOLE, true);
    const decode_snapshot_t raw_bytes =
        run_decoder(&decoder, data, size, true, size, CHUNKS_BYTES, false);
    const decode_snapshot_t raw_random =
        run_decoder(&decoder, data, size, true, size, CHUNKS_PSEUDORANDOM, false);
    assert_equivalent(&raw_whole, &raw_bytes);
    assert_equivalent(&raw_whole, &raw_random);

    /* A raw_data payload and an equivalent Transaction wrapper must expose
     * exactly the same decoded fields and trigger-data observer stream. */
    const decode_snapshot_t wrapped_random = run_decoder(&decoder,
                                                         wrapped,
                                                         wrapped_len,
                                                         false,
                                                         wrapped_len,
                                                         CHUNKS_PSEUDORANDOM,
                                                         false);
    assert_equivalent(&raw_whole, &wrapped_random);

    /* Keep malformed declared-length coverage separate from the differential
     * oracle: these calls intentionally exercise truncation and overrun paths. */
    if (size != 0U) {
        (void) run_decoder(&decoder, data, size, true, size - 1U, CHUNKS_PSEUDORANDOM, false);
    }
    if (size < SIZE_MAX) {
        (void) run_decoder(&decoder, data, size, true, size + 1U, CHUNKS_BYTES, false);
    }
    run_observer_failure(data, size);

    free(wrapped);
    return 0;
}
