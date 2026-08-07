#include <string.h>
#include "os_math.h"  // MIN
#include "calldata.h"
#include "os_print.h"
#include "lists.h"
#include "gcs_limits.h"
#include "gcs_memory.h"

#define COVERAGE_BITS_PER_BYTE 8U
#define COVERAGE_MAP_COUNT     2U

static size_t calldata_coverage_size(size_t calldata_size) {
    return (calldata_size / COVERAGE_BITS_PER_BYTE) +
           ((calldata_size % COVERAGE_BITS_PER_BYTE) != 0U ? 1U : 0U);
}

static s_calldata *calldata_init_with_limit(
    size_t size,
    const uint8_t selector[CALLDATA_SELECTOR_SIZE],
    size_t gcs_size_limit,
    bool track_coverage) {
    s_calldata *calldata;
    size_t allocation_size;
    const size_t coverage_size = track_coverage ? calldata_coverage_size(size) : 0U;
    size_t coverage_allocation_size;

    if ((selector == NULL) || (size > gcs_size_limit) ||
        __builtin_mul_overflow(coverage_size,
                               (size_t) COVERAGE_MAP_COUNT,
                               &coverage_allocation_size) ||
        __builtin_add_overflow(sizeof(*calldata),
                               coverage_allocation_size,
                               &allocation_size)) {
        return NULL;
    }
    calldata = gcs_mem_calloc(allocation_size, GCS_MEM_CALLDATA);
    if (calldata == NULL) {
        return NULL;
    }
    calldata->expected_size = size;
    calldata->tracks_coverage = track_coverage;
    calldata_set_selector(calldata, selector);
    return calldata;
}

s_calldata *calldata_init(size_t size, const uint8_t selector[CALLDATA_SELECTOR_SIZE]) {
    return calldata_init_with_limit(size, selector, SIZE_MAX, false);
}

s_calldata *calldata_init_root(size_t size,
                               const uint8_t selector[CALLDATA_SELECTOR_SIZE]) {
    return calldata_init_with_limit(size,
                                    selector,
                                    GCS_MAX_ROOT_CALLDATA_TOTAL_SIZE -
                                        CALLDATA_SELECTOR_SIZE,
                                    true);
}

s_calldata *calldata_init_nested(size_t size,
                                 const uint8_t selector[CALLDATA_SELECTOR_SIZE]) {
    return calldata_init_with_limit(size,
                                    selector,
                                    GCS_MAX_NESTED_CALLDATA_SIZE,
                                    false);
}

s_calldata *calldata_init_nested_gcs(
    size_t size,
    const uint8_t selector[CALLDATA_SELECTOR_SIZE]) {
    return calldata_init_with_limit(size,
                                    selector,
                                    GCS_MAX_NESTED_CALLDATA_SIZE,
                                    true);
}

bool calldata_set_selector(s_calldata *calldata, const uint8_t selector[CALLDATA_SELECTOR_SIZE]) {
    if ((calldata == NULL) || (selector == NULL)) {
        return false;
    }
    memcpy(calldata->selector, selector, sizeof(calldata->selector));
    return true;
}

static bool compress_chunk(s_calldata *calldata) {
    uint8_t strip_left = 0;
    uint8_t strip_right = 0;
    uint8_t start_idx;
    uint8_t chunk_size;
    e_chunk_strip_dir direction;
    s_calldata_chunk *chunk;

    if (calldata == NULL) {
        return false;
    }

    for (int i = 0; (i < CALLDATA_CHUNK_SIZE) && (calldata->chunk[i] == 0x00); ++i) {
        strip_left += 1;
    }
    for (int i = CALLDATA_CHUNK_SIZE - 1; (i >= 0) && (calldata->chunk[i] == 0x00); --i) {
        strip_right += 1;
    }
    if (strip_left >= strip_right) {
        direction = CHUNK_STRIP_LEFT;
        chunk_size = CALLDATA_CHUNK_SIZE - strip_left;
        start_idx = strip_left;
    } else {
        direction = CHUNK_STRIP_RIGHT;
        chunk_size = CALLDATA_CHUNK_SIZE - strip_right;
        start_idx = 0;
    }
    size_t allocation_size;
    if (__builtin_add_overflow(sizeof(*chunk), chunk_size, &allocation_size)) {
        return false;
    }
    chunk = gcs_mem_calloc(allocation_size, GCS_MEM_CALLDATA);
    if (chunk == NULL) {
        return false;
    }
    chunk->dir = direction;
    chunk->size = chunk_size;
    if (chunk->size > 0) {
        memcpy(chunk->data, calldata->chunk + start_idx, chunk->size);
    }
    flist_push_back((flist_node_t **) &calldata->chunks, (flist_node_t *) chunk);
    return true;
}

static bool decompress_chunk(const s_calldata_chunk *chunk, uint8_t *out) {
    size_t diff;

    if ((chunk == NULL) || (out == NULL)) {
        // Should never happen, but just in case
        return false;
    }
    if (chunk->size == 0) {
        // nothing to decompress
        explicit_bzero(out, CALLDATA_CHUNK_SIZE);
        return true;
    }
    diff = CALLDATA_CHUNK_SIZE - chunk->size;
    if (chunk->dir == CHUNK_STRIP_LEFT) {
        explicit_bzero(out, diff);
        memcpy(&out[diff], chunk->data, chunk->size);
    } else {
        memcpy(out, chunk->data, chunk->size);
        explicit_bzero(&out[chunk->size], diff);
    }
    return true;
}

bool calldata_append(s_calldata *calldata, const uint8_t *buffer, size_t size) {
    uint8_t cpy_length;

    size_t received_after;
    if ((calldata == NULL) || ((size != 0U) && (buffer == NULL))) return false;
    if (__builtin_add_overflow(calldata->received_size, size, &received_after) ||
        (received_after > calldata->expected_size)) {
        return false;
    }

    // chunk handling
    while (size > 0) {
        if (calldata->received_size > calldata->expected_size) {
            return false;
        }
        cpy_length = MIN(size, (sizeof(calldata->chunk) - calldata->chunk_size));
        memcpy(&calldata->chunk[calldata->chunk_size], buffer, cpy_length);
        calldata->chunk_size += cpy_length;
        if (calldata->chunk_size == CALLDATA_CHUNK_SIZE) {
            if (!compress_chunk(calldata)) {
                return false;
            }
            calldata->chunk_size = 0;
        }
        buffer += cpy_length;
        size -= cpy_length;
        calldata->received_size += cpy_length;
    }
#ifdef HAVE_PRINTF
    if (calldata->received_size == calldata->expected_size) {
        // get allocated size
        size_t compressed_size =
            sizeof(*calldata) +
            (calldata->tracks_coverage
                 ? COVERAGE_MAP_COUNT *
                       calldata_coverage_size(calldata->expected_size)
                 : 0U);
        for (s_calldata_chunk *chunk = calldata->chunks; chunk != NULL;
             chunk = (s_calldata_chunk *) ((flist_node_t *) chunk)->next) {
            compressed_size += sizeof(*chunk);
            compressed_size += chunk->size;
        }

        PRINTF("calldata size went from %u to %u bytes with compression\n",
               calldata->received_size,
               compressed_size);
        calldata_dump(calldata);
    }
#endif
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_calldata_chunk(s_calldata_chunk *node) {
    gcs_mem_free(node);
}

void calldata_delete(s_calldata *node) {
    if (node == NULL) {
        return;
    }
    flist_clear((flist_node_t **) &node->chunks, (f_list_node_del) &delete_calldata_chunk);
    gcs_mem_free(node);
}

static bool has_valid_calldata(const s_calldata *calldata) {
    if (calldata == NULL) {
        PRINTF("Error: no calldata!\n");
        return false;
    }
    if (calldata->received_size != calldata->expected_size) {
        PRINTF("Error: incomplete calldata!\n");
        return false;
    }
    return true;
}

const uint8_t *calldata_get_selector(const s_calldata *calldata) {
    if (!has_valid_calldata(calldata)) {
        return NULL;
    }
    return calldata->selector;
}

const uint8_t *calldata_get_chunk(s_calldata *calldata, size_t idx) {
    s_calldata_chunk *chunk;

    if (!has_valid_calldata(calldata) || (calldata->chunks == NULL)) {
        return NULL;
    }
    chunk = calldata->chunks;
    for (size_t i = 0; i < idx; ++i) {
        if (((flist_node_t *) chunk)->next == NULL) return NULL;
        chunk = (s_calldata_chunk *) ((flist_node_t *) chunk)->next;
    }
    if (!decompress_chunk(chunk, calldata->chunk)) return NULL;
    return calldata->chunk;
}

static bool calldata_range_is_valid(const s_calldata *calldata,
                                    size_t first_byte,
                                    size_t byte_count,
                                    size_t *end_byte) {
    return (calldata != NULL) && calldata->tracks_coverage &&
           (end_byte != NULL) &&
           !__builtin_add_overflow(first_byte, byte_count, end_byte) &&
           (first_byte <= calldata->expected_size) &&
           (*end_byte <= calldata->expected_size);
}

static bool bitmap_contains(const uint8_t *bitmap, size_t byte) {
    return (bitmap[byte / COVERAGE_BITS_PER_BYTE] &
            (uint8_t) (1U << (byte % COVERAGE_BITS_PER_BYTE))) != 0U;
}

static void bitmap_insert(uint8_t *bitmap, size_t byte) {
    bitmap[byte / COVERAGE_BITS_PER_BYTE] |=
        (uint8_t) (1U << (byte % COVERAGE_BITS_PER_BYTE));
}

bool calldata_claim_bytes(s_calldata *calldata,
                          size_t first_byte,
                          size_t byte_count) {
    size_t end_byte;

    if (!calldata_range_is_valid(calldata,
                                 first_byte,
                                 byte_count,
                                 &end_byte)) {
        return false;
    }
    /* A descriptor byte has exactly one owner. Check the complete range before
     * mutating it so complementary slices work but overlap and aliasing fail. */
    for (size_t byte = first_byte; byte < end_byte; ++byte) {
        if (bitmap_contains(calldata->coverage, byte)) {
            return false;
        }
    }
    for (size_t byte = first_byte; byte < end_byte; ++byte) {
        bitmap_insert(calldata->coverage, byte);
    }
    return true;
}

bool calldata_cover_canonical_zero(s_calldata *calldata,
                                   size_t first_byte,
                                   size_t byte_count) {
    size_t end_byte;
    uint8_t *canonical_zero;

    if (!calldata_range_is_valid(calldata,
                                 first_byte,
                                 byte_count,
                                 &end_byte)) {
        return false;
    }
    canonical_zero = calldata->coverage +
                     calldata_coverage_size(calldata->expected_size);
    for (size_t byte = first_byte; byte < end_byte; ++byte) {
        if (bitmap_contains(calldata->coverage, byte) &&
            !bitmap_contains(canonical_zero, byte)) {
            return false;
        }
    }
    for (size_t byte = first_byte; byte < end_byte; ++byte) {
        bitmap_insert(calldata->coverage, byte);
        bitmap_insert(canonical_zero, byte);
    }
    return true;
}

bool calldata_tracks_coverage(const s_calldata *calldata) {
    return (calldata != NULL) && calldata->tracks_coverage;
}

bool calldata_is_fully_covered(const s_calldata *calldata) {
    if (!has_valid_calldata(calldata) || !calldata->tracks_coverage) {
        return false;
    }
    for (size_t byte = 0U; byte < calldata->expected_size; ++byte) {
        if (!bitmap_contains(calldata->coverage, byte)) {
            return false;
        }
    }
    return true;
}

void calldata_dump(const s_calldata *calldata) {
#ifdef HAVE_PRINTF
    int i = 0;
    uint8_t buf[CALLDATA_CHUNK_SIZE];

    PRINTF("=== calldata at 0x%p ===\n", calldata);
    PRINTF("selector = 0x%.*h\n", sizeof(calldata->selector), calldata->selector);
    for (s_calldata_chunk *chunk = calldata->chunks; chunk != NULL;
         chunk = (s_calldata_chunk *) ((flist_node_t *) chunk)->next) {
        if (!decompress_chunk(chunk, buf)) break;
        PRINTF("[%02u] %.*h\n", i++, CALLDATA_CHUNK_SIZE, buf);
    }
    PRINTF("========================\n");
#else
    (void) calldata;
#endif
}
