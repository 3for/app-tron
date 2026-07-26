#include <string.h>
#include "os_math.h"  // MIN
#include "calldata.h"
#include "os_print.h"
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "lists.h"
#include "shared_context.h"
#include "gcs_limits.h"

static size_t g_calldata_allocated_bytes;

static bool gcs_calldata_limits_apply(void) {
    return (appState == APP_STATE_SIGNING_GCS_STORE) ||
           (appState == APP_STATE_SIGNING_TX) ||
           (appState == APP_STATE_GCS_FIELDS_AUTHENTICATED);
}

static bool reserve_calldata_bytes(size_t amount) {
    size_t total;

    if (__builtin_add_overflow(g_calldata_allocated_bytes, amount, &total)) {
        return false;
    }
    if (gcs_calldata_limits_apply() && (total > GCS_MAX_SESSION_CALLDATA_BYTES)) {
        return false;
    }
    g_calldata_allocated_bytes = total;
    return true;
}

s_calldata *calldata_init(size_t size, const uint8_t selector[CALLDATA_SELECTOR_SIZE]) {
    s_calldata *calldata;

    if ((selector == NULL) ||
        (gcs_calldata_limits_apply() && (size > GCS_MAX_CALLDATA_SIZE)) ||
        !reserve_calldata_bytes(sizeof(*calldata))) {
        return NULL;
    }
    if (APP_MEM_CALLOC((void **) &calldata, sizeof(*calldata)) == false) {
        g_calldata_allocated_bytes -= sizeof(*calldata);
        return NULL;
    }
    calldata->allocated_size = sizeof(*calldata);
    calldata->expected_size = size;
    calldata_set_selector(calldata, selector);
    return calldata;
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
    if (__builtin_add_overflow(sizeof(*chunk), chunk_size, &allocation_size) ||
        !reserve_calldata_bytes(allocation_size)) {
        return false;
    }
    if (APP_MEM_CALLOC((void **) &chunk, sizeof(*chunk)) == false) {
        g_calldata_allocated_bytes -= allocation_size;
        return false;
    }
    chunk->dir = direction;
    chunk->size = chunk_size;
    if (chunk->size > 0) {
        if ((chunk->buf = APP_MEM_ALLOC(chunk->size)) == NULL) {
            APP_MEM_FREE(chunk);
            g_calldata_allocated_bytes -= allocation_size;
            return false;
        }
        memcpy(chunk->buf, calldata->chunk + start_idx, chunk->size);
    }
    flist_push_back((flist_node_t **) &calldata->chunks, (flist_node_t *) chunk);
    calldata->allocated_size += allocation_size;
    return true;
}

static bool decompress_chunk(const s_calldata_chunk *chunk, uint8_t *out) {
    size_t diff;

    if ((chunk == NULL) || (out == NULL)) {
        // Should never happen, but just in case
        return false;
    }
    if ((chunk->buf == NULL) || (chunk->size == 0)) {
        // nothing to decompress
        explicit_bzero(out, CALLDATA_CHUNK_SIZE);
        return true;
    }
    diff = CALLDATA_CHUNK_SIZE - chunk->size;
    if (chunk->dir == CHUNK_STRIP_LEFT) {
        explicit_bzero(out, diff);
        memcpy(&out[diff], chunk->buf, chunk->size);
    } else {
        memcpy(out, chunk->buf, chunk->size);
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
        size_t compressed_size = sizeof(*calldata);
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
    APP_MEM_FREE(node->buf);
    APP_MEM_FREE(node);
}

void calldata_delete(s_calldata *node) {
    if (node == NULL) {
        return;
    }
    if (node->allocated_size <= g_calldata_allocated_bytes) {
        g_calldata_allocated_bytes -= node->allocated_size;
    } else {
        g_calldata_allocated_bytes = 0U;
    }
    flist_clear((flist_node_t **) &node->chunks, (f_list_node_del) &delete_calldata_chunk);
    APP_MEM_FREE(node);
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
