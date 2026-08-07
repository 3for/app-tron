#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "lists.h"

#define CALLDATA_SELECTOR_SIZE 4
#define CALLDATA_CHUNK_SIZE    32

_Static_assert(CALLDATA_CHUNK_SIZE <= UINT8_MAX,
               "calldata chunk size must fit its byte counter");

typedef enum {
    CHUNK_STRIP_LEFT = 0,
    CHUNK_STRIP_RIGHT = 1,
} e_chunk_strip_dir;

typedef struct {
    flist_node_t _list;
    e_chunk_strip_dir dir : 1;
    uint8_t size : 7;
    uint8_t data[];
} s_calldata_chunk;

typedef struct {
    size_t expected_size;
    size_t received_size;
    uint8_t selector[CALLDATA_SELECTOR_SIZE];
    s_calldata_chunk *chunks;

    uint8_t chunk[CALLDATA_CHUNK_SIZE];
    uint8_t chunk_size;
    bool tracks_coverage;

    /* Two one-bit maps per post-selector byte: the complete covered-byte union,
     * followed by canonical-zero provenance. Keeping both maps in this
     * allocation prevents nested contexts from sharing coverage ownership. */
    uint8_t coverage[];
} s_calldata;

s_calldata *calldata_init(size_t size, const uint8_t selector[CALLDATA_SELECTOR_SIZE]);
s_calldata *calldata_init_root(size_t size,
                               const uint8_t selector[CALLDATA_SELECTOR_SIZE]);
s_calldata *calldata_init_nested(size_t size,
                                 const uint8_t selector[CALLDATA_SELECTOR_SIZE]);
s_calldata *calldata_init_nested_gcs(
    size_t size,
    const uint8_t selector[CALLDATA_SELECTOR_SIZE]);
bool calldata_set_selector(s_calldata *calldata, const uint8_t selector[CALLDATA_SELECTOR_SIZE]);
bool calldata_append(s_calldata *calldata, const uint8_t *buffer, size_t size);
void calldata_delete(s_calldata *node);
const uint8_t *calldata_get_selector(const s_calldata *calldata);
const uint8_t *calldata_get_chunk(s_calldata *calldata, size_t idx);
bool calldata_claim_bytes(s_calldata *calldata,
                          size_t first_byte,
                          size_t byte_count);
bool calldata_cover_canonical_zero(s_calldata *calldata,
                                   size_t first_byte,
                                   size_t byte_count);
bool calldata_tracks_coverage(const s_calldata *calldata);
bool calldata_is_fully_covered(const s_calldata *calldata);
void calldata_dump(const s_calldata *calldata);
