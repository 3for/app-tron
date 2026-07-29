#include <string.h>  // memcpy / explicit_bzero
#include "os_print.h"
#include "os_math.h"  // MIN
#include "gtp_data_path.h"
#include "read.h"
#include "utils.h"
#include "calldata.h"
#include "app_mem_utils.h"
#include "tx_ctx.h"
#include "tlv_library.h"
#include "tlv_apdu.h"
#include "gcs_limits.h"
#include "gcs_memory.h"

#define DATA_PATH_TAGS(X)                                    \
    X(0x00, TAG_VERSION, handle_version, ENFORCE_UNIQUE_TAG) \
    X(0x01, TAG_TUPLE, handle_tuple, ALLOW_MULTIPLE_TAG)     \
    X(0x02, TAG_ARRAY, handle_array, ALLOW_MULTIPLE_TAG)     \
    X(0x03, TAG_REF, handle_ref, ALLOW_MULTIPLE_TAG)         \
    X(0x04, TAG_LEAF, handle_leaf, ALLOW_MULTIPLE_TAG)       \
    X(0x05, TAG_SLICE, handle_slice, ALLOW_MULTIPLE_TAG)

static bool handle_version(const tlv_data_t *data, s_data_path_context *context) {
    return tlv_get_uint8_range(data, &context->data_path->version, 0, UINT8_MAX);
}

static bool data_path_has_room(const s_data_path_context *context) {
    return (context != NULL) && (context->data_path != NULL) &&
           (context->data_path->size < PATH_MAX_SIZE);
}

static bool handle_tuple(const tlv_data_t *data, s_data_path_context *context) {
    if (!data_path_has_room(context)) return false;
    if (!tlv_get_uint16_range(data,
                              &context->data_path->elements[context->data_path->size].tuple.value,
                              0,
                              UINT16_MAX)) {
        return false;
    }
    context->data_path->elements[context->data_path->size].type = ELEMENT_TYPE_TUPLE;
    context->data_path->size += 1;
    return true;
}

static bool handle_array(const tlv_data_t *data, s_data_path_context *context) {
    s_path_array_context ctx = {0};

    if (!data_path_has_room(context)) return false;
    ctx.args = &context->data_path->elements[context->data_path->size].array;
    explicit_bzero(ctx.args, sizeof(*ctx.args));
    if (!handle_array_struct(&data->value, &ctx)) {
        return false;
    }
    context->data_path->elements[context->data_path->size].type = ELEMENT_TYPE_ARRAY;
    context->data_path->size += 1;
    return true;
}

static bool handle_ref(const tlv_data_t *data, s_data_path_context *context) {
    if (!data_path_has_room(context) || (data->value.size != 0)) {
        return false;
    }
    context->data_path->elements[context->data_path->size].type = ELEMENT_TYPE_REF;
    context->data_path->size += 1;
    return true;
}

static bool handle_leaf(const tlv_data_t *data, s_data_path_context *context) {
    uint8_t leaf_type;

    if (!data_path_has_room(context) ||
        !tlv_get_uint8_range(data, &leaf_type, LEAF_TYPE_STATIC, LEAF_TYPE_DYNAMIC)) {
        return false;
    }
    context->data_path->elements[context->data_path->size].leaf.type =
        (e_path_leaf_type) leaf_type;
    context->data_path->elements[context->data_path->size].type = ELEMENT_TYPE_LEAF;
    context->data_path->size += 1;
    return true;
}

static bool handle_slice(const tlv_data_t *data, s_data_path_context *context) {
    s_path_slice_context ctx = {0};

    if (!data_path_has_room(context)) return false;
    ctx.args = &context->data_path->elements[context->data_path->size].slice;
    explicit_bzero(ctx.args, sizeof(*ctx.args));
    if (!handle_slice_struct(&data->value, &ctx)) {
        return false;
    }
    context->data_path->elements[context->data_path->size].type = ELEMENT_TYPE_SLICE;
    context->data_path->size += 1;
    return true;
}

static bool data_path_common_handler(const tlv_data_t *data, s_data_path_context *context);

DEFINE_TLV_PARSER(DATA_PATH_TAGS, &data_path_common_handler, data_path_tlv_parser)

// Common handler to check path size limits
static bool data_path_common_handler(const tlv_data_t *data, s_data_path_context *context) {
    // Check size limit for non-VERSION tags
    if (data->tag != TAG_VERSION) {
        if (context->data_path->size >= PATH_MAX_SIZE) {
            PRINTF("Error: PATH_MAX_SIZE exceeded\n");
            return false;
        }
    }
    return true;
}

bool handle_data_path_struct(const buffer_t *buf, s_data_path_context *context) {
    TLV_reception_t received_tags = {0};
    return (context != NULL) && (context->data_path != NULL) &&
           data_path_tlv_parser(buf, context, &received_tags) &&
           TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_VERSION) &&
           (context->data_path->version == 1U) && (context->data_path->size != 0U);
}

static bool path_tuple(const s_tuple_args *tuple, uint32_t *offset, uint32_t *ref_offset) {
    *ref_offset = *offset;
    return !__builtin_add_overflow(*offset, tuple->value, offset);
}

static bool abi_word_to_u16(const uint8_t *word, uint16_t *value) {
    if ((word == NULL) || (value == NULL)) {
        return false;
    }
    /* ABI offsets and lengths are uint256 values. This implementation supports
     * the low 16-bit range, so reject rather than silently truncate any high
     * byte that would change the decoded value. */
    for (size_t i = 0U; i < (CALLDATA_CHUNK_SIZE - sizeof(*value)); ++i) {
        if (word[i] != 0U) {
            return false;
        }
    }
    *value = read_u16_be(word, CALLDATA_CHUNK_SIZE - sizeof(*value));
    return true;
}

static bool path_ref(uint32_t *offset, uint32_t *ref_offset) {
    uint16_t raw_offset;
    const uint8_t *chunk;

    if ((chunk = calldata_get_chunk(get_current_calldata(), (size_t) *offset)) == NULL) {
        return false;
    }
    if (!abi_word_to_u16(chunk, &raw_offset)) {
        return false;
    }
    if ((raw_offset % CALLDATA_CHUNK_SIZE) != 0) {
        // reject unaligned offsets
        return false;
    }
    *offset = raw_offset / CALLDATA_CHUNK_SIZE;
    return !__builtin_add_overflow(*offset, *ref_offset, offset);
}

static bool path_leaf(const s_leaf_args *leaf,
                      uint32_t *offset,
                      s_parsed_value_collection *collection) {
    const uint8_t *chunk;
    uint8_t *leaf_buf = NULL;
    uint8_t cpy_length;
    size_t total_allocated = 0U;
    size_t next_total;

    if (collection->size >= MAX_VALUE_COLLECTION_SIZE) {
        return false;
    }

    switch (leaf->type) {
        case LEAF_TYPE_STATIC:
            collection->value[collection->size].size = CALLDATA_CHUNK_SIZE;
            break;

        case LEAF_TYPE_DYNAMIC:
            if ((chunk = calldata_get_chunk(get_current_calldata(), (size_t) *offset)) == NULL) {
                return false;
            }
            if (!abi_word_to_u16(chunk, &collection->value[collection->size].size)) {
                return false;
            }
            if (collection->value[collection->size].size > GCS_MAX_DYNAMIC_VALUE_SIZE) {
                return false;
            }
            if (__builtin_add_overflow(*offset, 1U, offset)) {
                return false;
            }
            break;

        default:
            return false;
    }
    collection->value[collection->size].length = collection->value[collection->size].size;
    collection->value[collection->size].offset = 0;
    for (size_t i = 0U; i < collection->size; i++) {
        if (__builtin_add_overflow(total_allocated,
                                   collection->value[i].size,
                                   &total_allocated)) {
            return false;
        }
    }
    if (__builtin_add_overflow(total_allocated,
                               collection->value[collection->size].size,
                               &next_total) ||
        (next_total > GCS_MAX_DYNAMIC_VALUE_SIZE)) {
        return false;
    }
    if (collection->value[collection->size].length > 0) {
        if ((leaf_buf = gcs_mem_alloc(collection->value[collection->size].length,
                                      GCS_MEM_CALLDATA)) == NULL) {
            return false;
        }
        for (int chunk_idx = 0;
             (chunk_idx * CALLDATA_CHUNK_SIZE) < collection->value[collection->size].length;
             ++chunk_idx) {
            size_t chunk_offset;
            if (__builtin_add_overflow((size_t) *offset, (size_t) chunk_idx, &chunk_offset) ||
                (chunk = calldata_get_chunk(get_current_calldata(), chunk_offset)) == NULL) {
                gcs_mem_free(leaf_buf);
                return false;
            }
            cpy_length =
                MIN(CALLDATA_CHUNK_SIZE,
                    collection->value[collection->size].length - (chunk_idx * CALLDATA_CHUNK_SIZE));
            memcpy(leaf_buf + (chunk_idx * CALLDATA_CHUNK_SIZE), chunk, cpy_length);
        }
    }
    collection->value[collection->size].ptr = leaf_buf;
    collection->size += 1;
    return true;
}

static bool path_slice(const s_slice_args *slice, s_parsed_value_collection *collection) {
    int32_t start;
    int32_t end;
    uint16_t value_length;

    if (collection->size == 0) {
        return false;
    }

    value_length = collection->value[collection->size - 1].length;
    if (slice->has_start) {
        start = (slice->start < 0) ? ((int32_t) value_length + slice->start) : slice->start;
    } else {
        start = 0;
    }

    if (slice->has_end) {
        end = (slice->end < 0) ? ((int32_t) value_length + slice->end) : slice->end;
    } else {
        end = value_length;
    }

    if ((start < 0) || (end < 0) || (start >= end) ||
        (end > (int32_t) value_length)) {
        return false;
    }
    collection->value[collection->size - 1].ptr += (size_t) start;
    collection->value[collection->size - 1].length = (uint16_t) (end - start);
    collection->value[collection->size - 1].offset += (uint16_t) start;
    return true;
}

#define MAX_ARRAYS 8

typedef struct {
    uint8_t depth;
    uint16_t passes_remaining[MAX_ARRAYS];
    uint8_t index;
} s_arrays_info;

static bool path_array(const s_array_args *array,
                       uint32_t *offset,
                       uint32_t *ref_offset,
                       s_arrays_info *arrays_info) {
    uint16_t array_size;
    uint16_t idx;
    int32_t start;
    int32_t end;
    uint16_t passes;
    const uint8_t *chunk;
    uint32_t product;

    if (arrays_info->index >= MAX_ARRAYS) {
        return false;
    }
    if ((chunk = calldata_get_chunk(get_current_calldata(), (size_t) *offset)) == NULL) {
        return false;
    }
    if (!abi_word_to_u16(chunk, &array_size)) {
        return false;
    }

    if (array->has_start) {
        start = (array->start < 0) ? ((int32_t) array_size + array->start) : array->start;
    } else {
        start = 0;
    }

    if (array->has_end) {
        end = (array->end < 0) ? ((int32_t) array_size + array->end) : array->end;
    } else {
        end = array_size;
    }

    if ((start < 0) || (end < 0) || (end <= start) ||
        (end > (int32_t) array_size)) {
        return false;
    }
    passes = (uint16_t) (end - start);
    if ((passes == 0U) || (passes > MAX_VALUE_COLLECTION_SIZE)) {
        return false;
    }

    if (__builtin_add_overflow(*offset, 1U, offset)) {
        return false;
    }
    if (arrays_info->index == arrays_info->depth) {
        // New depth. The total number of traversed combinations is bounded in
        // data_path_get(). Do not multiply this branch's size into a sticky
        // product: an inner array is re-entered for every outer element, and a
        // product that is not restored on unwind rejects valid nested arrays.
        arrays_info->passes_remaining[arrays_info->index] = passes;
        arrays_info->depth += 1;
    }
    idx = (uint16_t) start +
          (passes - arrays_info->passes_remaining[arrays_info->index]);
    *ref_offset = *offset;
    if (__builtin_mul_overflow(idx, array->weight, &product) ||
        __builtin_add_overflow(*offset, product, offset)) {
        return false;  // overflow detected
    }
    arrays_info->index += 1;
    return true;
}

static void arrays_update(s_arrays_info *arrays_info) {
    while (arrays_info->depth > 0) {
        if ((arrays_info->passes_remaining[arrays_info->depth - 1] -= 1) > 0) {
            break;
        }
        arrays_info->depth -= 1;
    }
}

bool data_path_get(const s_data_path *data_path, s_parsed_value_collection *collection) {
    bool ret;
    uint32_t offset;
    uint32_t ref_offset;
    uint8_t combinations_processed = 0U;
    s_arrays_info arinf = {0};

    do {
        arinf.index = 0;
        offset = 0;
        ref_offset = offset;
        for (int i = 0; i < data_path->size; ++i) {
            switch (data_path->elements[i].type) {
                case ELEMENT_TYPE_TUPLE:
                    ret = path_tuple(&data_path->elements[i].tuple, &offset, &ref_offset);
                    break;

                case ELEMENT_TYPE_ARRAY:
                    ret = path_array(&data_path->elements[i].array, &offset, &ref_offset, &arinf);
                    break;

                case ELEMENT_TYPE_REF:
                    ret = path_ref(&offset, &ref_offset);
                    break;

                case ELEMENT_TYPE_LEAF:
                    ret = path_leaf(&data_path->elements[i].leaf, &offset, collection);
                    break;

                case ELEMENT_TYPE_SLICE:
                    ret = path_slice(&data_path->elements[i].slice, collection);
                    break;

                default:
                    ret = false;
            }

            if (!ret) return false;
        }
        combinations_processed += 1U;
        arrays_update(&arinf);
        /* A path without a leaf would not grow collection->size, so keep an
         * independent exact bound on complete path traversals. Exactly 16
         * combinations are supported; reject only if another one is pending. */
        if ((arinf.depth > 0U) &&
            (combinations_processed >= MAX_VALUE_COLLECTION_SIZE)) {
            return false;
        }
    } while (arinf.depth > 0);
    return true;
}

void data_path_cleanup(const s_parsed_value_collection *collection) {
    for (int i = 0; i < collection->size; ++i) {
        if (collection->value[i].ptr != NULL) {
            gcs_mem_free((void *) collection->value[i].ptr - collection->value[i].offset);
        }
    }
}
