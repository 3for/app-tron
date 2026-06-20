#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "buffer.h"

typedef uint32_t TLV_tag_t;
typedef uint64_t TLV_flag_t;
typedef TLV_flag_t(tag_to_flag_function_t)(TLV_tag_t tag);

typedef struct {
    TLV_flag_t flags;
    tag_to_flag_function_t *tag_to_flag_function;
} TLV_reception_t;

typedef struct {
    TLV_tag_t tag;
    buffer_t value;
    buffer_t raw;
} tlv_data_t;

// TLV value accessors. In the firmware these live in the SDK TLV library; the
// standalone fuzz build implements them over the value buffer. Integers are
// big-endian with a variable length up to the type width (matching the SDK).
static inline bool fuzz_tlv_get_uint(const tlv_data_t *data, uint64_t *out, size_t maxbytes) {
    if ((data == NULL) || (out == NULL) || (data->value.ptr == NULL)) {
        return false;
    }
    if ((data->value.size == 0U) || (data->value.size > maxbytes)) {
        return false;
    }
    uint64_t value = 0U;
    for (size_t i = 0U; i < data->value.size; i++) {
        value = (value << 8U) | data->value.ptr[i];
    }
    *out = value;
    return true;
}

static inline bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *out) {
    uint64_t v;
    if (!fuzz_tlv_get_uint(data, &v, sizeof(uint8_t))) return false;
    *out = (uint8_t) v;
    return true;
}

static inline bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *out) {
    uint64_t v;
    if (!fuzz_tlv_get_uint(data, &v, sizeof(uint16_t))) return false;
    *out = (uint16_t) v;
    return true;
}

static inline bool get_uint32_t_from_tlv_data(const tlv_data_t *data, uint32_t *out) {
    uint64_t v;
    if (!fuzz_tlv_get_uint(data, &v, sizeof(uint32_t))) return false;
    *out = (uint32_t) v;
    return true;
}

static inline bool get_uint64_t_from_tlv_data(const tlv_data_t *data, uint64_t *out) {
    return fuzz_tlv_get_uint(data, out, sizeof(uint64_t));
}

// Returns a view (ptr+size) onto the TLV value, after bounds-checking its length.
static inline bool get_buffer_from_tlv_data(const tlv_data_t *data,
                                            buffer_t *out,
                                            uint16_t min_size,
                                            uint16_t max_size) {
    if ((data == NULL) || (out == NULL) || (data->value.ptr == NULL)) {
        return false;
    }
    if ((data->value.size < min_size) || (data->value.size > max_size)) {
        return false;
    }
    out->ptr = data->value.ptr;
    out->size = data->value.size;
    out->offset = 0U;
    return true;
}

// Copies the TLV value as a NUL-terminated string. max_size is the output
// capacity including the terminator (matching the SDK contract).
static inline bool get_string_from_tlv_data(const tlv_data_t *data,
                                            char *out,
                                            uint16_t min_size,
                                            uint16_t max_size) {
    if ((data == NULL) || (out == NULL) || (data->value.ptr == NULL) || (max_size == 0U)) {
        return false;
    }
    if ((data->value.size < min_size) || (data->value.size >= max_size)) {
        return false;
    }
    memcpy(out, data->value.ptr, data->value.size);
    out[data->value.size] = '\0';
    return true;
}

typedef bool(tlv_handler_cb_t)(const tlv_data_t *data, void *tlv_extracted);

typedef enum {
    ENFORCE_UNIQUE_TAG,
    ALLOW_MULTIPLE_TAG,
} tag_unicity_t;

typedef struct {
    TLV_tag_t tag;
    tlv_handler_cb_t *func;
    bool is_unique;
} _internal_tlv_handler_t;

#define __X_DEFINE_TLV__TAG_ASSIGN(value, name, callback, unicity) name = value,
#define __X_DEFINE_TLV__TAG_INDEX(value, name, callback, unicity) name##_INDEX,
#define __X_DEFINE_TLV__TAG_FLAG(value, name, callback, unicity) \
    name##_FLAG = ((TLV_flag_t) 1 << name##_INDEX),
#define __X_DEFINE_TLV__TAG_TO_FLAG_CASE(value, name, callback, unicity) \
    case name:                                                           \
        return name##_FLAG;
#define __X_DEFINE_TLV__TAG_CALLBACKS(value, name, callback, unicity) \
    {.tag = name, .func = (tlv_handler_cb_t *) callback, .is_unique = (unicity == ENFORCE_UNIQUE_TAG)},

static inline bool tlv_get_der_uint32(const buffer_t *payload, size_t *offset, uint32_t *value) {
    uint8_t first;
    uint8_t byte_count;

    if ((payload == NULL) || (offset == NULL) || (value == NULL) || (*offset >= payload->size)) {
        return false;
    }

    first = payload->ptr[*offset];
    *offset += 1U;
    if ((first & 0x80U) == 0U) {
        *value = first;
        return true;
    }

    byte_count = first & 0x7fU;
    if ((byte_count == 0U) || (byte_count > sizeof(*value)) ||
        ((*offset + byte_count) > payload->size)) {
        return false;
    }

    *value = 0U;
    for (uint8_t i = 0U; i < byte_count; i++) {
        *value = (*value << 8) | payload->ptr[*offset + i];
    }
    *offset += byte_count;
    return true;
}

static inline const _internal_tlv_handler_t *tlv_find_handler(
    const _internal_tlv_handler_t *handlers,
    uint8_t handlers_count,
    TLV_tag_t tag) {
    for (uint8_t i = 0U; i < handlers_count; i++) {
        if (handlers[i].tag == tag) {
            return &handlers[i];
        }
    }
    return NULL;
}

static inline bool _parse_tlv_internal(const _internal_tlv_handler_t *handlers,
                                       uint8_t handlers_count,
                                       tlv_handler_cb_t *common_handler,
                                       tag_to_flag_function_t *tag_to_flag,
                                       const buffer_t *payload,
                                       void *tlv_out,
                                       TLV_reception_t *received_tags) {
    size_t offset;

    if ((handlers == NULL) || (payload == NULL) || (payload->ptr == NULL) ||
        (received_tags == NULL) || (payload->offset > payload->size)) {
        return false;
    }

    received_tags->flags = 0U;
    received_tags->tag_to_flag_function = tag_to_flag;
    offset = payload->offset;

    while (offset < payload->size) {
        uint32_t tag;
        uint32_t length;
        size_t raw_start = offset;
        const _internal_tlv_handler_t *handler;
        tlv_data_t data;

        if (!tlv_get_der_uint32(payload, &offset, &tag) ||
            !tlv_get_der_uint32(payload, &offset, &length) ||
            (length > UINT16_MAX) || ((offset + length) > payload->size)) {
            return false;
        }

        data.tag = tag;
        data.value = (buffer_t){.ptr = &payload->ptr[offset], .size = length, .offset = 0U};
        data.raw =
            (buffer_t){.ptr = &payload->ptr[raw_start], .size = offset + length - raw_start, .offset = 0U};
        offset += length;

        handler = tlv_find_handler(handlers, handlers_count, tag);
        if (handler == NULL) {
            return false;
        }
        if (handler->is_unique) {
            TLV_flag_t flag = tag_to_flag(tag);

            if ((flag == 0U) || ((received_tags->flags & flag) != 0U)) {
                return false;
            }
            received_tags->flags |= flag;
        }
        if ((handler->func != NULL) && !handler->func(&data, tlv_out)) {
            return false;
        }
        if ((common_handler != NULL) && !common_handler(&data, tlv_out)) {
            return false;
        }
    }
    return true;
}

#define DEFINE_TLV_PARSER(TAG_LIST, COMMON_HANDLER, PARSE_FUNCTION_NAME)                 \
    enum { TAG_LIST(__X_DEFINE_TLV__TAG_ASSIGN) };                                      \
    enum { TAG_LIST(__X_DEFINE_TLV__TAG_INDEX) PARSE_FUNCTION_NAME##_TAG_COUNT };       \
    enum { TAG_LIST(__X_DEFINE_TLV__TAG_FLAG) };                                        \
    static inline TLV_flag_t PARSE_FUNCTION_NAME##_tag_to_flag(TLV_tag_t tag) {          \
        switch (tag) {                                                                  \
            TAG_LIST(__X_DEFINE_TLV__TAG_TO_FLAG_CASE)                                  \
            default:                                                                    \
                return 0;                                                               \
        }                                                                               \
    }                                                                                   \
    static inline bool PARSE_FUNCTION_NAME(const buffer_t *payload,                     \
                                           void *tlv_out,                               \
                                           TLV_reception_t *received_tags_flags) {      \
        _internal_tlv_handler_t handlers[PARSE_FUNCTION_NAME##_TAG_COUNT] = {           \
            TAG_LIST(__X_DEFINE_TLV__TAG_CALLBACKS)                                     \
        };                                                                              \
        return _parse_tlv_internal(handlers,                                            \
                                   PARSE_FUNCTION_NAME##_TAG_COUNT,                     \
                                   (tlv_handler_cb_t *) COMMON_HANDLER,                 \
                                   PARSE_FUNCTION_NAME##_tag_to_flag,                   \
                                   payload,                                             \
                                   tlv_out,                                             \
                                   received_tags_flags);                                \
    }

static inline bool tlv_check_received_tags(TLV_reception_t received,
                                           const TLV_tag_t *tags,
                                           size_t tag_count) {
    if (received.tag_to_flag_function == NULL) {
        return false;
    }
    for (size_t i = 0U; i < tag_count; i++) {
        TLV_flag_t flag = received.tag_to_flag_function(tags[i]);

        if ((flag == 0U) || ((received.flags & flag) != flag)) {
            return false;
        }
    }
    return true;
}

#define TLV_CHECK_RECEIVED_TAGS(received, ...)                                      \
    tlv_check_received_tags(received,                                               \
                            (const TLV_tag_t[]){__VA_ARGS__},                      \
                            sizeof((const TLV_tag_t[]){__VA_ARGS__}) / sizeof(TLV_tag_t))
