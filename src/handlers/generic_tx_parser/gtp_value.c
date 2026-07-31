#include <string.h>
#include "os_print.h"
#include "gtp_value.h"
#include "gtp_data_path.h"
#include "shared_context.h"  // txContext
#include "apdu_constants.h"  // SWO_SUCCESS
#include "get_public_key.h"
#include "gtp_parsed_value.h"
#include "ui_utils.h"
#include "tx_ctx.h"
#include "tlv_library.h"
#include "tlv_apdu.h"

#define VALUE_TAGS(X)                                                      \
    X(0x00, TAG_VERSION, handle_version, ENFORCE_UNIQUE_TAG)               \
    X(0x01, TAG_TYPE_FAMILY, handle_type_family, ENFORCE_UNIQUE_TAG)       \
    X(0x02, TAG_TYPE_SIZE, handle_type_size, ENFORCE_UNIQUE_TAG)           \
    X(0x03, TAG_DATA_PATH, handle_data_path, ENFORCE_UNIQUE_TAG)           \
    X(0x04, TAG_CONTAINER_PATH, handle_container_path, ENFORCE_UNIQUE_TAG) \
    X(0x05, TAG_CONSTANT, handle_constant, ENFORCE_UNIQUE_TAG)

static bool handle_version(const tlv_data_t *data, s_value_context *context) {
    return tlv_get_uint8_range(data, &context->value->version, 0, UINT8_MAX);
}

static bool handle_type_family(const tlv_data_t *data, s_value_context *context) {
    return tlv_get_uint8_range(data,
                               (uint8_t *) &context->value->type_family,
                               TF_UINT,
                               TF_TRC_TOKEN);
}

static bool handle_type_size(const tlv_data_t *data, s_value_context *context) {
    return tlv_get_uint8_range(data, &context->value->type_size, 1, 32);
}

static bool handle_data_path(const tlv_data_t *data, s_value_context *context) {
    s_data_path_context ctx = {0};

    ctx.data_path = &context->value->data_path;
    explicit_bzero(ctx.data_path, sizeof(*ctx.data_path));
    if (!handle_data_path_struct(&data->value, &ctx)) {
        return false;
    }
    context->value->source = SOURCE_CALLDATA;
    return true;
}

static bool handle_container_path(const tlv_data_t *data, s_value_context *context) {
    if (!tlv_get_uint8_range(data,
                             (uint8_t *) &context->value->container_path,
                             CP_FROM,
                             CP_CHAIN_ID)) {
        return false;
    }
    context->value->source = SOURCE_RLP;
    return true;
}

static bool handle_constant(const tlv_data_t *data, s_value_context *context) {
    if (data->value.size > sizeof(context->value->constant.buf)) {
        return false;
    }
    context->value->constant.size = data->value.size;
    memcpy(context->value->constant.buf, data->value.ptr, data->value.size);
    context->value->source = SOURCE_CONSTANT;
    return true;
}

DEFINE_TLV_PARSER(VALUE_TAGS, NULL, value_tlv_parser)

bool handle_value_struct(const buffer_t *buf, s_value_context *context) {
    TLV_reception_t received_tags = {0};
    unsigned int source_count = 0U;

    if ((context == NULL) || (context->value == NULL) ||
        !value_tlv_parser(buf, context, &received_tags) ||
        !TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_VERSION, TAG_TYPE_FAMILY) ||
        (context->value->version != 1U)) {
        return false;
    }
    source_count += TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_DATA_PATH) ? 1U : 0U;
    source_count += TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_CONTAINER_PATH) ? 1U : 0U;
    source_count += TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_CONSTANT) ? 1U : 0U;
    if (source_count != 1U) {
        return false;
    }
    switch (context->value->type_family) {
        case TF_INT:
        case TF_UFIXED:
        case TF_FIXED:
            return TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_TYPE_SIZE);
        case TF_UINT:
        case TF_ADDRESS:
        case TF_BOOL:
        case TF_BYTES:
        case TF_STRING:
        case TF_TRC_TOKEN:
            return true;
        default:
            return false;
    }
}

bool value_get(const s_value *value, s_parsed_value_collection *collection) {
    static uint64_t chain_id = 0;
    const s_tx_info *tx_info = NULL;

    switch (value->source) {
        case SOURCE_CALLDATA:
            collection->size = 0;
            if (!data_path_get(&value->data_path, collection) ||
                (collection->size == 0U)) {
                return false;
            }
            break;

        case SOURCE_RLP:
            switch (value->container_path) {
                case CP_FROM:
                    if (((collection->value[0].ptr = get_current_tx_from())) == NULL) {
                        return false;
                    }
                    collection->value[0].length = ADDRESS_LENGTH;
                    collection->size = 1;
                    break;

                case CP_TO:
                    if ((collection->value[0].ptr = get_current_tx_to()) == NULL) {
                        return false;
                    }
                    collection->value[0].length = ADDRESS_LENGTH;
                    collection->size = 1;
                    break;

                case CP_VALUE:
                    if ((collection->value[0].ptr = get_current_tx_amount()) == NULL) {
                        return false;
                    }
                    collection->value[0].length = INT256_LENGTH;
                    collection->size = 1;
                    break;

                case CP_CHAIN_ID:
                    // Get chain ID as uint64_t
                    tx_info = get_current_tx_info();
                    if (tx_info == NULL) {
                        return false;
                    }
                    chain_id = tx_info->chain_id;
                    // Convert to big-endian byte array
                    chain_id = u64_from_BE((const uint8_t *) &chain_id, sizeof(uint64_t));
                    collection->value[0].ptr = (const uint8_t *) &chain_id;
                    collection->value[0].length = sizeof(uint64_t);
                    collection->size = 1;
                    break;

                default:
                    return false;
            }
            break;

        case SOURCE_CONSTANT:
            collection->value[0].ptr = value->constant.buf;
            collection->value[0].length = value->constant.size;
            collection->size = 1;
            break;

        default:
            return false;
    }
    return true;
}

void value_cleanup(const s_value *value, const s_parsed_value_collection *collection) {
    if (value->source == SOURCE_CALLDATA) {
        data_path_cleanup(collection);
    }
}

bool parsed_value_to_uint_be(const s_parsed_value *value, uint8_t *out, size_t out_size) {
    const uint8_t *src;
    size_t src_size;

    if ((value == NULL) || (out == NULL) || (out_size == 0U) ||
        (value->ptr == NULL) || (value->length == 0U) ||
        (value->length > INT256_LENGTH)) {
        return false;
    }
    src = value->ptr;
    src_size = value->length;
    if (src_size > out_size) {
        const size_t discarded = src_size - out_size;
        for (size_t i = 0U; i < discarded; ++i) {
            if (src[i] != 0U) {
                return false;
            }
        }
        src += discarded;
        src_size = out_size;
    }
    memset(out, 0, out_size - src_size);
    memcpy(out + out_size - src_size, src, src_size);
    return true;
}

bool parsed_value_to_typed_uint_be(const s_value *definition,
                                   const s_parsed_value *value,
                                   uint8_t *out,
                                   size_t out_size) {
    size_t type_size;
    size_t discarded;

    if ((definition == NULL) ||
        ((definition->type_family != TF_UINT) &&
         (definition->type_family != TF_TRC_TOKEN)) ||
        (definition->type_size > INT256_LENGTH) ||
        (value == NULL) || (value->ptr == NULL) ||
        (value->length == 0U) || (value->length > INT256_LENGTH)) {
        return false;
    }

    /* type_size is optional for legacy uint256 descriptors. If a narrower
     * Solidity/TVM width is declared, an ABI word may be wider only through
     * canonical zero extension. Never silently interpret discarded high bits. */
    type_size = (definition->type_size == 0U) ? INT256_LENGTH
                                              : definition->type_size;
    if (value->length > type_size) {
        discarded = value->length - type_size;
        for (size_t i = 0U; i < discarded; ++i) {
            if (value->ptr[i] != 0U) {
                return false;
            }
        }
    }
    return parsed_value_to_uint_be(value, out, out_size);
}

bool parsed_value_to_address(const s_parsed_value *value, uint8_t out[static ADDRESS_LENGTH]) {
    const uint8_t *addr;

    if ((value == NULL) || (out == NULL) || (value->ptr == NULL)) {
        return false;
    }
    addr = value->ptr;
    if (value->length == ADDRESS_LENGTH) {
        /* Already the canonical EVM-style address used internally by GCS. */
    } else if (value->length == TRON_ADDRESS_SIZE) {
        if (addr[0] != TRON_MAINNET_ADDRESS_PREFIX) {
            return false;
        }
        addr += 1U;
    } else if (value->length == INT256_LENGTH) {
        const size_t prefix_index = INT256_LENGTH - TRON_ADDRESS_SIZE;
        const size_t address_index = INT256_LENGTH - ADDRESS_LENGTH;

        for (size_t i = 0U; i < prefix_index; ++i) {
            if (addr[i] != 0U) {
                return false;
            }
        }
        if ((addr[prefix_index] != 0U) &&
            (addr[prefix_index] != TRON_MAINNET_ADDRESS_PREFIX)) {
            return false;
        }
        addr += address_index;
    } else {
        return false;
    }
    memcpy(out, addr, ADDRESS_LENGTH);
    return true;
}

bool parsed_value_to_selector(const s_parsed_value *value,
                              uint8_t out[static CALLDATA_SELECTOR_SIZE]) {
    if ((value == NULL) || (out == NULL) || (value->ptr == NULL) ||
        (value->length != CALLDATA_SELECTOR_SIZE)) {
        return false;
    }
    memcpy(out, value->ptr, CALLDATA_SELECTOR_SIZE);
    return true;
}
