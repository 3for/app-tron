#include "gtp_param_datetime.h"
#include "gtp_field_table.h"
#include "read.h"
#include "time_format.h"
#include "utils.h"
#include "shared_context.h"
#include "tlv_library.h"
#include "tlv_apdu.h"

#define PARAM_DATETIME_TAGS(X)                               \
    X(0x00, TAG_VERSION, handle_version, ENFORCE_UNIQUE_TAG) \
    X(0x01, TAG_VALUE, handle_value, ENFORCE_UNIQUE_TAG)     \
    X(0x02, TAG_TYPE, handle_type, ENFORCE_UNIQUE_TAG)

static bool handle_version(const tlv_data_t *data, s_param_datetime_context *context) {
    return tlv_get_uint8_range(data, &context->param->version, 0, UINT8_MAX);
}

static bool handle_value(const tlv_data_t *data, s_param_datetime_context *context) {
    s_value_context ctx = {0};

    ctx.value = &context->param->value;
    explicit_bzero(ctx.value, sizeof(*ctx.value));
    return handle_value_struct(&data->value, &ctx);
}

static bool handle_type(const tlv_data_t *data, s_param_datetime_context *context) {
    uint8_t datetime_type;

    if (!tlv_get_uint8_range(data, &datetime_type, 0, UINT8_MAX)) {
        return false;
    }
    context->param->type = (e_datetime_type) datetime_type;
    switch (context->param->type) {
        case DT_UNIX:
        case DT_BLOCKHEIGHT:
            break;
        default:
            return false;
    }
    return true;
}

DEFINE_TLV_PARSER(PARAM_DATETIME_TAGS, NULL, param_datetime_tlv_parser)

bool handle_param_datetime_struct(const buffer_t *buf, s_param_datetime_context *context) {
    TLV_reception_t received_tags = {0};
    return param_datetime_tlv_parser(buf, context, &received_tags) &&
           TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_VERSION, TAG_VALUE, TAG_TYPE) &&
           (context->param->version == 1U);
}

static bool is_unlimited_timestamp(const s_value *definition,
                                   const s_parsed_value *value) {
    uint8_t normalized[INT256_LENGTH] = {0};
    size_t width;

    if ((definition == NULL) || (value == NULL) ||
        (definition->type_size == 0U) ||
        (definition->type_size > sizeof(normalized))) {
        return false;
    }
    width = definition->type_size;
    return parsed_value_to_uint_be(value, normalized, width) &&
           ismaxint(normalized, width);
}

static bool uint64_to_time_t(uint64_t value, time_t *timestamp) {
    time_t converted;

    if (timestamp == NULL) {
        return false;
    }
    converted = (time_t) value;
    /* time_t is signed on Ledger targets. Keep the round-trip check as well
     * so this remains safe on hosts where it is narrower than uint64_t. */
    if ((converted < (time_t) 0) || ((uint64_t) converted != value)) {
        return false;
    }
    *timestamp = converted;
    return true;
}

bool format_param_datetime(const s_param_datetime *param, const char *name) {
    bool ret;
    s_parsed_value_collection collec = {0};
    char *buf = strings.tmp.tmp;
    size_t buf_size = sizeof(strings.tmp.tmp);
    uint8_t time_buf[sizeof(uint64_t)] = {0};
    time_t timestamp;
    uint64_t timestamp_value;
    uint256_t block_height = {0};
    uint8_t block_buf[INT256_LENGTH] = {0};

    if (param->value.type_family != TF_UINT) {
        return false;
    }
    if ((ret = value_get(&param->value, &collec))) {
        for (int i = 0; i < collec.size; ++i) {
            if ((collec.value[i].ptr == NULL) ||
                (collec.value[i].length == 0U) ||
                (collec.value[i].length > INT256_LENGTH)) {
                ret = false;
                break;
            }
            if (param->type == DT_UNIX) {
                if (is_unlimited_timestamp(&param->value, &collec.value[i])) {
                    snprintf(buf, buf_size, "Unlimited");
                } else {
                    if (!parsed_value_to_uint_be(&collec.value[i],
                                                 time_buf,
                                                 sizeof(time_buf))) {
                        ret = false;
                        break;
                    }
                    timestamp_value = read_u64_be(time_buf, 0);
                    if (!uint64_to_time_t(timestamp_value, &timestamp)) {
                        ret = false;
                        break;
                    }
                    if (!(ret = time_format_to_utc(&timestamp, buf, buf_size))) {
                        break;
                    }
                }
            } else if (param->type == DT_BLOCKHEIGHT) {
                if (!parsed_value_to_uint_be(&collec.value[i],
                                             block_buf,
                                             sizeof(block_buf))) {
                    ret = false;
                    break;
                }
                convertUint256BE(block_buf, sizeof(block_buf), &block_height);
                if (!(ret = tostring256(&block_height, 10, buf, buf_size))) {
                    break;
                }
            }
            if (!(ret = add_to_field_table(PARAM_TYPE_DATETIME, name, buf, NULL))) {
                break;
            }
        }
    }
    value_cleanup(&param->value, &collec);
    return ret;
}
