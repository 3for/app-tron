#include "gtp_param_enum.h"
#include "network.h"
#include "enum_value.h"
#include "gtp_field_table.h"
#include "gtp_tx_info.h"  // get_contract_addr
#include "calldata.h"
#include "shared_context.h"
#include "tx_ctx.h"
#include "tlv_library.h"
#include "tlv_apdu.h"

#define PARAM_ENUM_TAGS(X)                                   \
    X(0x00, TAG_VERSION, handle_version, ENFORCE_UNIQUE_TAG) \
    X(0x01, TAG_ID, handle_id, ENFORCE_UNIQUE_TAG)           \
    X(0x02, TAG_VALUE, handle_value, ENFORCE_UNIQUE_TAG)

static bool handle_version(const tlv_data_t *data, s_param_enum_context *context) {
    return tlv_get_uint8_range(data, &context->param->version, 0, UINT8_MAX);
}

static bool handle_id(const tlv_data_t *data, s_param_enum_context *context) {
    return tlv_get_uint8_range(data, &context->param->id, 0, UINT8_MAX);
}

static bool handle_value(const tlv_data_t *data, s_param_enum_context *context) {
    s_value_context ctx = {0};

    ctx.value = &context->param->value;
    explicit_bzero(ctx.value, sizeof(*ctx.value));
    return handle_value_struct(&data->value, &ctx);
}

DEFINE_TLV_PARSER(PARAM_ENUM_TAGS, NULL, param_enum_tlv_parser)

bool handle_param_enum_struct(const buffer_t *buf, s_param_enum_context *context) {
    TLV_reception_t received_tags = {0};
    return param_enum_tlv_parser(buf, context, &received_tags) &&
           TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_VERSION, TAG_ID, TAG_VALUE) &&
           (context->param->version == 1U);
}

bool format_param_enum(const s_param_enum *param, const char *name) {
    bool ret;
    uint64_t chain_id;
    s_parsed_value_collection collec = {0};
    const s_enum_value_entry *enum_entry;
    uint8_t value;
    const uint8_t *selector;

    if (param->value.type_family != TF_UINT) {
        return false;
    }
    if ((ret = value_get(&param->value, &collec))) {
        if (get_current_tx_info() == NULL) {
            ret = false;
            goto cleanup;
        }
        chain_id = get_current_tx_info()->chain_id;
        for (int i = 0; i < collec.size; ++i) {
            if (!parsed_value_to_typed_uint_be(&param->value,
                                               &collec.value[i],
                                               &value,
                                               sizeof(value))) {
                ret = false;
                break;
            }
            if ((selector = calldata_get_selector(get_current_calldata())) == NULL) {
                ret = false;
                break;
            }
            // TRON divergence from app-ethereum: the GCS contract address lives in
            // the TX_INFO descriptor (get_contract_addr), not in
            // txContext.content->destination, which is never populated by the GCS
            // STORE flow (dereferencing it would fault).
            if ((enum_entry = get_matching_enum(&chain_id,
                                                get_contract_addr(get_current_tx_info()),
                                                selector,
                                                param->id,
                                                value)) == NULL) {
                ret = false;
                break;
            }
            if (!(ret = add_to_field_table(PARAM_TYPE_ENUM, name, enum_entry->name, enum_entry))) {
                break;
            }
        }
    }
cleanup:
    value_cleanup(&param->value, &collec);
    return ret;
}
