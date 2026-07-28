#include <string.h>
#include "gtp_param_token.h"
#include "shared_context.h"
#include "utils.h"
#include "manage_asset_info.h"
#include "network.h"
#include "gtp_field_table.h"
#include "tx_ctx.h"
#include "tlv_library.h"
#include "tlv_apdu.h"

#define PARAM_TOKEN_TAGS(X)                                  \
    X(0x00, TAG_VERSION, handle_version, ENFORCE_UNIQUE_TAG) \
    X(0x01, TAG_ADDRESS, handle_address, ENFORCE_UNIQUE_TAG) \
    X(0x02, TAG_NATIVE_CURRENCY, handle_native_currency, ALLOW_MULTIPLE_TAG)

static bool handle_version(const tlv_data_t *data, s_param_token_context *context) {
    return tlv_get_uint8_range(data, &context->param->version, 0, UINT8_MAX);
}

static bool handle_address(const tlv_data_t *data, s_param_token_context *context) {
    s_value_context ctx = {0};

    ctx.value = &context->param->address;
    explicit_bzero(ctx.value, sizeof(*ctx.value));
    return handle_value_struct(&data->value, &ctx);
}

static bool handle_native_currency(const tlv_data_t *data, s_param_token_context *context) {
    if (data->value.size != ADDRESS_LENGTH) {
        return false;
    }
    if (context->param->native_addr_count == MAX_NATIVE_ADDRS) {
        return false;
    }
    memcpy(context->param->native_addrs[context->param->native_addr_count],
           data->value.ptr,
           ADDRESS_LENGTH);
    context->param->native_addr_count += 1;
    return true;
}

DEFINE_TLV_PARSER(PARAM_TOKEN_TAGS, NULL, param_token_tlv_parser)

bool handle_param_token_struct(const buffer_t *buf, s_param_token_context *context) {
    TLV_reception_t received_tags = {0};
    return param_token_tlv_parser(buf, context, &received_tags) &&
           TLV_CHECK_RECEIVED_TAGS(received_tags, TAG_VERSION, TAG_ADDRESS) &&
           (context->param->version == 1U);
}

static bool match_native(const uint8_t *addr, const s_param_token *param) {
    for (int i = 0; i < param->native_addr_count; ++i) {
        if (memcmp(addr, param->native_addrs[i], ADDRESS_LENGTH) == 0) {
            return true;
        }
    }
    return false;
}

bool format_param_token(const s_param_token *param, const char *name) {
    bool ret;
    s_parsed_value_collection collec = {0};
    uint8_t addr[ADDRESS_LENGTH];
    const tokenDefinition_t *token_def = NULL;
    uint64_t chain_id;
    const char *ticker = NULL;

    if (get_current_tx_info() == NULL) return false;
    chain_id = get_current_tx_info()->chain_id;
    if (param->address.type_family != TF_ADDRESS) return false;
    if ((ret = value_get(&param->address, &collec))) {
        for (int i = 0; i < collec.size; ++i) {
            ticker = NULL;
            token_def = NULL;
            if (!parsed_value_to_address(&collec.value[i], addr)) {
                ret = false;
                break;
            }
            if (match_native(addr, param)) {
                ticker = get_displayable_ticker(&chain_id, chainConfig, true);
            } else if ((token_def = get_token_info_by_addr(addr)) != NULL) {
                ticker = token_def->ticker;
            }
            if (ticker == NULL) {
                ret = false;
                break;
            }
            if (!(ret = add_to_field_table(PARAM_TYPE_TOKEN, name, ticker, token_def))) {
                break;
            }
        }
    }
    value_cleanup(&param->address, &collec);
    return ret;
}
