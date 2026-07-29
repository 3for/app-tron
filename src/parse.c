/*******************************************************************************
 *   TRON Ledger
 *   (c) 2018 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <stdint.h>
#include <string.h>

#include "pb.h"
#include "pb_decode.h"
#include "misc/TronApp.pb.h"
#include "format.h"
#include "parse.h"
#include "settings.h"
#include "trc_tokens.h"
#include "app_errors.h"
#include "ui_globals.h"
#include "app_mem_utils.h"
#include "create_smart_contract_stream.h"
#include "utils.h"

#define DEFAULT_DELEGATE_LOCK_PERIOD_BLOCKS 86400

static pb_size_t decoded_proposal_parameters_count;
static protocol_ProposalCreateContract_ParametersEntry *decoded_proposal_parameters;

void proposal_parameters_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &decoded_proposal_parameters);
    decoded_proposal_parameters_count = 0;
}

static bool proposal_parameters_init(void) {
    proposal_parameters_cleanup();
    decoded_proposal_parameters =
        APP_MEM_ALLOC(MAX_PROPOSAL_PARAMETERS * sizeof(*decoded_proposal_parameters));
    return decoded_proposal_parameters != NULL;
}

pb_size_t proposal_parameter_count(void) {
    return decoded_proposal_parameters_count;
}

bool proposal_parameter_at(pb_size_t index, int64_t *key, int64_t *value) {
    if ((decoded_proposal_parameters == NULL) || (index >= decoded_proposal_parameters_count) ||
        (key == NULL) || (value == NULL)) {
        return false;
    }

    *key = decoded_proposal_parameters[index].key;
    *value = decoded_proposal_parameters[index].value;
    return true;
}

static bool pb_decode_proposal_parameter(pb_istream_t *stream,
                                         const pb_field_t *field,
                                         void **arg) {
    protocol_ProposalCreateContract_ParametersEntry entry =
        protocol_ProposalCreateContract_ParametersEntry_init_zero;

    UNUSED(arg);
    if (decoded_proposal_parameters == NULL) {
        return false;
    }
    if (decoded_proposal_parameters_count >= MAX_PROPOSAL_PARAMETERS) {
        return false;
    }
    if (!pb_decode(stream, field->submsg_desc, &entry)) {
        return false;
    }
    /* java-tron materializes this protobuf map through getParametersMap(),
     * where a repeated wire key has last-value-wins semantics.  Reject the
     * non-canonical wire form instead of reviewing entries that the node will
     * later collapse into a different effective set. */
    for (pb_size_t i = 0; i < decoded_proposal_parameters_count; i++) {
        if (decoded_proposal_parameters[i].key == entry.key) {
            return false;
        }
    }
    decoded_proposal_parameters[decoded_proposal_parameters_count] = entry;
    decoded_proposal_parameters_count++;
    return true;
}

static bool is_stake_resource(protocol_ResourceCode resource) {
    return (resource == protocol_ResourceCode_BANDWIDTH) ||
           (resource == protocol_ResourceCode_ENERGY) ||
           (resource == protocol_ResourceCode_TRON_POWER);
}

static bool is_delegatable_resource(protocol_ResourceCode resource) {
    return (resource == protocol_ResourceCode_BANDWIDTH) ||
           (resource == protocol_ResourceCode_ENERGY);
}

tokenDefinition_t *getKnownToken(txContent_t *context) {
    uint16_t i;

    tokenDefinition_t *currentToken = NULL;
    for (i = 0; i < NUM_TOKENS_TRC20; i++) {
        currentToken = (tokenDefinition_t *) PIC(&TOKENS_TRC20[i]);
        if (memcmp(currentToken->address, context->contractAddress, ADDRESS_SIZE) == 0) {
            PRINTF("Selected token %d\n", i);
            return currentToken;
        }
    }
    return NULL;
}

unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun) {
    char raw_amount[21];
    size_t raw_amount_len;

    if ((out == NULL) || (outlen == 0)) {
        return 0;
    }
    out[0] = '\0';

    if (!u64_to_string(amount, raw_amount, sizeof(raw_amount))) {
        return 0;
    }
    raw_amount_len = strlen(raw_amount);
    if (!adjustDecimals(raw_amount, raw_amount_len, out, outlen, sun)) {
        out[0] = '\0';
        return 0;
    }

    return strlen(out);
}

bool setContractType(contractType_e type, char *out, size_t outlen) {
    switch (type) {
        case ACCOUNTCREATECONTRACT:
            strlcpy(out, "Account Create", outlen);
            break;
        case VOTEASSETCONTRACT:
            strlcpy(out, "Vote Asset", outlen);
            break;
        case WITNESSCREATECONTRACT:
            strlcpy(out, "Witness Create", outlen);
            break;
        case ASSETISSUECONTRACT:
            strlcpy(out, "Asset Issue", outlen);
            break;
        case WITNESSUPDATECONTRACT:
            strlcpy(out, "Witness Update", outlen);
            break;
        case PARTICIPATEASSETISSUECONTRACT:
            strlcpy(out, "Participate Asset", outlen);
            break;
        case ACCOUNTUPDATECONTRACT:
            strlcpy(out, "Account Update", outlen);
            break;
        case SETACCOUNTIDCONTRACT:
            strlcpy(out, "Set Account ID", outlen);
            break;
        case CREATESMARTCONTRACT:
            strlcpy(out, "Create Smart Contract", outlen);
            break;
        case UPDATESETTINGCONTRACT:
            strlcpy(out, "Update Setting", outlen);
            break;
        case UPDATEENERGYLIMITCONTRACT:
            strlcpy(out, "Update Energy Limit", outlen);
            break;
        case UNFREEZEBALANCECONTRACT:
            strlcpy(out, "Unfreeze Balance", outlen);
            break;
        case UNFREEZEBALANCEV2CONTRACT:
            strlcpy(out, "UnfreezeV2 Balance", outlen);
            break;
        case WITHDRAWBALANCECONTRACT:
            strlcpy(out, "Claim Rewards", outlen);
            break;
        case UNFREEZEASSETCONTRACT:
            strlcpy(out, "Unfreeze Asset", outlen);
            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:
            strlcpy(out, "Withdraw Unfreeze", outlen);
            break;
        case CANCELALLUNFREEZEV2CONTRACT:
            strlcpy(out, "Cancel All Unfreeze V2", outlen);
            break;
        case UPDATEBROKERAGECONTRACT:
            strlcpy(out, "Update Brokerage", outlen);
            break;
        case UPDATEASSETCONTRACT:
            strlcpy(out, "Update Asset", outlen);
            break;
        case PROPOSALCREATECONTRACT:
            strlcpy(out, "Proposal Create", outlen);
            break;
        case PROPOSALAPPROVECONTRACT:
            strlcpy(out, "Proposal Approve", outlen);
            break;
        case PROPOSALDELETECONTRACT:
            strlcpy(out, "Proposal Delete", outlen);
            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
            strlcpy(out, "Permission Update", outlen);
            break;
        case CLEARABICONTRACT:
            strlcpy(out, "Clear ABI", outlen);
            break;
        case UNKNOWN_CONTRACT:
            strlcpy(out, "Unknown Type", outlen);
            break;
        default:
            return false;
    }
    return true;
}

bool setExchangeContractDetail(contractType_e type, char *out, size_t outlen) {
    switch (type) {
        case EXCHANGECREATECONTRACT:
            strlcpy(out, "create", outlen);
            break;
        case EXCHANGEINJECTCONTRACT:
            strlcpy(out, "inject", outlen);
            break;
        case EXCHANGEWITHDRAWCONTRACT:
            strlcpy(out, "withdraw", outlen);
            break;
        case EXCHANGETRANSACTIONCONTRACT:
            strlcpy(out, "transaction", outlen);
            break;
        default:
            return false;
    }
    return true;
}

#include "../proto/core/Contract.pb.h"
#include "../proto/core/Tron.pb.h"
#include "../proto/misc/TronApp.pb.h"
#include "pb_decode.h"

_Static_assert(sizeof(((TokenDetails *) 0)->name) == MAX_TRC10_ASSET_NAME_LENGTH + 1,
               "TokenDetails.name must hold a 32-character name plus NUL");
_Static_assert(sizeof(((ExchangeDetails *) 0)->token1Id) == MAX_TRC10_TOKEN_ID_LENGTH + 1,
               "ExchangeDetails token IDs must hold 19 digits plus NUL");
_Static_assert(sizeof(((ExchangeDetails *) 0)->token1Name) ==
                   MAX_TRC10_ASSET_NAME_LENGTH + 1,
               "ExchangeDetails token names must hold 32 characters plus NUL");

typedef struct {
    uint32_t tag;
    uint8_t min_byte;
    uint8_t max_byte;
} protobuf_string_rule_t;

/* Nanopb's static STRING representation records only a C terminator, not the
 * original protobuf byte length. Inspect selected top-level string fields on
 * the wire before decoding so every signed/displayed byte is validated. */
static bool protobuf_string_fields_match_rules(const uint8_t *data,
                                               size_t length,
                                               const protobuf_string_rule_t *rules,
                                               size_t rule_count) {
    pb_istream_t stream;

    if ((data == NULL) || (rules == NULL) || (rule_count == 0U)) {
        return false;
    }
    stream = pb_istream_from_buffer(data, length);
    while (stream.bytes_left > 0U) {
        pb_wire_type_t wire_type;
        uint32_t tag;
        bool eof = false;
        const protobuf_string_rule_t *rule = NULL;

        if (!pb_decode_tag(&stream, &wire_type, &tag, &eof) || eof) {
            return false;
        }
        for (size_t i = 0; i < rule_count; i++) {
            if (tag == rules[i].tag) {
                rule = &rules[i];
                break;
            }
        }
        if (rule == NULL) {
            if (!pb_skip_field(&stream, wire_type)) {
                return false;
            }
            continue;
        }
        if (wire_type != PB_WT_STRING) {
            return false;
        }

        pb_istream_t field_stream;
        if (!pb_make_string_substream(&stream, &field_stream)) {
            return false;
        }
        while (field_stream.bytes_left > 0U) {
            uint8_t byte;
            if (!pb_read(&field_stream, &byte, 1U) || (byte < rule->min_byte) ||
                (byte > rule->max_byte)) {
                return false;
            }
        }
        if (!pb_close_string_substream(&stream, &field_stream)) {
            return false;
        }
    }
    return true;
}

/* Require a length-delimited protobuf field to be absent or encoded with an
 * empty value. This preserves the original wire-length distinction that a
 * nanopb static STRING would otherwise lose at the first NUL byte. */
static bool protobuf_string_field_is_empty(pb_istream_t *stream, uint32_t target_tag) {
    if (stream == NULL) {
        return false;
    }

    while (stream->bytes_left > 0U) {
        pb_wire_type_t wire_type;
        uint32_t tag;
        bool eof = false;

        if (!pb_decode_tag(stream, &wire_type, &tag, &eof) || eof) {
            return false;
        }
        if (tag != target_tag) {
            if (!pb_skip_field(stream, wire_type)) {
                return false;
            }
            continue;
        }
        if (wire_type != PB_WT_STRING) {
            return false;
        }

        pb_istream_t field_stream;
        if (!pb_make_string_substream(stream, &field_stream)) {
            return false;
        }
        bool is_empty = field_stream.bytes_left == 0U;
        if (!pb_close_string_substream(stream, &field_stream) || !is_empty) {
            return false;
        }
    }
    return true;
}

// ALLOW SAME NAME TOKEN
// CHECK SIGNATURE(ID+NAME+PRECISION)
// Parse token Name and Signature
static bool format_token_display(char *out,
                                 size_t out_size,
                                 const char *name,
                                 const char *id) {
    if ((out == NULL) || (name == NULL) || (id == NULL)) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t id_len = strlen(id);
    // name + '[' + id + ']' + NUL
    size_t required_size = name_len + id_len + 3;
    if ((name_len == 0) || (name_len > MAX_TRC10_ASSET_NAME_LENGTH) || (id_len == 0) ||
        (id_len > MAX_TRC10_TOKEN_ID_LENGTH) || (required_size > out_size)) {
        return false;
    }

    memcpy(out, name, name_len);
    out[name_len] = '[';
    memcpy(out + name_len + 1, id, id_len);
    out[name_len + id_len + 1] = ']';
    out[name_len + id_len + 2] = '\0';
    return true;
}

bool parseTokenName(uint8_t token_id, uint8_t *data, uint32_t dataLength, txContent_t *content) {
    TokenDetails details = {};
    static const protobuf_string_rule_t string_rules[] = {
        {TokenDetails_name_tag, 0x21, 0x7e},
    };

    if ((data == NULL) || (content == NULL) ||
        (token_id >= ARRAY_SIZE(content->tokenNames)) ||
        !protobuf_string_fields_match_rules(data,
                                            dataLength,
                                            string_rules,
                                            ARRAY_SIZE(string_rules))) {
        return false;
    }

    pb_istream_t stream = pb_istream_from_buffer(data, dataLength);
    if (!pb_decode(&stream, TokenDetails_fields, &details) ||
        (details.precision > MAX_TRC10_PRECISION)) {
        return false;
    }

    // Validate token ID + Name
    if (verifyTokenNameID((const char *) content->tokenNames[token_id],
                          details.name,
                          details.precision,
                          details.signature.bytes,
                          details.signature.size) != 1) {
        return false;
    }

    // UPDATE Token with Name[ID]
    char tmp[TOKEN_DISPLAY_BUFFER_SIZE];
    if (!format_token_display(tmp,
                              sizeof(tmp),
                              details.name,
                              content->tokenNames[token_id])) {
        return false;
    }
    content->tokenNamesLength[token_id] = strlen(tmp);
    strlcpy(content->tokenNames[token_id], tmp, sizeof(content->tokenNames[token_id]));
    content->decimals[token_id] = details.precision;
    return true;
}

static bool is_valid_token_id(const uint8_t *data, size_t size, bool allow_trx) {
    if ((data == NULL) || (size == 0) || (size > MAX_TRC10_TOKEN_ID_LENGTH)) {
        return false;
    }

    if ((size == 1) && (data[0] == '_')) {
        return allow_trx;
    }

    // Token IDs are positive, canonical decimal representations of java long values.
    if (data[0] == '0') {
        return false;
    }

    uint64_t token_id = 0;
    for (size_t i = 0; i < size; i++) {
        if ((data[i] < '0') || (data[i] > '9')) {
            return false;
        }

        uint8_t digit = data[i] - '0';
        if (token_id > (((uint64_t) INT64_MAX - digit) / 10)) {
            return false;
        }
        token_id = token_id * 10 + digit;
    }

    return token_id > 0;
}

static bool printTokenFromID(char *out,
                             size_t outlen,
                             const uint8_t *data,
                             size_t size,
                             bool allow_trx) {
    if ((out == NULL) || !is_valid_token_id(data, size, allow_trx)) {
        return false;
    }

    if ((size == 1) && (data[0] == '_')) {
        if (outlen < sizeof("TRX")) {
            return false;
        }
        memcpy(out, "TRX", sizeof("TRX"));
        return true;
    }

    if (size >= outlen) {
        return false;
    }
    memcpy(out, data, size);
    out[size] = '\0';
    return true;
}

static bool token_id_matches_display(const char *display_token_id, const char *raw_token_id) {
    if (strcmp(raw_token_id, "_") == 0) {
        return strcmp(display_token_id, "TRX") == 0;
    }
    return strcmp(display_token_id, raw_token_id) == 0;
}

static bool set_token_info(txContent_t *content,
                           unsigned int token_index,
                           const char *name,
                           const char *id,
                           int precision) {
    if ((content == NULL) || (token_index >= ARRAY_SIZE(content->tokenNames)) ||
        (precision < 0) || (precision > MAX_TRC10_PRECISION)) {
        return false;
    }

    if (!format_token_display(content->tokenNames[token_index],
                              sizeof(content->tokenNames[token_index]),
                              name,
                              id)) {
        return false;
    }
    content->tokenNamesLength[token_index] = strlen((char *) content->tokenNames[token_index]);
    content->decimals[token_index] = precision;
    return true;
}

#define MAX_UINT64_DECIMAL_LENGTH 20
#define EXCHANGE_SIGNATURE_PREIMAGE_SIZE                                       \
    (MAX_UINT64_DECIMAL_LENGTH + 2 * MAX_TRC10_TOKEN_ID_LENGTH +               \
     2 * MAX_TRC10_ASSET_NAME_LENGTH + 2)

static bool append_exchange_preimage(uint8_t *buffer,
                                     size_t buffer_size,
                                     size_t *offset,
                                     const void *value,
                                     size_t value_size) {
    if ((buffer == NULL) || (offset == NULL) || (value == NULL) ||
        (*offset > buffer_size) || (value_size > buffer_size - *offset)) {
        return false;
    }
    memcpy(buffer + *offset, value, value_size);
    *offset += value_size;
    return true;
}

// Exchange Token ID + Name
// CHECK SIGNATURE(EXCHANGEID+TOKEN1ID+NAME1+PRECISION1+TOKEN2ID+NAME2+PRECISION2)
// Parse token Name and Signature
bool parseExchange(const uint8_t *data, size_t length, txContent_t *content) {
    ExchangeDetails details = ExchangeDetails_init_zero;
    uint8_t buffer[EXCHANGE_SIGNATURE_PREIMAGE_SIZE];
    static const protobuf_string_rule_t string_rules[] = {
        /* IDs are validated structurally after decoding; preserve all non-NUL bytes here. */
        {ExchangeDetails_token1Id_tag, 0x01, UINT8_MAX},
        {ExchangeDetails_token1Name_tag, 0x21, 0x7e},
        {ExchangeDetails_token2Id_tag, 0x01, UINT8_MAX},
        {ExchangeDetails_token2Name_tag, 0x21, 0x7e},
    };

    if ((data == NULL) || (content == NULL) ||
        !protobuf_string_fields_match_rules(data,
                                            length,
                                            string_rules,
                                            ARRAY_SIZE(string_rules))) {
        return false;
    }

    pb_istream_t stream = pb_istream_from_buffer(data, length);
    if (!pb_decode(&stream, ExchangeDetails_fields, &details)) {
        return false;
    }

    if (content->exchangeID != details.exchangeId) {
        return false;
    }

    /* Replace token ID with Name[ID]. Exchange metadata may use "_" for TRX. */
    if (!is_valid_token_id((const uint8_t *) details.token1Id,
                           strlen(details.token1Id),
                           true)) {
        return false;
    }
    if (!is_valid_token_id((const uint8_t *) details.token2Id,
                           strlen(details.token2Id),
                           true)) {
        return false;
    }
    if ((details.token1Precision > MAX_TRC10_PRECISION) ||
        (details.token2Precision > MAX_TRC10_PRECISION)) {
        return false;
    }

    /* The legacy exchange signature covers the exact byte concatenation:
     * exchangeId || token1Id || token1Name || precision1 ||
     * token2Id || token2Name || precision2.
     */
    char exchange_id[MAX_UINT64_DECIMAL_LENGTH + 1];
    if (!u64_to_string(details.exchangeId, exchange_id, sizeof(exchange_id))) {
        return false;
    }
    uint8_t precision1 = (uint8_t) details.token1Precision;
    uint8_t precision2 = (uint8_t) details.token2Precision;
    size_t msg_size = 0;
    if (!append_exchange_preimage(buffer,
                                  sizeof(buffer),
                                  &msg_size,
                                  exchange_id,
                                  strlen(exchange_id)) ||
        !append_exchange_preimage(buffer,
                                  sizeof(buffer),
                                  &msg_size,
                                  details.token1Id,
                                  strlen(details.token1Id)) ||
        !append_exchange_preimage(buffer,
                                  sizeof(buffer),
                                  &msg_size,
                                  details.token1Name,
                                  strlen(details.token1Name)) ||
        !append_exchange_preimage(buffer, sizeof(buffer), &msg_size, &precision1, 1) ||
        !append_exchange_preimage(buffer,
                                  sizeof(buffer),
                                  &msg_size,
                                  details.token2Id,
                                  strlen(details.token2Id)) ||
        !append_exchange_preimage(buffer,
                                  sizeof(buffer),
                                  &msg_size,
                                  details.token2Name,
                                  strlen(details.token2Name)) ||
        !append_exchange_preimage(buffer, sizeof(buffer), &msg_size, &precision2, 1)) {
        return false;
    }

    if (!verifyExchangeID((uint8_t *) buffer,
                          msg_size,
                          details.signature.bytes,
                          details.signature.size)) {
        return false;
    }

    int first_token = 0, second_token = 0;
    if (token_id_matches_display(content->tokenNames[0], details.token1Id)) {
        first_token = 0;
        second_token = 1;
    } else if (token_id_matches_display(content->tokenNames[0], details.token2Id)) {
        first_token = 1;
        second_token = 0;
    } else {
        return false;
    }

    if (!set_token_info(content,
                        first_token,
                        details.token1Name,
                        details.token1Id,
                        details.token1Precision) ||
        !set_token_info(content,
                        second_token,
                        details.token2Name,
                        details.token2Id,
                        details.token2Precision)) {
        return false;
    }

    PRINTF("Lengths: %d,%d\n",
           content->tokenNamesLength[first_token],
           content->tokenNamesLength[second_token]);
    return true;
}

void initTx(txContext_t *context, txContent_t *content) {
    memset(context, 0, sizeof(txContext_t));
    memset(content, 0, sizeof(txContent_t));
    context->initialized = true;
    content->contractType = INVALID_CONTRACT;
    cx_sha256_init(&context->sha2);  // init sha
}

#define COPY_ADDRESS(a, b) memcpy((a), (b), ADDRESS_SIZE)

static bool is_mainnet_address(const uint8_t address[static ADDRESS_SIZE]) {
    return address[0] == ADD_PRE_FIX_BYTE_MAINNET;
}

static bool is_optional_mainnet_address(
    const uint8_t address[static ADDRESS_SIZE]) {
    return allzeroes(address, ADDRESS_SIZE) || is_mainnet_address(address);
}

contract_t msg;

static bool account_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_AccountCreateContract_fields,
                   &msg.account_create_contract)) {
        return false;
    }

    protocol_AccountCreateContract *contract = &msg.account_create_contract;
    if ((contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->account_address[0] != ADD_PRE_FIX_BYTE_MAINNET)) {
        return false;
    }

    switch (contract->type) {
        case protocol_AccountType_Normal:
        case protocol_AccountType_AssetIssue:
        case protocol_AccountType_Contract:
            break;
        default:
            return false;
    }

    COPY_ADDRESS(content->account, &contract->owner_address);
    COPY_ADDRESS(content->destination, &contract->account_address);
    content->accountType = contract->type;
    return true;
}

static bool asset_name_is_valid(const uint8_t *name, size_t name_len) {
    if ((name_len == 0) || (name_len > 32)) {
        return false;
    }
    for (size_t i = 0; i < name_len; i++) {
        if ((name[i] < 0x21) || (name[i] > 0x7e)) {
            return false;
        }
    }
    return true;
}

static bool asset_name_is_trx(const uint8_t *name, size_t name_len) {
    return (name_len == 3) && ((name[0] | 0x20) == 't') &&
           ((name[1] | 0x20) == 'r') && ((name[2] | 0x20) == 'x');
}

static bool asset_issue_contract(txContent_t *content, pb_istream_t *stream) {
    if ((content == NULL) || (stream == NULL)) {
        return false;
    }

    pb_istream_t validation_stream = *stream;
    if (!protobuf_string_field_is_empty(&validation_stream, protocol_AssetIssueContract_id_tag)) {
        return false;
    }

    if (!pb_decode(stream,
                   protocol_AssetIssueContract_fields,
                   &msg.asset_issue_contract)) {
        return false;
    }

    protocol_AssetIssueContract *contract = &msg.asset_issue_contract;
    if (contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    if (!asset_name_is_valid(contract->name.bytes, contract->name.size) ||
        asset_name_is_trx(contract->name.bytes, contract->name.size)) {
        return false;
    }
    if ((contract->abbr.size != 0) &&
        !asset_name_is_valid(contract->abbr.bytes, contract->abbr.size)) {
        return false;
    }
    if ((contract->total_supply <= 0) || (contract->trx_num <= 0) ||
        (contract->num <= 0) || (contract->precision < 0) ||
        (contract->precision > MAX_TRC10_PRECISION) || (contract->start_time <= 0) ||
        (contract->end_time <= contract->start_time) || (contract->url.size == 0) ||
        (contract->free_asset_net_limit < 0) ||
        (contract->public_free_asset_net_limit < 0) ||
        (contract->public_free_asset_net_usage != 0) || (contract->id[0] != '\0')) {
        return false;
    }
    if (contract->frozen_supply_count > MAX_ASSET_FROZEN_SUPPLY_COUNT) {
        return false;
    }

    uint64_t total_frozen = 0;
    uint64_t total_supply = (uint64_t) contract->total_supply;
    for (pb_size_t i = 0; i < contract->frozen_supply_count; i++) {
        protocol_AssetIssueContract_FrozenSupply *frozen = &contract->frozen_supply[i];
        if ((frozen->frozen_amount <= 0) || (frozen->frozen_days <= 0)) {
            return false;
        }
        uint64_t amount = (uint64_t) frozen->frozen_amount;
        if (amount > total_supply - total_frozen) {
            return false;
        }
        total_frozen += amount;
    }

    COPY_ADDRESS(content->account, &contract->owner_address);
    return true;
}

static bool participate_asset_issue_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ParticipateAssetIssueContract_fields,
                   &msg.participate_asset_issue_contract)) {
        return false;
    }

    protocol_ParticipateAssetIssueContract *contract =
        &msg.participate_asset_issue_contract;
    if ((contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->to_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (memcmp(contract->owner_address, contract->to_address, ADDRESS_SIZE) == 0) ||
        (contract->amount <= 0)) {
        return false;
    }
    if (!printTokenFromID(content->tokenNames[0],
                          sizeof(content->tokenNames[0]),
                          contract->asset_name.bytes,
                          contract->asset_name.size,
                          false)) {
        return false;
    }

    content->amount[0] = (uint64_t) contract->amount;
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);
    COPY_ADDRESS(content->account, &contract->owner_address);
    COPY_ADDRESS(content->destination, &contract->to_address);
    return true;
}

static bool unfreeze_asset_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnfreezeAssetContract_fields,
                   &msg.unfreeze_asset_contract)) {
        return false;
    }
    if (msg.unfreeze_asset_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.unfreeze_asset_contract.owner_address);
    return true;
}

static bool update_asset_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UpdateAssetContract_fields,
                   &msg.update_asset_contract)) {
        return false;
    }

    protocol_UpdateAssetContract *contract = &msg.update_asset_contract;
    if ((contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->url.size == 0) || (contract->new_limit < 0) ||
        (contract->new_public_limit < 0)) {
        return false;
    }

    COPY_ADDRESS(content->account, &contract->owner_address);
    return true;
}

static bool transfer_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_TransferContract_fields, &msg.transfer_contract)) {
        return false;
    }
    if ((msg.transfer_contract.amount <= 0) ||
        !is_mainnet_address(msg.transfer_contract.owner_address) ||
        !is_mainnet_address(msg.transfer_contract.to_address) ||
        (memcmp(msg.transfer_contract.owner_address,
                msg.transfer_contract.to_address,
                ADDRESS_SIZE) == 0)) {
        return false;
    }

    content->amount[0] = (uint64_t) msg.transfer_contract.amount;

    COPY_ADDRESS(content->account, &msg.transfer_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.transfer_contract.to_address);

    content->tokenNamesLength[0] = strlen("TRX");
    strcpy(content->tokenNames[0], "TRX");
    return true;
}

static bool transfer_asset_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_TransferAssetContract_fields, &msg.transfer_asset_contract)) {
        return false;
    }
    if ((msg.transfer_asset_contract.amount <= 0) ||
        !is_mainnet_address(msg.transfer_asset_contract.owner_address) ||
        !is_mainnet_address(msg.transfer_asset_contract.to_address) ||
        (memcmp(msg.transfer_asset_contract.owner_address,
                msg.transfer_asset_contract.to_address,
                ADDRESS_SIZE) == 0)) {
        return false;
    }
    content->amount[0] = (uint64_t) msg.transfer_asset_contract.amount;

    if (!printTokenFromID(content->tokenNames[0],
                          sizeof(content->tokenNames[0]),
                          msg.transfer_asset_contract.asset_name.bytes,
                          msg.transfer_asset_contract.asset_name.size,
                          false)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    COPY_ADDRESS(content->account, &msg.transfer_asset_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.transfer_asset_contract.to_address);
    return true;
}

static bool vote_witness_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_VoteWitnessContract_fields, &msg.vote_witness_contract)) {
        return false;
    }

    if (!is_mainnet_address(msg.vote_witness_contract.owner_address)) {
        return false;
    }
    for (pb_size_t i = 0; i < msg.vote_witness_contract.votes_count; i++) {
        if (!is_mainnet_address(msg.vote_witness_contract.votes[i].vote_address) ||
            (msg.vote_witness_contract.votes[i].vote_count <= 0)) {
            return false;
        }
    }

    COPY_ADDRESS(content->account, &msg.vote_witness_contract.owner_address);
    return true;
}

// Shared by WitnessCreateContract and WitnessUpdateContract: both require a
// 21-byte owner_address prefixed with 0x41 (java-tron DecodeUtil.addressValid).
bool pb_decode_witness_owner_address(pb_istream_t *stream,
                                     const pb_field_t *field,
                                     void **arg) {
    UNUSED(field);

    size_t left_addr_size = stream->bytes_left;
    if (left_addr_size != ADDRESS_SIZE) {
        return false;
    }

    txContent_t *content = *arg;
    uint8_t buf[ADDRESS_SIZE];  // 21 bytes `owner_address`

    // owner_address
    if (!pb_read(stream, buf, ADDRESS_SIZE)) {
        return false;
    }
    // TRON mainnet addresses must be prefixed with 0x41
    if (buf[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    memmove(content->account, buf, ADDRESS_SIZE);

    return true;
}

// Shared by WitnessCreateContract (`url`) and WitnessUpdateContract (`update_url`):
// both require 1..MAX_URL_SIZE bytes (java-tron TransactionUtil.validUrl).
bool pb_decode_witness_url(pb_istream_t *stream,
                           const pb_field_t *field,
                           void **arg) {
    UNUSED(field);

    size_t left_url_size = stream->bytes_left;
    // url must be non-empty and at most MAX_URL_SIZE bytes (matches java-tron
    // TransactionUtil.validUrl: validBytes(url, 256, allowEmpty=false))
    if (left_url_size == 0 || left_url_size > MAX_URL_SIZE) {
        return false;
    }

    txContent_t *content = *arg;
    uint8_t buf[MAX_URL_SIZE];  // max 256 bytes `url`

    // consume all left as url
    if (!pb_read(stream, buf, left_url_size)) {
        return false;
    }
    if (!is_printable((const char *) buf, left_url_size)) {
        return false;
    }
    memmove(content->url, buf, left_url_size);
    // NUL-terminate: content->url is MAX_URL_SIZE + 1 bytes, so index
    // left_url_size (<= MAX_URL_SIZE) is always in bounds even at max length
    content->url[left_url_size] = '\0';

    return true;
}
static bool witness_create_contract(txContent_t *content, pb_istream_t *stream) {
    msg.witness_create_contract.owner_address.funcs.decode =
        pb_decode_witness_owner_address;
    msg.witness_create_contract.owner_address.arg = content;
    msg.witness_create_contract.url.funcs.decode = pb_decode_witness_url;
    msg.witness_create_contract.url.arg = content;

    if (!pb_decode(stream, protocol_WitnessCreateContract_fields, &msg.witness_create_contract)) {
        return false;
    }

    // Reject empty url (matches java-tron TransactionUtil.validUrl, allowEmpty=false).
    // Proto3 omits an empty bytes field from the wire, so the url decode callback is
    // never invoked in that case; content->url stays zeroed. Catch both the absent-field
    // and the wire-present zero-length cases here.
    if (!is_mainnet_address(content->account) || (content->url[0] == '\0')) {
        return false;
    }

    return true;
}

static bool witness_update_contract(txContent_t *content, pb_istream_t *stream) {
    // Same owner_address (21 bytes + 0x41) and url (1..256 bytes) boundaries as
    // WitnessCreateContract; only the field name differs (`update_url`, tag 12).
    msg.witness_update_contract.owner_address.funcs.decode = pb_decode_witness_owner_address;
    msg.witness_update_contract.owner_address.arg = content;
    msg.witness_update_contract.update_url.funcs.decode = pb_decode_witness_url;
    msg.witness_update_contract.update_url.arg = content;

    if (!pb_decode(stream, protocol_WitnessUpdateContract_fields, &msg.witness_update_contract)) {
        return false;
    }

    // Reject empty update_url (java-tron TransactionUtil.validUrl, allowEmpty=false).
    // Proto3 omits an empty bytes field, so the url callback may never run; content->url
    // stays zeroed. Catch both the absent-field and wire-present zero-length cases here.
    if (!is_mainnet_address(content->account) || (content->url[0] == '\0')) {
        return false;
    }

    return true;
}

static bool freeze_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_FreezeBalanceContract_fields, &msg.freeze_balance_contract)) {
        return false;
    }
    /* Tron only accepts 3 days freezing */
    const bool has_receiver =
        !allzeroes(msg.freeze_balance_contract.receiver_address, ADDRESS_SIZE);
    if ((msg.freeze_balance_contract.frozen_duration != 3) ||
        (msg.freeze_balance_contract.frozen_balance < 1000000) ||
        !is_mainnet_address(msg.freeze_balance_contract.owner_address) ||
        !is_optional_mainnet_address(msg.freeze_balance_contract.receiver_address) ||
        !is_stake_resource(msg.freeze_balance_contract.resource) ||
        (has_receiver &&
         ((msg.freeze_balance_contract.resource == protocol_ResourceCode_TRON_POWER) ||
          (memcmp(msg.freeze_balance_contract.owner_address,
                  msg.freeze_balance_contract.receiver_address,
                  ADDRESS_SIZE) == 0)))) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.freeze_balance_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.freeze_balance_contract.receiver_address);
    content->amount[0] = (uint64_t) msg.freeze_balance_contract.frozen_balance;
    content->resource = msg.freeze_balance_contract.resource;
    return true;
}

static bool unfreeze_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnfreezeBalanceContract_fields,
                   &msg.unfreeze_balance_contract)) {
        return false;
    }
    const bool has_receiver =
        !allzeroes(msg.unfreeze_balance_contract.receiver_address, ADDRESS_SIZE);
    if (!is_mainnet_address(msg.unfreeze_balance_contract.owner_address) ||
        !is_optional_mainnet_address(msg.unfreeze_balance_contract.receiver_address) ||
        !is_stake_resource(msg.unfreeze_balance_contract.resource) ||
        (has_receiver &&
         ((msg.unfreeze_balance_contract.resource == protocol_ResourceCode_TRON_POWER) ||
          (memcmp(msg.unfreeze_balance_contract.owner_address,
                  msg.unfreeze_balance_contract.receiver_address,
                  ADDRESS_SIZE) == 0)))) {
        return false;
    }
    content->resource = msg.unfreeze_balance_contract.resource;

    COPY_ADDRESS(content->account, &msg.unfreeze_balance_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.unfreeze_balance_contract.receiver_address);
    return true;
}

static bool freeze_balance_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_FreezeBalanceV2Contract_fields,
                   &msg.freeze_balance_v2_contract)) {
        return false;
    }

    if (msg.freeze_balance_v2_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    if (msg.freeze_balance_v2_contract.frozen_balance < 1000000) {
        return false;
    }
    if (!is_stake_resource(msg.freeze_balance_v2_contract.resource)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.freeze_balance_v2_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.freeze_balance_v2_contract.owner_address);
    content->amount[0] = (uint64_t) msg.freeze_balance_v2_contract.frozen_balance;
    content->resource = msg.freeze_balance_v2_contract.resource;
    return true;
}

static bool unfreeze_balance_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnfreezeBalanceV2Contract_fields,
                   &msg.unfreeze_balance_v2_contract)) {
        return false;
    }
    if (msg.unfreeze_balance_v2_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    if (msg.unfreeze_balance_v2_contract.unfreeze_balance <= 0) {
        return false;
    }
    if (!is_stake_resource(msg.unfreeze_balance_v2_contract.resource)) {
        return false;
    }

    content->resource = msg.unfreeze_balance_v2_contract.resource;
    content->amount[0] = (uint64_t) msg.unfreeze_balance_v2_contract.unfreeze_balance;

    COPY_ADDRESS(content->account, &msg.unfreeze_balance_v2_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.unfreeze_balance_v2_contract.owner_address);
    return true;
}

static bool withdraw_expire_unfreeze_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_WithdrawExpireUnfreezeContract_fields,
                   &msg.withdraw_expire_unfreeze_contract)) {
        return false;
    }
    if (!is_mainnet_address(msg.withdraw_expire_unfreeze_contract.owner_address)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.withdraw_expire_unfreeze_contract.owner_address);
    return true;
}

static bool cancel_all_unfreeze_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_CancelAllUnfreezeV2Contract_fields,
                   &msg.cancel_all_unfreeze_v2_contract)) {
        return false;
    }
    // owner_address is a fixed_length 21-byte field, so nanopb already guarantees
    // the length; additionally require the 0x41 mainnet prefix to match java-tron
    // DecodeUtil.addressValid (CancelAllUnfreezeV2Actuator.validate).
    if (msg.cancel_all_unfreeze_v2_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.cancel_all_unfreeze_v2_contract.owner_address);
    return true;
}

static bool update_brokerage_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UpdateBrokerageContract_fields,
                   &msg.update_brokerage_contract)) {
        return false;
    }
    // owner_address is a fixed_length 21-byte field; additionally require the 0x41
    // mainnet prefix to match java-tron DecodeUtil.addressValid.
    if (msg.update_brokerage_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    // brokerage is a percentage in [0, 100] (java-tron UpdateBrokerageActuator.validate,
    // ActuatorConstant.ONE_HUNDRED).
    if (msg.update_brokerage_contract.brokerage < 0 ||
        msg.update_brokerage_contract.brokerage > 100) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.update_brokerage_contract.owner_address);
    content->amount[0] = (uint64_t) msg.update_brokerage_contract.brokerage;
    return true;
}

static bool delegate_resource_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_DelegateResourceContract_fields,
                   &msg.delegate_resource_contract)) {
        return false;
    }
    const bool lock = msg.delegate_resource_contract.lock;
    const int64_t lock_period = msg.delegate_resource_contract.lock_period;

    if ((msg.delegate_resource_contract.balance < 1000000) ||
        !is_mainnet_address(msg.delegate_resource_contract.owner_address) ||
        !is_mainnet_address(msg.delegate_resource_contract.receiver_address) ||
        !is_delegatable_resource(msg.delegate_resource_contract.resource) ||
        (lock && (lock_period < 0)) ||
        (memcmp(msg.delegate_resource_contract.owner_address,
                msg.delegate_resource_contract.receiver_address,
                ADDRESS_SIZE) == 0)) {
        return false;
    }
    content->resource = msg.delegate_resource_contract.resource;
    content->amount[0] = (uint64_t) msg.delegate_resource_contract.balance;
    content->lock = lock;
    // java-tron treats an omitted/zero lock_period as the mainnet default of
    // 259200000 ms / 3-second blocks = 86400 blocks.
    content->lockPeriod =
        (lock && (lock_period == 0)) ? DEFAULT_DELEGATE_LOCK_PERIOD_BLOCKS : lock_period;

    COPY_ADDRESS(content->account, &msg.delegate_resource_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.delegate_resource_contract.receiver_address);
    return true;
}

static bool undelegate_resource_contrace(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UnDelegateResourceContract_fields,
                   &msg.undelegate_resource_contract)) {
        return false;
    }
    if ((msg.undelegate_resource_contract.balance <= 0) ||
        !is_mainnet_address(msg.undelegate_resource_contract.owner_address) ||
        !is_mainnet_address(msg.undelegate_resource_contract.receiver_address) ||
        !is_delegatable_resource(msg.undelegate_resource_contract.resource) ||
        (memcmp(msg.undelegate_resource_contract.owner_address,
                msg.undelegate_resource_contract.receiver_address,
                ADDRESS_SIZE) == 0)) {
        return false;
    }
    content->resource = msg.undelegate_resource_contract.resource;
    content->amount[0] = (uint64_t) msg.undelegate_resource_contract.balance;

    COPY_ADDRESS(content->account, &msg.undelegate_resource_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.undelegate_resource_contract.receiver_address);
    return true;
}

static bool withdraw_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_WithdrawBalanceContract_fields,
                   &msg.withdraw_balance_contract)) {
        return false;
    }
    if (!is_mainnet_address(msg.withdraw_balance_contract.owner_address)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.withdraw_balance_contract.owner_address);
    return true;
}

static bool proposal_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!proposal_parameters_init()) {
        return false;
    }
    msg.proposal_create_contract.parameters.funcs.decode = pb_decode_proposal_parameter;
    msg.proposal_create_contract.parameters.arg = NULL;

    if (!pb_decode(stream, protocol_ProposalCreateContract_fields, &msg.proposal_create_contract)) {
        proposal_parameters_cleanup();
        return false;
    }

    if (msg.proposal_create_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        proposal_parameters_cleanup();
        return false;
    }
    if (decoded_proposal_parameters_count == 0) {
        proposal_parameters_cleanup();
        return false;
    }
    content->amount[0] = decoded_proposal_parameters_count;
    COPY_ADDRESS(content->account, &msg.proposal_create_contract.owner_address);
    return true;
}

static bool proposal_approve_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ProposalApproveContract_fields,
                   &msg.proposal_approve_contract)) {
        return false;
    }

    if (msg.proposal_approve_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    if (msg.proposal_approve_contract.proposal_id <= 0) {
        return false;
    }

    content->exchangeID = (uint64_t) msg.proposal_approve_contract.proposal_id;
    content->amount[0] = msg.proposal_approve_contract.is_add_approval ? 1 : 0;
    COPY_ADDRESS(content->account, &msg.proposal_approve_contract.owner_address);
    return true;
}

static bool proposal_delete_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ProposalDeleteContract_fields, &msg.proposal_delete_contract)) {
        return false;
    }

    if (msg.proposal_delete_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    if (msg.proposal_delete_contract.proposal_id <= 0) {
        return false;
    }

    content->exchangeID = (uint64_t) msg.proposal_delete_contract.proposal_id;
    COPY_ADDRESS(content->account, &msg.proposal_delete_contract.owner_address);
    return true;
}

static bool account_name_is_printable(const uint8_t *name, size_t name_len) {
    for (size_t i = 0; i < name_len; i++) {
        if ((name[i] < 0x20) || (name[i] > 0x7e)) {
            return false;
        }
    }
    return true;
}

static bool set_account_name_display(txContent_t *content, const uint8_t *name, size_t name_len) {
    content->accountNameLength = name_len;
    if (name_len == 0) {
        strlcpy(content->accountName, "(empty)", sizeof(content->accountName));
        return true;
    }

    if (account_name_is_printable(name, name_len)) {
        memcpy(content->accountName, name, name_len);
        content->accountName[name_len] = '\0';
        return true;
    }

    return bytes_to_string(content->accountName, sizeof(content->accountName), name, name_len) == 0;
}

static bool pb_decode_account_name(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    UNUSED(field);

    size_t name_len = stream->bytes_left;
    if (name_len > MAX_ACCOUNT_NAME_SIZE) {
        return false;
    }

    txContent_t *content = *arg;
    uint8_t name[MAX_ACCOUNT_NAME_SIZE];

    if (!pb_read(stream, name, name_len)) {
        return false;
    }

    return set_account_name_display(content, name, name_len);
}

static bool account_update_contract(txContent_t *content, pb_istream_t *stream) {
    content->accountName[0] = '\0';
    content->accountNameLength = 0;
    msg.account_update_contract.account_name.funcs.decode = pb_decode_account_name;
    msg.account_update_contract.account_name.arg = content;

    if (!pb_decode(stream, protocol_AccountUpdateContract_fields, &msg.account_update_contract)) {
        return false;
    }
    if (msg.account_update_contract.owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    if (content->accountName[0] == '\0' && !set_account_name_display(content, NULL, 0)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.account_update_contract.owner_address);
    return true;
}

static bool set_account_id_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_SetAccountIdContract_fields, &msg.set_account_id_contract)) {
        return false;
    }

    protocol_SetAccountIdContract *contract = &msg.set_account_id_contract;
    if (contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }

    // Match java-tron TransactionUtil.validAccountId(): 8..32 readable ASCII
    // bytes, where the accepted range is '!' (0x21) through '~' (0x7e).
    if ((contract->account_id.size < MIN_ACCOUNT_ID_SIZE) ||
        (contract->account_id.size > MAX_ACCOUNT_ID_SIZE)) {
        return false;
    }
    for (pb_size_t i = 0; i < contract->account_id.size; i++) {
        uint8_t byte = contract->account_id.bytes[i];
        if ((byte < 0x21) || (byte > 0x7e)) {
            return false;
        }
    }

    // AccountUpdateContract and SetAccountIdContract are mutually exclusive,
    // so reuse the existing display buffer instead of increasing txContent_t.
    memcpy(content->accountName, contract->account_id.bytes, contract->account_id.size);
    content->accountName[contract->account_id.size] = '\0';
    content->accountNameLength = contract->account_id.size;
    COPY_ADDRESS(content->account, &contract->owner_address);
    return true;
}

bool pb_decode_trigger_smart_contract_data(pb_istream_t *stream,
                                           const pb_field_t *field,
                                           void **arg) {
    UNUSED(field);

    if (stream->bytes_left < 4) {
        return false;
    }

    txContent_t *content = *arg;
    uint8_t buf[32];  // a single encoded TVM value

    // method selector
    if (!pb_read(stream, buf, 4)) {
        return false;
    }

    content->customSelector = U4BE(buf, 0);

    if (memcmp(buf, SELECTOR[0], 4) == 0) {
        content->TRC20Method = 1;  // a9059cbb -> transfer(address,uint256)
    } else if (memcmp(buf, SELECTOR[1], 4) == 0) {
        content->TRC20Method = 2;  // 095ea7b3 -> approve(address,uint256)
    } else {
        // arbitrary contracts
        if (stream->bytes_left % 32 != 0) {
            return false;
        }
        content->TRC20Method = 0;
        // consume this field
        return pb_read(stream, NULL, stream->bytes_left);
    }

    // TRC20 data size check: 32 + 32
    if (stream->bytes_left != 32 + 32) {
        return false;
    }

    // to address
    if (!pb_read(stream, buf, 32)) {
        return false;
    }
    /* A canonical ABI address word is twelve zero bytes followed by the
     * twenty-byte EVM address. Silently discarding non-zero high bytes would
     * make the reviewed address differ from the signed calldata. */
    if (!allzeroes(buf, 12U)) {
        return false;
    }
    memcpy(content->destination, buf + (32 - 21), ADDRESS_SIZE);
    // fix address prefix 0x41: mainnet
    content->destination[0] = ADD_PRE_FIX_BYTE_MAINNET;

    // amount
    if (!pb_read(stream, buf, 32)) {
        return false;
    }
    memmove(content->TRC20Amount, buf, 32);

    return true;
}

static bool validate_create_smart_contract(
    const protocol_CreateSmartContract *contract) {
    const protocol_SmartContract *new_contract = &contract->new_contract;

    if (!contract->has_new_contract ||
        (contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (new_contract->origin_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (memcmp(contract->owner_address, new_contract->origin_address, ADDRESS_SIZE) != 0) ||
        (new_contract->contract_address.size != 0) || (new_contract->code_hash.size != 0) ||
        (new_contract->trx_hash.size != 0) || (new_contract->version != 0) ||
        (new_contract->call_value < 0) ||
        (new_contract->consume_user_resource_percent < 0) ||
        (new_contract->consume_user_resource_percent > 100) ||
        (new_contract->origin_energy_limit <= 0) || (contract->call_token_value < 0) ||
        (contract->token_id < 0) ||
        ((contract->token_id != 0) && (contract->token_id <= MIN_TRC10_TOKEN_ID)) ||
        ((contract->call_token_value > 0) && (contract->token_id == 0))) {
        return false;
    }

    return true;
}

static bool trigger_smart_contract(txContent_t *content, pb_istream_t *stream) {
    msg.trigger_smart_contract.data.funcs.decode = pb_decode_trigger_smart_contract_data;
    msg.trigger_smart_contract.data.arg = content;

    if (!pb_decode(stream, protocol_TriggerSmartContract_fields, &msg.trigger_smart_contract)) {
        return false;
    }
    const int64_t call_value = msg.trigger_smart_contract.call_value;
    const int64_t token_value = msg.trigger_smart_contract.call_token_value;
    const int64_t token_id = msg.trigger_smart_contract.token_id;

    /* Mainnet currently has allowTvmTransferTrc10=1 and allowMultiSign=1.
     * Mirror VMActuator.checkTokenValueAndId() before deciding whether this
     * call can be clear-signed as a simple TRC20 operation. */
    if ((call_value < 0) || (token_value < 0) || (token_id < 0) ||
        ((token_id != 0) && (token_id <= MIN_TRC10_TOKEN_ID)) ||
        ((token_value > 0) && (token_id == 0)) ||
        !is_mainnet_address(msg.trigger_smart_contract.owner_address) ||
        !is_mainnet_address(msg.trigger_smart_contract.contract_address)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
    COPY_ADDRESS(content->contractAddress, &msg.trigger_smart_contract.contract_address);
    content->amount[0] = (uint64_t) call_value;
    content->callTokenValue = (uint64_t) token_value;
    content->tokenId = (uint64_t) token_id;

    tokenDefinition_t *trc20 = getKnownToken(content);

    if (trc20 == NULL) {
        // treat unknown TRC20 token as arbitrary contract
        content->TRC20Method = 0;
        return true;
    }

    /* The legacy TRC20 review has a single Amount field for the calldata
     * transfer/approval. Until attached assets have dedicated review fields,
     * fail closed instead of hiding extra TRX/TRC10 value behind that page.
     * Reject token_id by itself too: the reviewed wire form must be canonical
     * for this clear-sign route. */
    if ((call_value != 0) || (token_value != 0) || (token_id != 0)) {
        return false;
    }

    content->decimals[0] = trc20->decimals;
    content->tokenNamesLength[0] = strlen(trc20->ticker);
    memmove(content->tokenNames[0], trc20->ticker, content->tokenNamesLength[0] + 1);

    return true;
}

static bool clear_abi_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ClearABIContract_fields, &msg.clear_abi_contract)) {
        return false;
    }

    protocol_ClearABIContract *contract = &msg.clear_abi_contract;
    if ((contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->contract_address[0] != ADD_PRE_FIX_BYTE_MAINNET)) {
        return false;
    }

    COPY_ADDRESS(content->account, &contract->owner_address);
    COPY_ADDRESS(content->contractAddress, &contract->contract_address);
    return true;
}

static bool update_setting_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UpdateSettingContract_fields,
                   &msg.update_setting_contract)) {
        return false;
    }

    protocol_UpdateSettingContract *contract = &msg.update_setting_contract;
    if ((contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->contract_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->consume_user_resource_percent < 0) ||
        (contract->consume_user_resource_percent > 100)) {
        return false;
    }

    COPY_ADDRESS(content->account, &contract->owner_address);
    COPY_ADDRESS(content->contractAddress, &contract->contract_address);
    content->amount[0] = (uint64_t) contract->consume_user_resource_percent;
    return true;
}

static bool update_energy_limit_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_UpdateEnergyLimitContract_fields,
                   &msg.update_energy_limit_contract)) {
        return false;
    }

    protocol_UpdateEnergyLimitContract *contract = &msg.update_energy_limit_contract;
    if ((contract->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->contract_address[0] != ADD_PRE_FIX_BYTE_MAINNET) ||
        (contract->origin_energy_limit <= 0)) {
        return false;
    }

    COPY_ADDRESS(content->account, &contract->owner_address);
    COPY_ADDRESS(content->contractAddress, &contract->contract_address);
    content->amount[0] = (uint64_t) contract->origin_energy_limit;
    return true;
}

static bool exchange_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ExchangeCreateContract_fields, &msg.exchange_create_contract)) {
        return false;
    }
    if (!is_mainnet_address(msg.exchange_create_contract.owner_address) ||
        (msg.exchange_create_contract.first_token_balance <= 0) ||
        (msg.exchange_create_contract.second_token_balance <= 0) ||
        ((msg.exchange_create_contract.first_token_id.size ==
          msg.exchange_create_contract.second_token_id.size) &&
         (memcmp(msg.exchange_create_contract.first_token_id.bytes,
                 msg.exchange_create_contract.second_token_id.bytes,
                 msg.exchange_create_contract.first_token_id.size) == 0))) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.exchange_create_contract.owner_address);

    if (!printTokenFromID(content->tokenNames[0],
                          sizeof(content->tokenNames[0]),
                          msg.exchange_create_contract.first_token_id.bytes,
                          msg.exchange_create_contract.first_token_id.size,
                          true)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    if (!printTokenFromID(content->tokenNames[1],
                          sizeof(content->tokenNames[1]),
                          msg.exchange_create_contract.second_token_id.bytes,
                          msg.exchange_create_contract.second_token_id.size,
                          true)) {
        return false;
    }
    content->tokenNamesLength[1] = strlen(content->tokenNames[1]);

    content->amount[0] = (uint64_t) msg.exchange_create_contract.first_token_balance;
    content->amount[1] = (uint64_t) msg.exchange_create_contract.second_token_balance;
    return true;
}

static bool exchange_inject_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream, protocol_ExchangeInjectContract_fields, &msg.exchange_inject_contract)) {
        return false;
    }
    if (!is_mainnet_address(msg.exchange_inject_contract.owner_address) ||
        (msg.exchange_inject_contract.exchange_id < 0) ||
        (msg.exchange_inject_contract.quant <= 0)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_inject_contract.owner_address);
    content->exchangeID = (uint64_t) msg.exchange_inject_contract.exchange_id;

    if (!printTokenFromID(content->tokenNames[0],
                          sizeof(content->tokenNames[0]),
                          msg.exchange_inject_contract.token_id.bytes,
                          msg.exchange_inject_contract.token_id.size,
                          true)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    content->amount[0] = (uint64_t) msg.exchange_inject_contract.quant;
    return true;
}

static bool exchange_withdraw_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ExchangeWithdrawContract_fields,
                   &msg.exchange_withdraw_contract)) {
        return false;
    }
    if (!is_mainnet_address(msg.exchange_withdraw_contract.owner_address) ||
        (msg.exchange_withdraw_contract.exchange_id < 0) ||
        (msg.exchange_withdraw_contract.quant <= 0)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_withdraw_contract.owner_address);
    content->exchangeID = (uint64_t) msg.exchange_withdraw_contract.exchange_id;

    if (!printTokenFromID(content->tokenNames[0],
                          sizeof(content->tokenNames[0]),
                          msg.exchange_withdraw_contract.token_id.bytes,
                          msg.exchange_withdraw_contract.token_id.size,
                          true)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    content->amount[0] = (uint64_t) msg.exchange_withdraw_contract.quant;
    return true;
}

static bool exchange_transaction_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode(stream,
                   protocol_ExchangeTransactionContract_fields,
                   &msg.exchange_transaction_contract)) {
        return false;
    }
    if (!is_mainnet_address(msg.exchange_transaction_contract.owner_address) ||
        (msg.exchange_transaction_contract.exchange_id < 0) ||
        (msg.exchange_transaction_contract.quant <= 0) ||
        (msg.exchange_transaction_contract.expected <= 0)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_transaction_contract.owner_address);
    content->exchangeID = (uint64_t) msg.exchange_transaction_contract.exchange_id;

    if (!printTokenFromID(content->tokenNames[0],
                          sizeof(content->tokenNames[0]),
                          msg.exchange_transaction_contract.token_id.bytes,
                          msg.exchange_transaction_contract.token_id.size,
                          true)) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    content->amount[0] = (uint64_t) msg.exchange_transaction_contract.quant;
    content->amount[1] = (uint64_t) msg.exchange_transaction_contract.expected;
    return true;
}

static bool permission_name_wire_is_safe(pb_istream_t *stream) {
    bool name_seen = false;

    while (stream->bytes_left > 0U) {
        pb_wire_type_t wire_type;
        uint32_t tag;
        bool eof = false;

        if (!pb_decode_tag(stream, &wire_type, &tag, &eof) || eof) {
            return false;
        }
        if (tag != protocol_Permission_permission_name_tag) {
            if (!pb_skip_field(stream, wire_type)) {
                return false;
            }
            continue;
        }
        if (name_seen || (wire_type != PB_WT_STRING)) {
            return false;
        }
        name_seen = true;

        pb_istream_t name_stream;
        if (!pb_make_string_substream(stream, &name_stream)) {
            return false;
        }
        const size_t name_len = name_stream.bytes_left;
        uint8_t name[32];
        if ((name_len > sizeof(name)) ||
            !pb_read(&name_stream, name, name_len) ||
            !is_printable((const char *) name, name_len) ||
            !pb_close_string_substream(stream, &name_stream)) {
            return false;
        }
    }
    return true;
}

static bool permission_names_wire_are_safe(pb_istream_t stream) {
    while (stream.bytes_left > 0U) {
        pb_wire_type_t wire_type;
        uint32_t tag;
        bool eof = false;

        if (!pb_decode_tag(&stream, &wire_type, &tag, &eof) || eof) {
            return false;
        }
        if ((tag != protocol_AccountPermissionUpdateContract_owner_tag) &&
            (tag != protocol_AccountPermissionUpdateContract_witness_tag) &&
            (tag != protocol_AccountPermissionUpdateContract_actives_tag)) {
            if (!pb_skip_field(&stream, wire_type)) {
                return false;
            }
            continue;
        }
        if (wire_type != PB_WT_STRING) {
            return false;
        }

        pb_istream_t permission_stream;
        if (!pb_make_string_substream(&stream, &permission_stream) ||
            !permission_name_wire_is_safe(&permission_stream) ||
            !pb_close_string_substream(&stream, &permission_stream)) {
            return false;
        }
    }
    return true;
}

// Validate a single Permission against java-tron's AccountPermissionUpdateActuator
// checkPermission() (static, chain-state-independent subset). `expected_type` is the
// PermissionType this slot must carry (Owner/Witness/Active).
static bool check_permission(const protocol_Permission *perm,
                             protocol_Permission_PermissionType expected_type) {
    if (perm->type != expected_type) {
        return false;
    }
    // keys_count: >0, and a Witness permission must have exactly 1 key.
    // (nanopb max_count already caps keys at 5 = default totalSignNum.)
    if (perm->keys_count == 0) {
        return false;
    }
    if (expected_type == protocol_Permission_PermissionType_Witness && perm->keys_count != 1) {
        return false;
    }
    if (perm->threshold <= 0) {
        return false;
    }
    // permission_name is a static char[33]; a name longer than 32 chars cannot be
    // represented, so nanopb rejects it before we get here.
    if (perm->parent_id != 0) {
        return false;
    }
    if (expected_type == protocol_Permission_PermissionType_Active) {
        if (perm->operations.size != 32) {
            return false;
        }
    } else if (perm->operations.size != 0) {
        return false;
    }

    int64_t weight_sum = 0;
    for (pb_size_t i = 0; i < perm->keys_count; i++) {
        const protocol_Key *key = &perm->keys[i];
        // key address: 21 bytes (fixed_length) + 0x41 mainnet prefix
        if (key->address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
            return false;
        }
        if (key->weight <= 0) {
            return false;
        }
        // key addresses must be distinct within the permission
        for (pb_size_t j = 0; j < i; j++) {
            if (memcmp(key->address, perm->keys[j].address, ADDRESS_SIZE) == 0) {
                return false;
            }
        }
        if (key->weight > (INT64_MAX - weight_sum)) {
            return false;
        }
        weight_sum += key->weight;
    }
    // sum of all key weights must be able to reach the threshold
    if (weight_sum < perm->threshold) {
        return false;
    }
    return true;
}

static bool account_permission_update_contract(txContent_t *content, pb_istream_t *stream) {
    protocol_AccountPermissionUpdateContract *c = &msg.account_permission_update_contract;

    /* Static nanopb strings do not retain their encoded length, so validate
     * the nested permission_name fields on a copy of the wire stream before
     * decoding them into NUL-terminated UI strings. */
    if (!permission_names_wire_are_safe(*stream)) {
        return false;
    }
    memset(c, 0, sizeof(*c));
    if (!pb_decode(stream, protocol_AccountPermissionUpdateContract_fields, c)) {
        return false;
    }

    // owner_address: 21 bytes (fixed_length) + 0x41 mainnet prefix
    if (c->owner_address[0] != ADD_PRE_FIX_BYTE_MAINNET) {
        return false;
    }
    // owner permission is required
    if (!c->has_owner || !check_permission(&c->owner, protocol_Permission_PermissionType_Owner)) {
        return false;
    }
    // witness permission is optional (present only for witness accounts); validate if given
    if (c->has_witness &&
        !check_permission(&c->witness, protocol_Permission_PermissionType_Witness)) {
        return false;
    }
    // actives: 1..8 (MAX_ACTIVE_PERMISSION_CNT); each must be an Active permission
    if (c->actives_count == 0) {
        return false;
    }
    for (pb_size_t i = 0; i < c->actives_count; i++) {
        if (!check_permission(&c->actives[i], protocol_Permission_PermissionType_Active)) {
            return false;
        }
    }

    COPY_ADDRESS(content->account, &c->owner_address);
    return true;
}

typedef struct {
    const uint8_t *buf;
    size_t size;
} pb_buffer_t;

bool pb_decode_contract_parameter(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    PB_UNUSED(field);
    pb_buffer_t *buffer = *arg;

    buffer->buf = stream->state;
    buffer->size = stream->bytes_left;
    return true;
}

bool pb_get_tx_data_size(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    PB_UNUSED(field);
    uint64_t *data_size = *arg;
    *data_size = (uint64_t) stream->bytes_left;
    return true;
}

static parserStatus_e prepare_contract_context(
    protocol_Transaction_Contract_ContractType type,
    int32_t permission_id,
    int64_t fee_limit,
    uint64_t custom_data_len,
    txContent_t *content) {
    if (content == NULL || permission_id < 0 || permission_id > UINT8_MAX) {
        return USTREAM_FAULT;
    }
    if (((type == protocol_Transaction_Contract_ContractType_CreateSmartContract) ||
         (type == protocol_Transaction_Contract_ContractType_TriggerSmartContract)) &&
        (fee_limit < 0)) {
        return USTREAM_FAULT;
    }

    content->dataBytes = custom_data_len;
    if (!N_storage.dataAllowed && content->dataBytes != 0) {
        return USTREAM_MISSING_SETTING_DATA_ALLOWED;
    }

    content->permission_id = (uint8_t) permission_id;
    content->contractType = (contractType_e) type;
    content->feeLimit = (uint64_t) fee_limit;
    memset(&msg, 0, sizeof(msg));
    return USTREAM_PROCESSING;
}

parserStatus_e processStreamedCreateSmartContract(
    int32_t permission_id,
    int64_t fee_limit,
    uint64_t custom_data_len,
    const create_smart_contract_stream_result_t *result,
    txContent_t *content) {
    if (result == NULL) {
        return USTREAM_FAULT;
    }

    parserStatus_e status = prepare_contract_context(
        protocol_Transaction_Contract_ContractType_CreateSmartContract,
        permission_id,
        fee_limit,
        custom_data_len,
        content);
    if (status != USTREAM_PROCESSING) {
        return status;
    }

    msg.create_smart_contract = result->contract;
    content->bytecodeSize = result->bytecode_size;
    memcpy(content->bytecodeHash, result->bytecode_hash, sizeof(content->bytecodeHash));
    if (!validate_create_smart_contract(&msg.create_smart_contract)) {
        return USTREAM_FAULT;
    }

    COPY_ADDRESS(content->account, &msg.create_smart_contract.owner_address);
    return USTREAM_PROCESSING;
}

parserStatus_e processContractParameter(
    protocol_Transaction_Contract_ContractType type,
    int32_t permission_id,
    int64_t fee_limit,
    const uint8_t *parameter,
    size_t parameter_len,
    uint64_t custom_data_len,
    txContent_t *content) {
    bool ret;

    if (parameter == NULL) {
        return USTREAM_FAULT;
    }

    parserStatus_e status =
        prepare_contract_context(type, permission_id, fee_limit, custom_data_len, content);
    if (status != USTREAM_PROCESSING) {
        return status;
    }
    pb_istream_t tx_stream = pb_istream_from_buffer(parameter, parameter_len);

    switch (type) {
        case protocol_Transaction_Contract_ContractType_AccountCreateContract:
            ret = account_create_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_AssetIssueContract:
            ret = asset_issue_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ParticipateAssetIssueContract:
            ret = participate_asset_issue_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UnfreezeAssetContract:
            ret = unfreeze_asset_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UpdateAssetContract:
            ret = update_asset_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_TransferContract:
            ret = transfer_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_TransferAssetContract:
            ret = transfer_asset_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_VoteWitnessContract:
            ret = vote_witness_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_FreezeBalanceContract:
            ret = freeze_balance_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UnfreezeBalanceContract:
            ret = unfreeze_balance_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_FreezeBalanceV2Contract:
            ret = freeze_balance_v2_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UnfreezeBalanceV2Contract:
            ret = unfreeze_balance_v2_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_WithdrawExpireUnfreezeContract:
            ret = withdraw_expire_unfreeze_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_DelegateResourceContract:
            ret = delegate_resource_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UnDelegateResourceContract:
            ret = undelegate_resource_contrace(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_WithdrawBalanceContract:
            ret = withdraw_balance_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ProposalCreateContract:
            ret = proposal_create_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ProposalApproveContract:
            ret = proposal_approve_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ProposalDeleteContract:
            ret = proposal_delete_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_AccountUpdateContract:
            ret = account_update_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_SetAccountIdContract:
            ret = set_account_id_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_CreateSmartContract:
            return USTREAM_FAULT;
        case protocol_Transaction_Contract_ContractType_TriggerSmartContract:
            ret = trigger_smart_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UpdateSettingContract:
            ret = update_setting_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UpdateEnergyLimitContract:
            ret = update_energy_limit_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ClearABIContract:
            ret = clear_abi_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ExchangeCreateContract:
            ret = exchange_create_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ExchangeInjectContract:
            ret = exchange_inject_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ExchangeWithdrawContract:
            ret = exchange_withdraw_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_ExchangeTransactionContract:
            ret = exchange_transaction_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_AccountPermissionUpdateContract:
            ret = account_permission_update_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_WitnessCreateContract:
            ret = witness_create_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_WitnessUpdateContract:
            ret = witness_update_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_CancelAllUnfreezeV2Contract:
            ret = cancel_all_unfreeze_v2_contract(content, &tx_stream);
            break;
        case protocol_Transaction_Contract_ContractType_UpdateBrokerageContract:
            ret = update_brokerage_contract(content, &tx_stream);
            break;
        default:
            return USTREAM_FAULT;
    }

    return ret ? USTREAM_PROCESSING : USTREAM_FAULT;
}

parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content) {
    protocol_Transaction_raw transaction;

    if (length == 0) {
        return USTREAM_FINISHED;
    }

    memset(&transaction, 0, sizeof(transaction));
    pb_istream_t stream = pb_istream_from_buffer(buffer, length);

    /* Set callbacks to retrieve "Contract" message bounds.
     * This is required because contract type is not necessarily parsed at the
     * time of the transaction is decoded (fields are not required to be ordered)
     * and deserializing the nested contract inside the message requires too much
     * stack for Nano S
     */
    pb_buffer_t contract_buffer = {0};
    transaction.contract->parameter.value.funcs.decode = pb_decode_contract_parameter;
    transaction.contract->parameter.value.arg = &contract_buffer;

    /* Set callback to determine if transaction contains custom data.
     * This allows to retrieve the size of arbitrary data. */
    transaction.custom_data.funcs.decode = pb_get_tx_data_size;
    transaction.custom_data.arg = &content->dataBytes;

    if (!pb_decode(&stream, protocol_Transaction_raw_fields, &transaction)) {
        return USTREAM_FAULT;
    }

    /* Parse contract parameters if any...
       and it may come in different message chunk
       so test if chunk has the contract
     */
    if (transaction.contract->has_parameter) {
        /* `parameter.value` is optional in protobuf. If it was omitted, the
         * decode callback above was never called and there is no contract
         * payload to parse. Do not construct a stream from an unset pointer. */
        if (contract_buffer.buf == NULL) {
            return USTREAM_FAULT;
        }
        return processContractParameter(transaction.contract->type,
                                        transaction.contract->Permission_id,
                                        transaction.fee_limit,
                                        contract_buffer.buf,
                                        contract_buffer.size,
                                        content->dataBytes,
                                        content);
    }

    return USTREAM_PROCESSING;
}

int bytes_to_string(char *out, size_t outl, const void *value, size_t len) {
    if (outl <= 2) {
        // Need at least '0x' and 1 digit
        return -1;
    }
    if (strlcpy(out, "0x", outl) != 2) {
        goto err;
    }
    if (format_hex(value, len, out + 2, outl - 2) < 0) {
        goto err;
    }
    return 0;
err:
    *out = '\0';
    return -1;
}

void forget_known_assets(void) {
    memset(tmpCtx.transactionContext.assetSet, false, MAX_ASSETS);
    memset(tmpCtx.transactionContext.assetKind,
           ASSET_KIND_NONE,
           sizeof(tmpCtx.transactionContext.assetKind));
    tmpCtx.transactionContext.currentAssetIndex = 0;
}

static extraInfo_t *get_asset_info(int index) {
    if ((index < 0) || (index >= MAX_ASSETS)) {
        return NULL;
    }
    return &tmpCtx.transactionContext.extraInfo[index];
}

static bool asset_info_is_kind(int index, asset_kind_t kind) {
    if ((index < 0) || (index >= MAX_ASSETS)) {
        return false;
    }
    return tmpCtx.transactionContext.assetSet[index] &&
           (tmpCtx.transactionContext.assetKind[index] == kind);
}

bool asset_slot_is_kind(uint8_t index, asset_kind_t kind) {
    return asset_info_is_kind(index, kind);
}

static int get_asset_index_by_canonical_addr(const uint8_t *addr, asset_kind_t kind) {
    if (addr == NULL) {
        return -1;
    }

    for (int i = 0; i < MAX_ASSETS; i++) {
        extraInfo_t *asset = get_asset_info(i);
        if (asset_info_is_kind(i, kind) &&
            (memcmp(asset->token.address, addr, ADDRESS_LENGTH) == 0)) {
            PRINTF("Asset kind %u found at index %d\n", kind, i);
            return i;
        }
    }
    return -1;
}

static int get_asset_index_by_addr_and_kind(const uint8_t *addr, asset_kind_t kind) {
    // All clear-sign consumers normalize contract addresses to the canonical
    // 20-byte EVM form before lookup. Do not infer a 21-byte TRON address from
    // addr[0]: a valid 20-byte contract can itself start with 0x41.
    return get_asset_index_by_canonical_addr(addr, kind);
}

int get_token_index_by_addr(const uint8_t *addr) {
    return get_asset_index_by_addr_and_kind(addr, ASSET_KIND_TOKEN);
}

const tokenDefinition_t *get_token_info_by_addr(const uint8_t *addr) {
    extraInfo_t *asset = get_asset_info(get_token_index_by_addr(addr));
    return (asset == NULL) ? NULL : &asset->token;
}

#ifndef TARGET_NANOS
const nftInfo_t *get_nft_info_by_addr(const uint8_t *addr) {
    extraInfo_t *asset =
        get_asset_info(get_asset_index_by_addr_and_kind(addr, ASSET_KIND_NFT));
    return (asset == NULL) ? NULL : &asset->nft;
}
#endif

int commit_current_asset_info(asset_kind_t kind, const extraInfo_t *candidate) {
    uint8_t index = tmpCtx.transactionContext.currentAssetIndex;
    extraInfo_t *destination;

    if ((candidate == NULL) || (index >= MAX_ASSETS) ||
        ((kind != ASSET_KIND_TOKEN) && (kind != ASSET_KIND_NFT))) {
        return -1;
    }
    destination = get_asset_info(index);
    if (destination == NULL) {
        return -1;
    }

    memcpy(destination, candidate, sizeof(*destination));
    tmpCtx.transactionContext.assetKind[index] = kind;
    tmpCtx.transactionContext.assetSet[index] = true;
    tmpCtx.transactionContext.currentAssetIndex = (index + 1U) % MAX_ASSETS;
    return index;
}
