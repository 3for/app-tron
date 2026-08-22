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

#include <string.h>

#include "pb.h"
#include "misc/TronApp.pb.h"
#include "exchange_serialization.h"
#include "format.h"
#include "parse.h"
#include "protobuf_validation.h"
#include "settings.h"
#include "tokens.h"

// java-tron reserves IDs up to and including 1,000,000. A non-zero TRC10
// token ID carried by TriggerSmartContract must be above that boundary.
#define MAX_RESERVED_TRC10_TOKEN_ID 1000000

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

/**
 * Adjusts a numeric string by adding a decimal point at the specified position and trimming
 * trailing zeros.
 *
 * @param[in] src
 *   Pointer to the source numeric string.
 * @param[in] srcLength
 *   Length of the number as the number of actual characters (not the size of the buffer).
 * @param[out] target
 *   Pointer to the buffer where the adjusted string will be stored.
 * @param[in] targetLength
 *   Size of the target buffer.
 * @param[in] decimals
 *   Number of decimal places to shift.
 *
 * @return
 *   True if successful, false otherwise (e.g., if the target buffer is too small).
 */
bool adjustDecimals(const char *src,
                    uint32_t srcLength,
                    char *target,
                    uint32_t targetLength,
                    uint8_t decimals) {
    uint32_t startOffset;
    uint32_t lastZeroOffset = 0;
    uint32_t offset = 0;

    if ((srcLength == 1) && (*src == '0')) {
        if (targetLength < 2) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '\0';
        return true;
    }
    if (srcLength <= decimals) {
        uint32_t delta = decimals - srcLength;
        if (targetLength < srcLength + 1 + 2 + delta) {
            return false;
        }
        target[offset++] = '0';
        target[offset++] = '.';
        for (uint32_t i = 0; i < delta; i++) {
            target[offset++] = '0';
        }
        startOffset = offset;
        for (uint32_t i = 0; i < srcLength; i++) {
            target[offset++] = src[i];
        }
        target[offset] = '\0';
    } else {
        uint32_t sourceOffset = 0;
        uint32_t delta = srcLength - decimals;
        if (targetLength < srcLength + 1 + 1) {
            return false;
        }
        while (offset < delta) {
            target[offset++] = src[sourceOffset++];
        }
        if (decimals != 0) {
            target[offset++] = '.';
        }
        startOffset = offset;
        while (sourceOffset < srcLength) {
            target[offset++] = src[sourceOffset++];
        }
        target[offset] = '\0';
    }
    for (uint32_t i = startOffset; i < offset; i++) {
        if (target[i] == '0') {
            if (lastZeroOffset == 0) {
                lastZeroOffset = i;
            }
        } else {
            lastZeroOffset = 0;
        }
    }
    if (lastZeroOffset != 0) {
        target[lastZeroOffset] = '\0';
        if (target[lastZeroOffset - 1] == '.') {
            target[lastZeroOffset - 1] = '\0';
        }
    }
    return true;
}
unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun) {
    char tmp[21];
    char tmp2[25];
    uint32_t numDigits = 0;

    if ((out == NULL) || (outlen == 0)) {
        return 0;
    }

    // Extract at most 20 uint64_t digits without multiplying a same-width
    // base that can wrap to zero and make the old loop non-terminating.
    if (amount == 0) {
        // Keep the existing fixed-decimal representation (for example,
        // "0.000000" TRX) by passing an empty digit sequence to adjustDecimals.
        tmp[0] = '\0';
    } else {
        do {
            tmp[numDigits++] = '0' + (amount % 10);
            amount /= 10;
        } while (amount != 0);
    }

    for (uint32_t i = 0; i < numDigits / 2; i++) {
        char digit = tmp[i];
        tmp[i] = tmp[numDigits - i - 1];
        tmp[numDigits - i - 1] = digit;
    }
    tmp[numDigits] = '\0';

    if (!adjustDecimals(tmp, numDigits, tmp2, sizeof(tmp2), sun)) {
        out[0] = '\0';
        return 0;
    }

    // Preserve the caller contract of leaving one spare byte in addition to
    // the terminator.
    if ((outlen > 1) && (strlen(tmp2) < outlen - 1)) {
        strlcpy(out, tmp2, outlen);
    } else {
        out[0] = '\0';
    }
    return strlen(out);
}

bool setContractType(contractType_e type, char *out, size_t outlen) {
    switch (type) {
        case ACCOUNTCREATECONTRACT:
            strlcpy(out, "Account Create", outlen);
            break;
        case TRANSFERCONTRACT:
            strlcpy(out, "TRX Transfer", outlen);
            break;
        case TRANSFERASSETCONTRACT:
            strlcpy(out, "TRC10 Transfer", outlen);
            break;
        case VOTEASSETCONTRACT:
            strlcpy(out, "Vote Asset", outlen);
            break;
        case VOTEWITNESSCONTRACT:
            strlcpy(out, "Vote Witness", outlen);
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
        case FREEZEBALANCECONTRACT:
            strlcpy(out, "Freeze Balance", outlen);
            break;
        case UNFREEZEBALANCECONTRACT:
            strlcpy(out, "Unfreeze Balance", outlen);
            break;
        case UNFREEZEBALANCEV2CONTRACT:
            strlcpy(out, "UnfreezeV2 Balance", outlen);
            break;
        case FREEZEBALANCEV2CONTRACT:
            strlcpy(out, "FreezeV2 Balance", outlen);
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
        case TRIGGERSMARTCONTRACT:
            strlcpy(out, "Smart Contract", outlen);
            break;
        case EXCHANGECREATECONTRACT:
            strlcpy(out, "Exchange Create", outlen);
            break;
        case EXCHANGEINJECTCONTRACT:
            strlcpy(out, "Exchange Inject", outlen);
            break;
        case EXCHANGEWITHDRAWCONTRACT:
            strlcpy(out, "Exchange Withdraw", outlen);
            break;
        case EXCHANGETRANSACTIONCONTRACT:
            strlcpy(out, "Exchange Transaction", outlen);
            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
            strlcpy(out, "Permission Update", outlen);
            break;
        case DELEGATERESOURCECONTRACT:
            strlcpy(out, "Delegate Resource", outlen);
            break;
        case UNDELEGATERESOURCECONTRACT:
            strlcpy(out, "Undelegate Resource", outlen);
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

// ALLOW SAME NAME TOKEN
// CHECK SIGNATURE(ID+NAME+PRECISION)
// Parse token Name and Signature
bool parseTokenName(uint8_t token_id, uint8_t *data, uint32_t dataLength, txContent_t *content) {
    TokenDetails details = {};

    pb_istream_t stream = pb_istream_from_buffer(data, dataLength);
    if (!pb_decode(&stream, TokenDetails_fields, &details)) {
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
    char tmp[MAX_TOKEN_LENGTH];
    snprintf(tmp, MAX_TOKEN_LENGTH, "%s[%s]", details.name, content->tokenNames[token_id]);
    content->tokenNamesLength[token_id] = strlen((const char *) tmp);
    strlcpy(content->tokenNames[token_id], tmp, MAX_TOKEN_LENGTH);
    content->decimals[token_id] = details.precision;
    return true;
}

static bool printTokenFromID(char *out,
                             size_t outlen,
                             const uint8_t *data,
                             size_t size,
                             bool *is_native) {
    *is_native = false;
    if ((size == 0u) || (size > TOKEN_ID_MAX_LENGTH) || (outlen <= size)) {
        return false;
    }

    if (size == 1) {
        if (data[0] != '_') {
            return false;
        }
        *is_native = true;
        strlcpy(out, "TRX", outlen);
        return true;
    }
    if ((size > 1u) && (data[0] == '0')) {
        return false;
    }
    for (size_t i = 0; i < size; i++) {
        if ((data[i] < '0') || (data[i] > '9')) {
            return false;
        }
    }
    memcpy(out, data, size);
    out[size] = '\0';
    return true;
}

static bool set_token_info(txContent_t *content,
                           unsigned int token_index,
                           const char *name,
                           const char *id,
                           int precision) {
    if (token_index >= 2) {
        return false;
    }

    /* Ugly, but snprintf does not have a return value... */
    snprintf((char *) content->tokenNames[token_index], MAX_TOKEN_LENGTH, "%s[%s]", name, id);
    content->tokenNamesLength[token_index] = strlen((char *) content->tokenNames[token_index]);
    content->decimals[token_index] = precision;
    return true;
}

// Parse token names and verify either the canonical v1 signed payload or a
// strictly validated, unambiguous legacy payload during migration.
bool parseExchange(const uint8_t *data, size_t length, txContent_t *content) {
    ExchangeDetails details = ExchangeDetails_init_zero;
    uint8_t buffer[EXCHANGE_SIGNATURE_PAYLOAD_MAX_SIZE];

    pb_istream_t stream = pb_istream_from_buffer(data, length);
    if (!pb_decode(&stream, ExchangeDetails_fields, &details)) {
        return false;
    }

    if (content->exchangeID != details.exchangeId) {
        return false;
    }

    size_t msg_size;
    if (!serialize_exchange_signature_payload(buffer,
                                              sizeof(buffer),
                                              &msg_size,
                                              details.exchangeId,
                                              details.token1Id,
                                              details.token1Name,
                                              details.token1Precision,
                                              details.token2Id,
                                              details.token2Name,
                                              details.token2Precision)) {
        return false;
    }

    if (!verifyExchangeID(buffer, msg_size, details.signature.bytes, details.signature.size)) {
        if (!serialize_legacy_exchange_signature_payload(buffer,
                                                         sizeof(buffer),
                                                         &msg_size,
                                                         details.exchangeId,
                                                         details.token1Id,
                                                         details.token1Name,
                                                         details.token1Precision,
                                                         details.token2Id,
                                                         details.token2Name,
                                                         details.token2Precision) ||
            !verifyExchangeID(buffer, msg_size, details.signature.bytes, details.signature.size)) {
            return false;
        }
    }

    int first_token = 0, second_token = 0;
    if (strcmp((char *) content->tokenNames[0], details.token1Id) == 0) {
        first_token = 0;
        second_token = 1;
    } else if (strcmp((char *) content->tokenNames[0], details.token2Id) == 0) {
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

contract_t msg;

void initTx(txContext_t *context, txContent_t *content) {
    memset(context, 0, sizeof(txContext_t));
    memset(content, 0, sizeof(txContent_t));
    // The decoded contract is consumed when the complete, cumulatively hashed
    // transaction is reviewed. Keep it for the same signing-session lifetime
    // so a trailing APDU containing only other top-level fields cannot erase it.
    memset(&msg, 0, sizeof(msg));
    context->initialized = true;
    content->contractType = INVALID_CONTRACT;
    cx_sha256_init(&context->sha2);  // init sha
}

#define COPY_ADDRESS(a, b) memcpy((a), (b), ADDRESS_SIZE)

static bool copy_nonnegative_int64(uint64_t *destination, int64_t value) {
    if (value < 0) {
        return false;
    }
    *destination = (uint64_t) value;
    return true;
}

static bool transfer_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_TransferContract_fields,
                               &msg.transfer_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    if (!copy_nonnegative_int64(&content->amount[0], msg.transfer_contract.amount)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.transfer_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.transfer_contract.to_address);

    content->tokenNamesLength[0] = 4;
    strcpy(content->tokenNames[0], "TRX");
    return true;
}

static bool transfer_asset_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_TransferAssetContract_fields,
                               &msg.transfer_asset_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    if (!copy_nonnegative_int64(&content->amount[0], msg.transfer_asset_contract.amount)) {
        return false;
    }

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.transfer_asset_contract.asset_name.bytes,
                          msg.transfer_asset_contract.asset_name.size,
                          &content->tokenIsNative[0])) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    COPY_ADDRESS(content->account, &msg.transfer_asset_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.transfer_asset_contract.to_address);
    return true;
}

static bool vote_witness_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_VoteWitnessContract_fields,
                               &msg.vote_witness_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    for (pb_size_t i = 0; i < msg.vote_witness_contract.votes_count; i++) {
        if (msg.vote_witness_contract.votes[i].vote_count < 0) {
            return false;
        }
    }

    COPY_ADDRESS(content->account, &msg.vote_witness_contract.owner_address);
    return true;
}

static bool freeze_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_FreezeBalanceContract_fields,
                               &msg.freeze_balance_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    /* Tron only accepts 3 days freezing */
    if (msg.freeze_balance_contract.frozen_duration != 3) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.freeze_balance_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.freeze_balance_contract.receiver_address);
    if (!copy_nonnegative_int64(&content->amount[0], msg.freeze_balance_contract.frozen_balance)) {
        return false;
    }
    content->resource = msg.freeze_balance_contract.resource;
    return true;
}

static bool unfreeze_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_UnfreezeBalanceContract_fields,
                               &msg.unfreeze_balance_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    content->resource = msg.unfreeze_balance_contract.resource;

    COPY_ADDRESS(content->account, &msg.unfreeze_balance_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.unfreeze_balance_contract.receiver_address);
    return true;
}

static bool freeze_balance_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_FreezeBalanceV2Contract_fields,
                               &msg.freeze_balance_v2_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.freeze_balance_v2_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.freeze_balance_v2_contract.owner_address);
    if (!copy_nonnegative_int64(&content->amount[0],
                                msg.freeze_balance_v2_contract.frozen_balance)) {
        return false;
    }
    content->resource = msg.freeze_balance_v2_contract.resource;
    return true;
}

static bool unfreeze_balance_v2_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_UnfreezeBalanceV2Contract_fields,
                               &msg.unfreeze_balance_v2_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    content->resource = msg.unfreeze_balance_v2_contract.resource;
    if (!copy_nonnegative_int64(&content->amount[0],
                                msg.unfreeze_balance_v2_contract.unfreeze_balance)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.unfreeze_balance_v2_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.unfreeze_balance_v2_contract.owner_address);
    return true;
}

static bool withdraw_expire_unfreeze_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_WithdrawExpireUnfreezeContract_fields,
                               &msg.withdraw_expire_unfreeze_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.withdraw_expire_unfreeze_contract.owner_address);
    return true;
}

static bool delegate_resource_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_DelegateResourceContract_fields,
                               &msg.delegate_resource_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    content->resource = msg.delegate_resource_contract.resource;
    if (!copy_nonnegative_int64(&content->amount[0], msg.delegate_resource_contract.balance)) {
        return false;
    }
    content->customData = msg.delegate_resource_contract.lock;
    content->lockPeriod = msg.delegate_resource_contract.lock_period;

    COPY_ADDRESS(content->account, &msg.delegate_resource_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.delegate_resource_contract.receiver_address);
    return true;
}

static bool undelegate_resource_contrace(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_UnDelegateResourceContract_fields,
                               &msg.undelegate_resource_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    content->resource = msg.undelegate_resource_contract.resource;
    if (!copy_nonnegative_int64(&content->amount[0], msg.undelegate_resource_contract.balance)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.undelegate_resource_contract.owner_address);
    COPY_ADDRESS(content->destination, &msg.undelegate_resource_contract.receiver_address);
    return true;
}

static bool withdraw_balance_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_WithdrawBalanceContract_fields,
                               &msg.withdraw_balance_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.withdraw_balance_contract.owner_address);
    return true;
}

static bool proposal_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ProposalCreateContract_fields,
                               &msg.proposal_create_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    content->amount[0] = msg.proposal_create_contract.parameters_count;
    COPY_ADDRESS(content->account, &msg.proposal_create_contract.owner_address);
    return true;
}

static bool proposal_approve_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ProposalApproveContract_fields,
                               &msg.proposal_approve_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.proposal_approve_contract.owner_address);
    return true;
}

static bool proposal_delete_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ProposalDeleteContract_fields,
                               &msg.proposal_delete_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    if (!copy_nonnegative_int64(&content->exchangeID, msg.proposal_delete_contract.proposal_id)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.proposal_delete_contract.owner_address);
    return true;
}

static bool account_update_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_AccountUpdateContract_fields,
                               &msg.account_update_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.account_update_contract.owner_address);
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

static bool trigger_smart_contract(txContent_t *content, pb_istream_t *stream) {
    msg.trigger_smart_contract.data.funcs.decode = pb_decode_trigger_smart_contract_data;
    msg.trigger_smart_contract.data.arg = content;

    if (!pb_decode_transaction(stream,
                               protocol_TriggerSmartContract_fields,
                               &msg.trigger_smart_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    const int64_t call_value = msg.trigger_smart_contract.call_value;
    const int64_t call_token_value = msg.trigger_smart_contract.call_token_value;
    const int64_t token_id = msg.trigger_smart_contract.token_id;

    // Validate signed protobuf values before converting them to uint64_t.
    // call_token_value without a token_id cannot identify the transferred
    // asset, and IDs in java-tron's reserved range are not valid TRC10 IDs.
    if ((call_value < 0) || (call_token_value < 0) || (token_id < 0) ||
        ((token_id != 0) && (token_id <= MAX_RESERVED_TRC10_TOKEN_ID)) ||
        ((call_token_value > 0) && (token_id == 0))) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.trigger_smart_contract.owner_address);
    COPY_ADDRESS(content->contractAddress, &msg.trigger_smart_contract.contract_address);
    content->amount[0] = (uint64_t) call_value;
    content->callTokenValue = (uint64_t) call_token_value;
    content->tokenId = (uint64_t) token_id;

    tokenDefinition_t *trc20 = getKnownToken(content);

    if (trc20 == NULL) {
        // treat unknown TRC20 token as arbitrary contract
        content->TRC20Method = 0;
        return true;
    }

    content->decimals[0] = trc20->decimals;
    content->tokenNamesLength[0] = strlen(trc20->ticker) + 1;
    memmove(content->tokenNames[0], trc20->ticker, content->tokenNamesLength[0]);

    return true;
}

static bool exchange_create_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ExchangeCreateContract_fields,
                               &msg.exchange_create_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.exchange_create_contract.owner_address);

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_create_contract.first_token_id.bytes,
                          msg.exchange_create_contract.first_token_id.size,
                          &content->tokenIsNative[0])) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    if (!printTokenFromID(content->tokenNames[1],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_create_contract.second_token_id.bytes,
                          msg.exchange_create_contract.second_token_id.size,
                          &content->tokenIsNative[1])) {
        return false;
    }
    content->tokenNamesLength[1] = strlen(content->tokenNames[1]);

    if (!copy_nonnegative_int64(&content->amount[0],
                                msg.exchange_create_contract.first_token_balance) ||
        !copy_nonnegative_int64(&content->amount[1],
                                msg.exchange_create_contract.second_token_balance)) {
        return false;
    }
    return true;
}

static bool exchange_inject_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ExchangeInjectContract_fields,
                               &msg.exchange_inject_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_inject_contract.owner_address);
    if (!copy_nonnegative_int64(&content->exchangeID, msg.exchange_inject_contract.exchange_id)) {
        return false;
    }

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_inject_contract.token_id.bytes,
                          msg.exchange_inject_contract.token_id.size,
                          &content->tokenIsNative[0])) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    if (!copy_nonnegative_int64(&content->amount[0], msg.exchange_inject_contract.quant)) {
        return false;
    }
    return true;
}

static bool exchange_withdraw_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ExchangeWithdrawContract_fields,
                               &msg.exchange_withdraw_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_withdraw_contract.owner_address);
    if (!copy_nonnegative_int64(&content->exchangeID, msg.exchange_withdraw_contract.exchange_id)) {
        return false;
    }

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_withdraw_contract.token_id.bytes,
                          msg.exchange_withdraw_contract.token_id.size,
                          &content->tokenIsNative[0])) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    if (!copy_nonnegative_int64(&content->amount[0], msg.exchange_withdraw_contract.quant)) {
        return false;
    }
    return true;
}

static bool exchange_transaction_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_ExchangeTransactionContract_fields,
                               &msg.exchange_transaction_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }
    COPY_ADDRESS(content->account, &msg.exchange_transaction_contract.owner_address);
    if (!copy_nonnegative_int64(&content->exchangeID,
                                msg.exchange_transaction_contract.exchange_id)) {
        return false;
    }

    if (!printTokenFromID(content->tokenNames[0],
                          MAX_TOKEN_LENGTH,
                          msg.exchange_transaction_contract.token_id.bytes,
                          msg.exchange_transaction_contract.token_id.size,
                          &content->tokenIsNative[0])) {
        return false;
    }
    content->tokenNamesLength[0] = strlen(content->tokenNames[0]);

    if (!copy_nonnegative_int64(&content->amount[0], msg.exchange_transaction_contract.quant) ||
        !copy_nonnegative_int64(&content->amount[1], msg.exchange_transaction_contract.expected)) {
        return false;
    }
    return true;
}

static bool account_permission_update_contract(txContent_t *content, pb_istream_t *stream) {
    if (!pb_decode_transaction(stream,
                               protocol_AccountPermissionUpdateContract_fields,
                               &msg.account_permission_update_contract,
                               &content->hasUnreviewedFields)) {
        return false;
    }

    COPY_ADDRESS(content->account, &msg.account_permission_update_contract.owner_address);
    // TODO: Update tx content
    return true;
}

typedef struct {
    const uint8_t *buf;
    size_t size;
    bool has_value;
} buffer_t;

bool pb_decode_contract_parameter(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    PB_UNUSED(field);
    buffer_t *buffer = *arg;

    buffer->buf = stream->state;
    buffer->size = stream->bytes_left;
    buffer->has_value = true;
    return true;
}

bool pb_get_tx_data_size(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    PB_UNUSED(field);
    uint64_t *data_size = *arg;
    *data_size = (uint64_t) stream->bytes_left;
    return true;
}

static bool parse_fee_limit(const uint8_t *buffer, size_t length, uint64_t *fee_limit) {
    pb_istream_t stream = pb_istream_from_buffer(buffer, length);
    pb_wire_type_t wire_type;
    uint32_t tag;
    bool eof;

    while (pb_decode_tag(&stream, &wire_type, &tag, &eof)) {
        if (tag == protocol_Transaction_raw_fee_limit_tag) {
            if ((wire_type != PB_WT_VARINT) || !pb_decode_varint(&stream, fee_limit)) {
                return false;
            }
        } else if (!pb_skip_field(&stream, wire_type)) {
            return false;
        }
    }

    return eof;
}

parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content) {
    protocol_Transaction_raw transaction;
    uint64_t fee_limit = content->feeLimit;

    if (length == 0) {
        return USTREAM_FINISHED;
    }

    memset(&transaction, 0, sizeof(transaction));

    // Each APDU contains complete top-level protobuf fields. Scan tag 18 on a
    // separate stream so an absent field in a later APDU cannot reset a value
    // decoded earlier. Repeated singular fields retain protobuf's last-value-
    // wins semantics.
    if (!parse_fee_limit(buffer, length, &fee_limit)) {
        return USTREAM_FAULT;
    }

    pb_istream_t stream = pb_istream_from_buffer(buffer, length);

    /* Set callbacks to retrieve "Contract" message bounds.
     * This is required because contract type is not necessarily parsed at the
     * time of the transaction is decoded (fields are not required to be ordered)
     * and deserializing the nested contract inside the message requires too much
     * stack for Nano S
     */
    buffer_t contract_buffer = {0};
    transaction.contract->parameter.value.funcs.decode = pb_decode_contract_parameter;
    transaction.contract->parameter.value.arg = &contract_buffer;

    /* Set callback to determine if transaction contains custom data.
     * This allows to retrieve the size of arbitrary data. */
    transaction.custom_data.funcs.decode = pb_get_tx_data_size;
    transaction.custom_data.arg = &content->dataBytes;

    if (!pb_decode_transaction(&stream,
                               protocol_Transaction_raw_fields,
                               &transaction,
                               &content->hasUnreviewedFields)) {
        return USTREAM_FAULT;
    }

    content->feeLimit = fee_limit;

    if (transaction.contract_count != 0) {
        if (content->contractSeen) {
            // processTx() decodes one APDU-local protobuf fragment at a time.
            // Without this transaction-wide guard, a later Contract field
            // would overwrite the model reviewed for the cumulative hash.
            return USTREAM_FAULT;
        }
        content->contractSeen = true;
    }

    if (!HAS_SETTING(S_DATA_ALLOWED) && content->dataBytes != 0) {
        return USTREAM_MISSING_SETTING_DATA_ALLOWED;
    }

    /* Parse contract parameters if any...
       and it may come in different message chunk
       so test if chunk has the contract
     */
    if (transaction.contract->has_parameter) {
        if (!contract_buffer.has_value || contract_buffer.buf == NULL ||
            contract_buffer.size == 0) {
            return USTREAM_FAULT;
        }

        content->permission_id = transaction.contract->Permission_id;
        content->contractType = (contractType_e) transaction.contract->type;

        pb_istream_t tx_stream = pb_istream_from_buffer(contract_buffer.buf, contract_buffer.size);
        bool ret;

        switch (transaction.contract->type) {
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
            case protocol_Transaction_Contract_ContractType_TriggerSmartContract:
                ret = trigger_smart_contract(content, &tx_stream);
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
            default:
                return USTREAM_FAULT;
        }
        return ret ? USTREAM_PROCESSING : USTREAM_FAULT;
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
