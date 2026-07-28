/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#include <stdint.h>
#include <stdio.h>

#include "app_mem_utils.h"
#include "io.h"

#include "format.h"

#include "helpers.h"
#include "apdu_constants.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "uint256.h"
#include "app_errors.h"
#include "legacy_tx_stream.h"
#include "create_smart_contract_stream.h"
#include "parse.h"
#include "settings.h"
#ifdef HAVE_GATING_SUPPORT
#include "cmd_get_gating.h"  // set_blind_sign_gating_warning
#endif  // HAVE_GATING_SUPPORT
#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

extern void reset_app_context();

static int send_sign_status(uint16_t sw) {
    if (sw != E_OK) {
        reset_app_context();
    }
    return io_send_sw(sw);
}

#ifdef HAVE_SWAP
static void __attribute__((noreturn)) finalize_swap_with_error(uint16_t sw) {
    io_send_sw(sw);
    swap_finalize_exchange_sign_transaction(false);
}
#endif  // HAVE_SWAP

#ifdef SCREEN_SIZE_WALLET
static void fillVoteAddressSlot(char *destination, const char *from, uint8_t index) {
    memset(destination + voteSlot(index, VOTE_ADDRESS), 0, VOTE_PACK);
    memcpy(destination + voteSlot(index, VOTE_ADDRESS), from, VOTE_ADDRESS_SIZE);
}

static bool fillVoteAmountSlot(char *destination, uint64_t value, uint8_t index) {
    if (print_amount(value,
                     destination + voteSlot(index, VOTE_AMOUNT),
                     VOTE_AMOUNT_SIZE,
                     0) == 0) {
        return false;
    }
    PRINTF("Amount: %d - %s\n", index, destination + (voteSlot(index, VOTE_AMOUNT)));
    return true;
}
#endif

#if !defined(SCREEN_SIZE_WALLET)
static bool fillVoteCombinedSlot(char *destination,
                                 const char *address,
                                 uint64_t value,
                                 uint8_t index) {
    char *slot = destination + voteSlot(index, VOTE_ADDRESS);
    int prefix_len;

    memset(slot, 0, VOTE_PACK);
    prefix_len = snprintf(slot, VOTE_PACK, "%s\n", address);
    if ((prefix_len < 0) || ((size_t) prefix_len >= VOTE_PACK) ||
        (print_amount(value, slot + prefix_len, VOTE_PACK - (size_t) prefix_len, 0) == 0)) {
        return false;
    }
    PRINTF("Vote: %d - %s\n", index, slot);
    return true;
}
#endif

static void setV2ResourceName(protocol_ResourceCode resource) {
    switch (resource) {
        case protocol_ResourceCode_BANDWIDTH:
            strcpy(strings.common.fullContract, "Bandwidth");
            break;
        case protocol_ResourceCode_ENERGY:
            strcpy(strings.common.fullContract, "Energy");
            break;
        case protocol_ResourceCode_TRON_POWER:
            strcpy(strings.common.fullContract, "Tron Power");
            break;
        default:
            strcpy(strings.common.fullContract, "Unknown");
            break;
    }
}

typedef struct {
    uint8_t id;
    const char *name;
} permission_operation_t;

static const permission_operation_t permission_operations[] = {
    {0, "Activate Account"},
    {1, "Transfer TRX"},
    {2, "Transfer TRC10"},
    {3, "Vote Asset"},
    {4, "Vote"},
    {5, "Apply to Become a SR Candidate"},
    {6, "Issue TRC10"},
    {8, "Update SR Info"},
    {9, "Participate in TRC10 Issuance"},
    {10, "Update Account Name"},
    {11, "TRX Stake (1.0)"},
    {12, "TRX Unstake (1.0)"},
    {13, "Claim Voter/SR Rewards"},
    {14, "Unstake TRC10"},
    {15, "Update TRC10 Parameters"},
    {16, "Create Proposal"},
    {17, "Approve Proposal"},
    {18, "Cancel Proposal"},
    {19, "Set Account ID"},
    {20, "Custom Contract"},
    {30, "Create Smart Contract"},
    {31, "Trigger Smart Contract"},
    {32, "Get Contract"},
    {33, "Update Contract Parameters"},
    {41, "Create Bancor Transaction"},
    {42, "Inject Assets into Bancor Transaction"},
    {43, "Withdraw Assets from Bancor Transaction"},
    {44, "Execute Bancor Transaction"},
    {45, "Update Contract Energy Limit"},
    {46, "Update Account Permission"},
    {48, "Clear Contract ABI"},
    {49, "Update SR Commission Ratio"},
    {54, "TRX Stake (2.0)"},
    {55, "TRX Unstake (2.0)"},
    {56, "Withdraw Expired Unfreeze"},
    {57, "Delegate Resource"},
    {58, "Undelegate Resource"},
    {59, "Cancel All Unfreeze V2"},
};

static size_t append_text(char *out, size_t outlen, const char *text) {
    size_t len = strlen(out);
    size_t text_len = strlen(text);

    if (len >= outlen) {
        return len;
    }
    if (text_len >= outlen - len) {
        text_len = outlen - len - 1;
    }
    memcpy(out + len, text, text_len);
    out[len + text_len] = '\0';
    return len + text_len;
}

static bool append_text_checked(char *out, size_t outlen, const char *text) {
    if (strlen(out) + strlen(text) >= outlen) {
        return false;
    }
    append_text(out, outlen, text);
    return true;
}

static bool format_trx_amount(uint64_t amount, char *out, size_t outlen) {
    if (amount == 0) {
        strlcpy(out, "0", outlen);
    } else if (print_amount(amount, out, outlen, TRX_DECIMALS) == 0) {
        return false;
    }
    return append_text_checked(out, outlen, " TRX");
}

static void append_uint64(char *out, size_t outlen, uint64_t value) {
    char amount[21];

    print_amount(value, amount, sizeof(amount), 0);
    append_text(out, outlen, amount);
}

static bool operation_id_known(uint8_t id) {
    for (size_t i = 0; i < sizeof(permission_operations) / sizeof(permission_operations[0]); i++) {
        if (permission_operations[i].id == id) {
            return true;
        }
    }
    return false;
}

static bool operation_enabled(const protocol_Permission_operations_t *operations, uint8_t id) {
    return (operations->bytes[id / 8] & (1U << (id % 8))) != 0;
}

static bool operations_all_bytes(const protocol_Permission_operations_t *operations, uint8_t byte) {
    for (uint8_t i = 0; i < 32; i++) {
        if (operations->bytes[i] != byte) {
            return false;
        }
    }
    return true;
}

static bool operations_have_unknown_bits(const protocol_Permission_operations_t *operations) {
    for (uint16_t id = 0; id < 256; id++) {
        if ((operations->bytes[id / 8] & (1U << (id % 8))) && !operation_id_known((uint8_t) id)) {
            return true;
        }
    }
    return false;
}

static bool operations_match_common_default(const protocol_Permission_operations_t *operations) {
    static const uint8_t default_operations[32] = {
        0x7f, 0xff, 0x1f, 0xc0, 0x03, 0x7e, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    return memcmp(operations->bytes, default_operations, sizeof(default_operations)) == 0;
}

static void format_operations(const protocol_Permission_operations_t *operations,
                              char *out,
                              size_t outlen) {
    bool first = true;

    out[0] = '\0';
    if (operations_all_bytes(operations, 0x00)) {
        strlcpy(out, "None", outlen);
        return;
    }
    if (operations_all_bytes(operations, 0xff)) {
        strlcpy(out, "All operations", outlen);
        return;
    }
    if (operations_match_common_default(operations)) {
        strlcpy(out, "All supported operations", outlen);
        return;
    }

    for (size_t i = 0; i < sizeof(permission_operations) / sizeof(permission_operations[0]); i++) {
        if (!operation_enabled(operations, permission_operations[i].id)) {
            continue;
        }
        if (!first && !append_text_checked(out, outlen, "\n")) {
            goto raw_hex;
        }
        if (!append_text_checked(out, outlen, permission_operations[i].name)) {
            goto raw_hex;
        }
        first = false;
    }

    if (first || operations_have_unknown_bits(operations)) {
        goto raw_hex;
    }
    return;

raw_hex:
    bytes_to_string(out, outlen, operations->bytes, 32);
}

static bool add_permission_field(uint8_t *field_index, const char *label, const char *value) {
    if (*field_index >= PERM_MAX_FIELDS) {
        return false;
    }

    strlcpy(perm_field_labels[*field_index], label, PERM_ITEM_LEN);
    perm_field_items[*field_index] = perm_field_labels[*field_index];
    strlcpy(perm_field_values[*field_index], value, PERM_VAL_LEN);
    (*field_index)++;
    return true;
}

static bool add_permission_uint_field(uint8_t *field_index, const char *label, uint64_t value) {
    char amount[21];

    print_amount(value, amount, sizeof(amount), 0);
    return add_permission_field(field_index, label, amount);
}

static bool format_permission_fields(uint8_t *field_index,
                                     const char *prefix,
                                     const protocol_Permission *perm,
                                     bool include_operations) {
    char label[PERM_ITEM_LEN];
    char value[PERM_VAL_LEN];
    char address[BASE58CHECK_ADDRESS_SIZE + 1];

#ifdef SCREEN_SIZE_WALLET
    snprintf(label, sizeof(label), "%s Name", prefix);
#else
    strlcpy(label, prefix, sizeof(label));
#endif
    if (!add_permission_field(field_index,
                              label,
                              (perm->permission_name[0] == '\0') ? "(empty)" : perm->permission_name)) {
        return false;
    }

    if (include_operations) {
#ifdef SCREEN_SIZE_WALLET
        snprintf(label, sizeof(label), "%s Operations", prefix);
#else
        strlcpy(label, "Operations", sizeof(label));
#endif
        format_operations(&perm->operations, value, sizeof(value));
        if (!add_permission_field(field_index, label, value)) {
            return false;
        }
    }

#ifdef SCREEN_SIZE_WALLET
    snprintf(label, sizeof(label), "%s Threshold", prefix);
#else
    strlcpy(label, "Threshold", sizeof(label));
#endif
    if (!add_permission_uint_field(field_index, label, (uint64_t) perm->threshold)) {
        return false;
    }

    for (pb_size_t i = 0; i < perm->keys_count; i++) {
        getBase58FromAddress(perm->keys[i].address, address);
#ifdef SCREEN_SIZE_WALLET
        snprintf(label, sizeof(label), "%s Authorized To %u", prefix, (unsigned) i + 1);
#else
        strlcpy(label, "Authorized To", sizeof(label));
#endif
        snprintf(value, sizeof(value), "%s\nWeight: ", address);
        append_uint64(value, sizeof(value), (uint64_t) perm->keys[i].weight);
        if (!add_permission_field(field_index, label, value)) {
            return false;
        }
    }

    return true;
}

static bool format_permission_update_fields(const protocol_AccountPermissionUpdateContract *perm) {
    uint8_t field = 0;

    perm_field_labels = APP_MEM_ALLOC(PERM_MAX_FIELDS * sizeof(*perm_field_labels));
    perm_field_values = APP_MEM_ALLOC(PERM_MAX_FIELDS * sizeof(*perm_field_values));
    if ((perm_field_labels == NULL) || (perm_field_values == NULL)) {
        APP_MEM_FREE_AND_NULL((void **) &perm_field_labels);
        APP_MEM_FREE_AND_NULL((void **) &perm_field_values);
        return false;
    }

    if (!format_permission_fields(&field, "Owner", &perm->owner, false)) {
        return false;
    }
    if (perm->has_witness &&
        !format_permission_fields(&field,
                                  "Witness",
                                  &perm->witness,
                                  false)) {
        return false;
    }
    for (pb_size_t i = 0; i < perm->actives_count; i++) {
        char prefix[PERM_ITEM_LEN];

        if (perm->actives_count == 1) {
            strlcpy(prefix, "Active", sizeof(prefix));
        } else {
            snprintf(prefix, sizeof(prefix), "Active %u", (unsigned) i + 1);
        }
        if (!format_permission_fields(&field, prefix, &perm->actives[i], true)) {
            return false;
        }
    }

    perm_field_count = field;
    return true;
}

typedef enum {
    SIGN_PHASE_IDLE = 0,
    SIGN_PHASE_RAW_DATA,
    SIGN_PHASE_METADATA,
    SIGN_PHASE_REVIEW,
} sign_phase_t;

// Legacy INS_SIGN streams the Transaction.raw envelope, retains bounded
// parameters for the existing contract parsers, and observes the same bytes
// with the dedicated CreateSmartContract parser.
typedef struct {
    legacy_tx_stream_t envelope;
    create_smart_contract_stream_t create;
    bool create_started;
    bool create_complete;
    bool create_valid;
} sign_stream_context_t;

static sign_stream_context_t *sign_stream;
static sign_phase_t sign_phase;

bool sign_review_in_progress(void) {
    return sign_phase == SIGN_PHASE_REVIEW;
}

static bool start_sign_review(ui_approval_state_t state, bool data_warning) {
    // Mark the session non-resumable before handing control to asynchronous UI.
    // A preparation failure sends an error and resets this phase via
    // reset_app_context()/sign_cleanup().
    sign_phase = SIGN_PHASE_REVIEW;
    return ux_flow_display(state, data_warning);
}

static void create_parameter_begin(void *ctx, size_t parameter_len) {
    sign_stream_context_t *stream = ctx;
    create_smart_contract_stream_init(&stream->create, parameter_len);
    stream->create_started = true;
    stream->create_complete = false;
    stream->create_valid = true;
}

static void create_parameter_chunk(void *ctx, const uint8_t *data, size_t data_len) {
    sign_stream_context_t *stream = ctx;
    if (stream->create_valid &&
        !create_smart_contract_stream_feed(&stream->create, data, data_len)) {
        // This is only a CreateSmartContract candidate. A decode failure must
        // not reject a different contract type using the buffered path.
        stream->create_valid = false;
    }
}

static void create_parameter_end(void *ctx) {
    sign_stream_context_t *stream = ctx;
    stream->create_complete = true;
}

static parserStatus_e finish_streamed_transaction(void) {
    legacy_tx_stream_result_t result;
    parserStatus_e status = USTREAM_FAULT;

    if (sign_stream == NULL ||
        !legacy_tx_stream_finish(&sign_stream->envelope, &result)) {
        goto cleanup;
    }

    if (result.contract_type ==
        protocol_Transaction_Contract_ContractType_CreateSmartContract) {
        create_smart_contract_stream_result_t create_result;
        if (!sign_stream->create_started ||
            !sign_stream->create_complete ||
            !sign_stream->create_valid ||
            !create_smart_contract_stream_finish(&sign_stream->create, &create_result)) {
            goto cleanup;
        }
        status = processStreamedCreateSmartContract(result.permission_id,
                                                    result.fee_limit,
                                                    result.custom_data_len,
                                                    &create_result,
                                                    &txContent);
        goto cleanup;
    }

    if (result.parameter_overflow) {
        goto cleanup;
    }

    status = processContractParameter(result.contract_type,
                                      result.permission_id,
                                      result.fee_limit,
                                      result.parameter,
                                      result.parameter_len,
                                      result.custom_data_len,
                                      &txContent);

cleanup:
    // Contract decoding has copied everything needed by the review flow into
    // msg/txContent. Release the stream before UI-specific allocations.
    APP_MEM_FREE_AND_NULL((void **) &sign_stream);
    return status;
}

void sign_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &sign_stream);
    APP_MEM_FREE_AND_NULL((void **) &vote_display_buffer);
    APP_MEM_FREE_AND_NULL((void **) &perm_field_labels);
    APP_MEM_FREE_AND_NULL((void **) &perm_field_values);
    ui_review_menu_cleanup();
    proposal_parameters_cleanup();
    sign_phase = SIGN_PHASE_IDLE;
    votes_count = 0;
    perm_field_count = 0;
}

int handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    uint256_t uint256;
    bool data_warning;
    const bool metadata_apdu = ((p1 & 0xF0) == P1_TRC10_NAME);
    bool finalize_transaction = false;
    parserStatus_e txResult = USTREAM_PROCESSING;

    // Defense in depth for tests/direct callers that bypass apdu_dispatcher().
    // Never reset here: the active NBGL page still owns review allocations.
    if (sign_review_in_progress()) {
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    if (p2 != 0x00) {
        return send_sign_status(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        }
        appState = APP_STATE_SIGNING;
        off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
        if (ret < 0) {
            return send_sign_status(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        initTx(&txContext, &txContent);
        customContractField = 0;
        sign_cleanup();
        sign_stream = APP_MEM_ALLOC(sizeof(*sign_stream));
        if (sign_stream == NULL) {
            return send_sign_status(E_INCORRECT_DATA);
        }
        memset(sign_stream, 0, sizeof(*sign_stream));
        const legacy_parameter_observer_t observer = {
            .on_begin = create_parameter_begin,
            .on_chunk = create_parameter_chunk,
            .on_end = create_parameter_end,
            .ctx = sign_stream,
        };
        legacy_tx_stream_init(&sign_stream->envelope, &observer);
        sign_phase = SIGN_PHASE_RAW_DATA;

    } else if (metadata_apdu) {
        if (sign_phase == SIGN_PHASE_RAW_DATA) {
            txResult = finish_streamed_transaction();
            if (txResult != USTREAM_PROCESSING) {
                goto handle_parser_result;
            }
            sign_phase = SIGN_PHASE_METADATA;
        } else if (sign_phase != SIGN_PHASE_METADATA) {
            return send_sign_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }

        PRINTF("Setting token name\nContract type: %d\n", txContent.contractType);
        switch (txContent.contractType) {
            case TRANSFERASSETCONTRACT:
            case EXCHANGECREATECONTRACT:
                // Max 2 Tokens Name
                if ((p1 & 0x07) > 1) {
                    return send_sign_status(E_INCORRECT_P1_P2);
                }
                // Decode Token name and validate signature
                if (!parseTokenName((p1 & 0x07), workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    return send_sign_status(E_INCORRECT_DATA);
                }
                // if not last token name, return
                if (!(p1 & 0x08)) {
                    return send_sign_status(E_OK);
                }
                finalize_transaction = true;

                break;
            case EXCHANGEINJECTCONTRACT:
            case EXCHANGEWITHDRAWCONTRACT:
            case EXCHANGETRANSACTIONCONTRACT:
                // Max 1 pair set
                if ((p1 & 0x07) > 0) {
                    return send_sign_status(E_INCORRECT_P1_P2);
                }
                // error if not last
                if (!(p1 & 0x08)) {
                    return send_sign_status(E_INCORRECT_P1_P2);
                }
                PRINTF("Decoding Exchange\n");
                // Decode Token name and validate signature
                if (!parseExchange(workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    return send_sign_status(E_INCORRECT_DATA);
                }
                finalize_transaction = true;
                break;
            default:
                // Error if any other contract
                return send_sign_status(E_INCORRECT_DATA);
        }
    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return send_sign_status(E_INCORRECT_P1_P2);
    }

    if ((p1 == P1_MORE || p1 == P1_LAST) &&
        (appState != APP_STATE_SIGNING || sign_phase != SIGN_PHASE_RAW_DATA)) {
        PRINTF("Signature not initialized\n");
        return send_sign_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        // NOTE: if txContext is not initialized, then there must be seq errors in P1/P2.
        return send_sign_status(E_INCORRECT_P1_P2);
    }

    if (!metadata_apdu) {
        if (sign_phase != SIGN_PHASE_RAW_DATA || sign_stream == NULL) {
            return send_sign_status(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        // Parse before hashing so an oversized/malformed chunk cannot leave a
        // resumable partial hash. send_sign_status() resets all state on error.
        if (!legacy_tx_stream_feed(&sign_stream->envelope, workBuffer, dataLength)) {
            PRINTF("Invalid streamed raw transaction\n");
            return send_sign_status(E_INCORRECT_DATA);
        }
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                                   0,
                                   workBuffer,
                                   dataLength,
                                   NULL,
                                   32));
        finalize_transaction = (p1 == P1_LAST || p1 == P1_SIGN);
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap && G_swap_response_ready) {
        // Safety against trying to make the app sign multiple TX. The flag is
        // only raised after the final raw-data chunk has parsed successfully,
        // so continuation chunks from the same transaction remain valid.
        PRINTF("Safety against double signing triggered\n");
        os_sched_exit(-1);
    }
#endif

    if (!finalize_transaction) {
        return send_sign_status(E_OK);
    }

    if (!metadata_apdu) {
        txResult = finish_streamed_transaction();
    }

handle_parser_result:
    PRINTF("txResult: %04x\n", txResult);
    switch (txResult) {
        case USTREAM_PROCESSING:
            break;
        case USTREAM_FAULT:
            return send_sign_status(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                finalize_swap_with_error(E_SWAP_CHECKING_FAIL);
            }
#endif
            return send_sign_status(E_MISSING_SETTING_DATA_ALLOWED);
        default:
            PRINTF("Unexpected parser status\n");
            return send_sign_status(txResult);
    }

    // Last data hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                               CX_LAST,
                               workBuffer,
                               0,
                               tmpCtx.transactionContext.hash,
                               32));

    if (txContent.permission_id > 0) {
        size_t prefix_len = 0U;
        int prefix_written;

        PRINTF("Set permission_id...\n");
        prefix_written = snprintf((char *) strings.common.fromAddress,
                                  sizeof(strings.common.fromAddress),
                                  "P%d - ",
                                  txContent.permission_id);
        if ((prefix_written > 0) &&
            ((size_t) prefix_written <=
             (sizeof(strings.common.fromAddress) - (BASE58CHECK_ADDRESS_SIZE + 1U)))) {
            prefix_len = (size_t) prefix_written;
        } else {
            strings.common.fromAddress[0] = '\0';
        }

        getBase58FromAddress(txContent.account, strings.common.fromAddress + prefix_len);
    } else {
        getBase58FromAddress(txContent.account, strings.common.fromAddress);
    }

    data_warning = ((txContent.dataBytes > 0) ? true : false);

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((txContent.contractType != TRANSFERCONTRACT) &&      // TRX Transfer
            (txContent.contractType != TRIGGERSMARTCONTRACT)) {  // TRC20 Transfer
            PRINTF("Refused contract type when in SWAP mode\n");
            finalize_swap_with_error(E_SWAP_CHECKING_FAIL);
        }

        if (txContent.contractType == TRIGGERSMARTCONTRACT) {
            if (txContent.TRC20Method != 1) {
                // Only transfer method allowed for TRC20
                PRINTF("Refused method type when in SWAP mode\n");
                finalize_swap_with_error(E_SWAP_CHECKING_FAIL);
            }
        }

        if (data_warning) {
            PRINTF("Refused data warning when in SWAP mode\n");
            finalize_swap_with_error(E_SWAP_CHECKING_FAIL);
        }

        // We will quit after the response to this fully parsed and validated
        // transaction, whether the later swap/UI checks succeed or fail.
        PRINTF("Swap response is ready, the app will quit after the next send\n");
        G_swap_response_ready = true;
    }
#endif  // HAVE_SWAP

    switch (txContent.contractType) {
        case ACCOUNTCREATECONTRACT:
            getBase58FromAddress(txContent.destination, strings.common.toAddress);
            if (!setContractType(txContent.contractType,
                                 strings.common.fullContract,
                                 sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_ACCOUNTCREATE_TRANSACTION, data_warning);

            break;
        case ASSETISSUECONTRACT:
            start_sign_review(APPROVAL_ASSETISSUE_TRANSACTION, data_warning);
            break;
        case PARTICIPATEASSETISSUECONTRACT:
            getBase58FromAddress(txContent.destination, strings.common.toAddress);
            if (!format_trx_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            strlcpy(strings.common.fullContract,
                    txContent.tokenNames[0],
                    sizeof(strings.common.fullContract));
            start_sign_review(APPROVAL_PARTICIPATEASSETISSUE_TRANSACTION, data_warning);
            break;
        case UNFREEZEASSETCONTRACT:
            start_sign_review(APPROVAL_UNFREEZETRC10_TRANSACTION, data_warning);
            break;
        case UPDATEASSETCONTRACT:
            start_sign_review(APPROVAL_UPDATEASSET_TRANSACTION, data_warning);
            break;
        case CREATESMARTCONTRACT:
            // Deployment bytecode is opaque to the device. Require the same explicit
            // risk opt-in used for arbitrary TriggerSmartContract calls, while still
            // displaying the deployment parameters and bytecode hash.
            if (!N_storage.customContract) {
#ifdef SCREEN_SIZE_WALLET
                sign_phase = SIGN_PHASE_REVIEW;
#endif
                ui_error_custom_contract();
#ifdef SCREEN_SIZE_WALLET
                return APDU_NO_RESPONSE;
#else
                return send_sign_status(E_MISSING_SETTING_CUSTOM_CONTRACT);
#endif
            }
#ifdef HAVE_GATING_SUPPORT
            if (set_blind_sign_gating_warning() == false) {
                return send_sign_status(E_INCORRECT_DATA);
            }
#endif
            start_sign_review(APPROVAL_CREATESMARTCONTRACT_TRANSACTION, data_warning);
            break;
        case TRANSFERCONTRACT:       // TRX Transfer
        case TRANSFERASSETCONTRACT:  // TRC10 Transfer
        case TRIGGERSMARTCONTRACT:   // TRC20 Transfer

            strcpy(strings.common.TRC20ActionSendAllow, "To");
            if (txContent.contractType == TRIGGERSMARTCONTRACT) {
                if (txContent.TRC20Method == 1)
                    strcpy(strings.common.TRC20Action, "Asset");
                else if (txContent.TRC20Method == 2) {
                    strcpy(strings.common.TRC20ActionSendAllow, "Allow");
                    strcpy(strings.common.TRC20Action, "Approve");
                } else {
                    // Custom contract = blind signing, gated by the "Custom contracts"
                    // setting (NOT the separate "Blind signing" setting).
                    // Surface a page naming the correct setting, then return the precise
                    // TRON status word.
                    if (!N_storage.customContract) {
#ifdef SCREEN_SIZE_WALLET
                        sign_phase = SIGN_PHASE_REVIEW;
#endif
                        ui_error_custom_contract();
#ifdef SCREEN_SIZE_WALLET
                        return APDU_NO_RESPONSE;
#else
                        return send_sign_status(E_MISSING_SETTING_CUSTOM_CONTRACT);
#endif
                    }
                    customContractField = 1;

                    getBase58FromAddress(txContent.contractAddress, strings.common.fullContract);
                    snprintf((char *) strings.common.TRC20Action,
                             sizeof(strings.common.TRC20Action),
                             "%08x",
                             txContent.customSelector);
                    // A custom contract can only attach native TRX as its call value
                    // (txContent.amount[0]); amount[1]/token-name is never set on this
                    // path. Show a single "Amount" field: "<value> TRX", or "-"
                    // when no value is attached.
                    G_io_apdu_buffer[0] = '\0';
                    G_io_apdu_buffer[100] = '\0';
                    if (txContent.amount[0] > 0) {
                        if (!format_trx_amount(txContent.amount[0],
                                               (char *) G_io_apdu_buffer,
                                               100)) {
                            return send_sign_status(E_INCORRECT_LENGTH);
                        }
                        customContractField |= (1 << 0x05);
                        customContractField |= (1 << 0x06);
                    } else {
                        strlcpy((char *) G_io_apdu_buffer, "-", sizeof(G_io_apdu_buffer));
                    }

#ifdef HAVE_GATING_SUPPORT
                    // Custom contract = blind signing. A gating descriptor
                    // (INS_PROVIDE_GATING) may require this transaction to match
                    // before signing, and augments the review with a "safer signing"
                    // prelude. Mirrors app-ethereum's ux_approve_tx() gating block.
                    if (set_blind_sign_gating_warning() == false) {
                        return send_sign_status(E_INCORRECT_DATA);
                    }
#endif  // HAVE_GATING_SUPPORT

                    // approve custom contract
                    start_sign_review(APPROVAL_CUSTOM_CONTRACT, data_warning);

                    break;
                }

                convertUint256BE(txContent.TRC20Amount, 32, &uint256);
                tostring256(&uint256, 10, (char *) G_io_apdu_buffer + 100, 100);
                if (!adjustDecimals((char *) G_io_apdu_buffer + 100,
                                    strlen((const char *) G_io_apdu_buffer + 100),
                                    (char *) G_io_apdu_buffer,
                                    100,
                                    txContent.decimals[0])) {
                    return send_sign_status(E_INCORRECT_LENGTH);
                }
            } else {
                if (print_amount(
                        txContent.amount[0],
                        (void *) G_io_apdu_buffer,
                        100,
                        (txContent.contractType == TRANSFERCONTRACT) ? TRX_DECIMALS
                                                                    : txContent.decimals[0]) == 0) {
                    return send_sign_status(E_INCORRECT_LENGTH);
                }
            }

            getBase58FromAddress(txContent.destination, strings.common.toAddress);

            // get token name if any
            strlcpy(strings.common.fullContract,
                    txContent.tokenNames[0],
                    sizeof(strings.common.fullContract));
#ifdef HAVE_SWAP
            // If we are in swap context, do not redisplay the message data
            // Instead, ensure they are identical with what was previously displayed.
            // Swap consumes the amount and token name as separate strings, so this
            // must run before the two are merged for display below.
            if (G_called_from_swap) {
                if (swap_check_validity((char *) G_io_apdu_buffer,  // Amount
                                        strings.common.fullContract,               // Token name
                                        strings.common.TRC20ActionSendAllow,       // "Send To"
                                        strings.common.toAddress)) {
                    PRINTF("Signing valid swap transaction\n");
                    ui_callback_tx_ok(false);
                } else {
                    PRINTF("Refused signing incorrect Swap transaction\n");
                    finalize_swap_with_error(E_SWAP_CHECKING_FAIL);
                }
                break;
            }
#endif  // HAVE_SWAP

            // Merge the token ticker into the amount so the review shows a single
            // "Amount" field ("<value> <ticker>"), mirroring app-ethereum's fullAmount
            // pair rather than separate Amount + Token fields. TRC10 asset transfers
            // are excluded: their token is an asset id/name (often numeric), so the UI
            // keeps Amount and Token split to avoid an ambiguous "<number> <number>".
            if ((txContent.contractType != TRANSFERASSETCONTRACT) &&
                (strlen(strings.common.fullContract) > 0)) {
                if ((strlcat((char *) G_io_apdu_buffer,
                             " ",
                             sizeof(G_io_apdu_buffer)) >= sizeof(G_io_apdu_buffer)) ||
                    (strlcat((char *) G_io_apdu_buffer,
                             strings.common.fullContract,
                             sizeof(G_io_apdu_buffer)) >= sizeof(G_io_apdu_buffer))) {
                    return send_sign_status(E_INCORRECT_LENGTH);
                }
            }
            start_sign_review(APPROVAL_TRANSFER, data_warning);

            break;
        case EXCHANGECREATECONTRACT:
            if ((print_amount(
                     txContent.amount[0],
                     (void *) G_io_apdu_buffer,
                     100,
                     (strncmp((const char *) txContent.tokenNames[0], "TRX", 3) == 0)
                         ? TRX_DECIMALS
                         : txContent.decimals[0]) == 0) ||
                (print_amount(
                     txContent.amount[1],
                     (void *) G_io_apdu_buffer + 100,
                     100,
                     (strncmp((const char *) txContent.tokenNames[1], "TRX", 3) == 0)
                         ? TRX_DECIMALS
                         : txContent.decimals[1]) == 0)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }

            start_sign_review(APPROVAL_EXCHANGE_CREATE, data_warning);

            break;
        case EXCHANGEINJECTCONTRACT:
        case EXCHANGEWITHDRAWCONTRACT:
            if ((print_amount(txContent.exchangeID,
                              (void *) strings.common.toAddress,
                              sizeof(strings.common.toAddress),
                              0) == 0) ||
                (print_amount(
                     txContent.amount[0],
                     (void *) G_io_apdu_buffer,
                     100,
                     (strncmp((const char *) txContent.tokenNames[0], "TRX", 3) == 0)
                         ? TRX_DECIMALS
                         : txContent.decimals[0]) == 0)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            // write exchange contract type
            if (!setExchangeContractDetail(txContent.contractType,
                                           (char *) G_io_apdu_buffer + 100,
                                           sizeof(G_io_apdu_buffer) - 100)) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_EXCHANGE_WITHDRAW_INJECT, data_warning);

            break;
        case EXCHANGETRANSACTIONCONTRACT:
            if ((print_amount(txContent.exchangeID,
                              (void *) strings.common.toAddress,
                              sizeof(strings.common.toAddress),
                              0) == 0) ||
                (print_amount(txContent.amount[0],
                              (void *) G_io_apdu_buffer,
                              100,
                              txContent.decimals[0]) == 0) ||
                (print_amount(txContent.amount[1],
                              (void *) G_io_apdu_buffer + 100,
                              100,
                              txContent.decimals[1]) == 0)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }

            start_sign_review(APPROVAL_EXCHANGE_TRANSACTION, data_warning);

            break;
        case VOTEWITNESSCONTRACT: {
            // vote for SR
            protocol_VoteWitnessContract *contract = &msg.vote_witness_contract;

            PRINTF("Voting!!\n");
            PRINTF("Count: %d\n", contract->votes_count);
            txContent.amount[0] = 0;
            if ((contract->votes_count == 0) || (contract->votes_count > MAX_VOTE_COUNT)) {
                return send_sign_status(E_INCORRECT_DATA);
            }
            votes_count = (uint8_t) contract->votes_count;
            vote_display_buffer = APP_MEM_ALLOC((size_t) votes_count * VOTE_PACK);
            if (vote_display_buffer == NULL) {
                return send_sign_status(E_INCORRECT_DATA);
            }
            memset(vote_display_buffer, 0, (size_t) votes_count * VOTE_PACK);
            uint64_t total_votes = 0;

            for (uint8_t i = 0; i < votes_count; i++) {
                if ((contract->votes[i].vote_count <= 0) ||
                    ((uint64_t) contract->votes[i].vote_count > UINT64_MAX - total_votes)) {
                    return send_sign_status(E_INCORRECT_DATA);
                }
                getBase58FromAddress(contract->votes[i].vote_address,
                                     strings.common.fullContract);
                total_votes += (uint64_t) contract->votes[i].vote_count;
#ifdef SCREEN_SIZE_WALLET
                fillVoteAddressSlot(vote_display_buffer, strings.common.fullContract, i);
                bool vote_formatted = fillVoteAmountSlot(vote_display_buffer,
                                                         (uint64_t) contract->votes[i].vote_count,
                                                         i);
#else
                bool vote_formatted = fillVoteCombinedSlot(vote_display_buffer,
                                                           strings.common.fullContract,
                                                           (uint64_t) contract->votes[i].vote_count,
                                                           i);
#endif
                if (!vote_formatted) {
                    return send_sign_status(E_INCORRECT_LENGTH);
                }
            }

            int prefix_len = snprintf(strings.common.fullContract,
                                      sizeof(strings.common.fullContract),
                                      "%u: ",
                                      (unsigned int) votes_count);
            if ((prefix_len < 0) || ((size_t) prefix_len >= sizeof(strings.common.fullContract)) ||
                !u64_to_string(total_votes,
                               strings.common.fullContract + prefix_len,
                               (uint8_t) (sizeof(strings.common.fullContract) -
                                          (size_t) prefix_len))) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }

            start_sign_review(APPROVAL_WITNESSVOTE_TRANSACTION, data_warning);

        } break;
        case FREEZEBALANCECONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            if (!format_trx_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            if (!allzeroes(txContent.destination, ADDRESS_SIZE)) {
                getBase58FromAddress(txContent.destination, strings.common.toAddress);
            } else {
                getBase58FromAddress(txContent.account, strings.common.toAddress);
            }

            start_sign_review(APPROVAL_FREEZEASSET_TRANSACTION, data_warning);

            break;
        case UNFREEZEBALANCECONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            if (!allzeroes(txContent.destination, ADDRESS_SIZE)) {
                getBase58FromAddress(txContent.destination, strings.common.toAddress);
            } else {
                getBase58FromAddress(txContent.account, strings.common.toAddress);
            }

            start_sign_review(APPROVAL_UNFREEZEASSET_TRANSACTION, data_warning);

            break;
        case FREEZEBALANCEV2CONTRACT:  // Freeze TRX
            setV2ResourceName(txContent.resource);

            if (!format_trx_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            getBase58FromAddress(txContent.account, strings.common.toAddress);

            start_sign_review(APPROVAL_FREEZEASSETV2_TRANSACTION, data_warning);
            break;
        case UNFREEZEBALANCEV2CONTRACT:  // unreeze TRX
            setV2ResourceName(txContent.resource);

            if (!format_trx_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            getBase58FromAddress(txContent.account, strings.common.toAddress);

            start_sign_review(APPROVAL_UNFREEZEASSETV2_TRANSACTION, data_warning);

            break;
        case DELEGATERESOURCECONTRACT:  // Delegate resource
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            if (!txContent.lock) {
                strlcpy((char *) G_io_apdu_buffer + 100, "False", sizeof(G_io_apdu_buffer) - 100);
            } else {
                strlcpy((char *) G_io_apdu_buffer + 100, "True", sizeof(G_io_apdu_buffer) - 100);
            }

            if (!format_trx_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            getBase58FromAddress(txContent.destination, strings.common.toAddress);

            start_sign_review(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case UNDELEGATERESOURCECONTRACT:  // Undelegate resource
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            if (!format_trx_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100)) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            getBase58FromAddress(txContent.destination, strings.common.toAddress);

            start_sign_review(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:  // Withdraw Expire Unfreeze
            getBase58FromAddress(txContent.account, strings.common.toAddress);

            start_sign_review(APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION, data_warning);

            break;
        case CANCELALLUNFREEZEV2CONTRACT:  // Cancel all pending unstake (UnfreezeV2) requests
            getBase58FromAddress(txContent.account, strings.common.toAddress);

            start_sign_review(APPROVAL_CANCELALLUNFREEZEV2_TRANSACTION, data_warning);

            break;
        case UPDATEBROKERAGECONTRACT:  // Update witness brokerage (reward commission %)
            // brokerage is a percentage in [0, 100], stashed in amount[0] at parse
            snprintf((char *) G_io_apdu_buffer, 100, "%d%%", (int) txContent.amount[0]);

            start_sign_review(APPROVAL_UPDATEBROKERAGE_TRANSACTION, data_warning);

            break;
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account, strings.common.toAddress);

            start_sign_review(APPROVAL_WITHDRAWBALANCE_TRANSACTION, data_warning);

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT: {
            protocol_AccountPermissionUpdateContract *perm =
                &msg.account_permission_update_contract;

            if (!format_permission_update_fields(perm)) {
                return send_sign_status(E_INCORRECT_DATA);
            }
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_PERMISSION_UPDATE, data_warning);

        } break;
        case PROPOSALCREATECONTRACT:
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_PROPOSALCREATE_TRANSACTION, data_warning);

            break;
        case PROPOSALAPPROVECONTRACT:
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_PROPOSALAPPROVE_TRANSACTION, data_warning);

            break;
        case PROPOSALDELETECONTRACT:
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_PROPOSALDELETE_TRANSACTION, data_warning);

            break;
        case WITNESSCREATECONTRACT:
            memcpy(strings.common.url, txContent.url, sizeof(txContent.url));
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_WITNESSCREATE_TRANSACTION, data_warning);

            break;
        case WITNESSUPDATECONTRACT:
            memcpy(strings.common.url, txContent.url, sizeof(txContent.url));
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_WITNESSUPDATE_TRANSACTION, data_warning);

            break;
        case ACCOUNTUPDATECONTRACT:
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_ACCOUNTUPDATE_TRANSACTION, data_warning);

            break;
        case SETACCOUNTIDCONTRACT:
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_SETACCOUNTID_TRANSACTION, data_warning);

            break;
        case CLEARABICONTRACT:
            getBase58FromAddress(txContent.contractAddress, strings.common.toAddress);
            if (!setContractType(txContent.contractType,
                                 strings.common.fullContract,
                                 sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_CLEARABI_TRANSACTION, data_warning);

            break;
        case UPDATESETTINGCONTRACT:
            getBase58FromAddress(txContent.contractAddress, strings.common.toAddress);
            snprintf((char *) G_io_apdu_buffer,
                     100,
                     "%d%%",
                     (int) txContent.amount[0]);
            if (!setContractType(txContent.contractType,
                                 strings.common.fullContract,
                                 sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_UPDATESETTING_TRANSACTION, data_warning);

            break;
        case UPDATEENERGYLIMITCONTRACT:
            getBase58FromAddress(txContent.contractAddress, strings.common.toAddress);
            if (print_amount(txContent.amount[0],
                             (char *) G_io_apdu_buffer,
                             100,
                             0) == 0) {
                return send_sign_status(E_INCORRECT_LENGTH);
            }
            if (!setContractType(txContent.contractType,
                                 strings.common.fullContract,
                                 sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_UPDATEENERGYLIMIT_TRANSACTION, data_warning);

            break;
        case INVALID_CONTRACT:
            return send_sign_status(E_INCORRECT_DATA);  // Contract not initialized
            break;
        default:
            if (!N_storage.signByHash) {
                return send_sign_status(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write strings.common.fullHash ("0x" + lowercase hex)
            strlcpy(strings.common.fullHash, "0x", 3);
            bytes_to_lowercase_hex(strings.common.fullHash + 2,
                                   sizeof(strings.common.fullHash) - 2,
                                   tmpCtx.transactionContext.hash,
                                   HASH_SIZE);
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return send_sign_status(E_INCORRECT_DATA);
            }

            start_sign_review(APPROVAL_SIMPLE_TRANSACTION, data_warning);

            break;
    }

    return 0;
}
