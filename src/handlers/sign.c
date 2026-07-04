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

#ifdef HAVE_SWAP
static void __attribute__((noreturn)) finalize_swap_with_error(uint16_t sw) {
    io_send_sw(sw);
    swap_finalize_exchange_sign_transaction(false);
}
#endif  // HAVE_SWAP

static void fillVoteAddressSlot(void *destination, const char *from, uint8_t index) {
    memset(destination + voteSlot(index, VOTE_ADDRESS), 0, VOTE_PACK);
    memcpy(destination + voteSlot(index, VOTE_ADDRESS), from, VOTE_ADDRESS_SIZE);
}

static void fillVoteAmountSlot(void *destination, uint64_t value, uint8_t index) {
    print_amount(value, destination + voteSlot(index, VOTE_AMOUNT), VOTE_AMOUNT_SIZE, 0);
    PRINTF("Amount: %d - %s\n", index, destination + (voteSlot(index, VOTE_AMOUNT)));
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

static uint8_t count_known_operations(const protocol_Permission_operations_t *operations) {
    uint8_t count = 0;

    for (size_t i = 0; i < sizeof(permission_operations) / sizeof(permission_operations[0]); i++) {
        if (operation_enabled(operations, permission_operations[i].id)) {
            count++;
        }
    }
    return count;
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
    if (operations_match_common_default(operations) ||
        (!operations_have_unknown_bits(operations) && (count_known_operations(operations) > 20))) {
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
        getBase58FromAddress(perm->keys[i].address, address, false);
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

// Raw transaction accumulation buffer. A single top-level protobuf field (the
// `contract`) can exceed one APDU (MAX_APDU_LEN = 255) — e.g. AccountPermissionUpdate
// with multiple permissions. processTx() needs the full contract in one contiguous
// buffer (pb_decode_contract_parameter captures a pointer into it), so we accumulate
// every raw-tx chunk here and decode the growing buffer.
#define MAX_RAW_TX_SIZE 4096  // AccountPermissionUpdate max encoded contract is ~3 KiB.
static uint8_t *raw_tx;
static uint16_t raw_tx_len;

void sign_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &raw_tx);
    APP_MEM_FREE_AND_NULL((void **) &perm_field_labels);
    APP_MEM_FREE_AND_NULL((void **) &perm_field_values);
    raw_tx_len = 0;
    perm_field_count = 0;
}

int handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    uint256_t uint256;
    bool data_warning;

    if (p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        }
        appState = APP_STATE_SIGNING;
        off_t ret = read_bip32_path(workBuffer, dataLength, &tmpCtx.transactionContext.bip32_path);
        if (ret < 0) {
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        initTx(&txContext, &txContent);
        customContractField = 0;
        sign_cleanup();
        raw_tx = APP_MEM_ALLOC(MAX_RAW_TX_SIZE);
        if (raw_tx == NULL) {
            return io_send_sw(E_INCORRECT_DATA);
        }
        raw_tx_len = 0;

    } else if ((p1 & 0xF0) == P1_TRC10_NAME) {
        PRINTF("Setting token name\nContract type: %d\n", txContent.contractType);
        switch (txContent.contractType) {
            case TRANSFERASSETCONTRACT:
            case EXCHANGECREATECONTRACT:
                // Max 2 Tokens Name
                if ((p1 & 0x07) > 1) {
                    return io_send_sw(E_INCORRECT_P1_P2);
                }
                // Decode Token name and validate signature
                if (!parseTokenName((p1 & 0x07), workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    return io_send_sw(E_INCORRECT_DATA);
                }
                // if not last token name, return
                if (!(p1 & 0x08)) {
                    return io_send_sw(E_OK);
                }
                dataLength = 0;

                break;
            case EXCHANGEINJECTCONTRACT:
            case EXCHANGEWITHDRAWCONTRACT:
            case EXCHANGETRANSACTIONCONTRACT:
                // Max 1 pair set
                if ((p1 & 0x07) > 0) {
                    return io_send_sw(E_INCORRECT_P1_P2);
                }
                // error if not last
                if (!(p1 & 0x08)) {
                    return io_send_sw(E_INCORRECT_P1_P2);
                }
                PRINTF("Decoding Exchange\n");
                // Decode Token name and validate signature
                if (!parseExchange(workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    return io_send_sw(E_INCORRECT_DATA);
                }
                dataLength = 0;
                break;
            default:
                // Error if any other contract
                return io_send_sw(E_INCORRECT_DATA);
        }
    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if (p1 == P1_MORE && appState != APP_STATE_SIGNING) {
        PRINTF("Signature not initialized\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        // NOTE: if txContext is not initialized, then there must be seq errors in P1/P2.
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    // hash data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2, 0, workBuffer, dataLength, NULL, 32));

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (G_swap_response_ready) {
            // Safety against trying to make the app sign multiple TX
            // This code should never be triggered as the app is supposed to exit after
            // sending the signed transaction
            PRINTF("Safety against double signing triggered\n");
            os_sched_exit(-1);
        } else {
            // We will quit the app after this transaction, whether it succeeds or fails
            PRINTF("Swap response is ready, the app will quit after the next send\n");
            G_swap_response_ready = true;
        }
    }
#endif

    // Accumulate raw-tx chunks so a contract that spans multiple APDUs is decoded
    // as one contiguous buffer. Token-name chunks (handled above, with dataLength
    // forced to 0) are NOT part of the raw tx and must not re-decode it — re-running
    // the contract decoder would clobber the resolved token names in txContent.
    uint8_t *parse_buf;
    uint32_t parse_len;
    if ((p1 & 0xF0) == P1_TRC10_NAME) {
        parse_buf = workBuffer;
        parse_len = 0;  // token-name completion → processTx returns USTREAM_FINISHED
    } else {
        if ((uint32_t) raw_tx_len + dataLength > MAX_RAW_TX_SIZE) {
            PRINTF("Raw tx exceeds MAX_RAW_TX_SIZE\n");
            return io_send_sw(E_INCORRECT_DATA);
        }
        if (raw_tx == NULL) {
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        memcpy(raw_tx + raw_tx_len, workBuffer, dataLength);
        raw_tx_len += dataLength;
        parse_buf = raw_tx;
        parse_len = raw_tx_len;
    }

    // process buffer
    uint16_t txResult = processTx(parse_buf, parse_len, &txContent);
    PRINTF("txResult: %04x\n", txResult);
    switch (txResult) {
        case USTREAM_PROCESSING:
            // Last data should not return
            if (p1 == P1_LAST || p1 == P1_SIGN) {
                break;
            }
            return io_send_sw(E_OK);
        case USTREAM_FINISHED:
            break;
        case USTREAM_FAULT:
            // A contract spanning multiple APDUs is not fully decodable until its
            // last chunk arrives (pb_decode fails mid-field). On a non-final chunk,
            // treat this as "need more data" and keep accumulating.
            if (p1 != P1_LAST && p1 != P1_SIGN) {
                return io_send_sw(E_OK);
            }
            return io_send_sw(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                finalize_swap_with_error(E_SWAP_CHECKING_FAIL);
            }
#endif
            return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
        default:
            PRINTF("Unexpected parser status\n");
            return io_send_sw(txResult);
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

        getBase58FromAddress(txContent.account,
                             strings.common.fromAddress + prefix_len,
                             N_storage.truncateAddress);
    } else {
        getBase58FromAddress(txContent.account, strings.common.fromAddress, N_storage.truncateAddress);
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
    }
#endif  // HAVE_SWAP

    switch (txContent.contractType) {
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
                    // setting (NOT the separate "Blind signing"/Sign-by-Hash setting).
                    // Surface a page naming the correct setting, then return the precise
                    // TRON status word.
                    if (!N_storage.customContract) {
                        ui_error_custom_contract();
#ifdef SCREEN_SIZE_WALLET
                        return APDU_NO_RESPONSE;
#else
                        return io_send_sw(E_MISSING_SETTING_CUSTOM_CONTRACT);
#endif
                    }
                    customContractField = 1;

                    getBase58FromAddress(txContent.contractAddress,
                                         strings.common.fullContract,
                                         N_storage.truncateAddress);
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
                        print_amount(txContent.amount[0], (void *) G_io_apdu_buffer, 100, SUN_DIG);
                        strlcat((char *) G_io_apdu_buffer, " TRX", sizeof(G_io_apdu_buffer));
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
                        return io_send_sw(E_INCORRECT_DATA);
                    }
#endif  // HAVE_GATING_SUPPORT

                    // approve custom contract
                    ux_flow_display(APPROVAL_CUSTOM_CONTRACT, data_warning);

                    break;
                }

                convertUint256BE(txContent.TRC20Amount, 32, &uint256);
                tostring256(&uint256, 10, (char *) G_io_apdu_buffer + 100, 100);
                if (!adjustDecimals((char *) G_io_apdu_buffer + 100,
                                    strlen((const char *) G_io_apdu_buffer + 100),
                                    (char *) G_io_apdu_buffer,
                                    100,
                                    txContent.decimals[0])) {
                    return io_send_sw(E_INCORRECT_LENGTH);
                }
            } else {
                print_amount(
                    txContent.amount[0],
                    (void *) G_io_apdu_buffer,
                    100,
                    (txContent.contractType == TRANSFERCONTRACT) ? SUN_DIG : txContent.decimals[0]);
            }

            getBase58FromAddress(txContent.destination, strings.common.toAddress, N_storage.truncateAddress);

            // get token name if any
            memcpy(strings.common.fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
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
                strlcat((char *) G_io_apdu_buffer, " ", sizeof(G_io_apdu_buffer));
                strlcat((char *) G_io_apdu_buffer,
                        strings.common.fullContract,
                        sizeof(G_io_apdu_buffer));
            }
            ux_flow_display(APPROVAL_TRANSFER, data_warning);

            break;
        case EXCHANGECREATECONTRACT:

            memcpy(strings.common.fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            memcpy(strings.common.toAddress, txContent.tokenNames[1], txContent.tokenNamesLength[1] + 1);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         (strncmp((const char *) txContent.tokenNames[0], "TRX", 3) == 0)
                             ? SUN_DIG
                             : txContent.decimals[0]);
            print_amount(txContent.amount[1],
                         (void *) G_io_apdu_buffer + 100,
                         100,
                         (strncmp((const char *) txContent.tokenNames[1], "TRX", 3) == 0)
                             ? SUN_DIG
                             : txContent.decimals[1]);

            ux_flow_display(APPROVAL_EXCHANGE_CREATE, data_warning);

            break;
        case EXCHANGEINJECTCONTRACT:
        case EXCHANGEWITHDRAWCONTRACT:

            memcpy(strings.common.fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            print_amount(txContent.exchangeID, (void *) strings.common.toAddress, sizeof(strings.common.toAddress), 0);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         (strncmp((const char *) txContent.tokenNames[0], "TRX", 3) == 0)
                             ? SUN_DIG
                             : txContent.decimals[0]);
            // write exchange contract type
            if (!setExchangeContractDetail(txContent.contractType,
                                           (char *) G_io_apdu_buffer + 100,
                                           sizeof(G_io_apdu_buffer) - 100)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_EXCHANGE_WITHDRAW_INJECT, data_warning);

            break;
        case EXCHANGETRANSACTIONCONTRACT:
            // memcpy(strings.common.fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0]+1);
            snprintf(strings.common.fullContract,
                     sizeof(strings.common.fullContract),
                     "%s -> %s",
                     txContent.tokenNames[0],
                     txContent.tokenNames[1]);

            print_amount(txContent.exchangeID, (void *) strings.common.toAddress, sizeof(strings.common.toAddress), 0);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         txContent.decimals[0]);
            print_amount(txContent.amount[1],
                         (void *) G_io_apdu_buffer + 100,
                         100,
                         txContent.decimals[1]);

            ux_flow_display(APPROVAL_EXCHANGE_TRANSACTION, data_warning);

            break;
        case VOTEWITNESSCONTRACT: {
            // vote for SR
            protocol_VoteWitnessContract *contract = &msg.vote_witness_contract;

            PRINTF("Voting!!\n");
            PRINTF("Count: %d\n", contract->votes_count);
            memset(G_io_apdu_buffer, 0, 200);
            txContent.amount[0] = 0;
            votes_count = contract->votes_count;
            uint32_t total_votes = 0;

            for (int i = 0; i < contract->votes_count; i++) {
                getBase58FromAddress(contract->votes[i].vote_address,
                                     strings.common.fullContract,
                                     N_storage.truncateAddress);
                total_votes += (unsigned int) contract->votes[i].vote_count;
                fillVoteAddressSlot((void *) G_io_apdu_buffer, (const char *) strings.common.fullContract, i);
                fillVoteAmountSlot((void *) G_io_apdu_buffer, contract->votes[i].vote_count, i);
            }

            snprintf((char *) strings.common.fullContract,
                     sizeof(strings.common.fullContract),
                     "%d: %u",
                     contract->votes_count,
                     total_votes);

            ux_flow_display(APPROVAL_WITNESSVOTE_TRANSACTION, data_warning);

        } break;
        case FREEZEBALANCECONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination,
                                     strings.common.toAddress,
                                     N_storage.truncateAddress);
            } else {
                getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);
            }

            ux_flow_display(APPROVAL_FREEZEASSET_TRANSACTION, data_warning);

            break;
        case UNFREEZEBALANCECONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination,
                                     strings.common.toAddress,
                                     N_storage.truncateAddress);
            } else {
                getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);
            }

            ux_flow_display(APPROVAL_UNFREEZEASSET_TRANSACTION, data_warning);

            break;
        case FREEZEBALANCEV2CONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_FREEZEASSETV2_TRANSACTION, data_warning);
            break;
        case UNFREEZEBALANCEV2CONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_UNFREEZEASSETV2_TRANSACTION, data_warning);

            break;
        case DELEGATERESOURCECONTRACT:  // Delegate resource
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            if (txContent.customData == 0) {
                strlcpy((char *) G_io_apdu_buffer + 100, "False", sizeof(G_io_apdu_buffer) - 100);
            } else {
                strlcpy((char *) G_io_apdu_buffer + 100, "True", sizeof(G_io_apdu_buffer) - 100);
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case UNDELEGATERESOURCECONTRACT:  // Undelegate resource
            if (txContent.resource == 0)
                strcpy(strings.common.fullContract, "Bandwidth");
            else
                strcpy(strings.common.fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:  // Withdraw Expire Unfreeze
            getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION, data_warning);

            break;
        case CANCELALLUNFREEZEV2CONTRACT:  // Cancel all pending unstake (UnfreezeV2) requests
            getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_CANCELALLUNFREEZEV2_TRANSACTION, data_warning);

            break;
        case UPDATEBROKERAGECONTRACT:  // Update witness brokerage (reward commission %)
            // brokerage is a percentage in [0, 100], stashed in amount[0] at parse
            snprintf((char *) G_io_apdu_buffer, 100, "%d%%", (int) txContent.amount[0]);

            ux_flow_display(APPROVAL_UPDATEBROKERAGE_TRANSACTION, data_warning);

            break;
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_WITHDRAWBALANCE_TRANSACTION, data_warning);

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT: {
            protocol_AccountPermissionUpdateContract *perm =
                &msg.account_permission_update_contract;

            if (!format_permission_update_fields(perm)) {
                return io_send_sw(E_INCORRECT_DATA);
            }
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_PERMISSION_UPDATE, data_warning);

        } break;
        case WITNESSCREATECONTRACT:
            memcpy(strings.common.url, txContent.url, sizeof(txContent.url));
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_WITNESSCREATE_TRANSACTION, data_warning);

            break;
        case WITNESSUPDATECONTRACT:
            memcpy(strings.common.url, txContent.url, sizeof(txContent.url));
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_WITNESSUPDATE_TRANSACTION, data_warning);

            break;
        case ACCOUNTUPDATECONTRACT:
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_ACCOUNTUPDATE_TRANSACTION, data_warning);

            break;
        case INVALID_CONTRACT:
            return io_send_sw(E_INCORRECT_DATA);  // Contract not initialized
            break;
        default:
            if (!N_storage.signByHash) {
                return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write strings.common.fullHash ("0x" + lowercase hex)
            strlcpy(strings.common.fullHash, "0x", 3);
            bytes_to_lowercase_hex(strings.common.fullHash + 2,
                                   sizeof(strings.common.fullHash) - 2,
                                   tmpCtx.transactionContext.hash,
                                   HASH_SIZE);
            // write contract type
            if (!setContractType(txContent.contractType, strings.common.fullContract, sizeof(strings.common.fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_SIMPLE_TRANSACTION, data_warning);

            break;
    }

    return 0;
}
