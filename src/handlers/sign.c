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

    // process buffer
    uint16_t txResult = processTx(workBuffer, dataLength, &txContent);
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
        PRINTF("Regular transaction...\n");
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
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account, strings.common.toAddress, N_storage.truncateAddress);

            ux_flow_display(APPROVAL_WITHDRAWBALANCE_TRANSACTION, data_warning);

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
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

            ux_flow_display(APPROVAL_PERMISSION_UPDATE, data_warning);

            break;
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
