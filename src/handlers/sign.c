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
#include "handlers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "uint256.h"
#include "app_errors.h"
#include "parse.h"
#include "settings.h"
#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

// TRON permission model: owner=0, witness=1, active=2..9 (max 8 active permissions).
// The largest valid ID is a single decimal digit, which is all the "Px - " prefix can hold.
#define MAX_PERMISSION_ID 9

static void fillVoteAddressSlot(void *destination, const char *from, uint8_t index) {
    memset(destination + voteSlot(index, VOTE_ADDRESS), 0, VOTE_PACK);
    memcpy(destination + voteSlot(index, VOTE_ADDRESS), from, VOTE_ADDRESS_SIZE);
    PRINTF("Vote Address: %d - %s\n", index, destination + (voteSlot(index, VOTE_ADDRESS)));
}

static void fillVoteAmountSlot(void *destination, uint64_t value, uint8_t index) {
    print_amount(value, destination + voteSlot(index, VOTE_AMOUNT), VOTE_AMOUNT_SIZE, 0);
    PRINTF("Amount: %d - %s\n", index, destination + (voteSlot(index, VOTE_AMOUNT)));
}

static bool trigger_has_attached_values(const txContent_t *content) {
    return (content->amount[0] != 0) || (content->callTokenValue != 0) || (content->tokenId != 0);
}

static bool copy_token_label(char *destination,
                             size_t destination_size,
                             const txContent_t *content,
                             uint8_t token_index) {
    if (token_index >= 2) {
        return false;
    }

    const size_t length = content->tokenNamesLength[token_index];
    if ((length >= sizeof(content->tokenNames[token_index])) || (length >= destination_size) ||
        (content->tokenNames[token_index][length] != '\0')) {
        return false;
    }

    memcpy(destination, content->tokenNames[token_index], length + 1);
    return true;
}

static bool set_resource_label(char *destination,
                               size_t destination_size,
                               uint8_t resource,
                               bool allow_tron_power) {
    const char *label;

    switch (resource) {
        case protocol_ResourceCode_BANDWIDTH:
            label = "Bandwidth";
            break;
        case protocol_ResourceCode_ENERGY:
            label = "Energy";
            break;
        case protocol_ResourceCode_TRON_POWER:
            if (!allow_tron_power) {
                return false;
            }
            label = "Tron Power";
            break;
        default:
            return false;
    }

    return strlcpy(destination, label, destination_size) < destination_size;
}

int handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    uint256_t uint256;
    bool data_warning;

    if (p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
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
            // Parsing happens after this fragment has entered the cumulative
            // hash. Poison the session so rejected bytes can never be followed
            // by another fragment and signed.
            txContext.initialized = false;
#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
#endif
            return io_send_sw(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
            txContext.initialized = false;
#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
#endif
            return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
        default:
            PRINTF("Unexpected parser status\n");
            return io_send_sw(txResult);
    }

    if (!txContent.contractSeen) {
        txContext.initialized = false;
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
#endif
        return io_send_sw(E_INCORRECT_DATA);
    }

    if ((txContent.contractType == TRIGGERSMARTCONTRACT) &&
        (txContent.feeLimit > MAX_PROTOCOL_FEE_LIMIT)) {
        // This also rejects negative int64 values, whose protobuf wire value
        // is larger than INT64_MAX. Poison the cumulative hash session.
        txContext.initialized = false;
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
#endif
        return io_send_sw(E_INCORRECT_DATA);
    }

    // Last data hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                               CX_LAST,
                               workBuffer,
                               0,
                               transactionContext.hash,
                               32));

    if (txContent.permission_id > 0) {
        // The fromAddress buffer only reserves 5 bytes for the "Px - " prefix, which fits a
        // single decimal digit. Refuse multi-digit IDs to avoid truncation and a misaligned
        // address being displayed/signed (fail closed).
        if (txContent.permission_id > MAX_PERMISSION_ID) {
            PRINTF("Unsupported permission_id: %d\n", txContent.permission_id);
            return io_send_sw(E_INCORRECT_DATA);
        }
        PRINTF("Set permission_id...\n");
        snprintf((char *) fromAddress, 6, "P%d - ", txContent.permission_id);
        getBase58FromAddress(txContent.account, fromAddress + 5);
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account, fromAddress);
    }

    data_warning = ((txContent.dataBytes > 0) ? true : false);

    if (txContent.hasUnreviewedFields) {
        /* java-tron currently preserves unknown protobuf fields in raw_data and
         * includes them in the transaction ID. They cannot be represented by
         * this app's clear-sign model, but remain compatible with the existing
         * full-hash review when blind signing is explicitly enabled.
         */
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
#endif
        if (!HAS_SETTING(S_SIGN_BY_HASH)) {
            txContext.initialized = false;
            return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);
        }
        format_hex(transactionContext.hash, 32, fullHash, sizeof(fullHash));
        if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
            return io_send_sw(E_INCORRECT_DATA);
        }

        ux_flow_display(txContent.contractType == ACCOUNTPERMISSIONUPDATECONTRACT
                            ? APPROVAL_PERMISSION_UPDATE
                            : APPROVAL_SIMPLE_TRANSACTION,
                        data_warning);
        return 0;
    }

    if (txContent.contractType == TRIGGERSMARTCONTRACT) {
        if (print_amount(txContent.feeLimit,
                         strings.common.maxFee,
                         sizeof(strings.common.maxFee),
                         SUN_DIG) == 0) {
            return io_send_sw(E_INCORRECT_LENGTH);
        }
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((txContent.contractType != TRANSFERCONTRACT) &&      // TRX Transfer
            (txContent.contractType != TRIGGERSMARTCONTRACT)) {  // TRC20 Transfer
            PRINTF("Refused contract type when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }

        if (txContent.contractType == TRIGGERSMARTCONTRACT) {
            if (txContent.TRC20Method != 1) {
                // Only transfer method allowed for TRC20
                PRINTF("Refused method type when in SWAP mode\n");
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
        }

        if (data_warning) {
            PRINTF("Refused data warning when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
    }
#endif  // HAVE_SWAP

    switch (txContent.contractType) {
        case TRANSFERCONTRACT:       // TRX Transfer
        case TRANSFERASSETCONTRACT:  // TRC10 Transfer
        case TRIGGERSMARTCONTRACT:   // TRC20 Transfer

            strcpy(TRC20ActionSendAllow, "To");
            if (txContent.contractType == TRIGGERSMARTCONTRACT) {
                // The standard TRC20 transfer/approve review has room for the
                // ABI operation only. Fail closed if the same contract call
                // also transfers TRX or TRC10 value. In Swap mode preserve the
                // status expected by app-exchange.
                if ((txContent.TRC20Method != 0) && trigger_has_attached_values(&txContent)) {
#ifdef HAVE_SWAP
                    if (G_called_from_swap) {
                        return io_send_sw(E_SWAP_CHECKING_FAIL);
                    }
#endif
                    return io_send_sw(E_INCORRECT_DATA);
                }

                if (txContent.TRC20Method == 1)
                    strcpy(TRC20Action, "Asset");
                else if (txContent.TRC20Method == 2) {
                    strcpy(TRC20ActionSendAllow, "Allow");
                    strcpy(TRC20Action, "Approve");
                } else {
                    if (!HAS_SETTING(S_CUSTOM_CONTRACT)) {
                        return io_send_sw(E_MISSING_SETTING_CUSTOM_CONTRACT);
                    }
                    customContractField = 1;

                    getBase58FromAddress(txContent.contractAddress, fullContract);
                    snprintf((char *) TRC20Action,
                             sizeof(TRC20Action),
                             "%08x",
                             txContent.customSelector);
                    G_io_apdu_buffer[0] = '\0';
                    G_io_apdu_buffer[CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET] = '\0';
                    toAddress[0] = '\0';

                    const bool has_attached_trc10 =
                        (txContent.callTokenValue != 0) || (txContent.tokenId != 0);
                    if (has_attached_trc10) {
                        // No trusted decimals/name metadata is available on
                        // this path. Display the exact token ID and raw amount,
                        // and keep an independently attached TRX value visible.
                        if (txContent.amount[0] > 0) {
                            if (print_amount(txContent.amount[0],
                                             (void *) G_io_apdu_buffer,
                                             CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET,
                                             SUN_DIG) == 0) {
                                return io_send_sw(E_INCORRECT_LENGTH);
                            }
                        } else {
                            strlcpy((char *) G_io_apdu_buffer,
                                    "-",
                                    CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET);
                        }

                        if (print_amount(txContent.tokenId, toAddress, sizeof(toAddress), 0) == 0) {
                            return io_send_sw(E_INCORRECT_LENGTH);
                        }

                        if (txContent.callTokenValue == 0) {
                            strlcpy((char *) G_io_apdu_buffer + CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET,
                                    "0",
                                    sizeof(G_io_apdu_buffer) - CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET);
                        } else if (print_amount(txContent.callTokenValue,
                                                (void *) G_io_apdu_buffer +
                                                    CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET,
                                                sizeof(G_io_apdu_buffer) -
                                                    CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET,
                                                0) == 0) {
                            return io_send_sw(E_INCORRECT_LENGTH);
                        }
                    } else if (txContent.amount[0] > 0) {
                        // Preserve the existing custom-contract review when
                        // only native TRX is attached.
                        strcpy(toAddress, "TRX");
                        print_amount(txContent.amount[0], (void *) G_io_apdu_buffer, 100, SUN_DIG);
                        customContractField |= (1 << 0x05);
                        customContractField |= (1 << 0x06);
                    } else {
                        strcpy(toAddress, "-");
                        strlcpy((char *) G_io_apdu_buffer, "0", sizeof(G_io_apdu_buffer));
                    }

                    // approve custom contract
                    ux_flow_display(APPROVAL_CUSTOM_CONTRACT, data_warning);

                    break;
                }

                if (!convertUint256BE(txContent.TRC20Amount, 32, &uint256)) {
                    return io_send_sw(E_INCORRECT_LENGTH);
                }
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

            getBase58FromAddress(txContent.destination, toAddress);

            // get token name if any
            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            if ((txContent.contractType == TRIGGERSMARTCONTRACT) &&
                txContent.tokenIdentityAmbiguous) {
                // A ticker and decimal count are not a unique TRC20 identity. Preserve the
                // exact contract selected by the signed transaction in the immutable review
                // model so equal-labelled known tokens cannot produce identical approvals.
                getBase58FromAddress(txContent.contractAddress, addressSummary);
            }
#ifdef HAVE_SWAP
            // If we are in swap context, do not redisplay the message data
            // Instead, ensure they are identical with what was previously displayed
            if (G_called_from_swap) {
                if (swap_check_validity(
                        (char *) G_io_apdu_buffer,  // Amount
                        fullContract,               // Token name
                        TRC20ActionSendAllow,       // "Send To"
                        txContent.destination,
                        (txContent.contractType == TRIGGERSMARTCONTRACT) ? txContent.contractAddress
                                                                         : NULL,
                        (txContent.contractType == TRIGGERSMARTCONTRACT) ? txContent.amount[0] : 0,
                        txContent.callTokenValue,
                        txContent.tokenId,
                        txContent.feeLimit,
                        txContent.contractType == TRIGGERSMARTCONTRACT)) {
                    PRINTF("Signing valid swap transaction\n");
                    if (!ui_review_begin(APPROVAL_TRANSFER)) {
                        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
                    }
                    ui_callback_tx_ok(false);
                } else {
                    PRINTF("Refused signing incorrect Swap transaction\n");
                    return io_send_sw(E_SWAP_CHECKING_FAIL);
                }
            } else {
                ux_flow_display(APPROVAL_TRANSFER, data_warning);
            }
#else   // HAVE_SWAP
            ux_flow_display(APPROVAL_TRANSFER, data_warning);
#endif  // HAVE_SWAP

            break;
        case EXCHANGECREATECONTRACT:
            if (!copy_token_label(fullContract, sizeof(fullContract), &txContent, 0) ||
                !copy_token_label(toAddress, sizeof(toAddress), &txContent, 1)) {
                return io_send_sw(E_INCORRECT_DATA);
            }
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         txContent.tokenIsNative[0] ? SUN_DIG : txContent.decimals[0]);
            print_amount(txContent.amount[1],
                         (void *) G_io_apdu_buffer + 100,
                         100,
                         txContent.tokenIsNative[1] ? SUN_DIG : txContent.decimals[1]);

            ux_flow_display(APPROVAL_EXCHANGE_CREATE, data_warning);

            break;
        case EXCHANGEINJECTCONTRACT:
        case EXCHANGEWITHDRAWCONTRACT:

            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            print_amount(txContent.exchangeID, (void *) toAddress, sizeof(toAddress), 0);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         txContent.tokenIsNative[0] ? SUN_DIG : txContent.decimals[0]);
            // write exchange contract type
            if (!setExchangeContractDetail(txContent.contractType,
                                           (char *) G_io_apdu_buffer + 100,
                                           sizeof(G_io_apdu_buffer) - 100)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_EXCHANGE_WITHDRAW_INJECT, data_warning);

            break;
        case EXCHANGETRANSACTIONCONTRACT:
            if (!format_exchange_pair_for_review(fullContract,
                                                 sizeof(fullContract),
                                                 txContent.tokenNames[0],
                                                 txContent.tokenNamesLength[0],
                                                 txContent.tokenNames[1],
                                                 txContent.tokenNamesLength[1])) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            print_amount(txContent.exchangeID, (void *) toAddress, sizeof(toAddress), 0);
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
            memset(G_io_apdu_buffer, 0, REVIEW_DATA_BUFFER_SIZE);
            txContent.amount[0] = 0;
            votes_count = contract->votes_count;
#if defined(HAVE_NBGL)
            uint64_t total_votes = 0;
#endif

            for (int i = 0; i < contract->votes_count; i++) {
                getBase58FromAddress(contract->votes[i].vote_address, fullContract);
#if defined(HAVE_NBGL)
                if ((contract->votes[i].vote_count < 0) ||
                    (UINT64_MAX - total_votes < (uint64_t) contract->votes[i].vote_count)) {
                    return io_send_sw(E_INCORRECT_DATA);
                }
                total_votes += (uint64_t) contract->votes[i].vote_count;
#endif
                fillVoteAddressSlot((void *) G_io_apdu_buffer, (const char *) fullContract, i);
                fillVoteAmountSlot((void *) G_io_apdu_buffer, contract->votes[i].vote_count, i);
            }

#if defined(HAVE_NBGL)
            size_t vote_summary_length = 0;
            if (contract->votes_count == 0u) {
                fullContract[vote_summary_length++] = '0';
            } else {
                vote_summary_length =
                    print_amount(contract->votes_count, fullContract, sizeof(fullContract), 0);
            }
            if ((vote_summary_length == 0u) ||
                (vote_summary_length + 2u >= sizeof(fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }
            fullContract[vote_summary_length++] = ':';
            fullContract[vote_summary_length++] = ' ';
            if (total_votes == 0u) {
                fullContract[vote_summary_length++] = '0';
                fullContract[vote_summary_length] = '\0';
            } else if (print_amount(total_votes,
                                    fullContract + vote_summary_length,
                                    sizeof(fullContract) - vote_summary_length,
                                    0) == 0) {
                return io_send_sw(E_INCORRECT_DATA);
            }
#endif

            ux_flow_display(APPROVAL_WITNESSVOTE_TRANSACTION, data_warning);

        } break;
        case FREEZEBALANCECONTRACT:  // Freeze TRX
            if (!set_resource_label(fullContract, sizeof(fullContract), txContent.resource, true)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination, toAddress);
            } else {
                getBase58FromAddress(txContent.account, toAddress);
            }

            ux_flow_display(APPROVAL_FREEZEASSET_TRANSACTION, data_warning);

            break;
        case UNFREEZEBALANCECONTRACT:  // unreeze TRX
            if (!set_resource_label(fullContract, sizeof(fullContract), txContent.resource, true)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination, toAddress);
            } else {
                getBase58FromAddress(txContent.account, toAddress);
            }

            ux_flow_display(APPROVAL_UNFREEZEASSET_TRANSACTION, data_warning);

            break;
        case FREEZEBALANCEV2CONTRACT:  // Freeze TRX
            if (!set_resource_label(fullContract, sizeof(fullContract), txContent.resource, true)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_FREEZEASSETV2_TRANSACTION, data_warning);
            break;
        case UNFREEZEBALANCEV2CONTRACT:  // unreeze TRX
            if (!set_resource_label(fullContract, sizeof(fullContract), txContent.resource, true)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_UNFREEZEASSETV2_TRANSACTION, data_warning);

            break;
        case DELEGATERESOURCECONTRACT:  // Delegate resource
            memset(G_io_apdu_buffer, 0, REVIEW_DATA_BUFFER_SIZE);
            if (!set_resource_label(fullContract,
                                    sizeof(fullContract),
                                    txContent.resource,
                                    false)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            if (txContent.customData == 0) {
                strlcpy((char *) G_io_apdu_buffer + 100, "False", sizeof(G_io_apdu_buffer) - 100);
            } else {
                strlcpy((char *) G_io_apdu_buffer + 100, "True", sizeof(G_io_apdu_buffer) - 100);
            }

            char *lock_period = (char *) G_io_apdu_buffer + DELEGATE_LOCK_PERIOD_OFFSET;
            if (txContent.customData == 0) {
                strlcpy(lock_period, "Not applied", 32);
            } else if (txContent.lockPeriod == 0) {
                strlcpy(lock_period, "Network default", 32);
            } else {
                if ((txContent.lockPeriod < 0) ||
                    (print_amount((uint64_t) txContent.lockPeriod, lock_period, 32, 0) == 0) ||
                    (strlcat(lock_period, " blocks", 32) >= 32)) {
                    return io_send_sw(E_INCORRECT_DATA);
                }
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, toAddress);

            ux_flow_display(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case UNDELEGATERESOURCECONTRACT:  // Undelegate resource
            if (!set_resource_label(fullContract,
                                    sizeof(fullContract),
                                    txContent.resource,
                                    false)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, toAddress);

            ux_flow_display(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:  // Withdraw Expire Unfreeze
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION, data_warning);

            break;
        case CANCELALLUNFREEZEV2CONTRACT:  // Cancel all pending Stake 2.0 unfreezes
            ux_flow_display(APPROVAL_CANCELALLUNFREEZEV2_TRANSACTION, data_warning);

            break;
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_WITHDRAWBALANCE_TRANSACTION, data_warning);

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            format_hex(transactionContext.hash, 32, fullHash, sizeof(fullHash));
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_PERMISSION_UPDATE, data_warning);

            break;
        case INVALID_CONTRACT:
            return io_send_sw(E_INCORRECT_DATA);  // Contract not initialized
            break;
        default:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            format_hex(transactionContext.hash, 32, fullHash, sizeof(fullHash));
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_SIMPLE_TRANSACTION, data_warning);

            break;
    }

    return 0;
}
