/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
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
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>

#include "app_errors.h"
#include "apdu_constants.h"
#include "ux.h"
#include "format.h"
#include "nbgl_use_case.h"
#include "ui_globals.h"
#include "ui_review_menu.h"
#include "ui_idle_menu.h"
#include "ui_nbgl.h"
#include "ui_callbacks.h"
#include "common_712.h"
#include "trusted_name.h"
#include "settings.h"
#include "utils.h"  // SET_BIT

// Macros
#define WARNING_TYPES_NUMBER 1
#define MAX_TX_FIELDS        20

static const char *stringLabelSenderAddress = "From";
static const char *stringLabelRecipientAddress = "To";
static const char *stringLabelTxAmount = "Amount";
static const char *stringLabelResource = "Resource";
static const char *stringLabelHash = "Hash";
#ifdef SCREEN_SIZE_WALLET
static const char *stringLabelTxHash = "Transaction hash";
#else
static const char *stringLabelTxHash = "Tx hash";
#endif
static const char *stringLabelUrl = "Url";
static const char *stringLabelGain = "Gain";

// Enums and structs
enum {
    DATA_WARNING = 0,
};

typedef struct {
    nbgl_layoutTagValue_t fields[MAX_TX_FIELDS];
    bool warnings[WARNING_TYPES_NUMBER];
    ui_approval_state_t state;
    const char *flowTitle;
    const char *flowSubtitle;
    const nbgl_icon_details_t *flowIcon;
} nbgl_tx_infos_t;

// Static variables
static nbgl_layoutTagValueList_t pairList;
static nbgl_contentInfoLongPress_t infoLongPress;
static nbgl_tx_infos_t txInfos;
// Alias extension for the recipient trusted name (lets the user reveal the
// underlying address behind the resolved name). Mirrors app-ethereum's
// ui_approve_tx() trusted-name display.
static nbgl_contentValueExt_t toTrustedNameExt;
// Composed review/sign titles derived from the contract type (e.g. "Review
// transaction to\nApprove Proposal"). Used by states that share one APPROVAL_* value
// across several contract types. They must outlive prepareTxInfos() since the async
// NBGL review keeps the pointers.
static char actionReviewTitle[48];
static char actionSignTitle[48];

// Static functions declarations
static bool prepareTxInfos(ui_approval_state_t state, bool data_warning);
static void reviewStart(void);
static void displayTransaction(void);
static void displayDataWarning(void);
static void reviewChoice(bool confirm);
static void rejectChoice(void);
static void rejectStatusDismissed(void);

#ifdef SCREEN_SIZE_WALLET
static void dataWarningChoice(bool accept) {
    if (accept) {
        displayTransaction();
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}
#else
static void continueDataWarning(void) {
    displayTransaction();
}
#endif

static void displayDataWarning(void) {
#ifdef SCREEN_SIZE_WALLET
    nbgl_useCaseChoice(&IMPORTANT_CIRCLE_ICON,
                       "WARNING\nThis transaction\ncontains\nextra data",
                       "Reject if you're not sure",
                       "Continue",
                       "Reject transaction",
                       dataWarningChoice);
#else
    nbgl_useCaseAction(&ICON_APP_WARNING, "Data Present", "Continue", continueDataWarning);
#endif
}

static void displayTransaction(void) {
    nbgl_operationType_t operationType = TYPE_TRANSACTION;

    if ((txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) ||
        (txInfos.state == APPROVAL_SIGN_TIP72_TRANSACTION)) {
        operationType = TYPE_MESSAGE;
    }

    if (txInfos.state == APPROVAL_CUSTOM_CONTRACT) {
        // The blind-signing review's finish title must convey the accepted risk,
        // mirroring app-ethereum's "Accept risk and sign" (ui_tx_simulation_finish_str),
        // rather than the plain "Sign transaction".
        const char *finish_title =
            (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))
                ? "Accept risk and sign transaction"
                : infoLongPress.text;
        nbgl_useCaseAdvancedReview(operationType,
                                   &pairList,
                                   txInfos.flowIcon,
                                   txInfos.flowTitle,
                                   txInfos.flowSubtitle,
                                   finish_title,
                                   NULL,
                                   &warning,
                                   reviewChoice);
        return;
    }

    // Start review
    nbgl_useCaseReview(operationType,
                       &pairList,
                       txInfos.flowIcon,
                       txInfos.flowTitle,
                       txInfos.flowSubtitle,
                       infoLongPress.text,
                       reviewChoice);
}

static void reviewStart() {
    // Custom contract goes straight to the advanced review, which renders the
    // blind-signing (and optional gating) warning itself, so skip the bespoke
    // data/custom-contract warning pages. Mirrors app-ethereum, where dataPresent
    // surfaces the blind-signing warning rather than a separate extra-data page.
    if (txInfos.state == APPROVAL_CUSTOM_CONTRACT) {
        displayTransaction();
        return;
    }
    if (txInfos.warnings[DATA_WARNING] == true) {
        displayDataWarning();
    } else {
        displayTransaction();
    }
}

static void reviewChoice(bool confirm) {
    bool ret;
    nbgl_reviewStatusType_t success_status = STATUS_TYPE_TRANSACTION_SIGNED;

    if (confirm) {
        if (txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) {
            ret = ui_callback_signMessage_ok(false);
            success_status = STATUS_TYPE_MESSAGE_SIGNED;
        } else if (txInfos.state == APPROVAL_SHARED_ECDH_SECRET) {
            ret = ui_callback_ecdh_ok(false);
        } else if (txInfos.state == APPROVAL_SIGN_TIP72_TRANSACTION) {
            ret = ui_712_approve_cb(false);
            success_status = STATUS_TYPE_MESSAGE_SIGNED;
        } else {
            ret = ui_callback_tx_ok(false);
        }

        if (ret) {
            nbgl_useCaseReviewStatus(success_status, ui_idle);
        } else {
            nbgl_useCaseStatus("Transaction failure", false, ui_idle);
        }
    } else {
        rejectChoice();
    }
}

static void rejectChoice(void) {
    nbgl_reviewStatusType_t reject_status = STATUS_TYPE_TRANSACTION_REJECTED;

    if (txInfos.state == APPROVAL_SIGN_TIP72_TRANSACTION) {
        ui_712_reject_cb(false);
        reject_status = STATUS_TYPE_MESSAGE_REJECTED;
    } else {
        if (txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) {
            reject_status = STATUS_TYPE_MESSAGE_REJECTED;
        }
        nbgl_useCaseReviewStatus(reject_status, rejectStatusDismissed);
        return;
    }
    nbgl_useCaseReviewStatus(reject_status, ui_idle);
}

static void rejectStatusDismissed(void) {
    ui_idle();
    io_seproxyhal_send_status(E_CONDITIONS_OF_USE_NOT_SATISFIED, 0, true, false);
}

// Verb-first action phrase for a contract type, so a review reads e.g. "Review
// transaction to Approve Proposal" / "Inject Exchange" instead of a generic or
// ambiguous label. Mirrors the verb-first title style used elsewhere ("Create
// Witness", "Claim Rewards"). Covers the blind-hash-signed types routed to the
// APPROVAL_SIMPLE_TRANSACTION catch-all and the exchange types whose APPROVAL_* value
// is shared across several contract types. Returns NULL for types without a dedicated
// phrase, in which case the review falls back to a plain "Review transaction".
static const char *tx_review_action(contractType_e type) {
    switch (type) {
        case PROPOSALCREATECONTRACT:
            return "Create Proposal";
        case PROPOSALAPPROVECONTRACT:
            return "Approve Proposal";
        case PROPOSALDELETECONTRACT:
            return "Delete Proposal";
        case ACCOUNTCREATECONTRACT:
            return "Create Account";
        case ACCOUNTUPDATECONTRACT:
            return "Update Account";
        case EXCHANGECREATECONTRACT:
            return "Create Exchange";
        case EXCHANGEINJECTCONTRACT:
            return "Inject Exchange";
        case EXCHANGEWITHDRAWCONTRACT:
            return "Withdraw Exchange";
        case EXCHANGETRANSACTIONCONTRACT:
            return "Exchange Swap";
        default:
            return NULL;
    }
}

// Set txInfos.flowTitle / infoLongPress.text from the contract type's verb-first
// action phrase (composed into static buffers), falling back to a plain title.
static void set_action_title(contractType_e type) {
    const char *action = tx_review_action(type);
    if (action != NULL) {
        snprintf(actionReviewTitle, sizeof(actionReviewTitle), "Review transaction to\n%s", action);
        snprintf(actionSignTitle, sizeof(actionSignTitle), "Sign transaction to\n%s", action);
        txInfos.flowTitle = actionReviewTitle;
        infoLongPress.text = actionSignTitle;
    } else {
        txInfos.flowTitle = "Review transaction";
        infoLongPress.text = "Sign transaction";
    }
}

// Whether the optional "Transaction hash" field (the displayHash setting) applies to
// this review. Mirrors app-ethereum's displayHash, which augments clear-signed
// transactions. Excluded are: the states that already display a hash
// (SIMPLE_TRANSACTION / PERMISSION_UPDATE -> blind hash signing), the message/ECDH
// flows (which show their own message hash), and address verification.
static bool state_shows_tx_hash(ui_approval_state_t state) {
    switch (state) {
        case APPROVAL_SIMPLE_TRANSACTION:
        case APPROVAL_PERMISSION_UPDATE:
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
        case APPROVAL_SIGN_TIP72_TRANSACTION:
        case APPROVAL_SHARED_ECDH_SECRET:
        case APPROVAL_VERIFY_ADDRESS:
            return false;
        default:
            return true;
    }
}

static bool prepareTxInfos(ui_approval_state_t state, bool data_warning) {
    memset(&txInfos, 0, sizeof(txInfos));
    memset(&infoLongPress, 0, sizeof(infoLongPress));

    txInfos.warnings[DATA_WARNING] = data_warning;
    txInfos.flowTitle = "Review transaction";
    txInfos.flowIcon = &APP_TRON_ICON;
    txInfos.state = state;

    infoLongPress.text = "Sign transaction";
    infoLongPress.longPressText = "Hold to sign";
    infoLongPress.icon = &APP_TRON_ICON;

    pairList.pairs = (nbgl_layoutTagValue_t *) txInfos.fields;

    uint64_t chain_id = chainConfig->chainId;
    e_name_type type = TN_TYPE_ACCOUNT;
    e_name_source source = TN_SOURCE_ENS;
    bool trusted_name_loaded = has_trusted_name();
    const s_trusted_name *trusted_name =
        get_trusted_name(1, &type, 1, &source, &chain_id, &txContent.destination[1]);
    bool trusted_name_match = trusted_name != NULL;
    PRINTF("### trusted_name_match:%d\n", trusted_name_match);
    if (trusted_name_loaded) {
        txInfos.flowIcon = &APP_TRON_HOME_ICON;
        infoLongPress.icon = &APP_TRON_HOME_ICON;
    }
    switch (state) {
        case APPROVAL_TRANSFER:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
        {
            // Field order mirrors app-ethereum's ui_approve_tx(): From, Amount, To.
            uint8_t idx = 0;
            txInfos.fields[idx].item = stringLabelSenderAddress;
            txInfos.fields[idx].value = strings.common.fromAddress;
            idx++;

            // Single "Amount" field carrying "<value> <ticker>" (the token ticker is
            // merged into G_io_apdu_buffer in sign.c), mirroring app-ethereum's
            // single fullAmount pair instead of separate Amount + Token fields.
            txInfos.fields[idx].item = stringLabelTxAmount;
            txInfos.fields[idx].value = (const char *) G_io_apdu_buffer;
            idx++;

            // TRC10 asset transfers keep Amount and Token split: the token is an
            // asset id/name (often numeric), so merging it into the amount would be
            // ambiguous. sign.c skips the merge for this contract type.
            if (txContent.contractType == TRANSFERASSETCONTRACT) {
                txInfos.fields[idx].item = "Token";
                txInfos.fields[idx].value = strings.common.fullContract;
                idx++;
            }

            txInfos.fields[idx].item = strings.common.TRC20ActionSendAllow;
            if (trusted_name_match) {
                // Show the resolved name with an ENS alias so the user can reveal
                // the underlying address. Mirrors app-ethereum's ui_approve_tx().
                txInfos.fields[idx].value = trusted_name->name;
                toTrustedNameExt.aliasType = ENS_ALIAS;
                toTrustedNameExt.title = trusted_name->name;
                toTrustedNameExt.fullValue = strings.common.toAddress;
                toTrustedNameExt.explanation = strings.common.toAddress;
                txInfos.fields[idx].extension = &toTrustedNameExt;
                txInfos.fields[idx].aliasValue = true;
            } else {
                txInfos.fields[idx].value = strings.common.toAddress;
            }
            idx++;

            // First-screen title describes the transfer type, mirroring app-ethereum's
            // "Review transaction to send/approve ERC20 token" (test_transfer_erc20 /
            // test_approve_erc20). TRC20 distinguishes approve (TRC20Method 2) from send;
            // native TRX and TRC10 keep a "Send" wording.
            const char *transfer_action;
            if (txContent.contractType == TRIGGERSMARTCONTRACT) {
                transfer_action =
                    (txContent.TRC20Method == 2) ? "Approve TRC20 token" : "Send TRC20 token";
            } else if (txContent.contractType == TRANSFERASSETCONTRACT) {
                transfer_action = "Send TRC10 token";
            } else {
                transfer_action = "Send TRX";
            }
            snprintf(actionReviewTitle,
                     sizeof(actionReviewTitle),
                     "Review transaction to\n%s",
                     transfer_action);
            snprintf(actionSignTitle,
                     sizeof(actionSignTitle),
                     "Sign transaction to\n%s",
                     transfer_action);
            txInfos.flowTitle = actionReviewTitle;
            infoLongPress.text = actionSignTitle;
            pairList.nbPairs = idx;
            break;
        }
        case APPROVAL_SIMPLE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelHash;
            txInfos.fields[1].value = strings.common.fullHash;
            // This catch-all state is shared by several blind-hash-signed contract
            // types, so derive the title from the actual contract type rather than
            // hardcoding one action.
            set_action_title(txContent.contractType);
            pairList.nbPairs = 2;
            break;
        case APPROVAL_WITNESSCREATE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelUrl;
            txInfos.fields[1].value = strings.common.url;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nCreate Witness";
            infoLongPress.text = "Sign transaction to\nCreate Witness";
            break;
        case APPROVAL_WITNESSUPDATE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelUrl;
            txInfos.fields[1].value = strings.common.url;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nUpdate Witness";
            infoLongPress.text = "Sign transaction to\nUpdate Witness";
            break;
        case APPROVAL_PERMISSION_UPDATE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelHash;
            txInfos.fields[1].value = strings.common.fullHash;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nUpdate Permission";
            infoLongPress.text = "Sign transaction to\nUpdate Permission";
            break;
        case APPROVAL_EXCHANGE_CREATE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Token 1";
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = "Amount 1";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Token 2";
            txInfos.fields[3].value = strings.common.toAddress;
            txInfos.fields[4].item = "Amount 2";
            txInfos.fields[4].value = (const char *) G_io_apdu_buffer + 100;
            pairList.nbPairs = 5;
            set_action_title(txContent.contractType);
            break;
        case APPROVAL_EXCHANGE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Exchange ID";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = "Token pair";
            txInfos.fields[2].value = strings.common.fullContract;
            txInfos.fields[3].item = stringLabelTxAmount;
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = "Expected";
            txInfos.fields[4].value = (const char *) G_io_apdu_buffer + 100;
            set_action_title(txContent.contractType);
            pairList.nbPairs = 5;
            break;
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Action";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[2].item = "Exchange ID";
            txInfos.fields[2].value = strings.common.toAddress;
            txInfos.fields[3].item = "Token Name";
            txInfos.fields[3].value = strings.common.fullContract;
            txInfos.fields[4].item = stringLabelTxAmount;
            txInfos.fields[4].value = (const char *) G_io_apdu_buffer;
            // Shared by EXCHANGEINJECT/EXCHANGEWITHDRAW; the title now reflects the
            // actual one ("Inject Exchange" / "Withdraw Exchange") instead of both.
            set_action_title(txContent.contractType);
            pairList.nbPairs = 5;
            break;
        case APPROVAL_WITNESSVOTE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if (votes_count > MAX_TX_FIELDS - 2) {
                THROW(E_INCORRECT_DATA);
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            for (uint8_t i = 0; i < votes_count; i++) {
#ifdef SCREEN_SIZE_WALLET
                txInfos.fields[i + 1].item =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i + 1].value =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_AMOUNT));
#else
                txInfos.fields[i + 1].item =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_AMOUNT));
                txInfos.fields[i + 1].value =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_ADDRESS));
#endif
            }
            txInfos.fields[votes_count + 1].item = "Total Vote Count";
            txInfos.fields[votes_count + 1].value = strings.common.fullContract;
            pairList.nbPairs = votes_count + 2;
            txInfos.flowTitle = "Review transaction to\nVote";
            infoLongPress.text = "Sign transaction to\nVote";
            break;
        case APPROVAL_FREEZEASSET_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelGain;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Freeze To";
            txInfos.fields[3].value = strings.common.toAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nFreeze";
            infoLongPress.text = "Sign transaction to\nFreeze";
            break;
        case APPROVAL_UNFREEZEASSET_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelResource;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = "Delegated To";
            txInfos.fields[2].value = strings.common.toAddress;
            pairList.nbPairs = 3;
            txInfos.flowTitle = "Review transaction to\nUnfreeze";
            infoLongPress.text = "Sign transaction to\nUnfreeze";
            break;
        case APPROVAL_WITHDRAWBALANCE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nClaim Rewards";
            infoLongPress.text = "Sign transaction to\nClaim Rewards";
            break;
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "Message hash";
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = "Sign with";
            txInfos.fields[1].value = strings.common.fromAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review message";
            infoLongPress.text = "Sign message";
            break;
        case APPROVAL_SIGN_TIP72_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            tip712_format_hash(0, &txInfos.fields[0].item, &txInfos.fields[0].value);
            tip712_format_hash(1, &txInfos.fields[1].item, &txInfos.fields[1].value);
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review message";
            infoLongPress.text = "Sign message";
            break;
        case APPROVAL_CUSTOM_CONTRACT:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Contract";
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = "Selector";
            txInfos.fields[2].value = strings.common.TRC20Action;
            // Custom contracts only ever pay native TRX, so the token + amount are
            // merged into a single "Amount" field ("<value> TRX", built in sign.c).
            txInfos.fields[3].item = "Amount";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            pairList.nbPairs = 4;
            txInfos.flowSubtitle = "Custom Contract";
            break;
        case APPROVAL_SHARED_ECDH_SECRET:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "ECDH Address";
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Shared With";
            txInfos.fields[1].value = strings.common.toAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nShare ECDH Secret";
            infoLongPress.text = "Sign transaction to\nShare ECDH Secret";
            break;
        case APPROVAL_FREEZEASSETV2_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelGain;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nFreezeV2";
            infoLongPress.text = "Sign transaction to\nFreezeV2";
            break;
        case APPROVAL_UNFREEZEASSETV2_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelResource;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nUnfreezeV2";
            infoLongPress.text = "Sign transaction to\nUnfreezeV2";
            break;
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelResource;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Lock";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelRecipientAddress;
            txInfos.fields[4].value = strings.common.toAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review transaction to\nDelegate Resource";
            infoLongPress.text = "Sign transaction to\nDelegate";
            break;
        case APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelResource;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nUndelegate Resource";
            infoLongPress.text = "Sign transaction to\nUndelegate";
            break;
        case APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nWithdraw Unfreeze";
            infoLongPress.text = "Sign transaction to\nWithdraw";
            break;
        case APPROVAL_CANCELALLUNFREEZEV2_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nCancel All Unfreeze V2";
            infoLongPress.text = "Sign transaction to\nCancel All Unfreeze V2";
            break;
        case APPROVAL_UPDATEBROKERAGE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Brokerage";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nUpdate Brokerage";
            infoLongPress.text = "Sign transaction to\nUpdate Brokerage";
            break;
        default:
            PRINTF("This should not happen !\n");
            break;
    }

    // Append the transaction hash when the displayHash setting is on, or always for the
    // custom-contract blind-signing path. Mirrors app-ethereum's ux_init_strings
    // (`if (N_storage.displayHash || tmpContent.txContent.dataPresent)`): a custom
    // contract only exposes a few raw protobuf fields (the calldata arguments are
    // discarded at parse), so the hash is the only complete commitment to what is
    // actually signed. Only when there is room left in the fields array.
    bool blind_sign = (state == APPROVAL_CUSTOM_CONTRACT);
    if ((N_storage.displayHash || blind_sign) && state_shows_tx_hash(state) &&
        (pairList.nbPairs < MAX_TX_FIELDS)) {
        strlcpy(strings.common.fullHash, "0x", 3);
        bytes_to_lowercase_hex(strings.common.fullHash + 2,
                               sizeof(strings.common.fullHash) - 2,
                               tmpCtx.transactionContext.hash,
                               HASH_SIZE);
        txInfos.fields[pairList.nbPairs].item = stringLabelTxHash;
        txInfos.fields[pairList.nbPairs].value = strings.common.fullHash;
        pairList.nbPairs++;
    }

    return true;
}

static void display_address_callback(bool confirm) {
    if (confirm) {
        ui_callback_address_ok(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle);
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle);
    }
}

void ux_flow_display(ui_approval_state_t state, bool data_warning) {
    if (state == APPROVAL_VERIFY_ADDRESS) {
        nbgl_useCaseAddressReview(strings.common.toAddress,
                                  NULL,
                                  &APP_TRON_HOME_ICON,
                                  "Verify Tron\naddress",
                                  NULL,
                                  display_address_callback);
    } else {
        // Prepare transaction infos to be displayed (field values etc.)
        if (!prepareTxInfos(state, data_warning)) {
            return;
        }
        // Display transaction
        reviewStart();
    }
}
