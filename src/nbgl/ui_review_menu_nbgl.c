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
#include "common_712.h"
#include "trusted_name.h"
#include "settings.h"

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

// Static functions declarations
static bool prepareTxInfos(ui_approval_state_t state, bool data_warning);
static void reviewStart(void);
static void displayTransaction(void);
static void displayDataWarning(void);
static void reviewChoice(bool confirm);
static void rejectChoice(void);

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
        // Custom contract is a blind-signing path: render through the NBGL advanced
        // review so it shows the blind-signing warning and, when a matching gating
        // descriptor was provided, the "safer signing" prelude. The warning set is
        // populated before this point by set_blind_sign_gating_warning() (sign.c).
        // Mirrors app-ethereum's ux_approve_tx().
#ifndef HAVE_GATING_SUPPORT
        explicit_bzero(&warning, sizeof(nbgl_warning_t));
        warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
#endif  // HAVE_GATING_SUPPORT
        nbgl_useCaseAdvancedReview(operationType,
                                   &pairList,
                                   txInfos.flowIcon,
                                   txInfos.flowTitle,
                                   txInfos.flowSubtitle,
                                   infoLongPress.text,
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
        ui_callback_tx_cancel(false);
        if (txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) {
            reject_status = STATUS_TYPE_MESSAGE_REJECTED;
        }
    }
    nbgl_useCaseReviewStatus(reject_status, ui_idle);
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
            txInfos.fields[0].item = stringLabelTxAmount;
            txInfos.fields[0].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[1].item = "Token";
            txInfos.fields[1].value = strings.common.fullContract;
            if (trusted_name_match) {
                txInfos.fields[2].item = "To (Domain)";
                txInfos.fields[2].value = trusted_name->name;
            } else {
                txInfos.fields[2].item = strings.common.TRC20ActionSendAllow;
                txInfos.fields[2].value = strings.common.toAddress;
            }
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = strings.common.fromAddress;
            txInfos.flowTitle = "Review Transaction";
            infoLongPress.text = "Sign Transaction";
            pairList.nbPairs = 4;
            break;
        case APPROVAL_SIMPLE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelHash;
            txInfos.fields[0].value = strings.common.fullHash;
            txInfos.fields[1].item = stringLabelSenderAddress;
            txInfos.fields[1].value = strings.common.fromAddress;
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
        case APPROVAL_PERMISSION_UPDATE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelHash;
            txInfos.fields[0].value = strings.common.fullHash;
            txInfos.fields[1].item = stringLabelSenderAddress;
            txInfos.fields[1].value = strings.common.fromAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nUpdate Permission";
            infoLongPress.text = "Sign transaction to\nUpdate Permission";
            break;
        case APPROVAL_EXCHANGE_CREATE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "Token 1";
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = "Amount 1";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Token 2";
            txInfos.fields[2].value = strings.common.toAddress;
            txInfos.fields[3].item = "Amount 2";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = strings.common.fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review transaction to\nExchange";
            infoLongPress.text = "Sign transaction to\nExchange";
            break;
        case APPROVAL_EXCHANGE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "Exchange ID";
            txInfos.fields[0].value = strings.common.toAddress;
            txInfos.fields[1].item = "Token pair";
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Expected";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = strings.common.fromAddress;
            pairList.nbPairs = 5;
            break;
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "Action";
            txInfos.fields[0].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[1].item = "Exchange ID";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = "Token Name";
            txInfos.fields[2].value = strings.common.fullContract;
            txInfos.fields[3].item = stringLabelTxAmount;
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = strings.common.fromAddress;
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
            for (uint8_t i = 0; i < votes_count; i++) {
                txInfos.fields[i].item =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i].value =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_AMOUNT));
            }
            txInfos.fields[votes_count].item = "Total Vote Count";
            txInfos.fields[votes_count].value = strings.common.fullContract;
            txInfos.fields[votes_count + 1].item = stringLabelSenderAddress;
            txInfos.fields[votes_count + 1].value = strings.common.fromAddress;
            pairList.nbPairs = votes_count + 2;
            txInfos.flowTitle = "Review transaction to\nVote";
            infoLongPress.text = "Sign transaction to\nVote";
            break;
        case APPROVAL_FREEZEASSET_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelGain;
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Freeze To";
            txInfos.fields[2].value = strings.common.toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = strings.common.fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nFreeze";
            infoLongPress.text = "Sign transaction to\nFreeze";
            break;
        case APPROVAL_UNFREEZEASSET_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = "Delegated To";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = stringLabelSenderAddress;
            txInfos.fields[2].value = strings.common.fromAddress;
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
            txInfos.fields[0].item = "Contract";
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = "Selector";
            txInfos.fields[1].value = strings.common.TRC20Action;
            // Custom contracts only ever pay native TRX, so the token + amount are
            // merged into a single "Amount" field ("<value> TRX", built in sign.c).
            txInfos.fields[2].item = "Amount";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = strings.common.fromAddress;
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
            txInfos.fields[0].item = stringLabelGain;
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = strings.common.toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = strings.common.fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nFreezeV2";
            infoLongPress.text = "Sign transaction to\nFreezeV2";
            break;
        case APPROVAL_UNFREEZEASSETV2_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = strings.common.toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = strings.common.fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nUnfreezeV2";
            infoLongPress.text = "Sign transaction to\nUnfreezeV2";
            break;
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Lock";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = strings.common.fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review transaction to\nDelegate Resource";
            infoLongPress.text = "Sign transaction to\nDelegate";
            break;
        case APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = strings.common.fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = strings.common.fromAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
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
