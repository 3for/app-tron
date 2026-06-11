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
#include "nbgl_use_case.h"
#include "ui_globals.h"
#include "ui_review_menu.h"
#include "ui_idle_menu.h"
#include "ui_nbgl.h"
#include "common_712.h"
#include "trusted_name.h"

// Macros
#define WARNING_TYPES_NUMBER          2
#define MAX_TX_FIELDS                 20
#define MAX_EXTERNAL_PLUGIN_UI_FIELDS EXTERNAL_PLUGIN_UI_MAX_ITEMS_NBGL

#if (MAX_EXTERNAL_PLUGIN_UI_FIELDS != (MAX_TX_FIELDS - 3))
#error "MAX_EXTERNAL_PLUGIN_UI_FIELDS must be MAX_TX_FIELDS - 3"
#endif

static const char *stringLabelSenderAddress = "From";
static const char *stringLabelRecipientAddress = "To";
static const char *stringLabelTxAmount = "Amount";
static const char *stringLabelResource = "Resource";
static const char *stringLabelHash = "Hash";
static const char *stringLabelUrl = "Url";
static const char *stringLabelGain = "Gain";

// Enums and structs
enum {
    DATA_WARNING = 0,
    CUSTOM_CONTRACT_WARNING,
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
static void displayCustomContractWarning(void);
static void reviewChoice(bool confirm);
static void rejectChoice(void);
static bool prepareClearSignCustomContractPluginUi(void);

#ifdef SCREEN_SIZE_WALLET
static void dataWarningChoice(bool accept) {
    if (accept) {
        if (txInfos.warnings[CUSTOM_CONTRACT_WARNING] == true) {
            displayCustomContractWarning();
        } else {
            displayTransaction();
        }
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

static void customContractWarningChoice(bool accept) {
    if (accept) {
        displayTransaction();
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}
#else
static void continueCustomContractWarning(void) {
    displayTransaction();
}

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

static void displayCustomContractWarning(void) {
#ifdef SCREEN_SIZE_WALLET
    nbgl_useCaseChoice(&IMPORTANT_CIRCLE_ICON,
                       "WARNING\nCustom Contract\nProceed with care",
                       "Reject if you're not sure",
                       "Continue",
                       "Reject transaction",
                       customContractWarningChoice);
#else
    nbgl_useCaseAction(&ICON_APP_WARNING,
                       "Custom Contract",
                       "Continue",
                       continueCustomContractWarning);
#endif
}

static void displayTransaction(void) {
    nbgl_operationType_t operationType = TYPE_TRANSACTION;

    if ((txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) ||
        (txInfos.state == APPROVAL_SIGN_TIP72_TRANSACTION)) {
        operationType = TYPE_MESSAGE;
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

static bool prepareClearSignCustomContractPluginUi(void) {
    uint8_t pluginUiItems = 0;
    uint8_t fieldIndex = 0;
    const char *title_msg;
    const char *finish_msg;
    const char *item_title;
    const char *item_msg;

    if (!external_plugin_get_cached_ui_items_count(&pluginUiItems)) {
        return false;
    }

    if ((pluginUiItems == 0) || (pluginUiItems > MAX_EXTERNAL_PLUGIN_UI_FIELDS)) {
        return false;
    }

    title_msg = external_plugin_get_cached_title_msg_ref();
    finish_msg = external_plugin_get_cached_finish_msg_ref();
    if ((title_msg == NULL) || (finish_msg == NULL)) {
        return false;
    }

    txInfos.flowTitle = title_msg;
    txInfos.flowSubtitle = NULL;
    infoLongPress.text = finish_msg;

    for (uint8_t i = 0; i < pluginUiItems; i++) {
        if (!external_plugin_get_cached_contract_ui_ref(i, &item_title, &item_msg)) {
            return false;
        }
        txInfos.fields[fieldIndex].item = item_title;
        txInfos.fields[fieldIndex++].value = item_msg;
    }

    txInfos.fields[fieldIndex].item = "From Address";
    txInfos.fields[fieldIndex++].value = fromAddress;
    pairList.nbPairs = fieldIndex;

    return true;
}

static void reviewStart() {
    if (txInfos.warnings[DATA_WARNING] == true) {
        displayDataWarning();
    } else if (txInfos.warnings[CUSTOM_CONTRACT_WARNING] == true) {
        displayCustomContractWarning();
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
            txInfos.fields[1].value = fullContract;
            if (trusted_name_match) {
                txInfos.fields[2].item = "To (Domain)";
                txInfos.fields[2].value = trusted_name->name;
            } else {
                txInfos.fields[2].item = TRC20ActionSendAllow;
                txInfos.fields[2].value = toAddress;
            }
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
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
            txInfos.fields[0].value = fullHash;
            txInfos.fields[1].item = stringLabelSenderAddress;
            txInfos.fields[1].value = fromAddress;
            pairList.nbPairs = 2;
            break;
        case APPROVAL_WITNESSCREATE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = fromAddress;
            txInfos.fields[1].item = stringLabelUrl;
            txInfos.fields[1].value = url;
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
            txInfos.fields[0].value = fullHash;
            txInfos.fields[1].item = stringLabelSenderAddress;
            txInfos.fields[1].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount 1";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Token 2";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "Amount 2";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
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
            txInfos.fields[0].value = toAddress;
            txInfos.fields[1].item = "Token pair";
            txInfos.fields[1].value = fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Expected";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
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
            txInfos.fields[1].value = toAddress;
            txInfos.fields[2].item = "Token Name";
            txInfos.fields[2].value = fullContract;
            txInfos.fields[3].item = stringLabelTxAmount;
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
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
            txInfos.fields[votes_count].value = fullContract;
            txInfos.fields[votes_count + 1].item = stringLabelSenderAddress;
            txInfos.fields[votes_count + 1].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Freeze To";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Delegated To";
            txInfos.fields[1].value = toAddress;
            txInfos.fields[2].item = stringLabelSenderAddress;
            txInfos.fields[2].value = fromAddress;
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
            txInfos.fields[0].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Sign with";
            txInfos.fields[1].value = fromAddress;
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
            txInfos.warnings[CUSTOM_CONTRACT_WARNING] = true;
            txInfos.fields[0].item = "Contract";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Selector";
            txInfos.fields[1].value = TRC20Action;
            txInfos.fields[2].item = "Pay Token";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "Call Amount";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowSubtitle = "Custom Contract";
            break;
        case APPROVAL_SIGN_EXTERNAL_PLUGIN_CUSTOM_CONTRACT:
#ifndef SCREEN_SIZE_WALLET
            // Limited by the screen size of Nano-series devices
            // External plugin flows already have a descriptive title, so keep the intro card text-only.
            txInfos.flowIcon = NULL;
#endif
            if (!prepareClearSignCustomContractPluginUi()) {
                ui_callback_tx_cancel(false);
                nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
                return false;
            }
            break;
        case APPROVAL_SHARED_ECDH_SECRET:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "ECDH Address";
            txInfos.fields[0].value = fromAddress;
            txInfos.fields[1].item = "Shared With";
            txInfos.fields[1].value = toAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Lock";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = toAddress;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
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
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = fromAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = toAddress;
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
            txInfos.fields[0].value = fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nWithdraw Unfreeze";
            infoLongPress.text = "Sign transaction to\nWithdraw";
            break;
        default:
            PRINTF("This should not happen !\n");
            break;
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
        nbgl_useCaseAddressReview(toAddress,
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
