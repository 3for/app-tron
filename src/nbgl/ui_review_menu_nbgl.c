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
#include "app_mem_utils.h"
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
#include "ui_utils.h"
#include "parse.h"

// Macros
#define WARNING_TYPES_NUMBER 1
#define MAX_TX_FIELDS        (PERM_MAX_FIELDS + 1)
#define PROPOSAL_ITEM_LEN    10
#define PROPOSAL_VALUE_LEN   80
#define ASSET_ISSUE_NUMBER_LEN       22
#define ASSET_ISSUE_FROZEN_LABEL_LEN 24

#if MAX_VOTE_COUNT + 3 > MAX_TX_FIELDS
#error "MAX_TX_FIELDS is too small for the vote review flow"
#endif

#if MAX_ASSET_FROZEN_SUPPLY_COUNT * 2 + 17 > MAX_TX_FIELDS
#error "MAX_TX_FIELDS is too small for the asset issue review flow"
#endif

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
    nbgl_contentTagValue_t *fields;
    bool warnings[WARNING_TYPES_NUMBER];
    ui_approval_state_t state;
    const char *flowTitle;
    const char *flowSubtitle;
    const nbgl_icon_details_t *flowIcon;
} nbgl_tx_infos_t;

typedef struct {
    char name[33];
    char abbreviation[33];
    char totalSupply[ASSET_ISSUE_NUMBER_LEN];
    char precision[ASSET_ISSUE_NUMBER_LEN];
    char trxAmount[ASSET_ISSUE_NUMBER_LEN];
    char tokenAmount[ASSET_ISSUE_NUMBER_LEN];
    char startTime[ASSET_ISSUE_NUMBER_LEN];
    char endTime[ASSET_ISSUE_NUMBER_LEN];
    char order[ASSET_ISSUE_NUMBER_LEN];
    char voteScore[ASSET_ISSUE_NUMBER_LEN];
    char description[403];
    char url[515];
    char freeBandwidth[ASSET_ISSUE_NUMBER_LEN];
    char publicFreeBandwidth[ASSET_ISSUE_NUMBER_LEN];
    char publicLatestFreeNetTime[ASSET_ISSUE_NUMBER_LEN];
    char frozenLabels[MAX_ASSET_FROZEN_SUPPLY_COUNT][ASSET_ISSUE_FROZEN_LABEL_LEN];
    char frozenAmounts[MAX_ASSET_FROZEN_SUPPLY_COUNT][ASSET_ISSUE_NUMBER_LEN];
    char frozenDays[MAX_ASSET_FROZEN_SUPPLY_COUNT][ASSET_ISSUE_NUMBER_LEN];
} asset_issue_display_t;

typedef struct {
    char name[67];
    char callValue[32];
    char feeLimit[32];
    char userResourcePercent[24];
    char originEnergyLimit[24];
    char bytecodeSize[24];
    char bytecodeHash[67];
    char tokenId[24];
    char tokenValue[24];
} create_smart_contract_display_t;

// Static variables
static nbgl_contentInfoLongPress_t infoLongPress;
static nbgl_tx_infos_t txInfos;
static char (*proposalFieldLabels)[PROPOSAL_ITEM_LEN];
static char (*proposalFieldValues)[PROPOSAL_VALUE_LEN];
static char proposalIdValue[22];
static asset_issue_display_t *assetIssueDisplay;
static create_smart_contract_display_t *createSmartContractDisplay;
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
// Reviews are asynchronous while the APDU transport immediately reuses its
// buffer. Keep a stable snapshot for all review fields prepared in sign.c.
static uint8_t reviewDisplayBuffer[sizeof(G_io_apdu_buffer)];

// Static functions declarations
static bool prepareTxInfos(ui_approval_state_t state, bool data_warning);
static void reviewStart(void);
static void displayTransaction(void);
static void displayDataWarning(void);
static void reviewChoice(bool confirm);
static void rejectChoice(void);
static void rejectStatusDismissed(void);

static void proposal_fields_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &proposalFieldLabels);
    APP_MEM_FREE_AND_NULL((void **) &proposalFieldValues);
}

static void asset_issue_display_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &assetIssueDisplay);
}

static void create_smart_contract_display_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &createSmartContractDisplay);
}

void ui_review_menu_cleanup(void) {
    proposal_fields_cleanup();
    asset_issue_display_cleanup();
    create_smart_contract_display_cleanup();
    ui_pairs_cleanup();
}

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

    if ((txInfos.state == APPROVAL_CUSTOM_CONTRACT) ||
        (txInfos.state == APPROVAL_CREATESMARTCONTRACT_TRANSACTION)) {
        // The blind-signing review's finish title must convey the accepted risk,
        // mirroring app-ethereum's "Accept risk and sign" (ui_tx_simulation_finish_str),
        // rather than the plain "Sign transaction".
        const char *finish_title =
            (warning.predefinedSet & SET_BIT(BLIND_SIGNING_WARN))
                ? "Accept risk and sign transaction"
                : infoLongPress.text;
        nbgl_useCaseAdvancedReview(operationType,
                                   g_pairsList,
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
                       g_pairsList,
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
    if ((txInfos.state == APPROVAL_CUSTOM_CONTRACT) ||
        (txInfos.state == APPROVAL_CREATESMARTCONTRACT_TRANSACTION)) {
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

static const char *account_type_name(uint8_t type) {
    switch (type) {
        case protocol_AccountType_Normal:
            return "Normal";
        case protocol_AccountType_AssetIssue:
            return "Asset Issue";
        case protocol_AccountType_Contract:
            return "Contract";
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

static bool format_int64_value(int64_t value, char *out, size_t outlen) {
    if (outlen == 0) {
        return false;
    }
    if (value < 0) {
        uint64_t magnitude = (uint64_t) (-(value + 1)) + 1;

        if (outlen < 3) {
            return false;
        }
        out[0] = '-';
        return u64_to_string(magnitude, out + 1, outlen - 1);
    }
    return u64_to_string((uint64_t) value, out, outlen);
}

static bool format_asset_bytes(const uint8_t *value,
                               size_t value_len,
                               char *out,
                               size_t outlen) {
    if (value_len == 0) {
        return strlcpy(out, "-", outlen) == 1;
    }

    bool printable = true;
    for (size_t i = 0; i < value_len; i++) {
        if ((value[i] < 0x20) || (value[i] > 0x7e)) {
            printable = false;
            break;
        }
    }
    if (printable) {
        if (value_len >= outlen) {
            return false;
        }
        memcpy(out, value, value_len);
        out[value_len] = '\0';
        return true;
    }
    return bytes_to_string(out, outlen, value, value_len) == 0;
}

static bool prepare_asset_issue_display(void) {
    protocol_AssetIssueContract *contract = &msg.asset_issue_contract;

    asset_issue_display_cleanup();
    assetIssueDisplay = APP_MEM_ALLOC(sizeof(*assetIssueDisplay));
    if (assetIssueDisplay == NULL) {
        return false;
    }
    memset(assetIssueDisplay, 0, sizeof(*assetIssueDisplay));

    if (!format_asset_bytes(contract->name.bytes,
                            contract->name.size,
                            assetIssueDisplay->name,
                            sizeof(assetIssueDisplay->name)) ||
        !format_asset_bytes(contract->abbr.bytes,
                            contract->abbr.size,
                            assetIssueDisplay->abbreviation,
                            sizeof(assetIssueDisplay->abbreviation)) ||
        !u64_to_string((uint64_t) contract->total_supply,
                       assetIssueDisplay->totalSupply,
                       sizeof(assetIssueDisplay->totalSupply)) ||
        !u64_to_string((uint64_t) contract->precision,
                       assetIssueDisplay->precision,
                       sizeof(assetIssueDisplay->precision)) ||
        !u64_to_string((uint64_t) contract->trx_num,
                       assetIssueDisplay->trxAmount,
                       sizeof(assetIssueDisplay->trxAmount)) ||
        !u64_to_string((uint64_t) contract->num,
                       assetIssueDisplay->tokenAmount,
                       sizeof(assetIssueDisplay->tokenAmount)) ||
        !u64_to_string((uint64_t) contract->start_time,
                       assetIssueDisplay->startTime,
                       sizeof(assetIssueDisplay->startTime)) ||
        !u64_to_string((uint64_t) contract->end_time,
                       assetIssueDisplay->endTime,
                       sizeof(assetIssueDisplay->endTime)) ||
        !format_int64_value(contract->order,
                            assetIssueDisplay->order,
                            sizeof(assetIssueDisplay->order)) ||
        !format_int64_value(contract->vote_score,
                            assetIssueDisplay->voteScore,
                            sizeof(assetIssueDisplay->voteScore)) ||
        !format_asset_bytes(contract->description.bytes,
                            contract->description.size,
                            assetIssueDisplay->description,
                            sizeof(assetIssueDisplay->description)) ||
        !format_asset_bytes(contract->url.bytes,
                            contract->url.size,
                            assetIssueDisplay->url,
                            sizeof(assetIssueDisplay->url)) ||
        !u64_to_string((uint64_t) contract->free_asset_net_limit,
                       assetIssueDisplay->freeBandwidth,
                       sizeof(assetIssueDisplay->freeBandwidth)) ||
        !u64_to_string((uint64_t) contract->public_free_asset_net_limit,
                       assetIssueDisplay->publicFreeBandwidth,
                       sizeof(assetIssueDisplay->publicFreeBandwidth)) ||
        !format_int64_value(contract->public_latest_free_net_time,
                            assetIssueDisplay->publicLatestFreeNetTime,
                            sizeof(assetIssueDisplay->publicLatestFreeNetTime))) {
        asset_issue_display_cleanup();
        return false;
    }

    for (pb_size_t i = 0; i < contract->frozen_supply_count; i++) {
        snprintf(assetIssueDisplay->frozenLabels[i],
                 sizeof(assetIssueDisplay->frozenLabels[i]),
                 "Frozen amount %u",
                 (unsigned) i + 1);
        if (!u64_to_string((uint64_t) contract->frozen_supply[i].frozen_amount,
                           assetIssueDisplay->frozenAmounts[i],
                           sizeof(assetIssueDisplay->frozenAmounts[i])) ||
            !u64_to_string((uint64_t) contract->frozen_supply[i].frozen_days,
                           assetIssueDisplay->frozenDays[i],
                           sizeof(assetIssueDisplay->frozenDays[i]))) {
            asset_issue_display_cleanup();
            return false;
        }
    }
    return true;
}

static bool prepare_update_asset_display(void) {
    protocol_UpdateAssetContract *contract = &msg.update_asset_contract;

    asset_issue_display_cleanup();
    assetIssueDisplay = APP_MEM_ALLOC(sizeof(*assetIssueDisplay));
    if (assetIssueDisplay == NULL) {
        return false;
    }
    memset(assetIssueDisplay, 0, sizeof(*assetIssueDisplay));

    if (!format_asset_bytes(contract->description.bytes,
                            contract->description.size,
                            assetIssueDisplay->description,
                            sizeof(assetIssueDisplay->description)) ||
        !format_asset_bytes(contract->url.bytes,
                            contract->url.size,
                            assetIssueDisplay->url,
                            sizeof(assetIssueDisplay->url)) ||
        !u64_to_string((uint64_t) contract->new_limit,
                       assetIssueDisplay->freeBandwidth,
                       sizeof(assetIssueDisplay->freeBandwidth)) ||
        !u64_to_string((uint64_t) contract->new_public_limit,
                       assetIssueDisplay->publicFreeBandwidth,
                       sizeof(assetIssueDisplay->publicFreeBandwidth))) {
        asset_issue_display_cleanup();
        return false;
    }
    return true;
}

static bool format_create_trx_amount(uint64_t value, char *out, size_t outlen) {
    if (value == 0) {
        return strlcpy(out, "0 TRX", outlen) == 5;
    }
    if ((print_amount(value, out, outlen, TRX_DECIMALS) == 0) ||
        (strlcat(out, " TRX", outlen) >= outlen)) {
        return false;
    }
    return true;
}

static bool prepare_create_smart_contract_display(void) {
    protocol_CreateSmartContract *contract = &msg.create_smart_contract;
    protocol_SmartContract *new_contract = &contract->new_contract;

    create_smart_contract_display_cleanup();
    createSmartContractDisplay = APP_MEM_ALLOC(sizeof(*createSmartContractDisplay));
    if (createSmartContractDisplay == NULL) {
        return false;
    }
    memset(createSmartContractDisplay, 0, sizeof(*createSmartContractDisplay));

    if (!format_asset_bytes((const uint8_t *) new_contract->name,
                            strlen(new_contract->name),
                            createSmartContractDisplay->name,
                            sizeof(createSmartContractDisplay->name)) ||
        !format_create_trx_amount((uint64_t) new_contract->call_value,
                                  createSmartContractDisplay->callValue,
                                  sizeof(createSmartContractDisplay->callValue)) ||
        !format_create_trx_amount(txContent.feeLimit,
                                  createSmartContractDisplay->feeLimit,
                                  sizeof(createSmartContractDisplay->feeLimit)) ||
        !u64_to_string((uint64_t) new_contract->consume_user_resource_percent,
                       createSmartContractDisplay->userResourcePercent,
                       sizeof(createSmartContractDisplay->userResourcePercent)) ||
        (strlcat(createSmartContractDisplay->userResourcePercent,
                 "%",
                 sizeof(createSmartContractDisplay->userResourcePercent)) >=
         sizeof(createSmartContractDisplay->userResourcePercent)) ||
        !u64_to_string((uint64_t) new_contract->origin_energy_limit,
                       createSmartContractDisplay->originEnergyLimit,
                       sizeof(createSmartContractDisplay->originEnergyLimit)) ||
        !u64_to_string(txContent.bytecodeSize,
                       createSmartContractDisplay->bytecodeSize,
                       sizeof(createSmartContractDisplay->bytecodeSize)) ||
        (bytes_to_string(createSmartContractDisplay->bytecodeHash,
                         sizeof(createSmartContractDisplay->bytecodeHash),
                         txContent.bytecodeHash,
                         sizeof(txContent.bytecodeHash)) != 0) ||
        !u64_to_string((uint64_t) contract->token_id,
                       createSmartContractDisplay->tokenId,
                       sizeof(createSmartContractDisplay->tokenId)) ||
        !u64_to_string((uint64_t) contract->call_token_value,
                       createSmartContractDisplay->tokenValue,
                       sizeof(createSmartContractDisplay->tokenValue))) {
        create_smart_contract_display_cleanup();
        return false;
    }
    return true;
}

// Whether the optional "Transaction hash" field (the displayHash setting) applies to
// this review. Mirrors app-ethereum's displayHash, which augments clear-signed
// transactions. Excluded are: the states that already display a hash
// (SIMPLE_TRANSACTION), Permission Update (already renders the permission details),
// the message/ECDH flows (which show their own message hash), and address verification.
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
    memcpy(reviewDisplayBuffer, G_io_apdu_buffer, sizeof(reviewDisplayBuffer));
    memset(&txInfos, 0, sizeof(txInfos));
    memset(&infoLongPress, 0, sizeof(infoLongPress));

    txInfos.warnings[DATA_WARNING] = data_warning;
    txInfos.flowTitle = "Review transaction";
    txInfos.flowIcon = &APP_TRON_ICON;
    txInfos.state = state;

    infoLongPress.text = "Sign transaction";
    infoLongPress.longPressText = "Hold to sign";
    infoLongPress.icon = &APP_TRON_ICON;

    if (!ui_pairs_init(MAX_TX_FIELDS)) {
        return false;
    }
    txInfos.fields = g_pairs;

    uint64_t chain_id = chainConfig->chainId;
    e_name_type type = TN_TYPE_ACCOUNT;
    e_name_source sources[] = {TN_SOURCE_ENS, TN_SOURCE_MAB};
    const s_trusted_name *trusted_name =
        get_trusted_name(1,
                         &type,
                         ARRAYLEN(sources),
                         sources,
                         &chain_id,
                         &txContent.destination[1]);
    bool trusted_name_match = trusted_name != NULL;
    PRINTF("### trusted_name_match:%d\n", trusted_name_match);
    if (trusted_name_match) {
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
            txInfos.fields[idx].value = (const char *) reviewDisplayBuffer;
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
                toTrustedNameExt.aliasType = (trusted_name->name_source == TN_SOURCE_MAB)
                                                 ? ADDRESS_BOOK_ALIAS
                                                 : ENS_ALIAS;
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
            g_pairsList->nbPairs = idx;
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
            g_pairsList->nbPairs = 2;
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
            g_pairsList->nbPairs = 2;
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
            g_pairsList->nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nUpdate Witness";
            infoLongPress.text = "Sign transaction to\nUpdate Witness";
            break;
        case APPROVAL_ACCOUNTCREATE_TRANSACTION: {
            const char *accountType = account_type_name(txContent.accountType);
            if (accountType == NULL) {
                return false;
            }
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Account";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = "Account type";
            txInfos.fields[2].value = accountType;
            g_pairsList->nbPairs = 3;
            txInfos.flowTitle = "Review transaction to\nCreate Account";
            infoLongPress.text = "Sign transaction to\nCreate Account";
            break;
        }
        case APPROVAL_ASSETISSUE_TRANSACTION: {
            protocol_AssetIssueContract *contract = &msg.asset_issue_contract;
            uint8_t idx = 0;

#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if ((contract->frozen_supply_count > MAX_ASSET_FROZEN_SUPPLY_COUNT) ||
                !prepare_asset_issue_display()) {
                return false;
            }
#define ADD_ASSET_ISSUE_FIELD(label_, value_)           \
    do {                                                 \
        txInfos.fields[idx].item = (label_);             \
        txInfos.fields[idx].value = (value_);            \
        idx++;                                           \
    } while (0)
            ADD_ASSET_ISSUE_FIELD(stringLabelSenderAddress, strings.common.fromAddress);
            ADD_ASSET_ISSUE_FIELD("Name", assetIssueDisplay->name);
            ADD_ASSET_ISSUE_FIELD("Abbreviation", assetIssueDisplay->abbreviation);
            ADD_ASSET_ISSUE_FIELD("Total supply", assetIssueDisplay->totalSupply);
            ADD_ASSET_ISSUE_FIELD("Precision", assetIssueDisplay->precision);
            ADD_ASSET_ISSUE_FIELD("TRX amount", assetIssueDisplay->trxAmount);
            ADD_ASSET_ISSUE_FIELD("Token amount", assetIssueDisplay->tokenAmount);
            ADD_ASSET_ISSUE_FIELD("Start time (ms)", assetIssueDisplay->startTime);
            ADD_ASSET_ISSUE_FIELD("End time (ms)", assetIssueDisplay->endTime);
            ADD_ASSET_ISSUE_FIELD("Description", assetIssueDisplay->description);
            ADD_ASSET_ISSUE_FIELD(stringLabelUrl, assetIssueDisplay->url);
            ADD_ASSET_ISSUE_FIELD("Free bandwidth", assetIssueDisplay->freeBandwidth);
            ADD_ASSET_ISSUE_FIELD("Public bandwidth", assetIssueDisplay->publicFreeBandwidth);
            ADD_ASSET_ISSUE_FIELD("Vote score", assetIssueDisplay->voteScore);
            ADD_ASSET_ISSUE_FIELD("Public net time", assetIssueDisplay->publicLatestFreeNetTime);
            if (contract->order != 0) {
                ADD_ASSET_ISSUE_FIELD("Legacy order", assetIssueDisplay->order);
            }
            for (pb_size_t i = 0; i < contract->frozen_supply_count; i++) {
                ADD_ASSET_ISSUE_FIELD(assetIssueDisplay->frozenLabels[i],
                                      assetIssueDisplay->frozenAmounts[i]);
                ADD_ASSET_ISSUE_FIELD("Frozen days", assetIssueDisplay->frozenDays[i]);
            }
#undef ADD_ASSET_ISSUE_FIELD
            g_pairsList->nbPairs = idx;
            txInfos.flowTitle = "Review transaction to\nIssue Asset";
            infoLongPress.text = "Sign transaction to\nIssue Asset";
            break;
        }
        case APPROVAL_PARTICIPATEASSETISSUE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Issuer";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = "TRX amount";
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = "Asset ID";
            txInfos.fields[3].value = strings.common.fullContract;
            g_pairsList->nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nParticipate Asset Issue";
            infoLongPress.text = "Sign transaction to\nParticipate Asset Issue";
            break;
        case APPROVAL_UNFREEZETRC10_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            g_pairsList->nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nUnfreeze Asset";
            infoLongPress.text = "Sign transaction to\nUnfreeze Asset";
            break;
        case APPROVAL_UPDATEASSET_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if (!prepare_update_asset_display()) {
                return false;
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Description";
            txInfos.fields[1].value = assetIssueDisplay->description;
            txInfos.fields[2].item = stringLabelUrl;
            txInfos.fields[2].value = assetIssueDisplay->url;
            txInfos.fields[3].item = "Free bandwidth";
            txInfos.fields[3].value = assetIssueDisplay->freeBandwidth;
            txInfos.fields[4].item = "Public bandwidth";
            txInfos.fields[4].value = assetIssueDisplay->publicFreeBandwidth;
            g_pairsList->nbPairs = 5;
            txInfos.flowTitle = "Review transaction to\nUpdate Asset";
            infoLongPress.text = "Sign transaction to\nUpdate Asset";
            break;
        case APPROVAL_ACCOUNTUPDATE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Name";
            txInfos.fields[1].value = txContent.accountName;
            g_pairsList->nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nUpdate Account";
            infoLongPress.text = "Sign transaction to\nUpdate Account";
            break;
        case APPROVAL_SETACCOUNTID_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Account ID";
            txInfos.fields[1].value = txContent.accountName;
            g_pairsList->nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nSet Account ID";
            infoLongPress.text = "Sign transaction to\nSet Account ID";
            break;
        case APPROVAL_CREATESMARTCONTRACT_TRANSACTION: {
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if (!prepare_create_smart_contract_display()) {
                return false;
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Contract name";
            txInfos.fields[1].value = createSmartContractDisplay->name;
            txInfos.fields[2].item = "Call value";
            txInfos.fields[2].value = createSmartContractDisplay->callValue;
            txInfos.fields[3].item = "Fee limit";
            txInfos.fields[3].value = createSmartContractDisplay->feeLimit;
            txInfos.fields[4].item = "User resource share";
            txInfos.fields[4].value = createSmartContractDisplay->userResourcePercent;
            txInfos.fields[5].item = "Origin energy limit";
            txInfos.fields[5].value = createSmartContractDisplay->originEnergyLimit;
            txInfos.fields[6].item = "Bytecode size";
            txInfos.fields[6].value = createSmartContractDisplay->bytecodeSize;
            txInfos.fields[7].item = "Bytecode hash";
            txInfos.fields[7].value = createSmartContractDisplay->bytecodeHash;
            g_pairsList->nbPairs = 8;

            protocol_CreateSmartContract *contract = &msg.create_smart_contract;
            if ((contract->token_id != 0) || (contract->call_token_value != 0)) {
                txInfos.fields[8].item = "TRC10 ID";
                txInfos.fields[8].value = createSmartContractDisplay->tokenId;
                txInfos.fields[9].item = "TRC10 amount";
                txInfos.fields[9].value = createSmartContractDisplay->tokenValue;
                g_pairsList->nbPairs = 10;
            }
            txInfos.flowTitle = "Review transaction to\nDeploy Smart Contract";
            txInfos.flowSubtitle = "Smart contract deployment";
            infoLongPress.text = "Accept risk and deploy contract";
            break;
        }
        case APPROVAL_CLEARABI_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Contract";
            txInfos.fields[1].value = strings.common.toAddress;
            g_pairsList->nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nClear Contract ABI";
            infoLongPress.text = "Sign transaction to\nClear Contract ABI";
            break;
        case APPROVAL_UPDATESETTING_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Contract";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = "User resource share";
            txInfos.fields[2].value = (char *) reviewDisplayBuffer;
            g_pairsList->nbPairs = 3;
            txInfos.flowTitle = "Review transaction to\nUpdate Contract Setting";
            infoLongPress.text = "Sign transaction to\nUpdate Contract Setting";
            break;
        case APPROVAL_UPDATEENERGYLIMIT_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Contract";
            txInfos.fields[1].value = strings.common.toAddress;
            txInfos.fields[2].item = "Origin energy limit";
            txInfos.fields[2].value = (char *) reviewDisplayBuffer;
            g_pairsList->nbPairs = 3;
            txInfos.flowTitle = "Review transaction to\nUpdate Energy Limit";
            infoLongPress.text = "Sign transaction to\nUpdate Energy Limit";
            break;
        case APPROVAL_PROPOSALCREATE_TRANSACTION: {
            pb_size_t count = proposal_parameter_count();

#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if ((count == 0) || (count > MAX_PROPOSAL_PARAMETERS) ||
                (count > MAX_TX_FIELDS - 1)) {
                proposal_parameters_cleanup();
                return false;
            }
            proposal_fields_cleanup();
            proposalFieldLabels = APP_MEM_ALLOC(count * sizeof(*proposalFieldLabels));
            proposalFieldValues = APP_MEM_ALLOC(count * sizeof(*proposalFieldValues));
            if ((proposalFieldLabels == NULL) || (proposalFieldValues == NULL)) {
                proposal_fields_cleanup();
                proposal_parameters_cleanup();
                return false;
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            for (pb_size_t i = 0; i < count; i++) {
                int64_t key;
                int64_t value;
                char key_str[22];
                char value_str[22];

                if (!proposal_parameter_at(i, &key, &value)) {
                    proposal_fields_cleanup();
                    proposal_parameters_cleanup();
                    return false;
                }
                if (!format_int64_value(key, key_str, sizeof(key_str)) ||
                    !format_int64_value(value, value_str, sizeof(value_str))) {
                    proposal_fields_cleanup();
                    proposal_parameters_cleanup();
                    return false;
                }
                snprintf(proposalFieldLabels[i],
                         sizeof(proposalFieldLabels[i]),
                         "Param %u",
                         (unsigned) i + 1);
                snprintf(proposalFieldValues[i],
                         sizeof(proposalFieldValues[i]),
                         "Key: %s\nValue: %s",
                         key_str,
                         value_str);
                txInfos.fields[i + 1].item = proposalFieldLabels[i];
                txInfos.fields[i + 1].value = proposalFieldValues[i];
            }
            proposal_parameters_cleanup();
            g_pairsList->nbPairs = count + 1;
            txInfos.flowTitle = "Review transaction to\nCreate Proposal";
            infoLongPress.text = "Sign transaction to\nCreate Proposal";
            break;
        }
        case APPROVAL_PROPOSALAPPROVE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if (!u64_to_string(txContent.exchangeID, proposalIdValue, sizeof(proposalIdValue))) {
                return false;
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Proposal ID";
            txInfos.fields[1].value = proposalIdValue;
            txInfos.fields[2].item = "Action";
            txInfos.fields[2].value =
                (txContent.amount[0] == 0) ? "Remove Approval" : "Approve";
            g_pairsList->nbPairs = 3;
            txInfos.flowTitle = "Review transaction to\nApprove Proposal";
            infoLongPress.text = "Sign transaction to\nApprove Proposal";
            break;
        case APPROVAL_PROPOSALDELETE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if (!u64_to_string(txContent.exchangeID, proposalIdValue, sizeof(proposalIdValue))) {
                return false;
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Proposal ID";
            txInfos.fields[1].value = proposalIdValue;
            g_pairsList->nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nDelete Proposal";
            infoLongPress.text = "Sign transaction to\nDelete Proposal";
            break;
        case APPROVAL_PERMISSION_UPDATE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            if ((perm_field_count == 0) || (perm_field_count > PERM_MAX_FIELDS)) {
                return false;
            }
            for (uint8_t i = 0; i < perm_field_count; i++) {
                txInfos.fields[i + 1].item = perm_field_items[i];
                txInfos.fields[i + 1].value = perm_field_values[i];
            }
            g_pairsList->nbPairs = perm_field_count + 1;
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
            txInfos.fields[1].value = txContent.tokenNames[0];
            txInfos.fields[2].item = "Amount 1";
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = "Token 2";
            txInfos.fields[3].value = txContent.tokenNames[1];
            txInfos.fields[4].item = "Amount 2";
            txInfos.fields[4].value = (const char *) reviewDisplayBuffer + 100;
            g_pairsList->nbPairs = 5;
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
            txInfos.fields[2].item = "From token";
            txInfos.fields[2].value = txContent.tokenNames[0];
            txInfos.fields[3].item = "To token";
            txInfos.fields[3].value = txContent.tokenNames[1];
            txInfos.fields[4].item = stringLabelTxAmount;
            txInfos.fields[4].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[5].item = "Expected";
            txInfos.fields[5].value = (const char *) reviewDisplayBuffer + 100;
            set_action_title(txContent.contractType);
            g_pairsList->nbPairs = 6;
            break;
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = "Action";
            txInfos.fields[1].value = (const char *) reviewDisplayBuffer + 100;
            txInfos.fields[2].item = "Exchange ID";
            txInfos.fields[2].value = strings.common.toAddress;
            txInfos.fields[3].item = "Token Name";
            txInfos.fields[3].value = txContent.tokenNames[0];
            txInfos.fields[4].item = stringLabelTxAmount;
            txInfos.fields[4].value = (const char *) reviewDisplayBuffer;
            // Shared by EXCHANGEINJECT/EXCHANGEWITHDRAW; the title now reflects the
            // actual one ("Inject Exchange" / "Withdraw Exchange") instead of both.
            set_action_title(txContent.contractType);
            g_pairsList->nbPairs = 5;
            break;
        case APPROVAL_WITNESSVOTE_TRANSACTION:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            if ((votes_count > MAX_VOTE_COUNT) || (votes_count > MAX_TX_FIELDS - 2) ||
                (vote_display_buffer == NULL)) {
                THROW(E_INCORRECT_DATA);
            }
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            for (uint8_t i = 0; i < votes_count; i++) {
#ifdef SCREEN_SIZE_WALLET
                txInfos.fields[i + 1].item =
                    (vote_display_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i + 1].value =
                    (vote_display_buffer + voteSlot(i, VOTE_AMOUNT));
#else
                txInfos.fields[i + 1].item =
                    (vote_display_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i + 1].value = NULL;
#endif
            }
            txInfos.fields[votes_count + 1].item = "Total Vote Count";
            txInfos.fields[votes_count + 1].value = strings.common.fullContract;
            g_pairsList->nbPairs = votes_count + 2;
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
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = "Freeze To";
            txInfos.fields[3].value = strings.common.toAddress;
            g_pairsList->nbPairs = 4;
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
            g_pairsList->nbPairs = 3;
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
            g_pairsList->nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nClaim Rewards";
            infoLongPress.text = "Sign transaction to\nClaim Rewards";
            break;
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = "Message hash";
            txInfos.fields[0].value = strings.common.fullHash;
            txInfos.fields[1].item = "Sign with";
            txInfos.fields[1].value = strings.common.fromAddress;
            g_pairsList->nbPairs = 2;
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
            g_pairsList->nbPairs = 2;
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
            txInfos.fields[3].value = (const char *) reviewDisplayBuffer;
            g_pairsList->nbPairs = 4;
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
            g_pairsList->nbPairs = 2;
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
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            g_pairsList->nbPairs = 4;
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
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            g_pairsList->nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nUnfreezeV2";
            infoLongPress.text = "Sign transaction to\nUnfreezeV2";
            break;
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION: {
            uint8_t idx = 4;
#if !defined(SCREEN_SIZE_WALLET)
            txInfos.flowIcon = &APP_TRON_HOME_ICON;
            infoLongPress.icon = &APP_TRON_HOME_ICON;
#endif
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = strings.common.fromAddress;
            txInfos.fields[1].item = stringLabelResource;
            txInfos.fields[1].value = strings.common.fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = "Lock";
            txInfos.fields[3].value = (const char *) reviewDisplayBuffer + 100;
            if (txContent.lock) {
                if (!format_int64_value(txContent.lockPeriod,
                                        (char *) reviewDisplayBuffer + 106,
                                        sizeof(reviewDisplayBuffer) - 106)) {
                    return false;
                }
                txInfos.fields[idx].item = "Lock period (blocks)";
                txInfos.fields[idx].value = (const char *) reviewDisplayBuffer + 106;
                idx++;
            }
            txInfos.fields[idx].item = stringLabelRecipientAddress;
            txInfos.fields[idx].value = strings.common.toAddress;
            g_pairsList->nbPairs = idx + 1;
            txInfos.flowTitle = "Review transaction to\nDelegate Resource";
            infoLongPress.text = "Sign transaction to\nDelegate";
            break;
        }
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
            txInfos.fields[2].value = (const char *) reviewDisplayBuffer;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = strings.common.toAddress;
            g_pairsList->nbPairs = 4;
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
            g_pairsList->nbPairs = 1;
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
            g_pairsList->nbPairs = 1;
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
            txInfos.fields[1].value = (const char *) reviewDisplayBuffer;
            g_pairsList->nbPairs = 2;
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
    bool blind_sign = (state == APPROVAL_CUSTOM_CONTRACT) ||
                      (state == APPROVAL_CREATESMARTCONTRACT_TRANSACTION);
    if ((N_storage.displayHash || blind_sign) && state_shows_tx_hash(state) &&
        (g_pairsList->nbPairs < MAX_TX_FIELDS)) {
        strlcpy(strings.common.fullHash, "0x", 3);
        bytes_to_lowercase_hex(strings.common.fullHash + 2,
                               sizeof(strings.common.fullHash) - 2,
                               tmpCtx.transactionContext.hash,
                               HASH_SIZE);
        txInfos.fields[g_pairsList->nbPairs].item = stringLabelTxHash;
        txInfos.fields[g_pairsList->nbPairs].value = strings.common.fullHash;
        g_pairsList->nbPairs++;
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

bool ux_flow_display(ui_approval_state_t state, bool data_warning) {
    if (state == APPROVAL_VERIFY_ADDRESS) {
        nbgl_useCaseAddressReview(strings.common.toAddress,
                                  NULL,
                                  &APP_TRON_HOME_ICON,
                                  "Verify Tron\naddress",
                                  NULL,
                                  display_address_callback);
        return true;
    } else {
        // Prepare transaction infos to be displayed (field values etc.)
        if (!prepareTxInfos(state, data_warning)) {
            // Complete the APDU and reset state for every allocation failure,
            // including ui_pairs_init() and later preparation steps.
            if (appState != APP_STATE_IDLE) {
                io_seproxyhal_send_status(SWO_INSUFFICIENT_MEMORY, 0, true, true);
            }
            return false;
        }
        // Display transaction
        reviewStart();
        return true;
    }
}
