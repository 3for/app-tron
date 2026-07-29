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
#include "os.h"
#include "io.h"
#include "parser.h"

#include "apdu_constants.h"
#include "app_errors.h"
#include "parse.h"

#include "commands_712.h"
#include "context_712.h"
#include "filtering.h"

#include "trusted_name.h"
#include "challenge.h"
#include "cmd_trusted_name.h"

#include "cmd_tx_info.h"
#include "cmd_field.h"
#include "cmd_sign_flow.h"
#include "cmd_proxy_info.h"
#include "cmd_enum_value.h"
#include "tlv_apdu.h"
#include "gcs_signing_context.h"

#ifdef HAVE_GATING_SUPPORT
#include "cmd_get_gating.h"
#endif  // HAVE_GATING_SUPPORT

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

static int send_gtp_status(uint16_t sw) {
    if (sw != SWO_SUCCESS) {
        if ((appState != APP_STATE_IDLE) || (tip712_context != NULL)) {
            reset_app_context();
        }
    }
    return io_send_sw(sw);
}

static bool tip712_build_command_allowed(const command_t *cmd) {
    switch (cmd->ins) {
        case INS_TIP712_STRUCT_DEF:
        case INS_TIP712_STRUCT_IMPL:
        case INS_TIP712_FILTERING:
        case INS_PROVIDE_TRC20_TOKEN_INFORMATION:
        case INS_PROVIDE_NFT_INFORMATION:
        case INS_GET_CHALLENGE:
        case INS_PROVIDE_TRUSTED_NAME:
        case INS_PROVIDE_ENUM_VALUE:
        case INS_GTP_TRANSACTION_INFO:
        case INS_GTP_FIELD:
        case INS_PROVIDE_PROXY_INFO:
#ifdef HAVE_GATING_SUPPORT
        case INS_PROVIDE_GATING:
#endif
            return true;
        case INS_SIGN_TIP_712_MESSAGE:
            return cmd->p2 == P2_TIP712_FULL_IMPLEM;
        default:
            return false;
    }
}

static bool tip712_struct_impl_p1_valid(uint8_t p1, uint8_t p2) {
    switch (p2) {
        case 0x00: /* struct name */
        case 0x0F: /* array size */
            return p1 == 0x00;
        case 0xFF: /* field value: complete or partial */
            return (p1 == 0x00) || (p1 == 0x01);
        default:
            return true; /* the handler returns WRONG_P1_P2 for unknown P2 */
    }
}

static bool tip712_filtering_p1_valid(uint8_t p1, uint8_t p2) {
    switch (p2) {
        case 0x00: /* activate */
        case 0x01: /* discarded path */
        case 0x0F: /* message info */
        case 0xFA: /* calldata info */
            return p1 == 0x00;
        default:
            /* Field filters use P1=1 only for a path discarded because an
             * enclosing array was empty. */
            return (p1 == 0x00) || (p1 == 0x01);
    }
}

static int reject_tip712_command(uint16_t sw) {
    if ((tip712_get_phase() != TIP712_PHASE_NONE) ||
        (appState != APP_STATE_IDLE)) {
        reset_app_context();
    }
    return io_send_sw(sw);
}

// Check ADPU and process the assigned task
int apdu_dispatcher(const command_t *cmd) {
    if (tlv_apdu_in_progress() &&
        ((cmd->cla != CLA) || !tlv_apdu_owner_matches(cmd->ins, cmd->p2))) {
        PRINTF("Aborted metadata stream on mismatched APDU\n");
        if (appState != APP_STATE_IDLE) {
            reset_app_context();
        } else {
            tlv_apdu_reset();
        }
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // Personal-message reception owns tmpCtx.transactionContext until the
    // message hash is finalized. In particular, GET_PUBLIC_KEY uses another
    // member of the same union, so allowing any unrelated command here could
    // replace the path/hash that will later be signed. Fail closed and discard
    // the interrupted session; only its exact continuation is valid.
    if ((appState == APP_STATE_SIGNING_MESSAGE) ||
        (appState == APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY)) {
        const uint8_t expected_ins =
            (appState == APP_STATE_SIGNING_MESSAGE)
                ? INS_SIGN_PERSONAL_MESSAGE
                : INS_SIGN_PERSONAL_MESSAGE_FULL_DISPLAY;
        const bool allowed = (cmd->cla == CLA) &&
                             (cmd->ins == expected_ins) &&
                             (cmd->p1 == P1_MORE) &&
                             (cmd->p2 == 0);
        if (!allowed) {
            PRINTF("Refused APDU while personal-message reception is active\n");
            reset_app_context();
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
    }

    // Legacy INS_SIGN owns tmpCtx.transactionContext and its streamed hash from
    // the first raw-data chunk until parsing reaches review. Other handlers
    // reuse members of the same tmpCtx union, so an interleaved command could
    // otherwise replace the signing path/hash while leaving the stream valid.
    // Metadata for this protocol is carried by INS_SIGN itself (P1=0xA*).
    if (sign_reception_in_progress()) {
        const bool allowed = (cmd->cla == CLA) &&
                             (cmd->ins == INS_SIGN) &&
                             sign_reception_command_allowed(cmd->p1, cmd->p2);
        if (!allowed) {
            PRINTF("Refused APDU while INS_SIGN reception is active\n");
            reset_app_context();
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
    }
    if (cmd->cla != CLA) {
        if (tip712_get_phase() == TIP712_PHASE_FULL_BUILDING) {
            return reject_tip712_command(E_CLA_NOT_SUPPORTED);
        }
        return io_send_sw(E_CLA_NOT_SUPPORTED);
    }

    // GET_PUBLIC_KEY/P1_CONFIRM also owns an asynchronous NBGL page. Reject
    // every subsequent command without resetting tmpCtx or the active page;
    // only the address approval/rejection callback may finish this APDU.
    if (appState == APP_STATE_REVIEWING_ADDRESS) {
        PRINTF("Refused APDU while address review is active\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }

    // INS_SIGN review is asynchronous. Reject every subsequent command without
    // resetting the signing/UI allocations that the current NBGL page owns.
    if (sign_review_in_progress()) {
        PRINTF("Refused APDU while INS_SIGN review is active\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    if (tip712_review_in_progress()) {
        PRINTF("Refused APDU while TIP-712 review is active\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    if (personal_message_review_in_progress()) {
        PRINTF("Refused APDU while personal-message review is active\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    if (gcs_review_in_progress()) {
        PRINTF("Refused APDU while GCS review is active\n");
        return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
    }
    /* Full TIP-712 owns its type tree, tmpCtx and accumulated UI fields from
     * the first struct definition, while appState may still be IDLE. Only the
     * commands needed to finish that exact session may run in between. */
    if (tip712_get_phase() == TIP712_PHASE_FULL_BUILDING) {
        if (!tip712_build_command_allowed(cmd)) {
            PRINTF("Refused APDU outside the active TIP-712 build phase\n");
            reset_app_context();
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
        if (!tip712_note_build_apdu()) {
            PRINTF("TIP-712 build APDU limit exceeded\n");
            reset_app_context();
            return io_send_sw(E_INCORRECT_DATA);
        }
    }
    if (gcs_signing_in_progress()) {
        bool allowed = false;

        if (appState == APP_STATE_SIGNING_GCS_STORE) {
            allowed = (cmd->ins == INS_SIGN_GCS) && (cmd->p2 == P2_GCS_STORE);
        } else if (appState == APP_STATE_SIGNING_TX) {
            allowed = (cmd->ins == INS_GTP_TRANSACTION_INFO) ||
                      (cmd->ins == INS_GTP_FIELD) ||
                      ((cmd->ins == INS_SIGN_GCS) &&
                       (cmd->p2 == P2_GCS_START_FLOW));
        }
        if (!allowed) {
            PRINTF("Refused APDU outside the active GCS phase\n");
            reset_app_context();
            return io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);
        }
    }
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((cmd->ins != INS_GET_PUBLIC_KEY) && (cmd->ins != INS_SIGN)) {
            PRINTF("Refused INS when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
    }
#endif  // HAVE_SWAP

    switch (cmd->ins) {
        case INS_GET_PUBLIC_KEY:
            forget_known_assets();
            // Request Public Key
            return handleGetPublicKey(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN:
            // Request Signature
            return handleSign(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_TXN_HASH:
            // Request signature via transaction id
            return handleSignByHash(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_GET_APP_CONFIGURATION:
            // Request App configuration
            return handleGetAppConfiguration(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_GET_ECDH_SECRET:
            // Request Signature
            return handleECDHSecret(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_PERSONAL_MESSAGE_FULL_DISPLAY:
            // Personal-message signing consumes no cached transaction
            // metadata. Clear it before the first allocation so the advertised
            // maximum message size has deterministic heap capacity.
            if (((cmd->p1 == P1_FIRST) || (cmd->p1 == P1_SIGN)) &&
                (appState == APP_STATE_IDLE)) {
                reset_app_context();
            }
            return handleSignPersonalMessageFullDisplay(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_PERSONAL_MESSAGE:
            if (((cmd->p1 == P1_FIRST) || (cmd->p1 == P1_SIGN)) &&
                (appState == APP_STATE_IDLE)) {
                reset_app_context();
            }
            return handleSignPersonalMessage(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_TIP_712_MESSAGE: {
            uint16_t sw;
            uint32_t flags = 0;

            switch (cmd->p2) {
                case P2_TIP712_LEGACY_IMPLEM:
                    if (cmd->p1 != 0x00) {
                        return reject_tip712_command(E_INCORRECT_P1_P2);
                    }
                    forget_known_assets();
                    sw = handleSignTIP712Message(cmd->p1, cmd->data, cmd->lc);
                    break;

                case P2_TIP712_FULL_IMPLEM:
                    if (cmd->p1 == P1_TIP712_INIT) {
                        sw = handleTIP712Init(cmd->data, cmd->lc);
                    } else if (cmd->p1 == P1_TIP712_SIGN) {
                        sw = handleTIP712Sign(cmd->data, cmd->lc, &flags);
                    } else {
                        return reject_tip712_command(E_INCORRECT_P1_P2);
                    }
                    break;

                default:
                    sw = E_INCORRECT_P1_P2;
                    break;
            }
            if (sw == APDU_NO_RESPONSE) {
                return 0;
            }
            return io_send_sw(sw);
        }

        case INS_TIP712_STRUCT_DEF:
            if (cmd->p1 != 0x00) {
                return reject_tip712_command(E_INCORRECT_P1_P2);
            }
            return io_send_sw(handleTIP712StructDef(cmd->p2, cmd->data, cmd->lc));

        case INS_TIP712_STRUCT_IMPL: {
            if (!tip712_struct_impl_p1_valid(cmd->p1, cmd->p2)) {
                return reject_tip712_command(E_INCORRECT_P1_P2);
            }
            uint32_t flags = 0;
            uint16_t sw = handleTIP712StructImpl(cmd->p1, cmd->p2, cmd->data, cmd->lc, &flags);
            if (sw == APDU_NO_RESPONSE) {
                return 0;
            }
            return io_send_sw(sw);
        }

        case INS_TIP712_FILTERING: {
            if (!tip712_filtering_p1_valid(cmd->p1, cmd->p2)) {
                return reject_tip712_command(E_INCORRECT_P1_P2);
            }
            uint32_t flags = 0;
            uint16_t sw = handleTIP712Filtering(cmd->p1, cmd->p2, cmd->data, cmd->lc, &flags);
            if (sw == APDU_NO_RESPONSE) {
                return 0;
            }
            return io_send_sw(sw);
        }

        case INS_PROVIDE_TRC20_TOKEN_INFORMATION:
            return handleProvideTrc20TokenInformation(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_PROVIDE_NFT_INFORMATION:
            return handleProvideNFTInformation(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_GET_CHALLENGE:
            return handle_get_challenge(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_PROVIDE_TRUSTED_NAME:
            return io_send_sw(handle_trusted_name(cmd->p1, cmd->p2, cmd->data, cmd->lc));

        case INS_PROVIDE_ENUM_VALUE:
            return io_send_sw(handle_enum_value(cmd->p1, cmd->p2, cmd->lc, cmd->data));

        // Generic Clear Signing (generic_tx_parser). The ported handlers return a
        // status word (as app-ethereum's main loop expects) rather than sending it
        // themselves, so wrap them in io_send_sw here.
        case INS_GTP_TRANSACTION_INFO: {
            uint16_t sw = handle_tx_info(cmd->p1, cmd->p2, cmd->lc, cmd->data);
            return send_gtp_status(sw);
        }

        case INS_GTP_FIELD: {
            uint16_t sw = handle_field(cmd->p1, cmd->p2, cmd->lc, cmd->data);
            return send_gtp_status(sw);
        }

        case INS_PROVIDE_PROXY_INFO: {
            uint16_t sw = handle_proxy_info(cmd->p1, cmd->p2, cmd->lc, cmd->data);

            /* Nested-calldata clear signing legitimately provides unrelated
             * proxy mappings after outer message-info. Permit those, but tear
             * down the session if a newly committed mapping changes the
             * frozen outer CAL signature context. */
            if ((sw == SWO_SUCCESS) && (tip712_context != NULL) &&
                tip712_context->filtering_context_locked &&
                !filtering_context_matches_live()) {
                sw = SWO_CONDITIONS_NOT_SATISFIED;
            }
            if ((sw != SWO_SUCCESS) && (tip712_context != NULL)) {
                reset_app_context();
            }
            return io_send_sw(sw);
        }

#ifdef HAVE_GATING_SUPPORT
        case INS_PROVIDE_GATING:
            return io_send_sw(handle_gating(cmd->p1, cmd->p2, cmd->lc, cmd->data));
#endif  // HAVE_GATING_SUPPORT

        case INS_SIGN_GCS:
            // Generic Clear Signing: store calldata (P2=STORE) or review + sign (P2=START_FLOW)
            return handleSignGcs(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        default:
            return io_send_sw(E_INS_NOT_SUPPORTED);
    }

    return 0;
}
