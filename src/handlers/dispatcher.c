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

#include "trusted_name.h"
#include "challenge.h"
#include "cmd_trusted_name.h"

#include "cmd_tx_info.h"
#include "cmd_field.h"
#include "cmd_proxy_info.h"
#include "cmd_enum_value.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

// Check ADPU and process the assigned task
int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(E_CLA_NOT_SUPPORTED);
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
            forget_known_assets();
            return handleSignPersonalMessageFullDisplay(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_PERSONAL_MESSAGE:
            return handleSignPersonalMessage(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_TIP_712_MESSAGE: {
            uint16_t sw;
            uint32_t flags = 0;

            switch (cmd->p2) {
                case P2_TIP712_LEGACY_IMPLEM:
                    forget_known_assets();
                    sw = handleSignTIP712Message(cmd->p1, cmd->data, cmd->lc);
                    break;

                case P2_TIP712_FULL_IMPLEM:
                    sw = handleTIP712Sign(cmd->data, cmd->lc, &flags);
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
            return io_send_sw(handleTIP712StructDef(cmd->p2, cmd->data, cmd->lc));

        case INS_TIP712_STRUCT_IMPL: {
            uint32_t flags = 0;
            uint16_t sw = handleTIP712StructImpl(cmd->p1, cmd->p2, cmd->data, cmd->lc, &flags);
            if (sw == APDU_NO_RESPONSE) {
                return 0;
            }
            return io_send_sw(sw);
        }

        case INS_TIP712_FILTERING: {
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
            return io_send_sw(handle_trusted_name(cmd->p1, cmd->data, cmd->lc));

        case INS_PROVIDE_ENUM_VALUE:
            return io_send_sw(handle_enum_value(cmd->p1, cmd->p2, cmd->lc, cmd->data));

        // Generic Clear Signing (generic_tx_parser). The ported handlers return a
        // status word (as app-ethereum's main loop expects) rather than sending it
        // themselves, so wrap them in io_send_sw here.
        case INS_GTP_TRANSACTION_INFO:
            return io_send_sw(handle_tx_info(cmd->p1, cmd->p2, cmd->lc, cmd->data));

        case INS_GTP_FIELD:
            return io_send_sw(handle_field(cmd->p1, cmd->p2, cmd->lc, cmd->data));

        case INS_PROVIDE_PROXY_INFO:
            return io_send_sw(handle_proxy_info(cmd->p1, cmd->p2, cmd->lc, cmd->data));

        case INS_SET_EXTERNAL_PLUGIN:
            // Set External Plugin
            return handleSetExternalPlugin(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_EXTERNAL_PLUGIN:
            // Plugin Request Signature
            return handleSignExternalPlugin(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        default:
            return io_send_sw(E_INS_NOT_SUPPORTED);
    }

    return 0;
}
