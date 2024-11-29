/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2018 Ledger
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

#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "io.h"
#include "parser.h"
#include "ux.h"

#include "ui_idle_menu.h"
#include "settings.h"
#include "handlers.h"
#include "parse.h"
#include "app_errors.h"
#include "ui_globals.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

uint16_t apdu_response_code;

// The settings, stored in NVRAM.
const internal_storage_t N_storage_real;

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;

app_state_t appState;

const chain_config_t *chainConfig;

void reset_app_context() {
    appState = APP_STATE_IDLE;
    memset((uint8_t *) &txContext, 0, sizeof(txContext));
    memset((uint8_t *) &txContent, 0, sizeof(txContent));
    memset((uint8_t *) &global_ctx, 0, sizeof(global_ctx));
}

uint16_t io_seproxyhal_send_status(uint16_t sw, uint32_t tx, bool reset, bool idle) {
    uint16_t err = 0;
    if (reset) {
        reset_app_context();
    }
    U2BE_ENCODE(G_io_apdu_buffer, tx, sw);
    tx += 2;
    err = io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    if (idle) {
        // Display back the original UX
        ui_idle();
    }
    return err;
}


void handle_return_code(uint16_t response_code) {
    io_seproxyhal_send_status(response_code, 0, false, false);
}

static void nv_app_state_init(void) {
    if (!HAS_SETTING(S_INITIALIZED)) {
        SETTING_TOGGLE(S_INITIALIZED);
    }
}

void init_coin_config(chain_config_t *coin_config) {
    memset(coin_config, 0, sizeof(chain_config_t));
    strcpy(coin_config->coinName, APP_TICKER);
    coin_config->chainId = APP_CHAIN_ID;
}

// App main loop
void app_main(void) {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;
    // Structured APDU command
    command_t cmd;

    nv_app_state_init();

    io_init();
    chain_config_t config;
    if (chainConfig == NULL) {
        init_coin_config(&config);
        chainConfig = &config;
    }

#ifdef HAVE_SWAP
    if (!G_called_from_swap) {
        ui_idle();
    }
#endif  // HAVE_SWAP

    // Reset context
    explicit_bzero(&txContent, sizeof(txContent));

    for (;;) {
        BEGIN_TRY {
            TRY {
                // Reset structured APDU command
                memset(&cmd, 0, sizeof(cmd));

                // Receive command bytes in G_io_apdu_buffer
                if ((input_len = io_recv_command()) < 0) {
                    CLOSE_TRY;
                    return;
                }

                // Parse APDU command from G_io_apdu_buffer
                if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
                    PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
                    io_send_sw(E_WRONG_DATA_LENGTH);
                    CLOSE_TRY;
                    continue;
                }

                PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | LC=%02X | CData=%.*H\n",
                       cmd.cla,
                       cmd.ins,
                       cmd.p1,
                       cmd.p2,
                       cmd.lc,
                       cmd.lc,
                       cmd.data);

                // Dispatch structured APDU command to handler
                if (apdu_dispatcher(&cmd) < 0) {
                    CLOSE_TRY;
                    return;
                }
            }
            CATCH(EXCEPTION_IO_RESET) {
                CLOSE_TRY;
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                io_send_sw(e);
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    return;
}
