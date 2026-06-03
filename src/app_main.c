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
#include "mem_utils.h"
#include "ui_idle_menu.h"
#include "settings.h"
#include "handlers.h"
#include "parse.h"
#include "app_errors.h"
#include "ui_globals.h"
#include "trusted_name.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#endif  // HAVE_NBGL

uint16_t apdu_response_code;

// The settings, stored in NVRAM.
const internal_storage_t N_storage_real;

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;
dataContext_t dataContext;
pluginType_t pluginType;

app_state_t appState;

const chain_config_t *chainConfig;
caller_app_t *caller_app = NULL;

extern void roll_challenge(void);

void reset_app_context() {
    cleanupSignPersonalMessageFullDisplay();
    cleanupSignExternalPlugin();
    appState = APP_STATE_IDLE;
    G_called_from_swap = false;
    G_swap_response_ready = false;
    pluginType = PLUGIN_TYPE_NONE;
    clear_trusted_names();
    forget_known_assets();
    memset((uint8_t *) &txContext, 0, sizeof(txContext));
    memset((uint8_t *) &txContent, 0, sizeof(txContent));
    memset((uint8_t *) &tmpCtx, 0, sizeof(tmpCtx));
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

    // to prevent it from having a fixed value at boot
    roll_challenge();

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

#ifdef HAVE_SWAP
static void tron_library_main(tron_libargs_t *args) {
    BEGIN_TRY {
        TRY {
            PRINTF("Inside Tron library\n");
            switch (args->command) {
                case SIGN_TRANSACTION: {
                    bool success = swap_copy_transaction_parameters(args->create_transaction);
                    if (success) {
                        G_called_from_swap = true;
                        G_swap_response_ready = false;
                        G_swap_signing_return_value_address = &args->create_transaction->result;

                        common_app_init();
#ifdef HAVE_NBGL
                        nbgl_useCaseSpinner("Signing");
#endif  // HAVE_NBGL
                        app_main();
                    }
                    break;
                }
                case CHECK_ADDRESS:
                    swap_handle_check_address(args->check_address);
                    break;
                case GET_PRINTABLE_AMOUNT:
                    swap_handle_get_printable_amount(args->get_printable_amount);
                    break;
                default:
                    break;
            }
        }
        CATCH_OTHER(e) {
            (void) e;
            PRINTF("Exiting following exception: 0x%04X\n", e);
        }
        FINALLY {
            os_lib_end();
        }
    }
    END_TRY;
}
#endif  // HAVE_SWAP

// Common initialization for the application, both in Standalone or Library mode (Swap)
static void app_init(bool library_mode) {
    if (library_mode == false) {
        // If we are not in library mode, 1st init is the dynamic memory
        app_mem_init();
    }
    reset_app_context();
    common_app_init();
    // storage_init();
    if (library_mode == false) {
        // If we are not in library mode, we need to initialize the UX
        io_init();
        ui_idle();
    }

    // to prevent it from having a fixed value at boot
    roll_challenge();
}

void coin_main(tron_libargs_t *args) {
    if (args) {
        if ((caller_app = args->caller_app) != NULL) {
            caller_app->type = CALLER_TYPE_PLUGIN;
        }
    }

    app_init(false);

    app_main();
}

void app_quit(void) {
    reset_app_context();
    app_exit();
}

int tron_main(tron_libargs_t *args) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    if (args == NULL) {
        // called from dashboard as standalone tron app
        coin_main(NULL);
        return 0;
    }

    if (args->id != 0x100) {
        app_quit();
        return 0;
    }
    switch (args->command) {
        case RUN_APPLICATION:
            // called as tron from altcoin or plugin
            coin_main(args);
            break;
        default:
#ifdef HAVE_SWAP
            // called as tron or altcoin library
            tron_library_main(args);
#else
            app_quit();
#endif  // HAVE_SWAP
            break;
    }
    return 0;
}

__attribute__((section(".boot"))) int main(int arg0) {
    return tron_main((tron_libargs_t *) arg0);
}
