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
#include "apdu_constants.h"
#include "parse.h"
#include "app_errors.h"
#include "ui_globals.h"
#include "trusted_name.h"
#include "tx_ctx.h"        // gcs_cleanup (Generic Clear Signing)
#include "tron_tx_stream.h"  // tron_tx_stream_free
#include "gcs_signing_context.h"
#include "gcs_memory.h"
#include "proxy_info.h"    // proxy_cleanup
#include "enum_value.h"    // enum_value_cleanup
#include "tlv_apdu.h"      // tlv_apdu_reset
#include "context_712.h"    // tip712_context_cleanup

#ifdef HAVE_GATING_SUPPORT
#include "cmd_get_gating.h"  // clear_gating
#endif  // HAVE_GATING_SUPPORT

#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#endif  // HAVE_NBGL

uint16_t apdu_response_code;

// The settings, stored in NVRAM.
const internalStorage_t N_storage_real;

tmpCtx_t tmpCtx;
txContent_t txContent;
txContext_t txContext;

app_state_t appState;

const chain_config_t *chainConfig;
caller_app_t *caller_app = NULL;

extern void roll_challenge(void);

void reset_app_context() {
    message_cleanup();
    personal_message_legacy_cleanup();
    sign_cleanup();
    // Drop any incomplete metadata/GCS descriptor shared TLV stream.
    tlv_apdu_reset();
    // Release TIP-712 allocations without recursively resetting the app.
    tip712_context_cleanup();
    // Free the shared TriggerSmartContract stream decoder (GCS / legacy signing).
    tron_tx_stream_free();
    gcs_signing_context_cleanup();
    // Free any Generic Clear Signing state (tx contexts, field table, parked
    // calldata) so it never leaks across signing sessions.
    gcs_cleanup();
    // Free the cached proxy<->implementation mapping (INS_PROVIDE_PROXY_INFO).
    proxy_cleanup();
#ifdef HAVE_GATING_SUPPORT
    // Free the cached gated-signing descriptor (INS_PROVIDE_GATING).
    clear_gating();
#endif  // HAVE_GATING_SUPPORT
    appState = APP_STATE_IDLE;
    G_called_from_swap = false;
    G_swap_response_ready = false;
    trusted_name_cleanup();
    // Free cached enum-value descriptors (INS_PROVIDE_ENUM_VALUE).
    enum_value_cleanup();
    forget_known_assets();
    explicit_bzero(&global_sha3, sizeof(global_sha3));
    // UI cleanup above releases every asynchronous consumer before these
    // stable review snapshots are scrubbed.
    explicit_bzero(&strings, sizeof(strings));
    explicit_bzero(&msg, sizeof(msg));
    explicit_bzero(&txContext, sizeof(txContext));
    explicit_bzero(&txContent, sizeof(txContent));
    explicit_bzero(&tmpCtx, sizeof(tmpCtx));
    /* This must be last: asynchronous GCS UI and metadata remain charged until
     * every owner above has released its allocations. */
    if (!gcs_budget_end()) {
        PRINTF("GCS memory accounting invariant failed during cleanup: "
               "session=%u generic=%u calldata=%u descriptor=%u tx=%u "
               "field=%u ui=%u metadata=%u temporary=%u\n",
               (unsigned int) gcs_mem_session_live_bytes(),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_GENERIC),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_CALLDATA),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_DESCRIPTOR),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_TX_CONTEXT),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_FIELD),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_UI),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_METADATA),
               (unsigned int) gcs_mem_category_live_bytes(GCS_MEM_TEMPORARY));
    }
}

static void abort_active_context(void) {
    if ((appState == APP_STATE_IDLE) && (tip712_context == NULL) &&
        (tip712_get_phase() == TIP712_PHASE_NONE)) {
        // Metadata provisioning intentionally runs without entering a signing
        // app state. A malformed APDU or exception must still discard an
        // unfinished shared TLV reassembly, while preserving already verified
        // metadata cached for a subsequent signing request.
        if (tlv_apdu_in_progress()) {
            tlv_apdu_reset();
        }
        return;
    }

    // Replace any asynchronous review before releasing the buffers referenced
    // by it. During swap there is no standalone app home screen to restore.
#ifdef HAVE_SWAP
    if (!G_called_from_swap) {
        ui_idle();
    }
#else
    ui_idle();
#endif
    reset_app_context();
}

static void abort_and_send_status(uint16_t sw) {
#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        io_send_sw(sw);
        swap_finalize_exchange_sign_transaction(false);
    }
#endif  // HAVE_SWAP
    abort_active_context();
    io_send_sw(sw);
}

static uint16_t normalize_exception_status(uint32_t error) {
    uint16_t sw = (uint16_t) error;

    if ((sw & 0xF000U) != 0x6000U) {
        sw = SWO_NOT_SUPPORTED_ERROR_NO_INFO | (sw & 0x07FFU);
    }
    return sw;
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

static void nv_app_state_init(void) {
    // Mirrors app-ethereum's storage_init(): on first run, zero the whole struct and
    // mark it initialized in a single NVRAM write (all settings default to off).
    if (N_storage.initialized) {
        return;
    }
    internalStorage_t storage;
    explicit_bzero(&storage, sizeof(storage));
    storage.initialized = true;
    nvm_write((void *) &N_storage, (void *) &storage, sizeof(internalStorage_t));
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
#ifdef HAVE_SWAP
                    if (G_called_from_swap) {
                        swap_finalize_exchange_sign_transaction(false);
                    }
#endif  // HAVE_SWAP
                    CLOSE_TRY;
                    return;
                }

                // Parse APDU command from G_io_apdu_buffer
                if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
                    PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
                    abort_and_send_status(E_WRONG_DATA_LENGTH);
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
                abort_and_send_status(normalize_exception_status(e));
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
