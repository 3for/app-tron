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
#include "ui_globals.h"
#include "settings.h"
#include "handlers.h"
#include "parse.h"
#include "app_errors.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

// The settings, stored in NVRAM.
const internal_storage_t N_storage_real;

txContent_t txContent;
txContext_t txContext;

static void reset_signing_contexts(void) {
    /* app_main() may be entered again without BSS initialization after an I/O
     * reset. Unbind pending callbacks before invalidating every streamed
     * signing context so no continuation can reuse a stale hash or path. */
    ui_review_reset();
    explicit_bzero(&txContext, sizeof(txContext));
    explicit_bzero(&txContent, sizeof(txContent));
    explicit_bzero(&transactionContext, sizeof(transactionContext));
    explicit_bzero(&msg, sizeof(msg));
    resetPersonalMessageSigningContext();
}

static void nv_app_state_init(void) {
    if (!HAS_SETTING(S_INITIALIZED)) {
        internal_storage_t storage = 0x00;
        storage |= 0x80;
        nvm_write((void *) &N_settings, (void *) &storage, sizeof(internal_storage_t));
    }
}

// App main loop
void app_main(void) {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;
    // Structured APDU command
    command_t cmd;

    nv_app_state_init();

    io_init();
    reset_signing_contexts();

#ifdef HAVE_SWAP
    if (!G_called_from_swap) {
        ui_idle();
    }
#endif  // HAVE_SWAP

    for (;;) {
        BEGIN_TRY {
            TRY {
                // Reset structured APDU command
                memset(&cmd, 0, sizeof(cmd));

                // Receive command bytes in G_io_apdu_buffer
                if ((input_len = io_recv_command()) < 0) {
                    reset_signing_contexts();
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

                PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
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
                reset_signing_contexts();
                CLOSE_TRY;
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                // An exception aborts the command that may have started a
                // review or a streamed signature. Do not leave either live.
                reset_signing_contexts();
                io_send_sw(e);
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    return;
}
