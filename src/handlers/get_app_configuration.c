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
#include <stdint.h>

#include "io.h"

#include "settings.h"
#include "apdu_constants.h"
#include "app_errors.h"

int handleGetAppConfiguration(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);

    // Add info to buffer. resp[0] is the settings flag byte (mirrors app-ethereum's
    // handle_get_app_configuration); S_INITIALIZED is internal and never exposed here.
    uint8_t resp[4] = {0};
    resp[0] = (N_storage.dataAllowed ? APP_FLAG_DATA_ALLOWED : 0x00);
    resp[0] |= (N_storage.customContract ? APP_FLAG_CUSTOM_CONTRACT : 0x00);
    resp[0] |= (N_storage.truncateAddress ? APP_FLAG_TRUNCATE_ADDRESS : 0x00);
    resp[0] |= (N_storage.signByHash ? APP_FLAG_SIGN_BY_HASH : 0x00);
    resp[0] |= (N_storage.verbose_tip712 ? APP_FLAG_VERBOSE_TIP712 : 0x00);
    resp[0] |= (N_storage.displayHash ? APP_FLAG_DISPLAY_HASH : 0x00);
    resp[1] = MAJOR_VERSION;
    resp[2] = MINOR_VERSION;
    resp[3] = PATCH_VERSION;
    return io_send_response_pointer(resp, 4, E_OK);
}
