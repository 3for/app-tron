/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2026 Ledger
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
#include <string.h>
#include <stdint.h>

#include "io.h"
#include "parse.h"
#include "os_io_seproxyhal.h"
#include "public_keys.h"
#include "app_errors.h"
#include "eth_plugin_interface.h"

int handleSetExternalPlugin(uint8_t p1,
                            uint8_t p2,
                            const uint8_t *workBuffer,
                            uint16_t dataLength) {
    UNUSED(p1);
    UNUSED(p2);
    PRINTF("Handling set Plugin\n");
    uint8_t hash[INT256_LENGTH];
    uint8_t pluginNameLength = *workBuffer;
    uint32_t params[2];
    cx_err_t error = CX_INTERNAL_ERROR;

    PRINTF("plugin Name Length: %d\n", pluginNameLength);
    const size_t payload_size = 1 + pluginNameLength + TRON_ADDRESS_SIZE + SELECTOR_SIZE;

    if (dataLength <= payload_size) {
        PRINTF("data too small: expected at least %d got %d\n", payload_size, dataLength);
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (pluginNameLength + 1 > sizeof(dataContext.tokenContext.pluginName)) {
        PRINTF("name length too big: expected max %d, got %d\n",
               sizeof(dataContext.tokenContext.pluginName),
               pluginNameLength + 1);
        return io_send_sw(E_INCORRECT_DATA);
    }

    // check Ledger's signature over the payload
    cx_hash_sha256(workBuffer, payload_size, hash, sizeof(hash));

    error = check_signature_with_pubkey("External Plugin",
                                        hash,
                                        sizeof(hash),
                                        LEDGER_SIGNATURE_PUBLIC_KEY,
                                        sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                        CERTIFICATE_PUBLIC_KEY_USAGE_COIN_META,
                                        (uint8_t *) (workBuffer + payload_size),
                                        dataLength - payload_size);
    if (error != CX_OK) {
        PRINTF("Invalid signature\n");
#ifndef HAVE_BYPASS_SIGNATURES
        return io_send_sw(E_INCORRECT_DATA);;
#endif
    }

    // move on to the rest of the payload parsing
    workBuffer++;
    memmove(dataContext.tokenContext.pluginName, workBuffer, pluginNameLength);
    dataContext.tokenContext.pluginName[pluginNameLength] = '\0';
    workBuffer += pluginNameLength;

    PRINTF("Check external plugin %s\n", dataContext.tokenContext.pluginName);

    // Check if the plugin is present on the device
    params[0] = (uint32_t) dataContext.tokenContext.pluginName;
    params[1] = ETH_PLUGIN_CHECK_PRESENCE;
    BEGIN_TRY {
        TRY {
            os_lib_call(params);
        }
        CATCH_OTHER(e) {
            (void) e;
            PRINTF("%s external plugin is not present\n", dataContext.tokenContext.pluginName);
            memset(dataContext.tokenContext.pluginName,
                   0,
                   sizeof(dataContext.tokenContext.pluginName));
            CLOSE_TRY;
            return io_send_sw(E_PLUGIN_NOT_FOUND);
        }
        FINALLY {
        }
    }
    END_TRY;

    PRINTF("Plugin found\n");
    memmove(dataContext.tokenContext.contractAddress, workBuffer, TRON_ADDRESS_SIZE);
    workBuffer += TRON_ADDRESS_SIZE;
    memmove(dataContext.tokenContext.methodSelector, workBuffer, SELECTOR_SIZE);
    pluginType = PLUGIN_TYPE_EXTERNAL;

    return io_send_sw(E_OK);
}