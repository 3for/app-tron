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
#include "ui_globals.h"
#include "helpers.h"
#include "io.h"
#include "os.h"
#include "ux.h"
#include "crypto_helpers.h"
#include "ui_idle_menu.h"
#include "app_errors.h"

volatile uint8_t customContractField;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
char toAddress[MAX_TOKEN_LENGTH];
char addressSummary[40];
char fullContract[EXCHANGE_PAIR_REVIEW_MAX_SIZE];
char TRC20Action[9];
char TRC20ActionSendAllow[8];
char fullHash[HASH_SIZE * 2 + 1];
int8_t votes_count;
transactionContext_t transactionContext;
publicKeyContext_t publicKeyContext;
messageSigningContext712_t messageSigningContext712;
strings_t strings;
uint8_t reviewData[REVIEW_DATA_BUFFER_SIZE];

_Static_assert(REVIEW_DATA_BUFFER_SIZE <= sizeof(G_io_apdu_buffer),
               "review snapshot exceeds APDU buffer");
_Static_assert(CUSTOM_CONTRACT_TRC10_AMOUNT_OFFSET + 100 <= REVIEW_DATA_BUFFER_SIZE,
               "review snapshot does not cover amount slots");
_Static_assert(5 * VOTE_PACK <= REVIEW_DATA_BUFFER_SIZE,
               "review snapshot does not cover vote slots");
_Static_assert(DELEGATE_LOCK_PERIOD_OFFSET + 32 <= REVIEW_DATA_BUFFER_SIZE,
               "review snapshot does not cover delegate lock period");
_Static_assert(sizeof(toAddress) >= sizeof(((txContent_t *) 0)->tokenNames[0]),
               "review buffer cannot hold a complete token label");
_Static_assert(sizeof(addressSummary) > BASE58CHECK_ADDRESS_SIZE,
               "review buffer cannot hold a complete TRC20 contract address");
_Static_assert(MAX_TOKEN_LENGTH > EXCHANGE_TOKEN_LABEL_MAX_LENGTH,
               "token label buffer cannot hold maximum authenticated metadata");
_Static_assert(sizeof(fullContract) == EXCHANGE_PAIR_REVIEW_MAX_SIZE,
               "exchange pair review buffer has an unexpected size");

typedef enum {
    UI_REVIEW_NONE = 0,
    UI_REVIEW_TRANSACTION,
    UI_REVIEW_ADDRESS,
    UI_REVIEW_PERSONAL_MESSAGE,
    UI_REVIEW_ECDH,
    UI_REVIEW_TIP712,
} ui_review_operation_t;

static volatile ui_review_operation_t G_review_operation;

static ui_review_operation_t get_review_operation(ui_approval_state_t state) {
    switch (state) {
        case APPROVAL_VERIFY_ADDRESS:
            return UI_REVIEW_ADDRESS;
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
            return UI_REVIEW_PERSONAL_MESSAGE;
        case APPROVAL_SHARED_ECDH_SECRET:
            return UI_REVIEW_ECDH;
        case APPROVAL_SIGN_TIP72_TRANSACTION:
            return UI_REVIEW_TIP712;
        case APPROVAL_TRANSFER:
        case APPROVAL_SIMPLE_TRANSACTION:
        case APPROVAL_PERMISSION_UPDATE:
        case APPROVAL_EXCHANGE_CREATE:
        case APPROVAL_EXCHANGE_TRANSACTION:
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
        case APPROVAL_WITNESSVOTE_TRANSACTION:
        case APPROVAL_FREEZEASSET_TRANSACTION:
        case APPROVAL_UNFREEZEASSET_TRANSACTION:
        case APPROVAL_WITHDRAWBALANCE_TRANSACTION:
        case APPROVAL_CUSTOM_CONTRACT:
        case APPROVAL_FREEZEASSETV2_TRANSACTION:
        case APPROVAL_UNFREEZEASSETV2_TRANSACTION:
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION:
        case APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION:
        case APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION:
            return UI_REVIEW_TRANSACTION;
    }

    return UI_REVIEW_NONE;
}

bool ui_review_begin(ui_approval_state_t state) {
    ui_review_operation_t operation = get_review_operation(state);

    if ((operation == UI_REVIEW_NONE) || (G_review_operation != UI_REVIEW_NONE)) {
        return false;
    }

    // Seal every value backed by the APDU transport buffer before yielding to
    // asynchronous UX. All other reviewed values live in dedicated globals
    // that the dispatcher protects from later handler execution.
    memcpy(reviewData, G_io_apdu_buffer, sizeof(reviewData));
    G_review_operation = operation;
    return true;
}

bool ui_review_is_pending(void) {
    return G_review_operation != UI_REVIEW_NONE;
}

void ui_review_reset(void) {
    G_review_operation = UI_REVIEW_NONE;
    explicit_bzero(reviewData, sizeof(reviewData));
}

static bool ui_review_consume(ui_review_operation_t expected_operation) {
    if (G_review_operation != expected_operation) {
        return false;
    }

    G_review_operation = UI_REVIEW_NONE;
    return true;
}

static bool ui_review_cancel(void) {
    if (G_review_operation == UI_REVIEW_NONE) {
        return false;
    }

    G_review_operation = UI_REVIEW_NONE;
    return true;
}

static bool reject_unbound_callback(bool display_menu) {
    io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);

    if (display_menu) {
        ui_idle();
    }

    return false;
}

bool ui_callback_address_ok(bool display_menu) {
    if (!ui_review_consume(UI_REVIEW_ADDRESS)) {
        return reject_unbound_callback(display_menu);
    }

    helper_send_response_pubkey(&publicKeyContext);

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

bool ui_callback_signMessage_ok(bool display_menu) {
    bool ret = true;

    if (!ui_review_consume(UI_REVIEW_PERSONAL_MESSAGE)) {
        return reject_unbound_callback(display_menu);
    }

    if (signTransaction(&transactionContext) != 0) {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        ret = false;
    } else {
        io_send_response_pointer(transactionContext.signature,
                                 transactionContext.signatureLength,
                                 E_OK);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return ret;
}

bool ui_callback_tx_cancel(bool display_menu) {
    ui_review_cancel();
    io_send_sw(E_CONDITIONS_OF_USE_NOT_SATISFIED);

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}

bool ui_callback_tx_ok(bool display_menu) {
    bool ret = true;

    if (!ui_review_consume(UI_REVIEW_TRANSACTION)) {
        return reject_unbound_callback(display_menu);
    }

    if (signTransaction(&transactionContext) != 0) {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        ret = false;
    } else {
        io_send_response_pointer(transactionContext.signature,
                                 transactionContext.signatureLength,
                                 E_OK);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return ret;
}

bool ui_callback_ecdh_ok(bool display_menu) {
    cx_err_t err;
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;

    if (!ui_review_consume(UI_REVIEW_ECDH)) {
        return reject_unbound_callback(display_menu);
    }

    // Get private key
    err = bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                        transactionContext.bip32_path.indices,
                                        transactionContext.bip32_path.length,
                                        &privateKey,
                                        NULL);
    if (err != CX_OK) {
        goto end;
    }

    err = cx_ecdh_no_throw(&privateKey,
                           CX_ECDH_POINT,
                           transactionContext.signature,
                           65,
                           G_io_apdu_buffer,
                           sizeof(G_io_apdu_buffer));
    if (err != CX_OK) {
        goto end;
    }

    size_t size;
    err = cx_ecdomain_parameters_length(CX_CURVE_256K1, &size);
    tx = 1 + 2 * size;

end:
    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));

    if (err == CX_OK) {
        io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
    } else {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    if (err == CX_OK) {
        return true;
    } else {
        return false;
    }
}

static const uint8_t TIP_712_MAGIC[] = {0x19, 0x01};

void format_signature_out(const uint8_t *signature) {
    memset(G_io_apdu_buffer, 0x00, 64);
    uint8_t offset = 0;
    uint8_t xoffset = 4;  // point to r value
    // copy r
    uint8_t xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
    offset += 32;
    xoffset += xlength + 2;  // move over rvalue and TagLEn
    // copy s value
    xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
}

bool ui_callback_signMessage712_v0_ok(bool display_menu) {
    uint32_t tx = 0;
    cx_err_t err;

    if (!ui_review_consume(UI_REVIEW_TIP712)) {
        return reject_unbound_callback(display_menu);
    }

    cx_ecfp_private_key_t privateKey;
    uint8_t signature[100];
    unsigned int info = 0;

    cx_sha3_t sha3;
    uint8_t hash[32];
    io_seproxyhal_io_heartbeat();

    if (cx_keccak_init_no_throw(&sha3, 256) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         0,
                         (uint8_t *) TIP_712_MAGIC,
                         sizeof(TIP_712_MAGIC),
                         NULL,
                         0) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         0,
                         messageSigningContext712.domainHash,
                         sizeof(messageSigningContext712.domainHash),
                         NULL,
                         0) != CX_OK) {
        return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &sha3,
                         CX_LAST,
                         messageSigningContext712.messageHash,
                         sizeof(messageSigningContext712.messageHash),
                         hash,
                         sizeof(hash)) != CX_OK) {
        return false;
    }
    PRINTF("TIP712 hash to sign %.*H\n", 32, hash);

    io_seproxyhal_io_heartbeat();
    // Get private key
    err = bip32_derive_init_privkey_256(CX_CURVE_256K1,
                                        messageSigningContext712.bip32_path.indices,
                                        messageSigningContext712.bip32_path.length,
                                        &privateKey,
                                        NULL);
    if (err != CX_OK) {
        goto end;
    }

    io_seproxyhal_io_heartbeat();
    unsigned int signatureLength = sizeof(signature);
    if (cx_ecdsa_sign_no_throw(&privateKey,
                               CX_RND_RFC6979 | CX_LAST,
                               CX_SHA256,
                               hash,
                               sizeof(hash),
                               signature,
                               &signatureLength,
                               &info) != CX_OK) {
        return false;
    }

    format_signature_out(signature);
    G_io_apdu_buffer[64] = 0;
    if (info & CX_ECCINFO_PARITY_ODD) {
        G_io_apdu_buffer[64]++;
    }
    tx = 65;

end:
    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));

    if (err == CX_OK) {
        // Send back the response, do not restart the event loop
        io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
    } else {
        io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    if (err == CX_OK) {
        return true;
    } else {
        return false;
    }
}

bool ui_callback_signMessage712_v0_cancel(bool display_menu) {
    ui_review_cancel();
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    if (display_menu) {
        // Display back the original UX
        ui_idle();
    }

    return true;
}
