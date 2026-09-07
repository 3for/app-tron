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
#ifdef HAVE_SWAP

#include "handle_swap_sign_transaction.h"
#include "swap.h"

#include "parse.h"
#include "tokens.h"
#include "uint256.h"

typedef struct swap_validated_s {
    bool initialized;
    bool is_trc20;
    uint8_t decimals;
    char ticker[MAX_SWAP_TOKEN_LENGTH];
    uint8_t contract_address[ADDRESS_SIZE];
    uint256_t amount;
    uint64_t max_fee_limit;
    char recipient[BASE58CHECK_ADDRESS_SIZE + 1];
} swap_validated_t;

static swap_validated_t G_swap_validated;

// Save the BSS address where we will write the return value when finished
static uint8_t *G_swap_sign_return_value_address;

static bool token_metadata_matches(const tokenDefinition_t *token,
                                   const char *ticker,
                                   uint8_t decimals) {
    return (token->decimals == decimals) && (strcmp(token->ticker, ticker) == 0);
}

static bool resolve_trc20_contract(const char *ticker,
                                   uint8_t decimals,
                                   const uint8_t *configured_address,
                                   uint8_t contract_address[static ADDRESS_SIZE]) {
    const tokenDefinition_t *match = NULL;

    for (size_t i = 0; i < NUM_TOKENS_TRC20; i++) {
        const tokenDefinition_t *token = (const tokenDefinition_t *) PIC(&TOKENS_TRC20[i]);

        if (configured_address != NULL) {
            if (memcmp(token->address, configured_address, ADDRESS_SIZE) != 0) {
                continue;
            }
            if (!token_metadata_matches(token, ticker, decimals)) {
                // The allowlist may contain multiple metadata aliases for one contract.
                // Keep looking for an entry matching the signed configuration.
                continue;
            }
            memcpy(contract_address, token->address, ADDRESS_SIZE);
            return true;
        }

        if (!token_metadata_matches(token, ticker, decimals)) {
            continue;
        }

        if (match == NULL) {
            match = token;
        } else if (memcmp(match->address, token->address, ADDRESS_SIZE) != 0) {
            PRINTF("TRC20 ticker/decimals do not identify a unique contract\n");
            return false;
        }
    }

    if (match == NULL) {
        PRINTF("TRC20 configuration does not match the trusted token table\n");
        return false;
    }

    memcpy(contract_address, match->address, ADDRESS_SIZE);
    return true;
}

static bool parse_fee_limit(const uint8_t *fee_amount,
                            uint8_t fee_amount_length,
                            uint64_t *fee_limit) {
    // Exchange stores fee amounts in a 16-byte buffer. Accept equivalent
    // zero-padded encodings, but reject values that do not fit Tron int64.
    if (fee_amount_length == 0) {
        *fee_limit = 0;
        return true;
    }
    if ((fee_amount == NULL) || (fee_amount_length > 16)) {
        return false;
    }

    while ((fee_amount_length > 8) && (*fee_amount == 0)) {
        fee_amount++;
        fee_amount_length--;
    }
    if (fee_amount_length > 8) {
        return false;
    }

    uint64_t value = 0;
    for (uint8_t i = 0; i < fee_amount_length; i++) {
        value = (value << 8) | fee_amount[i];
    }

    // Transaction.raw.fee_limit is an int64 in the Tron protocol.
    if (value > INT64_MAX) {
        return false;
    }

    *fee_limit = value;
    return true;
}

// Save the data validated during the Exchange app flow
bool swap_copy_transaction_parameters(create_transaction_parameters_t *params) {
    PRINTF("Inside Tron swap_copy_transaction_parameters\n");

    if (params == NULL) {
        return false;
    }

    // Ensure no extraid
    if (params->destination_address_extra_id == NULL) {
        PRINTF("destination_address_extra_id expected\n");
        return false;
    } else if (params->destination_address_extra_id[0] != '\0') {
        PRINTF("destination_address_extra_id expected empty, not '%s'\n",
               params->destination_address_extra_id);
        return false;
    }

    if (params->destination_address == NULL) {
        PRINTF("Destination address expected\n");
        return false;
    }

    if ((params->amount == NULL) || (params->amount_length > MAX_SWAP_AMOUNT_LENGTH)) {
        PRINTF("Valid amount expected\n");
        return false;
    }

    // first copy parameters to stack, and then to global data.
    // We need this "trick" as the input data position can overlap with app globals
    // and also because we want to memset the whole bss segment as it is not done
    // when an app is called as a lib.
    // This is necessary as many part of the code expect bss variables to
    // initialized at 0.
    swap_validated_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // Parse config and save decimals, ticker and the canonical asset identity.
    // If there is no coin_configuration, consider that we are doing a TRX swap
    if (params->coin_configuration == NULL) {
        memcpy(swap_validated.ticker, "TRX", sizeof("TRX"));
        swap_validated.decimals = SUN_DIG;
    } else {
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               swap_validated.ticker,
                               sizeof(swap_validated.ticker),
                               &swap_validated.decimals)) {
            PRINTF("Fail to parse coin_configuration\n");
            return false;
        }

        // Legacy Tron sub-configurations contain [ticker length][ticker][decimals].
        // They remain supported when ticker/decimals identify exactly one trusted
        // contract. An optional trailing 21-byte address lets the signed CAL
        // configuration disambiguate colliding token metadata without changing
        // the app-exchange library ABI.
        const size_t base_config_length = 2u + params->coin_configuration[0];
        const uint8_t *configured_address = NULL;
        if (params->coin_configuration_length == base_config_length + ADDRESS_SIZE) {
            configured_address = params->coin_configuration + base_config_length;
        } else if (params->coin_configuration_length != base_config_length) {
            PRINTF("Unexpected Tron coin_configuration length\n");
            return false;
        }

        if (!resolve_trc20_contract(swap_validated.ticker,
                                    swap_validated.decimals,
                                    configured_address,
                                    swap_validated.contract_address)) {
            return false;
        }

        if (!parse_fee_limit(params->fee_amount,
                             params->fee_amount_length,
                             &swap_validated.max_fee_limit)) {
            PRINTF("Invalid TRC20 fee limit\n");
            return false;
        }
        swap_validated.is_trc20 = true;
    }

    // strlcpy() always NUL-terminates, so length must be checked before copying.
    if (strnlen(params->destination_address, BASE58CHECK_ADDRESS_SIZE + 1) !=
        BASE58CHECK_ADDRESS_SIZE) {
        PRINTF("Invalid destination address length\n");
        return false;
    }
    if (strlcpy(swap_validated.recipient,
                params->destination_address,
                sizeof(swap_validated.recipient)) >= sizeof(swap_validated.recipient)) {
        PRINTF("Address copy error\n");
        return false;
    }

    if (!convertUint256BE(params->amount, params->amount_length, &swap_validated.amount)) {
        PRINTF("Invalid amount conversion\n");
        return false;
    }

    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Keep the address at which we'll reply the signing status
    G_swap_sign_return_value_address = &params->result;

    // Commit from stack to global data, params becomes tainted but we won't access it anymore
    memcpy(&G_swap_validated, &swap_validated, sizeof(swap_validated));
    return true;
}

// Check that the amount in parameter is the same as the previously saved amount
static bool check_swap_amount(const char *amount, const uint8_t decimals) {
    char validated_amount[MAX_PRINTABLE_AMOUNT_SIZE] = {0};
    char amount_raw_string[MAX_PRINTABLE_AMOUNT_SIZE] = {0};

    tostring256(&G_swap_validated.amount, 10, amount_raw_string, sizeof(amount_raw_string));

    if (!adjustDecimals(amount_raw_string,
                        strnlen(amount_raw_string, sizeof(amount_raw_string)),
                        validated_amount,
                        sizeof(validated_amount),
                        decimals)) {
        PRINTF("Conversion failed\n");
        return false;
    }

    if (strncmp(amount, validated_amount, MAX_PRINTABLE_AMOUNT_SIZE) != 0) {
        PRINTF("Amount requested in this transaction = %s\n", amount);
        PRINTF("Amount validated in swap = %s\n", validated_amount);
        return false;
    }

    return true;
}

bool swap_check_validity(const char *amount,
                         const char *tokenName,
                         const char *action,
                         const char *toAddress,
                         const uint8_t *contractAddress,
                         uint64_t feeLimit) {
    PRINTF("Inside Tron swap_check_validity\n");

    if (!G_swap_validated.initialized) {
        return false;
    }

    if (!check_swap_amount(amount, G_swap_validated.decimals)) {
        return false;
    }

    // For TRC20, the exact contract address is the authorization boundary. A contract may
    // have multiple trusted ticker aliases, while getKnownToken() selects the first one.
    if (!G_swap_validated.is_trc20 &&
        (strncmp(tokenName, G_swap_validated.ticker, MAX_SWAP_TOKEN_LENGTH) != 0)) {
        PRINTF("Refused field '%s', expecting '%s'\n", tokenName, G_swap_validated.ticker);
        return false;
    }

    if (G_swap_validated.is_trc20) {
        if ((contractAddress == NULL) ||
            (memcmp(contractAddress, G_swap_validated.contract_address, ADDRESS_SIZE) != 0)) {
            PRINTF("TRC20 contract requested in this transaction does not match swap asset\n");
            return false;
        }
        if (feeLimit > G_swap_validated.max_fee_limit) {
            PRINTF("TRC20 fee limit requested in this transaction exceeds swap approval\n");
            return false;
        }
    } else if (contractAddress != NULL) {
        PRINTF("Refused TRC20 transaction for a native TRX swap\n");
        return false;
    }

    if (strncmp(action, "To", 3) != 0) {
        PRINTF("Refused field '%s', expecting 'To'\n", action);
        return false;
    }

    if (strncmp(G_swap_validated.recipient, toAddress, BASE58CHECK_ADDRESS_SIZE + 1) != 0) {
        PRINTF("Recipient requested in this transaction = %s\n", toAddress);
        PRINTF("Recipient validated in swap = %s\n", G_swap_validated.recipient);
        return false;
    }

    PRINTF("VALID!\n");

    return true;
}

void __attribute__((noreturn)) swap_finalize_exchange_sign_transaction(bool is_success) {
    *G_swap_sign_return_value_address = is_success;
    os_lib_end();
}

#endif  // HAVE_SWAP
