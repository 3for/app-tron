/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2025 Ledger
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
 *
 ********************************************************************************/

#ifdef HAVE_GATING_SUPPORT

#include "cmd_get_gating.h"
#include "gcs_memory.h"
#include "app_mem_utils.h"
#include "apdu_constants.h"  // appState, APP_STATE_*
#include "hash_bytes.h"
#include "public_keys.h"  // check_signature_with_pubkey
#include "tlv_apdu.h"
#include "utils.h"
#include "common_utils.h"  // ADDRESS_LENGTH, allzeroes
#include "nbgl_use_case.h"
#include "os_pki.h"
#include "network.h"  // get_tx_chain_id
#include "ui_nbgl.h"  // warning, ICON_LEDGER
#include "settings.h"  // N_storage.gating_counter
#include "proxy_info.h"
#include "context_712.h"  // tip712_context
#include "schema_hash.h"  // compute_schema_hash
#include "calldata.h"     // CALLDATA_SELECTOR_SIZE
#include "lcx_sha256.h"

// This module mirrors app-ethereum's src/features/provide_gating/cmd_get_gating.c
// (gated/"dated" signing). The TLV parsing/verification is a faithful port; the
// TRON divergences are: the TX path reads the shared txContent struct (populated by
// the legacy protobuf signing path; TRON has no RLP tx structures, and app-ethereum
// likewise reads its legacy tmpContent.txContent here), and the prelude icon reuses
// the app review icon (no Ledger-logo glyph in the TRON build). The NVM counter lives
// in N_storage.gating_counter, exactly like app-ethereum.

// Display the Dated Signing screen 1/X times
#define GATED_SIGNING_MAX_COUNT 10

#define TYPE_GATED_SIGNING 0x0D
#define STRUCT_VERSION     0x01

#define GATING_MSG_SIZE 100
#define GATING_URL_SIZE 30
#define GATING_DESCRIPTOR_MAX_LENGTH 512

// clang-format off
typedef enum {
    TX_TYPE_UNKNOWN,
    TX_TYPE_TRANSACTION,
    TX_TYPE_TYPED_DATA,
} tx_type_t;

typedef struct gating_s {
    uint64_t chain_id;
    uint8_t hash_selector[CX_SHA224_SIZE];  // function selector for SignTx or schemaHash for TIP712
    char intro_msg[GATING_MSG_SIZE + 1];    // +1 for the null terminator
    char tiny_url[GATING_URL_SIZE + 1];     // +1 for the null terminator
    uint8_t address[ADDRESS_LENGTH];        // Contract address to check in the gating
    tx_type_t type;
} gating_t;

typedef struct {
    gating_t *gating;
    uint8_t sig_size;
    const uint8_t *sig;
    cx_sha256_t hash_ctx;
    TLV_reception_t received_tags;
    uint8_t hash_selector_size;
} s_gating_ctx;
// clang-format on

// Global structure to store the tx gating parameters
static gating_t *GATING = NULL;
static nbgl_preludeDetails_t prelude_details = {0};
static nbgl_genericDetails_t generic_details = {0};

/**
 * @brief Parse the STRUCTURE_TYPE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_struct_type(const tlv_data_t *data, s_gating_ctx *context) {
    UNUSED(context);
    return tlv_check_struct_type(data, TYPE_GATED_SIGNING);
}

/**
 * @brief Parse the STRUCTURE_VERSION value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_struct_version(const tlv_data_t *data, s_gating_ctx *context) {
    UNUSED(context);
    return tlv_check_struct_version(data, STRUCT_VERSION);
}

/**
 * @brief Parse the HASH / SELECTOR value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 *
 * @note This field can be either
 *  - function selector (4 bytes for SignTX)
 *  - schema hash (28 bytes for tip712)
 */
static bool parse_hash_selector(const tlv_data_t *data, s_gating_ctx *context) {
    if ((data == NULL) ||
        ((data->value.size != CALLDATA_SELECTOR_SIZE) && (data->value.size != CX_SHA224_SIZE))) {
        PRINTF("HASH/SELECTOR: invalid size\n");
        return false;
    }
    if (!tlv_get_hash(data,
                      context->gating->hash_selector,
                      sizeof(context->gating->hash_selector),
                      data->value.size)) {
        return false;
    }
    context->hash_selector_size = data->value.size;
    return true;
}

/**
 * @brief Parse the ADDRESS value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_address(const tlv_data_t *data, s_gating_ctx *context) {
    if (!tlv_get_address(data, context->gating->address)) {
        return false;
    }
    if (allzeroes(context->gating->address, ADDRESS_LENGTH) == 1) {
        PRINTF("ADDRESS: all zeroes\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse the CHAIN_ID value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_chain_id(const tlv_data_t *data, s_gating_ctx *context) {
    return tlv_get_chain_id(data, &context->gating->chain_id);
}

/**
 * @brief Parse the INTRO_MSG value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_intro_msg(const tlv_data_t *data, s_gating_ctx *context) {
    if (!tlv_get_printable_string(data,
                                  context->gating->intro_msg,
                                  1,
                                  sizeof(context->gating->intro_msg))) {
        PRINTF("INTRO_MSG: error\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse the TINY_URL value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_tiny_url(const tlv_data_t *data, s_gating_ctx *context) {
    if (!tlv_get_printable_string(data,
                                  context->gating->tiny_url,
                                  1,
                                  sizeof(context->gating->tiny_url))) {
        PRINTF("TINY_URL: error\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse the TX_TYPE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_type(const tlv_data_t *data, s_gating_ctx *context) {
    uint8_t value = 0;
    if (!tlv_get_uint8_range(data, &value, 0, TX_TYPE_TYPED_DATA - 1)) {
        PRINTF("TX_TYPE: error\n");
        return false;
    }
    context->gating->type = value + 1;  // Because 0 is "unknown"
    return true;
}

/**
 * @brief Parse the SIGNATURE value.
 *
 * @param[in] data the tlv data
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool parse_signature(const tlv_data_t *data, s_gating_ctx *context) {
    buffer_t sig = {0};
    if (!get_buffer_from_tlv_data(data,
                                  &sig,
                                  CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH,
                                  CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH)) {
        PRINTF("SIGNATURE: failed to extract\n");
        return false;
    }
    context->sig_size = sig.size;
    context->sig = sig.ptr;
    return true;
}

// Define TLV tags for Gating
#define GATING_TAGS(X)                                                       \
    X(0x01, TAG_STRUCTURE_TYPE, parse_struct_type, ENFORCE_UNIQUE_TAG)       \
    X(0x02, TAG_STRUCTURE_VERSION, parse_struct_version, ENFORCE_UNIQUE_TAG) \
    X(0x22, TAG_ADDRESS, parse_address, ENFORCE_UNIQUE_TAG)                  \
    X(0x23, TAG_CHAIN_ID, parse_chain_id, ENFORCE_UNIQUE_TAG)                \
    X(0x40, TAG_HASH_SELECTOR, parse_hash_selector, ENFORCE_UNIQUE_TAG)      \
    X(0x82, TAG_INTRO_MSG, parse_intro_msg, ENFORCE_UNIQUE_TAG)              \
    X(0x83, TAG_TINY_URL, parse_tiny_url, ENFORCE_UNIQUE_TAG)               \
    X(0x84, TAG_TX_TYPE, parse_type, ENFORCE_UNIQUE_TAG)                     \
    X(0x15, TAG_DER_SIGNATURE, parse_signature, ENFORCE_UNIQUE_TAG)

// Forward declaration
static bool gating_common_handler(const tlv_data_t *data, s_gating_ctx *context);

// Generate TLV parser for Gating
DEFINE_TLV_PARSER(GATING_TAGS, &gating_common_handler, gating_tlv_parser)

/**
 * @brief Common handler called for all tags to hash them (except signature).
 *
 * @param[in] data the TLV data
 * @param[out] context Gating context
 * @return whether it was successful
 */
static bool gating_common_handler(const tlv_data_t *data, s_gating_ctx *context) {
    if (data->tag != TAG_DER_SIGNATURE) {
        hash_nbytes(data->raw.ptr, data->raw.size, (cx_hash_t *) &context->hash_ctx);
    }
    return true;
}

/**
 * @brief Verify the payload signature
 *
 * Verify the SHA-256 hash of the payload against the public key
 *
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool verify_signature(s_gating_ctx *context) {
    uint8_t hash[INT256_LENGTH];

    if (finalize_hash((cx_hash_t *) &context->hash_ctx, hash, sizeof(hash)) != true) {
        PRINTF("Could not finalize struct hash!\n");
        return false;
    }

    if (check_signature_with_pubkey(hash,
                                    sizeof(hash),
                                    NULL,
                                    0,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_GATED_SIGNING,
                                    (uint8_t *) context->sig,
                                    context->sig_size) != true) {
        return false;
    }
    return true;
}

/**
 * @brief Verify the received fields
 *
 * Check the mandatory fields are present
 *
 * @param[in] context Gating context
 * @return whether it was successful
 */
static bool verify_fields(s_gating_ctx *context) {
    // Common required tags for all types
    if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags,
                                 TAG_STRUCTURE_TYPE,
                                 TAG_STRUCTURE_VERSION,
                                 TAG_TX_TYPE,
                                 TAG_ADDRESS,
                                 TAG_INTRO_MSG,
                                 TAG_TINY_URL,
                                 TAG_DER_SIGNATURE)) {
        return false;
    }

    switch (context->gating->type) {
        case TX_TYPE_TRANSACTION:
            // For SignTx, we expect the chain ID
            if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags, TAG_CHAIN_ID)) {
                return false;
            }
            if (TLV_CHECK_RECEIVED_TAGS(context->received_tags, TAG_HASH_SELECTOR) &&
                (context->hash_selector_size != CALLDATA_SELECTOR_SIZE)) {
                return false;
            }
            break;
        case TX_TYPE_TYPED_DATA:
            // For TIP-712, we expect the schema hash
            if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags, TAG_HASH_SELECTOR) ||
                (context->hash_selector_size != CX_SHA224_SIZE)) {
                return false;
            }
            break;
        default:
            break;
    }

    return true;
}

/**
 * @brief Print the gating parameters.
 *
 * @param[in] context Gating context
 * Only for debug purpose.
 */
static void print_gating_info(s_gating_ctx *context) {
    uint8_t len = 0;
    PRINTF("****************************************************************************\n");
    PRINTF("[GATING] - Retrieved Gating descriptor:\n");
    PRINTF("[GATING] -    Address: %.*h\n", ADDRESS_LENGTH, context->gating->address);
    if (context->gating->chain_id != 0) {
        PRINTF("[GATING] -    ChainID: %llu\n", context->gating->chain_id);
    }
    len = (context->gating->type == TX_TYPE_TRANSACTION) ? CALLDATA_SELECTOR_SIZE
                                                         : sizeof(context->gating->hash_selector);
    if (allzeroes((const void *) context->gating->hash_selector, len) == 0) {
        PRINTF("[GATING] -    Hash Selector: %.*h\n", len, context->gating->hash_selector);
    }
    PRINTF("[GATING] -    Intro Msg: %s\n", context->gating->intro_msg);
    PRINTF("[GATING] -    Tiny URL: %s\n", context->gating->tiny_url);
}

/**
 * @brief Parse the TLV payload containing the TX Gating parameters.
 *
 * @param[in] buf buffer received
 * @return whether the TLV payload was handled successfully or not
 */
static bool handle_tlv_payload(const buffer_t *buf) {
    s_gating_ctx ctx = {0};
    gating_t candidate = {0};
    gating_t *committed = NULL;
    gating_t *previous;

    /* Parse and authenticate into stack storage. If a CX operation throws,
     * there is no uncommitted heap allocation to leak. */
    ctx.gating = &candidate;

    // Initialize the hash context
    cx_sha256_init(&ctx.hash_ctx);

    if (!gating_tlv_parser(buf, &ctx, &ctx.received_tags)) {
        return false;
    }

    if (!verify_fields(&ctx) || !verify_signature(&ctx)) {
        return false;
    }

    print_gating_info(&ctx);
    committed = gcs_mem_alloc(sizeof(*committed), GCS_MEM_METADATA);
    if (committed == NULL) {
        PRINTF("Error: Not enough memory!\n");
        return false;
    }
    memcpy(committed, &candidate, sizeof(*committed));
    previous = GATING;
    GATING = committed;
    gcs_mem_free(previous);
    return true;
}

/**
 * @brief Handle Gating APDU.
 *
 * @param[in] p1 APDU parameter 1 (indicates if the payload is the first chunk)
 * @param[in] p2 APDU parameter 2 (indicates Data payload or Opt-In request)
 * @param[in] length of the buffer
 * @param[in] data buffer received
 * @return APDU Response code
 */
uint16_t handle_gating(uint8_t p1, uint8_t p2, uint8_t length, const uint8_t *data) {
    uint16_t sw = SWO_PARAMETER_ERROR_NO_INFO;

    if ((p1 != P1_FIRST_CHUNK) && (p1 != P1_FOLLOWING_CHUNK)) {
        tlv_apdu_reset();
        return SWO_WRONG_P1_P2;
    }
    switch (p2) {
        case 0x00:
            if (!tlv_from_apdu(INS_PROVIDE_GATING,
                               p2,
                               p1 == P1_FIRST_CHUNK,
                               length,
                               data,
                               GATING_DESCRIPTOR_MAX_LENGTH,
                               &handle_tlv_payload)) {
                sw = gcs_mem_take_allocation_failure() ? SWO_INSUFFICIENT_MEMORY
                                                       : SWO_INCORRECT_DATA;
            } else {
                sw = SWO_SUCCESS;
            }
            break;
        default:
            PRINTF("Error: Unexpected P2 (%u)!\n", p2);
            tlv_apdu_reset();
            sw = SWO_WRONG_P1_P2;
            break;
    }
    return sw;
}

/**
 * @brief Clear the Gating parameters.
 *
 */
void clear_gating(void) {
    gcs_mem_free_and_null((void **) &GATING);
}

/**
 * @brief Check the TYPE in Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_type(void) {
    switch (GATING->type) {
        case TX_TYPE_TRANSACTION:
            // Legacy protobuf signing path (INS_SIGN -> sign.c) sets APP_STATE_SIGNING.
            // The GCS path is structured clear-signing and is intentionally not gated.
            if (appState != APP_STATE_SIGNING) {
                PRINTF("[GATING] Type mismatch: %u != %u\n", GATING->type, TX_TYPE_TRANSACTION);
                return false;
            }
            break;
        case TX_TYPE_TYPED_DATA:
            if (appState != APP_STATE_SIGNING_EIP712) {
                PRINTF("[GATING] Type mismatch: %u != %u\n", GATING->type, TX_TYPE_TYPED_DATA);
                return false;
            }
            break;
        default:
            PRINTF("[GATING] Invalid Type: %u\n", GATING->type);
            return false;
    }
    return true;
}

/**
 * @brief Check the TO_ADDRESS vs Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_address(void) {
    const uint8_t *address = NULL;
    const uint8_t *selector = NULL;
    const uint8_t *contract = NULL;

    if (allzeroes((const void *) GATING->address, ADDRESS_LENGTH)) {
        PRINTF("[GATING] TO address missing\n");
        return false;
    }
    switch (GATING->type) {
        case TX_TYPE_TRANSACTION:
            // Legacy protobuf path: txContent.contractAddress is a 21-byte TRON address
            // (0x41 prefix + 20-byte EVM). Gating descriptors carry the 20-byte EVM
            // address, so skip the prefix byte.
            contract = txContent.contractAddress + 1;
            selector = GATING->hash_selector;
            break;
        case TX_TYPE_TYPED_DATA:
            contract = tip712_context->contract_addr;
            break;
        default:
            return false;
    }
    if (contract == NULL) {
        return false;
    }

    PRINTF("[GATING] Tx TO address: %.*h\n", ADDRESS_LENGTH, contract);
    PRINTF("[GATING] Gating address: %.*h\n", ADDRESS_LENGTH, GATING->address);

    // Get the implementation address for the received descriptor address
    address = get_implem_contract(&GATING->chain_id, contract, selector);
    if (address != NULL) {
        // Implementation address found, a proxy exists for this descriptor
        // We will check the implementation address against the Gating descriptor address
        if (memcmp(address, GATING->address, ADDRESS_LENGTH) != 0) {
            PRINTF("[GATING] Proxy Implem ADDRESS mismatch: %.*h != %.*h\n",
                   ADDRESS_LENGTH,
                   address,
                   ADDRESS_LENGTH,
                   GATING->address);
            return false;
        }
        // Then we will check the transaction TO address against the proxy contract address
        address = get_proxy_contract(&GATING->chain_id, GATING->address, selector);
        if (address == NULL) {
            PRINTF("[GATING] No proxy found for this implementation address\n");
            return false;
        }
    } else {
        PRINTF("[GATING] No proxy found for this descriptor address\n");
        // Implementation address is NULL, checking with Descriptor address
        address = GATING->address;
    }

    if (memcmp(address, contract, ADDRESS_LENGTH) != 0) {
        PRINTF("[GATING] ADDRESS mismatch: %.*h != %.*h\n",
               ADDRESS_LENGTH,
               address,
               ADDRESS_LENGTH,
               contract);
        return false;
    }
    return true;
}

/**
 * @brief Check the CHAIN_ID vs Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_chain_id(void) {
    uint64_t chain_id = 0;
    switch (GATING->type) {
        case TX_TYPE_TRANSACTION:
            chain_id = get_tx_chain_id();
            if (GATING->chain_id != chain_id) {
                PRINTF("[GATING] Chain_ID mismatch: %llu != %llu\n", GATING->chain_id, chain_id);
                return false;
            }
            break;
        case TX_TYPE_TYPED_DATA:
            chain_id = tip712_context->chain_id;
            // For TIP-712, the chain_id is optional, and be 0 in the descriptor (any chain)
            if ((GATING->chain_id != 0) && (GATING->chain_id != chain_id)) {
                PRINTF("[GATING] Chain_ID mismatch: %llu != %llu\n", GATING->chain_id, chain_id);
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

/**
 * @brief Check the SELECTOR vs Gating payload.
 *
 * @return whether it was successful
 */
static bool check_gating_selector(void) {
    uint8_t selector[CALLDATA_SELECTOR_SIZE];
    uint8_t schema_hash[CX_SHA224_SIZE];
    switch (GATING->type) {
        case TX_TYPE_TRANSACTION:
            // Check if the descriptor is set
            if (allzeroes((const void *) GATING->hash_selector, CALLDATA_SELECTOR_SIZE)) {
                break;
            }
            if (!txContent.hasCalldata) {
                PRINTF("[GATING] Transaction has no calldata selector\n");
                return false;
            }
            // Legacy protobuf path: txContent.customSelector holds the 4-byte method
            // selector decoded big-endian (parse.c U4BE). Re-encode it big-endian to
            // compare against the descriptor selector.
            selector[0] = (uint8_t) (txContent.customSelector >> 24);
            selector[1] = (uint8_t) (txContent.customSelector >> 16);
            selector[2] = (uint8_t) (txContent.customSelector >> 8);
            selector[3] = (uint8_t) (txContent.customSelector);
            if (memcmp(GATING->hash_selector, selector, CALLDATA_SELECTOR_SIZE) != 0) {
                PRINTF("[GATING] SELECTOR mismatch: %.*h != %.*h\n",
                       CALLDATA_SELECTOR_SIZE,
                       GATING->hash_selector,
                       CALLDATA_SELECTOR_SIZE,
                       selector);
                return false;
            }
            break;
        case TX_TYPE_TYPED_DATA:
            if (compute_schema_hash_into(schema_hash) == false) {
                PRINTF("[GATING] Failed to compute schema hash\n");
                return false;
            }
            if (memcmp(GATING->hash_selector,
                       schema_hash,
                       sizeof(GATING->hash_selector)) != 0) {
                PRINTF("[GATING] schemaHash mismatch: %.*h != %.*h\n",
                       sizeof(GATING->hash_selector),
                       GATING->hash_selector,
                       sizeof(schema_hash),
                       schema_hash);
                explicit_bzero(schema_hash, sizeof(schema_hash));
                return false;
            }
            explicit_bzero(schema_hash, sizeof(schema_hash));
            break;
        default:
            return false;
    }
    return true;
}

/**
 * @brief Check the TX vs Gating parameters (CHAIN_ID, ADDRESS, SELECTOR).
 *
 * @return whether it was successful
 */
static bool check_tx_gating_params(void) {
    if (check_gating_type() == false) {
        return false;
    }
    if (check_gating_chain_id() == false) {
        return false;
    }
    if (check_gating_address() == false) {
        return false;
    }
    if (check_gating_selector() == false) {
        return false;
    }
    return true;
}

/**
 * @brief Configure the warning prelude set for the NBGL review flows.
 *
 */
static void set_gating_ui_screen(void) {
    explicit_bzero(&prelude_details, sizeof(prelude_details));
    explicit_bzero(&generic_details, sizeof(generic_details));

    generic_details.title = "Discover safer signing";
#ifdef SCREEN_SIZE_WALLET
    generic_details.type = QRCODE_WARNING;
    generic_details.qrCode.url = GATING->tiny_url;
    generic_details.qrCode.text1 = GATING->tiny_url;
    generic_details.qrCode.text2 = "Discover a safer way to sign your transactions";
    generic_details.qrCode.centered = true;
#endif

    prelude_details.icon = &ICON_LEDGER;
#ifdef SCREEN_SIZE_WALLET
    prelude_details.title = "There is a safer\nway to sign";
    prelude_details.description = GATING->intro_msg;
#else
    prelude_details.title = "\bA safer way exists:";
    prelude_details.description = GATING->tiny_url;
#endif
    prelude_details.buttonText = "Learn more";
    prelude_details.footerText = "Continue to blind signing";
    prelude_details.details = &generic_details;

    warning.prelude = &prelude_details;
}

/**
 * @brief Configure the warning prelude set for the NBGL review flows.
 *
 * @return whether the descriptor corresponds to the current transaction
 */
bool set_gating_warning(void) {
    uint8_t counter = 0;

    if (GATING == NULL) {
        return true;
    }

    // Gated signing received => Verify parameters of the Transaction
    if (check_tx_gating_params() == false) {
        PRINTF("[GATING] Parameters mismatch\n");
        return false;
    }

    // Check the counter
    counter = N_storage.gating_counter + 1;
    PRINTF("[GATING] Counter: %d/%d\n", counter, GATED_SIGNING_MAX_COUNT);
    nvm_write((void *) &N_storage.gating_counter, (void *) &counter, sizeof(counter));
    if (((counter - 1) % GATED_SIGNING_MAX_COUNT) != 0) {
        PRINTF("[GATING] Skip gating screen\n");
        return true;
    }

    // Gated signing valid => Adapt the UI screens
    set_gating_ui_screen();
    return true;
}

bool set_blind_sign_gating_warning(void) {
    // Mirrors app-ethereum's ux_approve_tx() gating block: a custom contract is a
    // blind-signing path, so reset the warning set, flag blind+gated signing, then
    // run the descriptor match (which may add the "safer signing" prelude).
    explicit_bzero(&warning, sizeof(nbgl_warning_t));
    warning.predefinedSet |= SET_BIT(BLIND_SIGNING_WARN);
    warning.predefinedSet |= SET_BIT(GATED_SIGNING_WARN);
    return set_gating_warning();
}

#endif  // HAVE_GATING_SUPPORT
