#ifdef HAVE_TIP712_FULL_SUPPORT

#include "filtering.h"
// #include "hash_bytes.h"
// #include "ethUstream.h"      // INT256_LENGTH
// #include "apdu_constants.h"  // APDU return codes
// #include "public_keys.h"
// #include "manage_asset_info.h"
#include "context_712.h"
#include "commands_712.h"
#include "typed_data.h"
#include "path.h"
#include "ui_logic.h"
#include "filtering.h"
#include "app_errors.h"
#include "parse.h"
#include "ui_globals.h"


#define FILT_MAGIC_MESSAGE_INFO      183
#define FILT_MAGIC_AMOUNT_JOIN_TOKEN 11
#define FILT_MAGIC_AMOUNT_JOIN_VALUE 22
#define FILT_MAGIC_DATETIME          33
#define FILT_MAGIC_RAW_FIELD         72

#define TOKEN_IDX_ADDR_IN_DOMAIN 0xff


static const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[] = {
#if defined(HAVE_CAL_TEST_KEY)
    0x04, 0x4c, 0xca, 0x8f, 0xad, 0x49, 0x6a, 0xa5, 0x04, 0x0a, 0x00, 0xa7, 0xeb, 0x2f,
    0x5c, 0xc3, 0xb8, 0x53, 0x76, 0xd8, 0x8b, 0xa1, 0x47, 0xa7, 0xd7, 0x05, 0x4a, 0x99,
    0xc6, 0x40, 0x56, 0x18, 0x87, 0xfe, 0x17, 0xa0, 0x96, 0xe3, 0x6c, 0x3b, 0x52, 0x3b,
    0x24, 0x4f, 0x3e, 0x2f, 0xf7, 0xf8, 0x40, 0xae, 0x26, 0xc4, 0xe7, 0x7a, 0xd3, 0xbc,
    0x73, 0x9a, 0xf5, 0xde, 0x6f, 0x2d, 0x77, 0xa7, 0xb6
#elif defined(HAVE_CAL_STAGING_KEY)
    // staging key 2019-01-11 03:07PM (erc20signer)
    0x04, 0x20, 0xda, 0x62, 0x00, 0x3c, 0x0c, 0xe0, 0x97, 0xe3, 0x36, 0x44, 0xa1, 0x0f,
    0xe4, 0xc3, 0x04, 0x54, 0x06, 0x9a, 0x44, 0x54, 0xf0, 0xfa, 0x9d, 0x4e, 0x84, 0xf4,
    0x50, 0x91, 0x42, 0x9b, 0x52, 0x20, 0xaf, 0x9e, 0x35, 0xc0, 0xb2, 0xd9, 0x28, 0x93,
    0x80, 0x13, 0x73, 0x07, 0xde, 0x4d, 0xd1, 0xd4, 0x18, 0x42, 0x8c, 0xf2, 0x1a, 0x93,
    0xb3, 0x35, 0x61, 0xbb, 0x09, 0xd8, 0x8f, 0xe5, 0x79
#else
    // production key 2019-01-11 03:07PM (erc20signer)
    0x04, 0x5e, 0x6c, 0x10, 0x20, 0xc1, 0x4d, 0xc4, 0x64, 0x42, 0xfe, 0x89, 0xf9, 0x7c,
    0x0b, 0x68, 0xcd, 0xb1, 0x59, 0x76, 0xdc, 0x24, 0xf2, 0x4c, 0x31, 0x6e, 0x7b, 0x30,
    0xfe, 0x4e, 0x8c, 0xc7, 0x6b, 0x14, 0x89, 0x15, 0x0c, 0x21, 0x51, 0x4e, 0xbf, 0x44,
    0x0f, 0xf5, 0xde, 0xa5, 0x39, 0x3d, 0x83, 0xde, 0x53, 0x58, 0xcd, 0x09, 0x8f, 0xce,
    0x8f, 0xd0, 0xf8, 0x1d, 0xaa, 0x94, 0x97, 0x91, 0x83
#endif
};

#define _PRINT_MACRO(x) #x
#define PRINT_MACRO(x) #x"="_PRINT_MACRO(x)

#pragma message(PRINT_MACRO(HAVE_CAL_TEST_KEY))

/**
 * Reconstruct the field path and hash it
 *
 * @param[in] hash_ctx the hashing context
 */
static void hash_filtering_path(cx_hash_t *hash_ctx) {
    const void *field_ptr;
    const char *key;
    uint8_t key_len;

    for (uint8_t i = 0; i < path_get_depth_count(); ++i) {
        if (i > 0) {
            hash_byte('.', hash_ctx);
        }
        if ((field_ptr = path_get_nth_field(i + 1)) != NULL) {
            if ((key = get_struct_field_keyname(field_ptr, &key_len)) != NULL) {
                // field name
                hash_nbytes((uint8_t *) key, key_len, hash_ctx);

                // array levels
                if (struct_field_is_array(field_ptr)) {
                    uint8_t lvl_count;

                    get_struct_field_array_lvls_array(field_ptr, &lvl_count);
                    for (int j = 0; j < lvl_count; ++j) {
                        hash_nbytes((uint8_t *) ".[]", 3, hash_ctx);
                    }
                }
            }
        }
    }
}

/**
 * Begin the hashing for signature verification
 *
 * @param[in] hash_ctx hashing context
 * @param[in] magic magic number used in the signature
 * @return \ref true
 */
static bool sig_verif_start(cx_sha256_t *hash_ctx, uint8_t magic) {
    uint64_t chain_id;

    cx_sha256_init(hash_ctx);

    // Magic number, makes it so a signature of one type can't be used as another
    hash_byte(magic, (cx_hash_t *) hash_ctx);

    // Chain ID
    chain_id = __builtin_bswap64(tip712_context->chain_id);
    hash_nbytes((uint8_t *) &chain_id, sizeof(chain_id), (cx_hash_t *) hash_ctx);

    // Contract address
    hash_nbytes(tip712_context->contract_addr,
                sizeof(tip712_context->contract_addr),
                (cx_hash_t *) hash_ctx);

    // Schema hash
    hash_nbytes(tip712_context->schema_hash,
                sizeof(tip712_context->schema_hash),
                (cx_hash_t *) hash_ctx);
    return true;
}

/**
 * End the hashing & do the signature verification
 *
 * @param[in] hash_ctx hashing context
 * @param[in] sig signature
 * @param[in] sig_length signature length
 * @return whether the signature verification worked or not
 */
static bool sig_verif_end(cx_sha256_t *hash_ctx, const uint8_t *sig, uint8_t sig_length) {
    uint8_t hash[INT256_LENGTH];
    cx_ecfp_public_key_t verifying_key;
    cx_err_t error = CX_INTERNAL_ERROR;

    // Finalize hash
    CX_CHECK(cx_hash_no_throw((cx_hash_t *) hash_ctx, CX_LAST, NULL, 0, hash, INT256_LENGTH));

    CX_CHECK(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1,
                                              LEDGER_SIGNATURE_PUBLIC_KEY,
                                              sizeof(LEDGER_SIGNATURE_PUBLIC_KEY),
                                              &verifying_key));

    if (!cx_ecdsa_verify_no_throw(&verifying_key, hash, sizeof(hash), sig, sig_length)) {
#ifndef HAVE_BYPASS_SIGNATURES
        PRINTF("Invalid TIP-712 filtering signature\n");
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
#endif
    }
    return true;
end:
    return false;
}

/**
 * Check if the given token index is valid
 *
 * @param[in] idx token index
 * @return whether the index is valid or not
 */
static bool check_token_index(uint8_t idx) {
    if (idx >= MAX_ASSETS) {
        PRINTF("Error: token index out of range (%u)\n", idx);
        return false;
    }
    if (!global_ctx.transactionContext.assetSet[idx]) {
        PRINTF("Error: token not set (%u)\n", idx);
        return false;
    }
    return true;
}

/**
 * Check if the current element's typename matches the expected one
 *
 * @param[in] expected the typename we expect
 * @return whether it is a match or not
 */
static bool check_typename(const char *expected) {
    uint8_t typename_len = 0;
    const char *typename;

    typename = get_struct_field_typename(path_get_field(), &typename_len);
    if ((typename_len != strlen(expected)) || (strncmp(typename, expected, typename_len) != 0)) {
        PRINTF("Error: expected field of type \"%s\" but got \"", expected);
        for (int i = 0; i < typename_len; ++i) PRINTF("%c", typename[i]);
        PRINTF("\" instead.\n");
        return false;
    }
    return true;
}

/**
 * Command to give the message information
 *
 * @param[in] payload the payload to parse
 * @param[in] length the payload length
 * @return whether it was successful or not
 */
bool filtering_message_info(const uint8_t *payload, uint8_t length) {
    uint8_t name_len;
    const char *name;
    uint8_t filters_count;
    uint8_t sig_len;
    const uint8_t *sig;
    uint8_t offset = 0;

    if (path_get_root_type() != ROOT_DOMAIN) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    // Parsing
    if ((offset + sizeof(name_len)) > length) {
        return false;
    }
    name_len = payload[offset++];
    if ((offset + name_len) > length) {
        return false;
    }
    name = (char *) &payload[offset];
    offset += name_len;
    if ((offset + sizeof(filters_count)) > length) {
        return false;
    }
    filters_count = payload[offset++];
    if (filters_count > MAX_FILTERS) {
        PRINTF("%u filters planned but can only store up to %u.\n", filters_count, MAX_FILTERS);
        return false;
    }
    if ((offset + sizeof(sig_len)) > length) {
        return false;
    }
    sig_len = payload[offset++];
    if ((offset + sig_len) != length) {
        return false;
    }
    sig = &payload[offset];

    // Verification
    cx_sha256_t hash_ctx;
    if (!sig_verif_start(&hash_ctx, FILT_MAGIC_MESSAGE_INFO)) {
        return false;
    }
    hash_byte(filters_count, (cx_hash_t *) &hash_ctx);
    hash_nbytes((uint8_t *) name, sizeof(char) * name_len, (cx_hash_t *) &hash_ctx);
    if (!sig_verif_end(&hash_ctx, sig, sig_len)) {
        return false;
    }

    // Handling
    ui_712_set_filters_count(filters_count);
    if (!N_storage.verbose_tip712) {
        ui_712_set_title("Contract", 8);
        ui_712_set_value(name, name_len);
        ui_712_redraw_generic_step();
    }
    return true;
}

/**
 * Command to display a field as a date-time
 *
 * @param[in] payload the payload to parse
 * @param[in] length the payload length
 * @return whether it was successful or not
 */
bool filtering_date_time(const uint8_t *payload, uint8_t length) {
    uint8_t name_len;
    const char *name;
    uint8_t sig_len;
    const uint8_t *sig;
    uint8_t offset = 0;

    if (path_get_root_type() != ROOT_MESSAGE) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    // Parsing
    if ((offset + sizeof(name_len)) > length) {
        return false;
    }
    name_len = payload[offset++];
    if ((offset + name_len) > length) {
        return false;
    }
    name = (char *) &payload[offset];
    offset += name_len;
    if ((offset + sizeof(sig_len)) > length) {
        return false;
    }
    sig_len = payload[offset++];
    if ((offset + sig_len) != length) {
        return false;
    }
    sig = &payload[offset];

    // Verification
    cx_sha256_t hash_ctx;
    if (!sig_verif_start(&hash_ctx, FILT_MAGIC_DATETIME)) {
        return false;
    }
    hash_filtering_path((cx_hash_t *) &hash_ctx);
    hash_nbytes((uint8_t *) name, sizeof(char) * name_len, (cx_hash_t *) &hash_ctx);
    if (!sig_verif_end(&hash_ctx, sig, sig_len)) {
        return false;
    }

    // Handling
    if (!check_typename("uint")) {
        return false;
    }
    if (name_len > 0) {  // don't substitute for an empty name
        ui_712_set_title(name, name_len);
    }
    ui_712_flag_field(true, name_len > 0, false, true);
    return true;
}

/**
 * Command to display a field as an amount-join (token part)
 *
 * @param[in] payload the payload to parse
 * @param[in] length the payload length
 * @return whether it was successful or not
 */
bool filtering_amount_join_token(const uint8_t *payload, uint8_t length) {
    uint8_t token_idx;
    uint8_t sig_len;
    const uint8_t *sig;
    uint8_t offset = 0;

    if (path_get_root_type() != ROOT_MESSAGE) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    // Parsing
    if ((offset + sizeof(token_idx)) > length) {
        return false;
    }
    token_idx = payload[offset++];
    if ((offset + sizeof(sig_len)) > length) {
        return false;
    }
    sig_len = payload[offset++];
    if ((offset + sig_len) != length) {
        return false;
    }
    sig = &payload[offset];

    // Verification
    cx_sha256_t hash_ctx;
    if (!sig_verif_start(&hash_ctx, FILT_MAGIC_AMOUNT_JOIN_TOKEN)) {
        return false;
    }
    hash_filtering_path((cx_hash_t *) &hash_ctx);
    hash_byte(token_idx, (cx_hash_t *) &hash_ctx);
    if (!sig_verif_end(&hash_ctx, sig, sig_len)) {
        return false;
    }

    // Handling
    if (!check_typename("address") || !check_token_index(token_idx)) {
        return false;
    }
    ui_712_flag_field(false, false, true, false);
    ui_712_token_join_prepare_addr_check(token_idx);
    return true;
}

/**
 * Command to display a field as an amount-join (value part)
 *
 * @param[in] payload the payload to parse
 * @param[in] length the payload length
 * @return whether it was successful or not
 */
bool filtering_amount_join_value(const uint8_t *payload, uint8_t length) {
    uint8_t name_len;
    const char *name;
    uint8_t token_idx;
    uint8_t sig_len;
    const uint8_t *sig;
    uint8_t offset = 0;

    if (path_get_root_type() != ROOT_MESSAGE) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    // Parsing
    if ((offset + sizeof(name_len)) > length) {
        return false;
    }
    name_len = payload[offset++];
    if ((offset + name_len) > length) {
        return false;
    }
    if (name_len == 0) {
        return false;
    }
    name = (char *) &payload[offset];
    offset += name_len;
    if ((offset + sizeof(token_idx)) > length) {
        return false;
    }
    token_idx = payload[offset++];
    if ((offset + sizeof(sig_len)) > length) {
        return false;
    }
    sig_len = payload[offset++];
    if ((offset + sig_len) != length) {
        return false;
    }
    sig = &payload[offset];

    // Verification
    cx_sha256_t hash_ctx;
    if (!sig_verif_start(&hash_ctx, FILT_MAGIC_AMOUNT_JOIN_VALUE)) {
        return false;
    }
    hash_filtering_path((cx_hash_t *) &hash_ctx);
    hash_nbytes((uint8_t *) name, sizeof(char) * name_len, (cx_hash_t *) &hash_ctx);
    hash_byte(token_idx, (cx_hash_t *) &hash_ctx);
    if (!sig_verif_end(&hash_ctx, sig, sig_len)) {
        return false;
    }

    // Handling
    if (token_idx == TOKEN_IDX_ADDR_IN_DOMAIN) {
        // Permit (ERC-2612)
        int resolved_idx = get_asset_index_by_addr(tip712_context->contract_addr);

        if (resolved_idx == -1) {
            PRINTF("ERROR: Could not find asset info for verifyingContract address!\n");
            return false;
        }
        token_idx = (uint8_t) resolved_idx;
        // simulate as if we had received a token-join addr
        ui_712_token_join_prepare_addr_check(token_idx);
        amount_join_set_token_received();
    }
    if (!check_typename("uint") || !check_token_index(token_idx)) {
        return false;
    }
    ui_712_flag_field(false, false, true, false);
    ui_712_token_join_prepare_amount(token_idx, name, name_len);
    return true;
}

/**
 * Command to display a field raw (without formatting)
 *
 * @param[in] payload the payload to parse
 * @param[in] length the payload length
 * @return whether it was successful or not
 */
bool filtering_raw_field(const uint8_t *payload, uint8_t length) {
    uint8_t name_len;
    const char *name;
    uint8_t sig_len;
    const uint8_t *sig;
    uint8_t offset = 0;

    if (path_get_root_type() != ROOT_MESSAGE) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }

    // Parsing
    if ((offset + sizeof(name_len)) > length) {
        return false;
    }
    name_len = payload[offset++];
    if ((offset + name_len) > length) {
        return false;
    }
    name = (char *) &payload[offset];
    offset += name_len;
    if ((offset + sizeof(sig_len)) > length) {
        return false;
    }
    sig_len = payload[offset++];
    if ((offset + sig_len) != length) {
        return false;
    }
    sig = &payload[offset];

    // Verification
    cx_sha256_t hash_ctx;
    if (!sig_verif_start(&hash_ctx, FILT_MAGIC_RAW_FIELD)) {
        return false;
    }
    hash_filtering_path((cx_hash_t *) &hash_ctx);
    hash_nbytes((uint8_t *) name, sizeof(char) * name_len, (cx_hash_t *) &hash_ctx);
    if (!sig_verif_end(&hash_ctx, sig, sig_len)) {
        return false;
    }

    // Handling
    if (name_len > 0) {  // don't substitute for an empty name
        ui_712_set_title(name, name_len);
    }
    ui_712_flag_field(true, name_len > 0, false, false);
    return true;
}

#endif  // HAVE_TIP712_FULL_SUPPORT
