#include <ctype.h>
#include "app_mem_utils.h"
#include "trusted_name.h"
#include "utils.h"
#include "read.h"
#include "challenge.h"
#include "hash_bytes.h"
#include "public_keys.h"
#include "helpers.h"

#define STRUCT_VERSION_1 0x01
#define STRUCT_VERSION_2 0x02

#define STRUCT_TYPE_TRUSTED_NAME 0x03
#define SIG_ALGO_SECP256K1       0x01
#define SLIP_44_ETHEREUM         60

static s_trusted_name *g_trusted_name_list = NULL;

static void delete_trusted_name(s_trusted_name *node) {
    APP_MEM_FREE(node);
}

bool has_trusted_name(void) {
    return g_trusted_name_list != NULL;
}

void trusted_name_cleanup(void) {
    while (g_trusted_name_list != NULL) {
        s_trusted_name *next = g_trusted_name_list->next;
        delete_trusted_name(g_trusted_name_list);
        g_trusted_name_list = next;
    }
}

static bool is_supported_v2_type(e_name_type type) {
    switch (type) {
        case TN_TYPE_ACCOUNT:
        case TN_TYPE_CONTRACT:
        case TN_TYPE_TOKEN:
            return true;
        default:
            return false;
    }
}

static bool is_supported_v2_source(e_name_source source) {
    switch (source) {
        case TN_SOURCE_CAL:
        case TN_SOURCE_ENS:
        case TN_SOURCE_MAB:
            return true;
        default:
            return false;
    }
}

static bool requires_ens_name_validation(const s_trusted_name *trusted_name) {
    if (trusted_name == NULL) {
        return false;
    }

    if (trusted_name->struct_version == 1U) {
        return true;
    }

    return (trusted_name->struct_version == 2U) &&
           (trusted_name->name_type == TN_TYPE_ACCOUNT) &&
           (trusted_name->name_source == TN_SOURCE_ENS);
}

static bool matching_type(e_name_type type, uint8_t type_count, const e_name_type *types) {
    for (int i = 0; i < type_count; ++i) {
        if (type == types[i]) return true;
    }
    return false;
}

static bool matching_source(e_name_source source,
                            uint8_t source_count,
                            const e_name_source *sources) {
    for (int i = 0; i < source_count; ++i) {
        if (source == sources[i]) return true;
    }
    return false;
}

static bool matching_trusted_name(const s_trusted_name *trusted_name,
                                  uint8_t type_count,
                                  const e_name_type *types,
                                  uint8_t source_count,
                                  const e_name_source *sources,
                                  const uint64_t *chain_id,
                                  const uint8_t *addr) {
    // const uint8_t *tmp;

    switch (trusted_name->struct_version) {
        case STRUCT_VERSION_1:
            if (!matching_type(TN_TYPE_ACCOUNT, type_count, types)) {
                return false;
            }
            // TODO. Always true for Tron now.
            /*if (!chain_is_ethereum_compatible(chain_id)) {
                return false;
            }*/
            break;
        case STRUCT_VERSION_2:
            if (!matching_type(trusted_name->name_type, type_count, types)) {
                return false;
            }
            if (!matching_source(trusted_name->name_source, source_count, sources)) {
                return false;
            }
            if (*chain_id != trusted_name->chain_id) {
                return false;
            }

            /* if (trusted_name->name_type == TN_TYPE_CONTRACT) {
                if ((tmp = get_implem_contract(chain_id, addr, NULL)) != NULL) {
                    addr = tmp;
                }
            } */ // TODO. Not support INS_PROVIDE_PROXY_INFO yet.
            break;
    }
    return memcmp(addr, trusted_name->addr, ADDRESS_LENGTH) == 0;
}

/**
 * Checks if a trusted name matches the given parameters
 *
 * @param[in] types_count number of given trusted name types
 * @param[in] types given trusted name types
 * @param[in] chain_id given chain ID
 * @param[in] addr given address
 * @return whether there is or not
 */
const s_trusted_name *get_trusted_name(uint8_t type_count,
                                       const e_name_type *types,
                                       uint8_t source_count,
                                       const e_name_source *sources,
                                       const uint64_t *chain_id,
                                       const uint8_t *addr) {
    for (s_trusted_name *node = g_trusted_name_list; node != NULL; node = node->next) {
        if (matching_trusted_name(node,
                                  type_count,
                                  types,
                                  source_count,
                                  sources,
                                  chain_id,
                                  addr)) {
            return node;
        }
    }

    return NULL;
}

/**
 * Handler for tag \ref STRUCT_TYPE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool tlv_check_struct_type(const tlv_data_t *data, uint8_t expected) {
    if ((data == NULL) || (data->value.size != sizeof(uint8_t))) {
        return false;
    }
    return data->value.ptr[0] == expected;
}

static bool handle_struct_type(const tlv_data_t *data, s_trusted_name_ctx *context) {
    UNUSED(context);
    return tlv_check_struct_type(data, STRUCT_TYPE_TRUSTED_NAME);
}

/**
 * Handler for tag \ref NOT_VALID_AFTER
 *
 * @param[in] data the tlv data
 * @param[] context the trusted name context
 * @return whether it was successful
 */
static bool handle_not_valid_after(const tlv_data_t *data, s_trusted_name_ctx *context) {
    const uint8_t app_version[] = {MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION};

    UNUSED(context);
    if (data->value.size != ARRAYLEN(app_version)) {
        return false;
    }
    for (int i = 0; i < (int) ARRAYLEN(app_version); ++i) {
        if (data->value.ptr[i] > app_version[i]) {
            break;
        } else if (data->value.ptr[i] < app_version[i]) {
            PRINTF("Expired trusted name : %u.%u.%u < %u.%u.%u\n",
                   data->value.ptr[0],
                   data->value.ptr[1],
                   data->value.ptr[2],
                   app_version[0],
                   app_version[1],
                   app_version[2]);
            return false;
        }
    }
    return true;
}

/**
 * Handler for tag \ref STRUCT_VERSION
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_struct_version(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size != sizeof(context->trusted_name.struct_version)) {
        return false;
    }
    context->trusted_name.struct_version = data->value.ptr[0];
    return true;
}

/**
 * Handler for tag \ref CHALLENGE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_challenge(const tlv_data_t *data, s_trusted_name_ctx *context) {
    uint8_t buf[sizeof(uint32_t)];

    UNUSED(context);
    if (data->value.size > sizeof(buf)) {
        return false;
    }
    buf_shrink_expand(data->value.ptr, data->value.size, buf, sizeof(buf));
    return (read_u32_be(buf, 0) == get_challenge());
}

/**
 * Handler for tag \ref SIGNER_KEY_ID
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_signer_key_id(const tlv_data_t *data, s_trusted_name_ctx *context) {
    // for some reason this is sent as 2 bytes
    uint16_t value;
    uint8_t buf[sizeof(value)];

    if (data->value.size > sizeof(buf)) {
        return false;
    }
    buf_shrink_expand(data->value.ptr, data->value.size, buf, sizeof(buf));
    value = read_u16_be(buf, 0);
    if (value > UINT8_MAX) {
        return false;
    }
    context->key_id = value;
    return true;
}

/**
 * Handler for tag \ref SIGNER_ALGO
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_signer_algo(const tlv_data_t *data, s_trusted_name_ctx *context) {
    // for some reason this is sent as 2 bytes
    uint8_t buf[sizeof(uint16_t)];

    UNUSED(context);
    if (data->value.size > sizeof(buf)) {
        return false;
    }
    buf_shrink_expand(data->value.ptr, data->value.size, buf, sizeof(buf));
    return (read_u16_be(buf, 0) == SIG_ALGO_SECP256K1);
}

/**
 * Handler for tag \ref SIGNATURE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_signature(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if ((data->value.size == 0U) || (data->value.size > ECDSA_SIGNATURE_MAX_LENGTH)) {
        return false;
    }
    context->sig_size = data->value.size;
    context->sig = data->value.ptr;
    return true;
}

/**
 * Tests if the given account name character is valid (in our subset of allowed characters)
 *
 * @param[in] c given character
 * @return whether the character is valid
 */
static bool is_valid_account_character(char c) {
    if (isalpha((int) c)) {
        if (!islower((int) c)) {
            return false;
        }
    } else if (!isdigit((int) c)) {
        switch (c) {
            case '.':
            case '-':
            case '_':
                break;
            default:
                return false;
        }
    }
    return true;
}

static bool is_valid_generic_character(char c) {
    if (isalnum((int) c)) {
        return true;
    }

    switch (c) {
        case '.':
        case '-':
        case '_':
        case ' ':
            return true;
        default:
            return false;
    }
}

static bool validate_trusted_name_value(const s_trusted_name *trusted_name) {
    size_t name_len;

    if (trusted_name == NULL) {
        return false;
    }

    name_len = strnlen(trusted_name->name, sizeof(trusted_name->name));
    if ((name_len == 0U) || (name_len > TRUSTED_NAME_MAX_LENGTH)) {
        return false;
    }

    if (requires_ens_name_validation(trusted_name)) {
        if ((name_len < 5U) || (strncmp(".eth", &trusted_name->name[name_len - 4U], 4U) != 0)) {
            PRINTF("Unexpected TLD!\n");
            return false;
        }
        for (size_t idx = 0; idx < name_len; idx++) {
            if (!is_valid_account_character(trusted_name->name[idx])) {
                PRINTF("Domain name contains non-allowed character! (0x%x)\n",
                       trusted_name->name[idx]);
                return false;
            }
        }
        return true;
    }

    for (size_t idx = 0; idx < name_len; idx++) {
        if (!is_valid_generic_character(trusted_name->name[idx])) {
            PRINTF("Trusted name contains non-allowed character! (0x%x)\n",
                   trusted_name->name[idx]);
            return false;
        }
    }
    return true;
}

/**
 * Handler for tag \ref TRUSTED_NAME
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_trusted_name(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size > TRUSTED_NAME_MAX_LENGTH) {
        PRINTF("Domain name too long! (%u)\n", data->value.size);
        return false;
    }
    memcpy(context->trusted_name.name, data->value.ptr, data->value.size);
    context->trusted_name.name[data->value.size] = '\0';
    return true;
}

/**
 * Handler for tag \ref COIN_TYPE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_coin_type(const tlv_data_t *data, s_trusted_name_ctx *context) {
    UNUSED(context);
    if (data->value.size != sizeof(uint8_t)) {
        return false;
    }
    return (data->value.ptr[0] == SLIP_44_ETHEREUM);
}

/**
 * Handler for tag \ref ADDRESS
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_address(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size != ADDRESS_LENGTH) {
        return false;
    }
    memcpy(context->trusted_name.addr, data->value.ptr, ADDRESS_LENGTH);
    return true;
}

/**
 * Handler for tag \ref CHAIN_ID
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_chain_id(const tlv_data_t *data, s_trusted_name_ctx *context) {
    context->trusted_name.chain_id = u64_from_BE(data->value.ptr, data->value.size);
    return true;
}

/**
 * Handler for tag \ref TRUSTED_NAME_TYPE
 *
 * @param[in] data the tlv data
 * @param[in,out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_trusted_name_type(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size != sizeof(e_name_type)) {
        return false;
    }
    context->trusted_name.name_type = data->value.ptr[0];
    if (!is_supported_v2_type(context->trusted_name.name_type)) {
        PRINTF("Error: unsupported trusted name type (%u)!\n", context->trusted_name.name_type);
        return false;
    }
    return true;
}

/**
 * Handler for tag \ref TRUSTED_NAME_SOURCE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_trusted_name_source(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size != sizeof(e_name_source)) {
        return false;
    }
    context->trusted_name.name_source = data->value.ptr[0];
    if (!is_supported_v2_source(context->trusted_name.name_source)) {
        PRINTF("Error: unsupported trusted name source (%u)!\n",
               context->trusted_name.name_source);
        return false;
    }
    return true;
}

static bool handle_owner(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size != ADDRESS_LENGTH) {
        return false;
    }

    memcpy(context->owner, data->value.ptr, ADDRESS_LENGTH);
    return true;
}

static bool handle_owner_deriv_path(const tlv_data_t *data, s_trusted_name_ctx *context) {
    off_t parsed = read_bip32_path(data->value.ptr, data->value.size, &context->owner_deriv_path);

    if ((parsed < 0) || ((uint16_t) parsed != data->value.size)) {
        return false;
    }
    return true;
}

/**
 * Handler for tag \ref NFT_ID
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_nft_id(const tlv_data_t *data, s_trusted_name_ctx *context) {
    if (data->value.size > sizeof(context->trusted_name.nft_id)) {
        return false;
    }
    buf_shrink_expand(data->value.ptr,
                      data->value.size,
                      context->trusted_name.nft_id,
                      sizeof(context->trusted_name.nft_id));
    return true;  // unhandled for now
}

// Define TLV tags and their handlers using X-macro pattern
#define TRUSTED_NAME_TAGS(X)                                                         \
    X(0x01, TAG_STRUCTURE_TYPE, handle_struct_type, ENFORCE_UNIQUE_TAG)              \
    X(0x02, TAG_STRUCTURE_VERSION, handle_struct_version, ENFORCE_UNIQUE_TAG)        \
    X(0x10, TAG_NOT_VALID_AFTER, handle_not_valid_after, ENFORCE_UNIQUE_TAG)         \
    X(0x12, TAG_CHALLENGE, handle_challenge, ENFORCE_UNIQUE_TAG)                     \
    X(0x13, TAG_SIGNER_KEY_ID, handle_signer_key_id, ENFORCE_UNIQUE_TAG)             \
    X(0x14, TAG_SIGNER_ALGO, handle_signer_algo, ENFORCE_UNIQUE_TAG)                 \
    X(0x20, TAG_TRUSTED_NAME, handle_trusted_name, ENFORCE_UNIQUE_TAG)               \
    X(0x21, TAG_COIN_TYPE, handle_coin_type, ENFORCE_UNIQUE_TAG)                     \
    X(0x22, TAG_ADDRESS, handle_address, ENFORCE_UNIQUE_TAG)                         \
    X(0x23, TAG_CHAIN_ID, handle_chain_id, ENFORCE_UNIQUE_TAG)                       \
    X(0x70, TAG_TRUSTED_NAME_TYPE, handle_trusted_name_type, ENFORCE_UNIQUE_TAG)     \
    X(0x71, TAG_TRUSTED_NAME_SOURCE, handle_trusted_name_source, ENFORCE_UNIQUE_TAG) \
    X(0x72, TAG_NFT_ID, handle_nft_id, ENFORCE_UNIQUE_TAG)                           \
    X(0x73, TAG_OWNER, handle_owner, ENFORCE_UNIQUE_TAG)                             \
    X(0x74, TAG_OWNER_DERIV_PATH, handle_owner_deriv_path, ENFORCE_UNIQUE_TAG)       \
    X(0x15, TAG_DER_SIGNATURE, handle_signature, ENFORCE_UNIQUE_TAG)

// Forward declaration
static bool trusted_name_common_handler(const tlv_data_t *data, s_trusted_name_ctx *context);

// Generate parser from X-macro
DEFINE_TLV_PARSER(TRUSTED_NAME_TAGS, &trusted_name_common_handler, parse_tlv_trusted_name)

/**
 * Common handler called for all tags to hash them (except signature)
 *
 * @param[in] data the TLV data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool trusted_name_common_handler(const tlv_data_t *data, s_trusted_name_ctx *context) {
    // Hash everything except signature (tag 0x15)
    if (data->tag != TAG_DER_SIGNATURE) {
        hash_nbytes(data->raw.ptr, data->raw.size, (cx_hash_t *) &context->hash_ctx);
    }
    return true;
}

/**
 * Wrapper function to integrate with existing code
 *
 * @param[in] payload the input buffer containing TLV data
 * @param[out] context the trusted name context
 * @return whether parsing was successful
 */
bool handle_trusted_name_tlv_payload(const buffer_t *payload, s_trusted_name_ctx *context) {
    return parse_tlv_trusted_name(payload, context, &context->received_tags);
}

/**
 * Verify the signature context
 *
 * Verify the SHA-256 hash of the payload against the public key
 *
 * @param[in] context the trusted name context
 * @return whether it was successful
 */
static bool verify_signature(const s_trusted_name_ctx *context) {
    uint8_t hash[INT256_LENGTH];
    const uint8_t *pk;
    size_t pk_size;

    switch (context->key_id) {
        case TN_KEY_ID_DOMAIN_SVC:
            pk = TRUSTED_NAME_PUB_KEY;
            pk_size = sizeof(TRUSTED_NAME_PUB_KEY);
            break;
        case TN_KEY_ID_CAL:
            pk = LEDGER_SIGNATURE_PUBLIC_KEY;
            pk_size = sizeof(LEDGER_SIGNATURE_PUBLIC_KEY);
            break;
        default:
            PRINTF("Error: Unknown metadata key ID %u\n", context->key_id);
            return false;
    }

    if (cx_hash_no_throw((cx_hash_t *) &context->hash_ctx, CX_LAST, NULL, 0, hash, INT256_LENGTH) !=
        CX_OK) {
        return false;
    }

    if (check_signature_with_pubkey("Trusted Name",
                                    hash,
                                    sizeof(hash),
                                    pk,
                                    pk_size,
                                    CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME,
                                    (uint8_t *) context->sig,
                                    context->sig_size) != CX_OK) {
        return false;
    }
    return true;
}

static bool verify_mab_owner(const s_trusted_name_ctx *context) {
    bip32_path_t owner_path;
    publicKeyContext_t public_key_context = {0};
    char owner_address58[BASE58CHECK_ADDRESS_SIZE + 1] = {0};
    uint8_t owner_address[ADDRESS_SIZE];

    if (context == NULL) {
        return false;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags, TAG_OWNER, TAG_OWNER_DERIV_PATH)) {
        PRINTF("Error: MAB trusted name requires owner metadata!\n");
        return false;
    }

    owner_path = context->owner_deriv_path;

    if (initPublicKeyContext(&owner_path, owner_address58, &public_key_context) < 0) {
        PRINTF("Error: failed to derive MAB owner public key!\n");
        return false;
    }

    getAddressFromPublicKey(public_key_context.publicKey, owner_address);
    if (memcmp(owner_address + 1, context->owner, ADDRESS_LENGTH) != 0) {
        PRINTF("Error: MAB owner does not match derivation path!\n");
        return false;
    }

    return true;
}

static bool verify_fields(const s_trusted_name_ctx *context) {
    if (context == NULL) {
        return false;
    }

    if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags, TAG_STRUCTURE_VERSION)) {
        PRINTF("Error: no struct version specified!\n");
        return false;
    }

    switch (context->trusted_name.struct_version) {
        case STRUCT_VERSION_1:
            if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags,
                                         TAG_STRUCTURE_TYPE,
                                         TAG_STRUCTURE_VERSION,
                                         TAG_SIGNER_KEY_ID,
                                         TAG_SIGNER_ALGO,
                                         TAG_DER_SIGNATURE,
                                         TAG_TRUSTED_NAME,
                                         TAG_ADDRESS,
                                         TAG_CHALLENGE,
                                         TAG_COIN_TYPE)) {
                PRINTF("Error: Missing mandatory fields in descriptor!\n");
                return false;
            }
            break;

        case STRUCT_VERSION_2:
            if (!TLV_CHECK_RECEIVED_TAGS(context->received_tags,
                                         TAG_STRUCTURE_TYPE,
                                         TAG_STRUCTURE_VERSION,
                                         TAG_SIGNER_KEY_ID,
                                         TAG_SIGNER_ALGO,
                                         TAG_DER_SIGNATURE,
                                         TAG_TRUSTED_NAME,
                                         TAG_ADDRESS,
                                         TAG_CHAIN_ID,
                                         TAG_TRUSTED_NAME_TYPE,
                                         TAG_TRUSTED_NAME_SOURCE)) {
                PRINTF("Error: Missing mandatory fields in descriptor!\n");
                return false;
            }
            if ((context->trusted_name.name_type == TN_TYPE_ACCOUNT) &&
                !TLV_CHECK_RECEIVED_TAGS(context->received_tags, TAG_CHALLENGE)) {
                PRINTF("Error: trusted account name requires a challenge!\n");
                return false;
            }
            if ((context->trusted_name.name_source == TN_SOURCE_MAB) &&
                !TLV_CHECK_RECEIVED_TAGS(context->received_tags,
                                         TAG_OWNER,
                                         TAG_OWNER_DERIV_PATH)) {
                PRINTF("Error: MAB trusted name requires owner metadata!\n");
                return false;
            }
            break;

        default:
            PRINTF("Error: unsupported trusted name struct version (%u) !\n",
                   context->trusted_name.struct_version);
            return false;
    }

    return true;
}

static void print_trusted_name_info(const s_trusted_name_ctx *context) {
    if (context == NULL) {
        return;
    }

    PRINTF("Registered : %s => %.*h\n",
           context->trusted_name.name,
           ADDRESS_LENGTH,
           context->trusted_name.addr);
}

/**
 * Verify the validity of the received trusted struct
 *
 * @param[in] context the trusted name context
 * @return whether the struct is valid
 */
bool verify_trusted_name_struct(const s_trusted_name_ctx *context) {
    s_trusted_name *node = NULL;

    if (!verify_fields(context)) {
        return false;
    }

    if (!validate_trusted_name_value(&context->trusted_name)) {
        return false;
    }

    if (context->trusted_name.struct_version == STRUCT_VERSION_2) {
        switch (context->trusted_name.name_type) {
            case TN_TYPE_ACCOUNT:
                if ((context->trusted_name.name_source != TN_SOURCE_ENS) &&
                    (context->trusted_name.name_source != TN_SOURCE_MAB)) {
                    PRINTF("Error: cannot accept an account name from given source (%u)!\n",
                           context->trusted_name.name_source);
                    return false;
                }
                if ((context->trusted_name.name_source == TN_SOURCE_MAB) &&
                    !verify_mab_owner(context)) {
                    return false;
                }
                break;
            case TN_TYPE_CONTRACT:
            case TN_TYPE_TOKEN:
                if (context->trusted_name.name_source != TN_SOURCE_CAL) {
                    PRINTF("Error: cannot accept this trusted name type from given source (%u)!\n",
                           context->trusted_name.name_source);
                    return false;
                }
                break;
            default:
                return false;
        }
    }

    if (!verify_signature(context)) {
        return false;
    }

    if ((node = APP_MEM_ALLOC(sizeof(*node))) == NULL) {
        PRINTF("Error: could not allocate trusted name struct!\n");
        return false;
    }
    memcpy(node, &context->trusted_name, sizeof(*node));
    node->next = NULL;

    if (g_trusted_name_list == NULL) {
        g_trusted_name_list = node;
    } else {
        s_trusted_name *tail = g_trusted_name_list;

        while (tail->next != NULL) {
            tail = tail->next;
        }
        tail->next = node;
    }

    print_trusted_name_info(context);
    return true;
}
