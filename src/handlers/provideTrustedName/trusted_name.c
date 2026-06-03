#include <ctype.h>
#include "app_mem_utils.h"
#include "trusted_name.h"
#include "utils.h"  // SET_BIT
#include "read.h"
#include "challenge.h"
#include "hash_bytes.h"
#include "public_keys.h"
#include "helpers.h"
#include "bip32_path_parser.h"

typedef enum { STRUCT_TYPE_TRUSTED_NAME = 0x03 } e_struct_type;

typedef enum { SIG_ALGO_SECP256K1 = 0x01 } e_sig_algo;

typedef enum {
    SLIP_44_ETHEREUM = 60,
} e_coin_type;

// This enum needs to be ordered the same way as the e_tlv_tag one !
typedef enum {
    STRUCT_TYPE_RCV_BIT = 0,
    STRUCT_VERSION_RCV_BIT,
    NOT_VALID_AFTER_RCV_BIT,
    CHALLENGE_RCV_BIT,
    SIGNER_KEY_ID_RCV_BIT,
    SIGNER_ALGO_RCV_BIT,
    SIGNATURE_RCV_BIT,
    TRUSTED_NAME_RCV_BIT,
    COIN_TYPE_RCV_BIT,
    ADDRESS_RCV_BIT,
    CHAIN_ID_RCV_BIT,
    TRUSTED_NAME_TYPE_RCV_BIT,
    TRUSTED_NAME_SOURCE_RCV_BIT,
    NFT_ID_RCV_BIT,
    OWNER_RCV_BIT,
    OWNER_DERIV_PATH_RCV_BIT,
} e_tlv_rcv_bit;

typedef enum {
    STRUCT_TYPE = 0x01,
    STRUCT_VERSION = 0x02,
    NOT_VALID_AFTER = 0x10,
    CHALLENGE = 0x12,
    SIGNER_KEY_ID = 0x13,
    SIGNER_ALGO = 0x14,
    SIGNATURE = 0x15,
    TRUSTED_NAME = 0x20,
    COIN_TYPE = 0x21,
    ADDRESS = 0x22,
    CHAIN_ID = 0x23,
    TRUSTED_NAME_TYPE = 0x70,
    TRUSTED_NAME_SOURCE = 0x71,
    NFT_ID = 0x72,
    OWNER = 0x73,
    OWNER_DERIV_PATH = 0x74,
} e_tlv_tag;

static s_trusted_name_info *g_trusted_name_list = NULL;
char g_trusted_name[TRUSTED_NAME_MAX_LENGTH + 1];

bool has_trusted_name(void) {
    return g_trusted_name_list != NULL;
}

void clear_trusted_names(void) {
    while (g_trusted_name_list != NULL) {
        s_trusted_name_info *next = g_trusted_name_list->next;
        APP_MEM_FREE(g_trusted_name_list);
        g_trusted_name_list = next;
    }
    memset(g_trusted_name, 0, sizeof(g_trusted_name));
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

static bool requires_ens_name_validation(const s_trusted_name_info *trusted_name) {
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

static bool register_trusted_name(const s_trusted_name_info *trusted_name) {
    s_trusted_name_info *node;

    if (trusted_name == NULL) {
        return false;
    }

    for (node = g_trusted_name_list; node != NULL; node = node->next) {
        if ((node->struct_version == trusted_name->struct_version) &&
            (node->chain_id == trusted_name->chain_id) &&
            (node->name_type == trusted_name->name_type) &&
            (node->name_source == trusted_name->name_source) &&
            (memcmp(node->addr, trusted_name->addr, ADDRESS_LENGTH) == 0)) {
            s_trusted_name_info *next = node->next;
            *node = *trusted_name;
            node->next = next;
            return true;
        }
    }

    if ((node = APP_MEM_ALLOC(sizeof(*node))) == NULL) {
        PRINTF("Error: could not allocate trusted name struct!\n");
        return false;
    }

    *node = *trusted_name;
    node->next = g_trusted_name_list;
    g_trusted_name_list = node;
    return true;
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

static bool matching_trusted_name(const s_trusted_name_info *trusted_name,
                                  uint8_t type_count,
                                  const e_name_type *types,
                                  uint8_t source_count,
                                  const e_name_source *sources,
                                  const uint64_t *chain_id,
                                  const uint8_t *addr) {
    // const uint8_t *tmp;

    switch (trusted_name->struct_version) {
        case 1:
            if (!matching_type(TN_TYPE_ACCOUNT, type_count, types)) {
                return false;
            }
            // TODO. Always true for Tron now.
            /*if (!chain_is_ethereum_compatible(chain_id)) {
                return false;
            }*/
            break;
        case 2:
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
const char *get_trusted_name(uint8_t type_count,
                             const e_name_type *types,
                             uint8_t source_count,
                             const e_name_source *sources,
                             const uint64_t *chain_id,
                             const uint8_t *addr) {
    for (s_trusted_name_info *node = g_trusted_name_list; node != NULL; node = node->next) {
        if (matching_trusted_name(node,
                                  type_count,
                                  types,
                                  source_count,
                                  sources,
                                  chain_id,
                                  addr)) {
            strlcpy(g_trusted_name, node->name, sizeof(g_trusted_name));
            return g_trusted_name;
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
static bool handle_struct_type(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != sizeof(e_struct_type)) {
        return false;
    }
    context->rcv_flags |= SET_BIT(STRUCT_TYPE_RCV_BIT);
    return (data->value[0] == STRUCT_TYPE_TRUSTED_NAME);
}

/**
 * Handler for tag \ref NOT_VALID_AFTER
 *
 * @param[in] data the tlv data
 * @param[] context the trusted name context
 * @return whether it was successful
 */
static bool handle_not_valid_after(const s_tlv_data *data, s_trusted_name_ctx *context) {
    const uint8_t app_version[] = {MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION};

    (void) context;
    if (data->length != ARRAYLEN(app_version)) {
        return false;
    }
    for (int i = 0; i < (int) ARRAYLEN(app_version); ++i) {
        if (data->value[i] > app_version[i]) {
            break;
        } else if (data->value[i] < app_version[i]) {
            PRINTF("Expired trusted name : %u.%u.%u < %u.%u.%u\n",
                   data->value[0],
                   data->value[1],
                   data->value[2],
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
static bool handle_struct_version(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != sizeof(context->trusted_name.struct_version)) {
        return false;
    }
    context->trusted_name.struct_version = data->value[0];
    context->rcv_flags |= SET_BIT(STRUCT_VERSION_RCV_BIT);
    return true;
}

/**
 * Handler for tag \ref CHALLENGE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_challenge(const s_tlv_data *data, s_trusted_name_ctx *context) {
    uint8_t buf[sizeof(uint32_t)];

    if (data->length > sizeof(buf)) {
        return false;
    }
    buf_shrink_expand(data->value, data->length, buf, sizeof(buf));
    context->rcv_flags |= SET_BIT(CHALLENGE_RCV_BIT);
    return (read_u32_be(buf, 0) == get_challenge());
}

/**
 * Handler for tag \ref SIGNER_KEY_ID
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_sign_key_id(const s_tlv_data *data, s_trusted_name_ctx *context) {
    // for some reason this is sent as 2 bytes
    uint16_t value;
    uint8_t buf[sizeof(value)];

    if (data->length > sizeof(buf)) {
        return false;
    }
    buf_shrink_expand(data->value, data->length, buf, sizeof(buf));
    value = read_u16_be(buf, 0);
    if (value > UINT8_MAX) {
        return false;
    }
    context->key_id = value;
    context->rcv_flags |= SET_BIT(SIGNER_KEY_ID_RCV_BIT);
    return true;
}

/**
 * Handler for tag \ref SIGNER_ALGO
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_sign_algo(const s_tlv_data *data, s_trusted_name_ctx *context) {
    // for some reason this is sent as 2 bytes
    uint8_t buf[sizeof(uint16_t)];

    if (data->length > sizeof(buf)) {
        return false;
    }
    buf_shrink_expand(data->value, data->length, buf, sizeof(buf));
    context->rcv_flags |= SET_BIT(SIGNER_ALGO_RCV_BIT);
    return (read_u16_be(buf, 0) == SIG_ALGO_SECP256K1);
}

/**
 * Handler for tag \ref SIGNATURE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_signature(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length > sizeof(context->input_sig)) {
        return false;
    }
    context->input_sig_size = data->length;
    memcpy(context->input_sig, data->value, data->length);
    context->rcv_flags |= SET_BIT(SIGNATURE_RCV_BIT);
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

static bool validate_trusted_name_value(const s_trusted_name_info *trusted_name) {
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
static bool handle_trusted_name(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length > TRUSTED_NAME_MAX_LENGTH) {
        PRINTF("Domain name too long! (%u)\n", data->length);
        return false;
    }
    memcpy(context->trusted_name.name, data->value, data->length);
    context->trusted_name.name[data->length] = '\0';
    context->rcv_flags |= SET_BIT(TRUSTED_NAME_RCV_BIT);
    return true;
}

/**
 * Handler for tag \ref COIN_TYPE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_coin_type(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != sizeof(e_coin_type)) {
        return false;
    }
    context->rcv_flags |= SET_BIT(COIN_TYPE_RCV_BIT);
    return (data->value[0] == SLIP_44_ETHEREUM);
}

/**
 * Handler for tag \ref ADDRESS
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_address(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != ADDRESS_LENGTH) {
        return false;
    }
    memcpy(context->trusted_name.addr, data->value, ADDRESS_LENGTH);
    context->rcv_flags |= SET_BIT(ADDRESS_RCV_BIT);
    return true;
}

/**
 * Handler for tag \ref CHAIN_ID
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_chain_id(const s_tlv_data *data, s_trusted_name_ctx *context) {
    context->trusted_name.chain_id = u64_from_BE(data->value, data->length);
    context->rcv_flags |= SET_BIT(CHAIN_ID_RCV_BIT);
    return true;
}

/**
 * Handler for tag \ref TRUSTED_NAME_TYPE
 *
 * @param[in] data the tlv data
 * @param[in,out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_trusted_name_type(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != sizeof(e_name_type)) {
        return false;
    }
    context->trusted_name.name_type = data->value[0];
    if (!is_supported_v2_type(context->trusted_name.name_type)) {
        PRINTF("Error: unsupported trusted name type (%u)!\n", context->trusted_name.name_type);
        return false;
    }
    context->rcv_flags |= SET_BIT(TRUSTED_NAME_TYPE_RCV_BIT);
    return true;
}

/**
 * Handler for tag \ref TRUSTED_NAME_SOURCE
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_trusted_name_source(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != sizeof(e_name_source)) {
        return false;
    }
    context->trusted_name.name_source = data->value[0];
    if (!is_supported_v2_source(context->trusted_name.name_source)) {
        PRINTF("Error: unsupported trusted name source (%u)!\n",
               context->trusted_name.name_source);
        return false;
    }
    context->rcv_flags |= SET_BIT(TRUSTED_NAME_SOURCE_RCV_BIT);
    return true;
}

static bool handle_owner(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length != ADDRESS_LENGTH) {
        return false;
    }

    memcpy(context->owner, data->value, ADDRESS_LENGTH);
    context->rcv_flags |= SET_BIT(OWNER_RCV_BIT);
    return true;
}

static bool handle_owner_deriv_path(const s_tlv_data *data, s_trusted_name_ctx *context) {
    off_t parsed = read_bip32_path_words(data->value,
                                         data->length,
                                         &context->owner_deriv_path_length,
                                         context->owner_deriv_path,
                                         TRUSTED_NAME_OWNER_MAX_BIP32_PATH);

    if ((parsed < 0) || ((uint16_t) parsed != data->length)) {
        return false;
    }

    context->rcv_flags |= SET_BIT(OWNER_DERIV_PATH_RCV_BIT);
    return true;
}

#ifdef HAVE_NFT_SUPPORT
/**
 * Handler for tag \ref NFT_ID
 *
 * @param[in] data the tlv data
 * @param[out] context the trusted name context
 * @return whether it was successful
 */
static bool handle_nft_id(const s_tlv_data *data, s_trusted_name_ctx *context) {
    if (data->length > sizeof(context->trusted_name.nft_id)) {
        return false;
    }
    buf_shrink_expand(data->value,
                      data->length,
                      context->trusted_name.nft_id,
                      sizeof(context->trusted_name.nft_id));
    context->rcv_flags |= SET_BIT(NFT_ID_RCV_BIT);
    return true;  // unhandled for now
}
#endif

bool handle_trusted_name_struct(const s_tlv_data *data, s_trusted_name_ctx *context) {
    bool ret;

    (void) context;
    switch (data->tag) {
        case STRUCT_TYPE:
            ret = handle_struct_type(data, context);
            break;
        case STRUCT_VERSION:
            ret = handle_struct_version(data, context);
            break;
        case NOT_VALID_AFTER:
            ret = handle_not_valid_after(data, context);
            break;
        case CHALLENGE:
            ret = handle_challenge(data, context);
            break;
        case SIGNER_KEY_ID:
            ret = handle_sign_key_id(data, context);
            break;
        case SIGNER_ALGO:
            ret = handle_sign_algo(data, context);
            break;
        case SIGNATURE:
            ret = handle_signature(data, context);
            break;
        case TRUSTED_NAME:
            ret = handle_trusted_name(data, context);
            break;
        case COIN_TYPE:
            ret = handle_coin_type(data, context);
            break;
        case ADDRESS:
            ret = handle_address(data, context);
            break;
        case CHAIN_ID:
            ret = handle_chain_id(data, context);
            break;
        case TRUSTED_NAME_TYPE:
            ret = handle_trusted_name_type(data, context);
            break;
        case TRUSTED_NAME_SOURCE:
            ret = handle_trusted_name_source(data, context);
            break;
        case OWNER:
            ret = handle_owner(data, context);
            break;
        case OWNER_DERIV_PATH:
            ret = handle_owner_deriv_path(data, context);
            break;
#ifdef HAVE_NFT_SUPPORT
        case NFT_ID:
            ret = handle_nft_id(data, context);
            break;
#endif
        default:
            PRINTF(TLV_TAG_ERROR_MSG, data->tag);
            ret = false;
    }
    if (ret && (data->tag != SIGNATURE)) {
        hash_nbytes(data->raw, data->raw_size, (cx_hash_t *) &context->hash_ctx);
    }
    return ret;
}

/**
 * Verify the signature context
 *
 * Verify the SHA-256 hash of the payload against the public key
 *
 * @param[in] context the trusted name context
 * @return whether it was successful
 */
static bool verify_trusted_name_signature(const s_trusted_name_ctx *context) {
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
                                    (uint8_t *) (context->input_sig),
                                    context->input_sig_size) != CX_OK) {
        return false;
    }
    return true;
}

static bool verify_mab_owner(const s_trusted_name_ctx *context) {
    bip32_path_t owner_path = {0};
    publicKeyContext_t public_key_context = {0};
    char owner_address58[BASE58CHECK_ADDRESS_SIZE + 1] = {0};
    uint8_t owner_address[ADDRESS_SIZE];

    if (context == NULL) {
        return false;
    }

    if (!(context->rcv_flags & SET_BIT(OWNER_RCV_BIT)) ||
        !(context->rcv_flags & SET_BIT(OWNER_DERIV_PATH_RCV_BIT))) {
        PRINTF("Error: MAB trusted name requires owner metadata!\n");
        return false;
    }

    owner_path.length = context->owner_deriv_path_length;
    memcpy(owner_path.indices, context->owner_deriv_path, sizeof(uint32_t) * owner_path.length);

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

/**
 * Verify the validity of the received trusted struct
 *
 * @param[in] context the trusted name context
 * @return whether the struct is valid
 */
bool verify_trusted_name_struct(const s_trusted_name_ctx *context) {
    uint32_t required_flags;

    if (!(SET_BIT(STRUCT_VERSION_RCV_BIT) & context->rcv_flags)) {
        PRINTF("Error: no struct version specified!\n");
        return false;
    }
    required_flags = SET_BIT(STRUCT_TYPE_RCV_BIT) | SET_BIT(STRUCT_VERSION_RCV_BIT) |
                     SET_BIT(SIGNER_KEY_ID_RCV_BIT) | SET_BIT(SIGNER_ALGO_RCV_BIT) |
                     SET_BIT(SIGNATURE_RCV_BIT) | SET_BIT(TRUSTED_NAME_RCV_BIT) |
                     SET_BIT(ADDRESS_RCV_BIT);
    switch (context->trusted_name.struct_version) {
        case 1:
            required_flags |= SET_BIT(CHALLENGE_RCV_BIT) | SET_BIT(COIN_TYPE_RCV_BIT);
            if ((context->rcv_flags & required_flags) != required_flags) {
                return false;
            }
            if (!validate_trusted_name_value(&context->trusted_name)) {
                return false;
            }
            break;
        case 2:
            required_flags |= SET_BIT(CHAIN_ID_RCV_BIT) | SET_BIT(TRUSTED_NAME_TYPE_RCV_BIT) |
                              SET_BIT(TRUSTED_NAME_SOURCE_RCV_BIT);
            if ((context->rcv_flags & required_flags) != required_flags) {
                return false;
            }
            if (!validate_trusted_name_value(&context->trusted_name)) {
                return false;
            }
            switch (context->trusted_name.name_type) {
                case TN_TYPE_ACCOUNT:
                    if ((context->trusted_name.name_source != TN_SOURCE_ENS) &&
                        (context->trusted_name.name_source != TN_SOURCE_MAB)) {
                        PRINTF("Error: cannot accept an account name from given source (%u)!\n",
                               context->trusted_name.name_source);
                        return false;
                    }
                    if (!(context->rcv_flags & SET_BIT(CHALLENGE_RCV_BIT))) {
                        PRINTF("Error: trusted account name requires a challenge!\n");
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
            break;
        default:
            PRINTF("Error: unsupported trusted name struct version (%u) !\n",
                   context->trusted_name.struct_version);
            return false;
    }

    if (!verify_trusted_name_signature(context)) {
        return false;
    }

    if (!register_trusted_name(&context->trusted_name)) {
        return false;
    }

    PRINTF("Registered : %s => %.*h\n",
           context->trusted_name.name,
           ADDRESS_LENGTH,
           context->trusted_name.addr);
    return true;
}
