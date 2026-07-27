#include <string.h>
#include "shared_context.h"
#include "ux.h"
#include "nbgl_use_case.h"  // nbgl_warning_t (needed by ui_nbgl.h)
#include "ui_nbgl.h"        // warning
#include "ui_globals.h"
#include "ui_idle_menu.h"  // ui_idle
#include "ui_callbacks.h"  // io_seproxyhal_touch_tx_ok / io_seproxyhal_touch_tx_cancel
#include "ui_utils.h"      // g_pairs / g_pairsList
#include "common_ui.h"     // ui_gcs / ui_gcs_cleanup
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "network.h"
#include "common_utils.h"  // ADDRESS_LENGTH
#include "helpers.h"       // getBase58FromAddress
#include "utils.h"         // SET_BIT
#include "parse.h"         // ADDRESS_SIZE, ADD_PRE_FIX_BYTE_MAINNET, BASE58CHECK_ADDRESS_SIZE
#include "gtp_tx_info.h"
#include "gtp_field_table.h"
#include "gtp_field.h"  // e_param_type, tokenDefinition_t/nftInfo_t via asset_info
#include "enum_value.h"
#include "proxy_info.h"
#include "trusted_name.h"
#include "tx_ctx.h"  // get_current_tx_info, get_tx_chain_id
#include "gcs_limits.h"
#include "gcs_memory.h"

/* Keep every allocation owned by the asynchronous GCS review in the same
 * tracked category, including strings and nested NBGL extension objects. */
#undef APP_MEM_CALLOC
#undef APP_MEM_FREE
#undef APP_MEM_FREE_AND_NULL
#undef APP_MEM_STRDUP
#define APP_MEM_CALLOC(buffer, size) \
    gcs_mem_calloc_into((void **) (buffer), (size), GCS_MEM_UI)
#define APP_MEM_FREE(ptr) gcs_mem_free((void *) (ptr))
#define APP_MEM_FREE_AND_NULL(buffer) gcs_mem_free_and_null((void **) (buffer))
#define APP_MEM_STRDUP(str) gcs_mem_strdup((str), GCS_MEM_UI)

// TRON contract addresses are 20-byte EVM internally; displayed as Base58Check
// (0x41 prefix + 20 bytes). This buffer holds one such "T..." string.
#define TRON_ADDR_STR_SIZE (BASE58CHECK_ADDRESS_SIZE + 1)

static bool *index_allocated = NULL;

/**
 * Format a 20-byte (EVM-style) contract address as a TRON Base58Check string.
 */
static bool format_contract_address(const uint8_t *addr20, char *out, size_t out_len) {
    uint8_t addr21[ADDRESS_SIZE];

    if ((addr20 == NULL) || (out == NULL) || (out_len < TRON_ADDR_STR_SIZE)) {
        return false;
    }
    addr21[0] = ADD_PRE_FIX_BYTE_MAINNET;
    memcpy(addr21 + 1, addr20, ADDRESS_LENGTH);
    getBase58FromAddress(addr21, out);
    return true;
}

static void review_choice(bool confirm) {
    if (confirm) {
        io_seproxyhal_touch_tx_ok();
#ifndef FUZZ
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
#endif
    } else {
        io_seproxyhal_touch_tx_cancel();
#ifndef FUZZ
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
#endif
    }
}

static void free_pair_extension_infolist_elem(const struct nbgl_contentInfoList_s *infolist,
                                              int idx) {
    if ((infolist == NULL) || (idx < 0) || (idx >= infolist->nbInfos)) {
        return;
    }
    if (infolist->infoTypes != NULL) {
        APP_MEM_FREE((void *) infolist->infoTypes[idx]);
    }
    if (infolist->infoContents != NULL) {
        APP_MEM_FREE((void *) infolist->infoContents[idx]);
    }
    if (infolist->infoExtensions != NULL) {
        APP_MEM_FREE((void *) infolist->infoExtensions[idx].title);
        APP_MEM_FREE((void *) infolist->infoExtensions[idx].explanation);
        APP_MEM_FREE((void *) infolist->infoExtensions[idx].fullValue);
    }
}

static void free_pair_extension(const nbgl_contentValueExt_t *ext) {
    if (ext == NULL) {
        return;
    }
    APP_MEM_FREE((void *) ext->backText);
    APP_MEM_FREE((void *) ext->fullValue);
    if (ext->infolist != NULL) {
        for (int i = 0; i < ext->infolist->nbInfos; ++i) {
            free_pair_extension_infolist_elem(ext->infolist, i);
        }
        APP_MEM_FREE((void *) ext->infolist->infoTypes);
        APP_MEM_FREE((void *) ext->infolist->infoContents);
        APP_MEM_FREE((void *) ext->infolist->infoExtensions);
        APP_MEM_FREE((void *) ext->infolist);
    }
    APP_MEM_FREE((void *) ext);
}

static void free_pair(const nbgl_contentTagValueList_t *pair_list, int idx) {
    if ((pair_list == NULL) || (pair_list->pairs == NULL) || (idx < 0) ||
        (idx >= pair_list->nbPairs)) {
        return;
    }
    // Only a few pairs are created from the UI, and need to be freed :
    // - the first one, that leads to the contract infos
    // - the second to last one, that shows the Network (optional)
    // - the last one, that shows the TX fees
    if ((index_allocated != NULL) && (index_allocated[idx] == true)) {
        APP_MEM_FREE((void *) pair_list->pairs[idx].item);
        APP_MEM_FREE((void *) pair_list->pairs[idx].value);
    }
    if (pair_list->pairs[idx].extension != NULL) {
        free_pair_extension(pair_list->pairs[idx].extension);
    }
}

#ifdef SCREEN_SIZE_WALLET
#define MAX_INFO_COUNT 3
#else
#define MAX_INFO_COUNT 4
#endif

static bool append_info(nbgl_contentInfoList_t *infos,
                        const char **types,
                        const char **contents,
                        uint8_t *count,
                        uint8_t capacity,
                        const char *key,
                        const char *value) {
    char *key_copy;
    char *value_copy;

    if ((infos == NULL) || (types == NULL) || (contents == NULL) ||
        (count == NULL) || (*count >= capacity) ||
        (key == NULL) || (value == NULL)) {
        return false;
    }
    if ((key_copy = APP_MEM_STRDUP(key)) == NULL) {
        return false;
    }
    if ((value_copy = APP_MEM_STRDUP(value)) == NULL) {
        APP_MEM_FREE(key_copy);
        return false;
    }
    types[*count] = key_copy;
    contents[*count] = value_copy;
    *count += 1U;
    /* Publish only entries for which both strings are fully owned. */
    infos->nbInfos = *count;
    return true;
}

/**
 * Fill the "smart contract information" info list (creator, contract name,
 * contract address, deploy date). Mirrors app-ethereum's prepare_infos(): on
 * wallet screens the contract address is a QR-code extension on the contract
 * row, on Nano it is a plain info row. TRON adaptations: Base58Check addresses
 * (instead of 0x-hex) and a Tronscan link (instead of Etherscan).
 */
static bool prepare_infos(nbgl_contentInfoList_t *infos) {
    char *tmp_buf = strings.tmp.tmp;
    size_t tmp_buf_size = sizeof(strings.tmp.tmp);
    size_t off;
    uint8_t count = 0;
    const char **keys;
    const char **values;
    const char *value;
#ifdef SCREEN_SIZE_WALLET
    nbgl_contentValueExt_t *extensions;
    int contract_idx = -1;
#endif

    infos->nbInfos = 0;
    if (APP_MEM_CALLOC((void **) &keys, sizeof(*keys) * MAX_INFO_COUNT) == false) return false;
    infos->infoTypes = keys;

    if (APP_MEM_CALLOC((void **) &values, sizeof(*values) * MAX_INFO_COUNT) == false) return false;
    infos->infoContents = values;

    if ((value = get_creator_legal_name(get_current_tx_info())) != NULL) {
#ifdef SCREEN_SIZE_WALLET
        const char *key = "Smart contract owner";
#else
        const char *key = "Contract owner";
#endif
        snprintf(tmp_buf, tmp_buf_size, "%s", value);
        if ((value = get_creator_url(get_current_tx_info())) != NULL) {
            off = strlen(tmp_buf);
            snprintf(tmp_buf + off, tmp_buf_size - off, "\n%s", value);
        }
        if (!append_info(infos, keys, values, &count, MAX_INFO_COUNT, key, tmp_buf)) return false;
    }

    if ((value = get_contract_name(get_current_tx_info())) != NULL) {
#ifdef SCREEN_SIZE_WALLET
        const char *key = "Smart contract";
#else
        const char *key = "Contract";
#endif
        snprintf(tmp_buf, tmp_buf_size, "%s", value);
#ifdef SCREEN_SIZE_WALLET
        contract_idx = count;
#endif
        if (!append_info(infos, keys, values, &count, MAX_INFO_COUNT, key, tmp_buf)) return false;
    }

#ifndef SCREEN_SIZE_WALLET
    if (!format_contract_address(get_contract_addr(get_current_tx_info()), tmp_buf, tmp_buf_size)) {
        return false;
    }
    if (!append_info(infos,
                     keys,
                     values,
                     &count,
                     MAX_INFO_COUNT,
                     "Contract address",
                     tmp_buf)) {
        return false;
    }
#endif

    if ((value = get_deploy_date(get_current_tx_info())) != NULL) {
        snprintf(tmp_buf, tmp_buf_size, "%s", value);
        if (!append_info(infos,
                         keys,
                         values,
                         &count,
                         MAX_INFO_COUNT,
                         "Deployed on",
                         tmp_buf)) {
            return false;
        }
    }

#ifdef SCREEN_SIZE_WALLET
    if (contract_idx != -1) {
        if (APP_MEM_CALLOC((void **) &extensions, sizeof(*extensions) * count) == false) {
            return false;
        }
        infos->infoExtensions = extensions;
        infos->withExtensions = true;

        if (!format_contract_address(get_contract_addr(get_current_tx_info()),
                                     tmp_buf,
                                     tmp_buf_size)) {
            return false;
        }
        if ((extensions[contract_idx].title = APP_MEM_STRDUP(tmp_buf)) == NULL) {
            return false;
        }
        // Tronscan link only for mainnet
        if (get_tx_chain_id() == TRON_MAINNET_CHAINID) {
            if ((extensions[contract_idx].explanation =
                     APP_MEM_STRDUP("Scan to view on Tronscan")) == NULL) {
                return false;
            }
            snprintf(tmp_buf,
                     tmp_buf_size,
                     "https://tronscan.org/#/address/%s",
                     extensions[contract_idx].title);
        } else {
            snprintf(tmp_buf, tmp_buf_size, "%s", extensions[contract_idx].title);
        }
        if ((extensions[contract_idx].fullValue = APP_MEM_STRDUP(tmp_buf)) == NULL) {
            return false;
        }
        extensions[contract_idx].aliasType = QR_CODE_ALIAS;
    }
#endif

    infos->nbInfos = count;
    return true;
}

void ui_gcs_cleanup(void) {
    if ((g_pairsList != NULL) && (g_pairsList->pairs != NULL)) {
        for (int i = 0; i < g_pairsList->nbPairs; ++i) {
            free_pair(g_pairsList, i);
        }
    }
    APP_MEM_FREE_AND_NULL((void *) &index_allocated);
    ui_all_cleanup();
    proxy_cleanup();
}

static nbgl_contentValueExt_t *get_infolist_extension(const char *title,
                                                      size_t count,
                                                      const char **keys,
                                                      const char **values) {
    nbgl_contentValueExt_t *ext;
    nbgl_contentInfoList_t *list;
    char **types;
    char **contents;

    if ((title == NULL) || (keys == NULL) || (values == NULL) ||
        (count == 0U) || (count > UINT8_MAX) ||
        (APP_MEM_CALLOC((void **) &ext, sizeof(*ext)) == false)) {
        return NULL;
    }
    if ((ext->backText = APP_MEM_STRDUP(title)) == NULL) {
        free_pair_extension(ext);
        return NULL;
    }
    ext->aliasType = INFO_LIST_ALIAS;

    if (APP_MEM_CALLOC((void **) &list, sizeof(*list)) == false) {
        free_pair_extension(ext);
        return NULL;
    }
    ext->infolist = list;
    list->nbInfos = 0;

    if (APP_MEM_CALLOC((void **) &types, sizeof(*types) * count) == false) {
        free_pair_extension(ext);
        return NULL;
    }
    list->infoTypes = (const char **) types;

    if (APP_MEM_CALLOC((void **) &contents, sizeof(*contents) * count) == false) {
        free_pair_extension(ext);
        return NULL;
    }
    list->infoContents = (const char **) contents;
    for (size_t idx = 0; idx < count; ++idx) {
        if ((keys[idx] == NULL) || (values[idx] == NULL) ||
            ((types[idx] = APP_MEM_STRDUP(keys[idx])) == NULL)) {
            free_pair_extension(ext);
            return NULL;
        }
        if ((contents[idx] = APP_MEM_STRDUP(PIC(values[idx]))) == NULL) {
            APP_MEM_FREE(types[idx]);
            types[idx] = NULL;
            free_pair_extension(ext);
            return NULL;
        }
        list->nbInfos = (uint8_t) (idx + 1U);
    }
    return ext;
}

static const nbgl_contentValueExt_t *handle_extra_data_trusted_name(
    const s_field_table_entry *field) {
    nbgl_contentValueAliasType_t alias_type;
    nbgl_contentValueExt_t *extension;
    const s_trusted_name *tname = (s_trusted_name *) field->extra_data;
    char formatted_addr[TRON_ADDR_STR_SIZE];

    switch (tname->name_source) {
        case TN_SOURCE_ENS:
            alias_type = ENS_ALIAS;
            break;
        case TN_SOURCE_LAB:
        case TN_SOURCE_MAB:
            alias_type = ADDRESS_BOOK_ALIAS;
            break;
        default:
            alias_type = INFO_LIST_ALIAS;
            break;
    }
    if (!format_contract_address(tname->addr, formatted_addr, sizeof(formatted_addr))) {
        return NULL;
    }
    if (alias_type == INFO_LIST_ALIAS) {
        const char *keys[] = {"Contract address"};
        const char *values[] = {formatted_addr};
        if ((extension = get_infolist_extension(tname->name, ARRAYLEN(keys), keys, values)) ==
            NULL) {
            return NULL;
        }
    } else {
        if (APP_MEM_CALLOC((void **) &extension, sizeof(*extension)) == false) {
            return NULL;
        }
        if ((extension->fullValue = APP_MEM_STRDUP(formatted_addr)) == NULL) {
            APP_MEM_FREE(extension);
            return NULL;
        }
        extension->title = tname->name;
        extension->aliasType = alias_type;
    }
    return extension;
}

static const nbgl_contentValueExt_t *handle_extra_data_token(const s_field_table_entry *field) {
    const tokenDefinition_t *token_def = (tokenDefinition_t *) field->extra_data;
    char formatted_addr[TRON_ADDR_STR_SIZE];
    const char *keys[] = {"Contract address"};
    const char *values[] = {formatted_addr};

    if (!format_contract_address(token_def->address, formatted_addr, sizeof(formatted_addr))) {
        return NULL;
    }
    return get_infolist_extension(token_def->ticker, ARRAYLEN(keys), keys, values);
}

static const nbgl_contentValueExt_t *handle_extra_data_nft(const s_field_table_entry *field) {
    const nftInfo_t *nft_def = (nftInfo_t *) field->extra_data;
    char formatted_addr[TRON_ADDR_STR_SIZE];
    const char *keys[] = {"Contract address"};
    const char *values[] = {formatted_addr};

    if (!format_contract_address(nft_def->contractAddress, formatted_addr, sizeof(formatted_addr))) {
        return NULL;
    }
    return get_infolist_extension(nft_def->collectionName, ARRAYLEN(keys), keys, values);
}

static const nbgl_contentValueExt_t *handle_extra_data_enum(const s_field_table_entry *field) {
    const s_enum_value_entry *enum_value = (s_enum_value_entry *) field->extra_data;
    char formatted_value[4];  // max value : 255 + '\0'
    const char *keys[] = {"Raw value"};
    const char *values[] = {formatted_value};

    if (snprintf(formatted_value, sizeof(formatted_value), "%u", enum_value->value) <= 0) {
        return NULL;
    }
    return get_infolist_extension(enum_value->name, ARRAYLEN(keys), keys, values);
}

static bool handle_extra_data(const s_field_table_entry *field, nbgl_contentTagValue_t *pair) {
    pair->aliasValue = true;
    switch (field->type) {
        case PARAM_TYPE_TRUSTED_NAME:
            if ((pair->extension = handle_extra_data_trusted_name(field)) == NULL) {
                return false;
            }
            break;
        case PARAM_TYPE_TOKEN_AMOUNT:
        case PARAM_TYPE_TOKEN:
            if ((pair->extension = handle_extra_data_token(field)) == NULL) {
                return false;
            }
            break;
        case PARAM_TYPE_NFT:
            if ((pair->extension = handle_extra_data_nft(field)) == NULL) {
                return false;
            }
            break;
        case PARAM_TYPE_ENUM:
            if ((pair->extension = handle_extra_data_enum(field)) == NULL) {
                return false;
            }
            break;
        default:
            PRINTF("Warning: Unsupported extra data for field of type %u\n", field->type);
            pair->aliasValue = false;
            break;
    }
    return true;
}

/**
 * Build the Generic Clear Signing review screen from the field table.
 *
 * Mirrors app-ethereum's ui_gcs() core flow (a leading contract-info pair, one
 * pair per rendered field, an optional Network pair, then an NBGL review).
 * Like app-ethereum it inserts a centered "Review transaction / n of m" separator
 * page before each sub-transaction of a batch. TRON adaptations: no gas "max fees"
 * pair (TRON uses an energy/bandwidth fee model, not gas), no transaction-simulation
 * warning, the TRON app icon, and signing through ui_callback_tx_ok/cancel.
 */
bool ui_gcs(void) {
    char *tmp_buf = strings.tmp.tmp;
    size_t tmp_buf_size = sizeof(strings.tmp.tmp);
    const s_field_table_entry *field;
    bool show_network;
    nbgl_contentValueExt_t *ext = NULL;
    nbgl_contentInfoList_t *infolist = NULL;
    size_t nb_pairs = 0U;
    size_t pair = 0U;
    size_t tx_idx = 0U;
    size_t batch_nb_tx = 0U;
    size_t title_len;
    size_t finish_len;
    const size_t field_count = field_table_size();
    const s_tx_info *info_tx = get_current_tx_info();
    const char *operation;

    explicit_bzero(&warning, sizeof(nbgl_warning_t));

    if ((info_tx == NULL) || ((operation = get_operation_type(info_tx)) == NULL) ||
        (field_count > GCS_MAX_RENDERED_FIELDS)) {
        return false;
    }

    // Finish (sign-confirmation) title: on wallet screens append the operation
    // ("Sign transaction to swap?"); on Nano keep the plain "Sign transaction".
    // Mirrors app-ethereum's ui_gcs() (which prefixes ui_tx_simulation_finish_str(),
    // a Web3-Checks feature TRON doesn't have, so we use a literal "Sign").
    title_len = strlen("Review transaction to ") + strlen(operation) + 1U;
#ifdef SCREEN_SIZE_WALLET
    finish_len = strlen("Sign transaction to ") + strlen(operation) + strlen("?") + 1U;
#else
    finish_len = strlen("Sign transaction") + 1U;
#endif
    if ((title_len > UINT8_MAX) || (finish_len > UINT8_MAX) ||
        !ui_buffers_init((uint8_t) title_len, 0U, (uint8_t) finish_len)) {
        return false;
    }
    snprintf(g_titleMsg, title_len, "Review transaction to %s", operation);
#ifdef SCREEN_SIZE_WALLET
    snprintf(g_finishMsg, finish_len, "Sign transaction to %s?", operation);
#else
    snprintf(g_finishMsg, finish_len, "Sign transaction");
#endif

    // Count batched sub-transactions: each nested calldata begins a new "intent",
    // so the number of start_intent fields is the number of sub-transactions.
    for (size_t i = 0; i < field_count; ++i) {
        const s_field_table_entry *f = get_from_field_table((int) i);
        if ((f != NULL) && f->start_intent) {
            batch_nb_tx++;
        }
    }

    // Contract info (1) + optional batch separators + TX fields + optional Network (1).
    nb_pairs = 1U;
    if (batch_nb_tx > 1) {
        if (__builtin_add_overflow(nb_pairs, batch_nb_tx, &nb_pairs)) return false;
    }
    if (__builtin_add_overflow(nb_pairs, field_count, &nb_pairs)) return false;
    // TRON raw_data carries no chain id. Always show the firmware's explicit
    // mainnet policy instead of implying that the transaction proves a network.
    show_network = true;
    if (__builtin_add_overflow(nb_pairs, 1U, &nb_pairs) ||
        (nb_pairs > GCS_MAX_UI_PAIRS) || (nb_pairs > UINT8_MAX)) return false;

    if (!ui_pairs_init((uint8_t) nb_pairs)) {
        return false;
    }
    if (APP_MEM_CALLOC((void **) &index_allocated, nb_pairs) == false) {
        return false;
    }

    // First pair: contract info, with an info-list alias.
    index_allocated[pair] = true;
    if ((g_pairs[pair].item = APP_MEM_STRDUP("Interaction with")) == NULL) {
        return false;
    }
    g_pairs[pair].value = get_creator_name(info_tx);
    if (g_pairs[pair].value == NULL) {
        // not great, but this cannot be NULL
        g_pairs[pair].value = APP_MEM_STRDUP("a smart contract");
    } else {
        g_pairs[pair].value = APP_MEM_STRDUP(g_pairs[pair].value);
    }
    if (g_pairs[pair].value == NULL) {
        return false;
    }
    if (APP_MEM_CALLOC((void **) &ext, sizeof(*ext)) == false) {
        return false;
    }
    g_pairs[pair].extension = ext;
    if (APP_MEM_CALLOC((void **) &infolist, sizeof(*infolist)) == false) {
        return false;
    }
    ext->infolist = infolist;
    if (!prepare_infos(infolist)) {
        return false;
    }
    ext->aliasType = INFO_LIST_ALIAS;
    if ((ext->backText = get_creator_name(info_tx)) == NULL) {
        ext->backText = APP_MEM_STRDUP("Smart contract information");
    } else {
        ext->backText = APP_MEM_STRDUP(ext->backText);
    }
    if (ext->backText == NULL) {
        return false;
    }
    g_pairs[pair].aliasValue = true;
    pair++;

    // TX fields
    for (size_t i = 0; i < field_count; ++i) {
        if ((field = get_from_field_table((int) i)) == NULL || (pair >= nb_pairs)) {
            return false;
        }
        // Batch intermediate page: a centered "Review transaction / n of m" before
        // each sub-transaction's first field (mirrors app-ethereum's ui_gcs).
        if (field->start_intent && (batch_nb_tx > 1)) {
            tx_idx++;
            snprintf(tmp_buf,
                     tmp_buf_size,
                     "%u of %u",
                     (unsigned int) tx_idx,
                     (unsigned int) batch_nb_tx);
            index_allocated[pair] = true;
            if (((g_pairs[pair].item = APP_MEM_STRDUP("Review transaction")) == NULL) ||
                ((g_pairs[pair].value = APP_MEM_STRDUP(tmp_buf)) == NULL)) {
                return false;
            }
            g_pairs[pair].centeredInfo = true;
            pair++;
        }
        if (pair >= nb_pairs) return false;
        g_pairs[pair].item = field->key;
        g_pairs[pair].value = field->value;
        if (field->extra_data != NULL) {
            if (!handle_extra_data(field, &g_pairs[pair])) {
                return false;
            }
        }
        pair++;
        // End of a sub-transaction: force the next pair onto a fresh page.
        if (field->end_intent && (batch_nb_tx > 1) && (pair < nb_pairs)) {
            g_pairs[pair].forcePageStart = true;
        }
    }

    if (show_network) {
        if (pair >= nb_pairs) return false;
        index_allocated[pair] = true;
        if ((g_pairs[pair].item = APP_MEM_STRDUP("Network")) == NULL) {
            return false;
        }
        if (get_network_as_string(tmp_buf, tmp_buf_size) != true) {
            return false;
        }
        if ((g_pairs[pair].value = APP_MEM_STRDUP(tmp_buf)) == NULL) {
            return false;
        }
        pair++;
    }

    if (pair != nb_pairs) {
        return false;
    }

#ifndef FUZZ
    nbgl_useCaseAdvancedReview(TYPE_TRANSACTION,
                               g_pairsList,
                               &APP_TRON_HOME_ICON,
                               g_titleMsg,
                               NULL,
                               g_finishMsg,
                               NULL,
                               &warning,
                               review_choice);
#endif
    return true;
}
