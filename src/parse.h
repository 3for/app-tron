#pragma once

#include "os.h"
#include "cx.h"
#include "bip32.h"
// #include "bip32_utils.h"
#include <stdbool.h>
#include "core/Contract.pb.h"
#include "common_utils.h"
#include "asset_info.h"
#include "tx_content.h"
#include "bip32_utils.h"
#include "tron_plugin_interface.h"
#include "caller_api.h"
#include "swap_lib_calls.h"
#include "main_std_app.h"

#define MAX_BIP32_PATH 10

#define ADD_PRE_FIX_STRING       "T"
#define ADDRESS_SIZE             21
#define TOKENID_SIZE             7
#define BASE58CHECK_ADDRESS_SIZE 34
#define PUBLIC_KEY_SIZE          65
#define CHAIN_CODE_SIZE          32
#define HASH_SIZE                32

#define TRC20_DATA_FIELD_SIZE 68

#define SUN_DIG                  6
#define ADD_PRE_FIX_BYTE_MAINNET 0x41
#define MAX_RAW_SIGNATURE        65

#define SHARED_CTX_FIELD_1_SIZE 256
#define SHARED_CTX_FIELD_2_SIZE 40

#define SHARED_BUFFER_SIZE SHARED_CTX_FIELD_1_SIZE

#define MAX_ASSETS 5

#define UNSUPPORTED_CHAIN_ID_MSG(id)                                              \
    do {                                                                          \
        PRINTF("Unsupported chain ID: %u (app: %u)\n", id, chainConfig->chainId); \
    } while (0)

typedef union {
    protocol_TransferContract transfer_contract;
    protocol_TransferAssetContract transfer_asset_contract;
    protocol_TriggerSmartContract trigger_smart_contract;
    protocol_VoteWitnessContract vote_witness_contract;
    protocol_WitnessCreateContract witness_create_contract;
    protocol_ProposalCreateContract proposal_create_contract;
    protocol_ExchangeCreateContract exchange_create_contract;
    protocol_ExchangeInjectContract exchange_inject_contract;
    protocol_ExchangeWithdrawContract exchange_withdraw_contract;
    protocol_ExchangeTransactionContract exchange_transaction_contract;
    protocol_AccountUpdateContract account_update_contract;
    protocol_ProposalApproveContract proposal_approve_contract;
    protocol_ProposalDeleteContract proposal_delete_contract;
    protocol_WithdrawBalanceContract withdraw_balance_contract;
    protocol_FreezeBalanceContract freeze_balance_contract;
    protocol_UnfreezeBalanceContract unfreeze_balance_contract;
    protocol_AccountPermissionUpdateContract account_permission_update_contract;
    protocol_FreezeBalanceV2Contract freeze_balance_v2_contract;
    protocol_UnfreezeBalanceV2Contract unfreeze_balance_v2_contract;
    protocol_WithdrawExpireUnfreezeContract withdraw_expire_unfreeze_contract;
    protocol_DelegateResourceContract delegate_resource_contract;
    protocol_UnDelegateResourceContract undelegate_resource_contract;
} contract_t;

extern contract_t msg;

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT,
    USTREAM_MISSING_SETTING_DATA_ALLOWED
} parserStatus_e;

enum { OFFSET_CLA = 0, OFFSET_INS, OFFSET_P1, OFFSET_P2, OFFSET_LC, OFFSET_CDATA };
typedef enum {
    APP_STATE_IDLE,
    APP_STATE_SIGNING_MESSAGE,
    APP_STATE_SIGNING_MESSAGE_FULL_DISPLAY,
    APP_STATE_SIGNING,
    APP_STATE_SIGNING_TIP712
} app_state_t;

typedef enum { STATE_191_HASH_DISPLAY = 0, STATE_191_HASH_ONLY } sign_message_state;
typedef struct states191_t {
    sign_message_state sign_state : 1;
    bool ui_started : 1;
} states191_t;

typedef struct stage_t {
    uint16_t total;
    uint16_t count;
} stage_t;

typedef struct txContext_t {
    cx_sha256_t sha2;
    bool initialized;
} txContext_t;

typedef struct publicKeyContext_t {
    uint8_t publicKey[PUBLIC_KEY_SIZE];
    char address58[BASE58CHECK_ADDRESS_SIZE + 1];
    uint8_t chainCode[CHAIN_CODE_SIZE];
    bool getChaincode;
} publicKeyContext_t;

typedef struct transactionContext_t {
    bip32_path_t bip32_path;
    uint8_t hash[HASH_SIZE];
    uint8_t signature[MAX_RAW_SIGNATURE];
    uint8_t signatureLength;
    union extraInfo_t extraInfo[MAX_ASSETS];
    bool assetSet[MAX_ASSETS];
    uint8_t currentAssetIndex;
} transactionContext_t;

typedef struct messageSigningContext712_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t domainHash[32];
    uint8_t messageHash[32];
} messageSigningContext712_t;

// typedef struct messageSigningContext_t {
//     bip32_path_t bip32;
//     uint8_t hash[HASH_SIZE];
//     uint32_t remainingLength;
// } messageSigningContext_t;

typedef union {
    transactionContext_t transactionContext;
    publicKeyContext_t publicKeyContext;
    messageSigningContext712_t messageSigningContext712;
    // messageSigningContext_t messageSigningContext;
} tmpCtx_t;

#define SELECTOR_LENGTH 4
#define PLUGIN_ID_LENGTH 30

typedef struct tokenContext_t {
    char pluginName[PLUGIN_ID_LENGTH];

    uint8_t data[INT256_LENGTH];
    uint16_t fieldIndex;
    uint8_t fieldOffset;

    uint8_t pluginUiMaxItems;
    uint8_t pluginUiCurrentItem;
    uint8_t pluginUiState;

    union {
        struct {
            uint8_t contractAddress[TRON_ADDRESS_SIZE];
            uint8_t methodSelector[SELECTOR_LENGTH];
        };
        // This needs to be strictly 4 bytes aligned since pointers to it will be casted as
        // plugin context struct pointers (structs that contain up to 4 bytes wide elements)
        uint8_t pluginContext[PLUGIN_CONTEXT_SIZE] __attribute__((aligned(4)));
    };

    uint8_t pluginStatus;

} tokenContext_t;

_Static_assert((offsetof(tokenContext_t, pluginContext) % 4) == 0, "Plugin context not aligned");

typedef union {
    tokenContext_t tokenContext;
} dataContext_t;


// must be able to hold in decimal up to : floor(MAX_UINT64 / 2) - 36
#define NETWORK_STRING_MAX_SIZE 19

typedef struct txStringProperties_s {
    char fromAddress[43];
    char toAddress[43];
    char fullAmount[MAX_TICKER_LEN + 1 + 78 + 1];  // 2^256 is 78 digits long
    char maxFee[50];
    char nonce[8];  // 10M tx per account ought to be enough for everybody
    char network_name[NETWORK_STRING_MAX_SIZE + 1];
    char tx_hash[2 + (INT256_LENGTH * 2) + 1];
} txStringProperties_t;

typedef struct strDataTmp_t {
    char tmp[SHARED_CTX_FIELD_1_SIZE];
    char tmp2[SHARED_CTX_FIELD_2_SIZE];
} strDataTmp_t;

typedef union {
    txStringProperties_t common;
    strDataTmp_t tmp;
} strings_t;

typedef struct chain_config_s {
    char coinName[10];  // ticker
    uint64_t chainId;
} chain_config_t;

extern const chain_config_t *chainConfig;

bool setContractType(contractType_e type, char *out, size_t outlen);
bool setExchangeContractDetail(contractType_e type, char *out, size_t outlen);

bool parseTokenName(uint8_t token_id, uint8_t *data, uint32_t dataLength, txContent_t *context);
bool parseExchange(const uint8_t *data, size_t dataLength, txContent_t *context);
tokenDefinition_t *getKnownToken(txContent_t *context);

unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun);

void initTx(txContext_t *context, txContent_t *content);

parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content);

typedef enum {
    PLUGIN_TYPE_NONE = 0,
    // External plugin, set by setExternalPlugin
    PLUGIN_TYPE_EXTERNAL,
    // Specific SWAP_WITH_CALLDATA internal plugin
    // set as fallback when started if calldata is provided in swap mode
    PLUGIN_TYPE_SWAP_WITH_CALLDATA,
    // Specific ERC721 internal plugin, set by setPlugin
    PLUGIN_TYPE_ERC721,
    // Specific ERC1155 internal plugin, set by setPlugin
    PLUGIN_TYPE_ERC1155,
    // Old internal plugin, not set by any command
    PLUGIN_TYPE_OLD_INTERNAL,
} pluginType_t;

extern tmpCtx_t tmpCtx;
extern txContent_t txContent;
extern txContext_t txContext;
extern dataContext_t dataContext;
extern pluginType_t pluginType;
extern uint8_t appState;
extern states191_t states191;
extern uint8_t processed_size_191;
extern uint16_t apdu_response_code;

int bytes_to_string(char *out, size_t outl, const void *value, size_t len);

void forget_known_assets(void);
extraInfo_t *get_current_asset_info(void);
int get_asset_index_by_addr(const uint8_t *addr);
extraInfo_t *get_asset_info_by_addr(const uint8_t *addr);
void validate_current_asset_info(void);

typedef struct tron_libargs_s {
    unsigned int id;
    unsigned int command;
    chain_config_t *chain_config;
    union {
        check_address_parameters_t *check_address;
        create_transaction_parameters_t *create_transaction;
        get_printable_amount_parameters_t *get_printable_amount;
        caller_app_t *caller_app;
    };
} tron_libargs_t;
