#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include "core/Contract.pb.h"

#ifndef PARSE_H
#define PARSE_H

#define MAX_BIP32_PATH 10

#define ADD_PRE_FIX_STRING       "T"
#define ADDRESS_SIZE             21
#define BASE58CHECK_ADDRESS_SIZE 34
#define PUBLIC_KEY_SIZE          65
#define CHAIN_CODE_SIZE          32
#define HASH_SIZE                32

#define TRC20_DATA_FIELD_SIZE 68

#define SUN_DIG                  6
#define ADD_PRE_FIX_BYTE_MAINNET 0x41
#define MAX_RAW_SIGNATURE        65
#define MAX_TOKEN_LENGTH         67
#define MAX_WITNESS_URL_LENGTH   256

// java-tron rejects smart-contract fee limits above this protocol-wide
// governance ceiling (100 billion TRX, expressed in sun). The live network
// limit may be lower, but an offline signer cannot safely predict it.
#define MAX_PROTOCOL_FEE_LIMIT UINT64_C(100000000000000000)

#define NETWORK_STRING_MAX_SIZE 16
#define SHARED_CTX_FIELD_1_SIZE 256
#define SHARED_CTX_FIELD_2_SIZE 40

typedef union {
    protocol_TransferContract transfer_contract;
    protocol_TransferAssetContract transfer_asset_contract;
    protocol_TriggerSmartContract trigger_smart_contract;
    protocol_VoteWitnessContract vote_witness_contract;
    protocol_WitnessCreateContract witness_create_contract;
    protocol_WitnessUpdateContract witness_update_contract;
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
    protocol_CancelAllUnfreezeV2Contract cancel_all_unfreeze_v2_contract;
} contract_t;

extern contract_t msg;

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT,
    USTREAM_MISSING_SETTING_DATA_ALLOWED
} parserStatus_e;

typedef enum contractType_e {
    ACCOUNTCREATECONTRACT = 0,
    TRANSFERCONTRACT,
    TRANSFERASSETCONTRACT,
    VOTEASSETCONTRACT,
    VOTEWITNESSCONTRACT,
    WITNESSCREATECONTRACT,
    ASSETISSUECONTRACT,
    WITNESSUPDATECONTRACT = 8,
    PARTICIPATEASSETISSUECONTRACT,
    ACCOUNTUPDATECONTRACT,
    FREEZEBALANCECONTRACT,
    UNFREEZEBALANCECONTRACT,
    WITHDRAWBALANCECONTRACT,
    UNFREEZEASSETCONTRACT,
    UPDATEASSETCONTRACT,
    PROPOSALCREATECONTRACT,
    PROPOSALAPPROVECONTRACT,
    PROPOSALDELETECONTRACT,
    SETACCOUNTIDCONTRACT,
    CUSTOMCONTRACT,
    CREATESMARTCONTRACT = 30,
    TRIGGERSMARTCONTRACT,
    EXCHANGECREATECONTRACT = 41,
    EXCHANGEINJECTCONTRACT,
    EXCHANGEWITHDRAWCONTRACT,
    EXCHANGETRANSACTIONCONTRACT,
    UPDATEENERGYLIMITCONTRACT,
    ACCOUNTPERMISSIONUPDATECONTRACT,
    FREEZEBALANCEV2CONTRACT = 54,
    UNFREEZEBALANCEV2CONTRACT,
    WITHDRAWEXPIREUNFREEZECONTRACT,
    DELEGATERESOURCECONTRACT,
    UNDELEGATERESOURCECONTRACT,
    CANCELALLUNFREEZEV2CONTRACT,

    UNKNOWN_CONTRACT = 254,
    INVALID_CONTRACT = 255
} contractType_e;

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

typedef struct {
    uint32_t indices[MAX_BIP32_PATH];
    uint8_t length;
} bip32_path_t;

typedef struct transactionContext_t {
    bip32_path_t bip32_path;
    uint8_t hash[HASH_SIZE];
    uint8_t signature[MAX_RAW_SIGNATURE];
    uint8_t signatureLength;
} transactionContext_t;

typedef struct txContent_t {
    uint64_t amount[2];
    uint64_t exchangeID;
    // Last-value-wins decoding of Transaction.raw.fee_limit across APDUs.
    // Keeping the unsigned wire value also makes negative int64 encodings
    // fail the protocol-ceiling check without implementation-defined casts.
    uint64_t feeLimit;
    // TriggerSmartContract can attach a TRC10 transfer independently of its
    // native TRX call value and ABI calldata. Keep both fields in the trusted
    // transaction model so every signing path can review or reject them.
    uint64_t callTokenValue;
    uint64_t tokenId;
    int64_t lockPeriod;
    uint8_t account[ADDRESS_SIZE];
    uint8_t destination[ADDRESS_SIZE];
    uint8_t contractAddress[ADDRESS_SIZE];
    uint8_t TRC20Amount[32];
    uint8_t decimals[2];
    // Preserve exact native-token identity before signed metadata replaces IDs with labels.
    bool tokenIsNative[2];
    char tokenNames[2][MAX_TOKEN_LENGTH];
    uint8_t tokenNamesLength[2];
    uint8_t resource;
    uint8_t TRC20Method;
    // Distinct known contracts can share a ticker. Such tokens require an
    // address-bearing approval rather than the ordinary ticker-only review.
    bool tokenIdentityAmbiguous;
    uint32_t customSelector;
    contractType_e contractType;
    uint64_t dataBytes;
    uint8_t permission_id;
    // Transaction.raw.contract is repeated on the wire, while this app can
    // safely review exactly one contract. Track the occurrence across every
    // APDU in the signing session, not only within one nanopb decode.
    bool contractSeen;
    // Unknown or deliberately omitted protobuf fields are included in the
    // signed hash but cannot be represented safely by the clear-signing UI.
    bool hasUnreviewedFields;
    uint32_t customData;
} txContent_t;

typedef struct messageSigningContext712_t {
    bip32_path_t bip32_path;
    uint8_t domainHash[32];
    uint8_t messageHash[32];
    char signerAddress[BASE58CHECK_ADDRESS_SIZE + 1];
} messageSigningContext712_t;

typedef struct txStringProperties_t {
    char fullAddress[43];
    char fullAmount[79];  // 2^256 is 78 digits long
    char maxFee[50];
    char nonce[8];  // 10M tx per account ought to be enough for everybody
    char network_name[NETWORK_STRING_MAX_SIZE];
} txStringProperties_t;

typedef struct strDataTmp_t {
    char tmp[SHARED_CTX_FIELD_1_SIZE];
    char tmp2[SHARED_CTX_FIELD_2_SIZE];
} strDataTmp_t;

typedef union {
    txStringProperties_t common;
    strDataTmp_t tmp;
} strings_t;

bool setContractType(contractType_e type, char *out, size_t outlen);
bool setExchangeContractDetail(contractType_e type, char *out, size_t outlen);

bool parseTokenName(uint8_t token_id, uint8_t *data, uint32_t dataLength, txContent_t *context);
bool parseExchange(const uint8_t *data, size_t dataLength, txContent_t *context);

unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun);
bool adjustDecimals(const char *src,
                    uint32_t srcLength,
                    char *target,
                    uint32_t targetLength,
                    uint8_t decimals);

void initTx(txContext_t *context, txContent_t *content);

parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content);

extern txContent_t txContent;
extern txContext_t txContext;

int bytes_to_string(char *out, size_t outl, const void *value, size_t len);

#endif
