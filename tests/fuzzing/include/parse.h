#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "asset_info.h"
#include "bip32_utils.h"
#include "chain_config.h"  // chain_config_t (real app header, lightweight)
#include "common_utils.h"
#include "core/Contract.pb.h"
#include "pb.h"
#include "tx_content.h"
// The application contexts (tmpCtx_t, txContext_t, strings_t, app_state_t,
// chainConfig, ...) are defined in the real shared_context.h, which is fully
// standalone-includable against these mocks. Deferring to it keeps a single
// definition source so the GCS sources (which pull the real apdu_constants.h ->
// shared_context.h) never clash with this header.
#include "shared_context.h"

#define ADDRESS_SIZE TRON_ADDRESS_SIZE
#define SUN_DIG      6

typedef union {
    protocol_AccountCreateContract account_create_contract;
    protocol_TransferContract transfer_contract;
    protocol_TransferAssetContract transfer_asset_contract;
    protocol_TriggerSmartContract trigger_smart_contract;
    protocol_ClearABIContract clear_abi_contract;
    protocol_VoteWitnessContract vote_witness_contract;
    protocol_WitnessCreateContract witness_create_contract;
    protocol_WitnessUpdateContract witness_update_contract;
    protocol_ProposalCreateContract proposal_create_contract;
    protocol_ExchangeCreateContract exchange_create_contract;
    protocol_ExchangeInjectContract exchange_inject_contract;
    protocol_ExchangeWithdrawContract exchange_withdraw_contract;
    protocol_ExchangeTransactionContract exchange_transaction_contract;
    protocol_AccountUpdateContract account_update_contract;
    protocol_SetAccountIdContract set_account_id_contract;
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
    protocol_UpdateBrokerageContract update_brokerage_contract;
} contract_t;

extern contract_t msg;

typedef enum parserStatus_e {
    USTREAM_PROCESSING,
    USTREAM_FINISHED,
    USTREAM_FAULT,
    USTREAM_MISSING_SETTING_DATA_ALLOWED
} parserStatus_e;

enum { OFFSET_CLA = 0, OFFSET_INS, OFFSET_P1, OFFSET_P2, OFFSET_LC, OFFSET_CDATA };

typedef struct stage_t {
    uint16_t total;
    uint16_t count;
} stage_t;

// App-side asset/token/amount helpers (declared in the firmware's parse.h).
void forget_known_assets(void);
extraInfo_t *get_current_asset_info(void);
int get_asset_index_by_addr(const uint8_t *addr);
extraInfo_t *get_asset_info_by_addr(const uint8_t *addr);
void validate_current_asset_info(void);
tokenDefinition_t *getKnownToken(txContent_t *context);
unsigned short print_amount(uint64_t amount, char *out, uint32_t outlen, uint8_t sun);
void initTx(txContext_t *context, txContent_t *content);
parserStatus_e processTx(uint8_t *buffer, uint32_t length, txContent_t *content);
bool parseTokenName(uint8_t token_id,
                    uint8_t *data,
                    uint32_t dataLength,
                    txContent_t *content);
bool parseExchange(const uint8_t *data, size_t length, txContent_t *content);
bool setContractType(contractType_e type, char *out, size_t outlen);
bool setExchangeContractDetail(contractType_e type, char *out, size_t outlen);
void proposal_parameters_cleanup(void);
pb_size_t proposal_parameter_count(void);
bool proposal_parameter_at(pb_size_t index, int64_t *key, int64_t *value);
int bytes_to_string(char *out, size_t outl, const void *value, size_t len);
