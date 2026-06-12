#pragma once

#include <stdint.h>
#include "ux.h"
#include "uint256.h"
#include "trusted_name.h"
#include "lists.h"
#include "calldata.h"

typedef enum { TIP712_FILTERING_BASIC, TIP712_FILTERING_FULL } e_tip712_filtering_mode;
typedef enum {
    TIP712_FIELD_LATER,
    TIP712_FIELD_INCOMING,
    TIP712_NO_MORE_FIELD
} e_tip712_nfs;  // next field state

typedef enum {
    CALLDATA_FLAG_ADDR_NONE = 0,
    CALLDATA_FLAG_ADDR_FILTER = 1,
    CALLDATA_FLAG_ADDR_VERIFYING_CONTRACT = 2,
} e_calldata_addr_flag;

typedef enum {
    EIP712_CALLDATA_VALUE,
    EIP712_CALLDATA_CALLEE,
    EIP712_CALLDATA_CHAIN_ID,
    EIP712_CALLDATA_SELECTOR,
    EIP712_CALLDATA_AMOUNT,
    EIP712_CALLDATA_SPENDER,
} e_eip712_calldata_state;

typedef enum {
    CALLDATA_INFO_PARAM_NONE = 0,
    CALLDATA_INFO_PARAM_UNSET,
    CALLDATA_INFO_PARAM_SET,
} e_calldata_info_param_state;

typedef struct {
    flist_node_t _list;
    uint8_t index;
    e_eip712_calldata_state state;

    e_calldata_info_param_state value_state : 2;
    e_calldata_info_param_state callee_state : 2;
    e_calldata_info_param_state chain_id_state : 2;
    e_calldata_info_param_state selector_state : 2;
    e_calldata_info_param_state amount_state : 2;
    e_calldata_info_param_state spender_state : 2;

    bool processed : 1;

    // value is stored in the TX context
    uint8_t callee[ADDRESS_LENGTH];
    uint64_t chain_id;
    uint8_t selector[CALLDATA_SELECTOR_SIZE];
    uint8_t amount[INT256_LENGTH];
    uint8_t spender[ADDRESS_LENGTH];
} s_tip712_calldata_info;

bool ui_712_init(void);
void ui_712_deinit(void);
void ui_712_nbgl_cleanup(void);
e_tip712_nfs ui_712_next_field(void);
bool ui_712_review_struct(const void *const struct_ptr);
bool ui_712_review_network(const uint64_t *chain_id);
bool ui_712_feed_to_display(const void *field_ptr,
                            const uint8_t *data,
                            uint8_t length,
                            const uint16_t *complete_length,
                            bool last);
void ui_712_end_sign(void);
unsigned int ui_712_approve(bool);
unsigned int ui_712_reject(bool);
void ui_712_set_title(const char *str, size_t length);
void ui_712_set_value(const char *str, size_t length);
// Used by the generic_tx_parser to mark a per-transaction "intent" separator
// when clear-signing a batch. Only reached in EIP712/TIP712 mode (not in the
// plain TriggerSmartContract path); currently a no-op stub.
void ui_712_set_intent(void);
bool ui_712_message_hash(void);
bool ui_712_prepare_current_pair(void);
bool ui_712_redraw_generic_step(void);
void ui_712_flag_field(bool show,
                       bool name_provided,
                       bool token_join,
                       bool datetime,
                       bool contract_name,
                       bool calldata);
void ui_712_field_flags_reset(void);
void ui_712_finalize_field(void);
void ui_712_set_filtering_mode(e_tip712_filtering_mode mode);
e_tip712_filtering_mode ui_712_get_filtering_mode(void);
void ui_712_set_filters_count(uint8_t count);
uint8_t ui_712_remaining_filters(void);
void ui_712_queue_struct_to_review(void);
void ui_712_token_join_prepare_addr_check(uint8_t index);
void ui_712_token_join_prepare_amount(uint8_t index, const char *name, uint8_t name_length);
void amount_join_set_token_received(void);
bool ui_712_show_raw_key(const void *field_ptr);
bool ui_712_push_new_filter_path(uint32_t path_crc);
void ui_712_set_discarded_path(const char *path, uint8_t length);
const char *ui_712_get_discarded_path(uint8_t *length);
void ui_712_set_trusted_name_requirements(uint8_t type_count,
                                          const e_name_type *types,
                                          uint8_t source_count,
                                          const e_name_source *sources);
uint16_t ui_712_pairs_count(void);
bool ui_712_get_pair(uint16_t index, const char **item, const char **value);
void add_calldata_info(s_tip712_calldata_info *node);
s_tip712_calldata_info *get_calldata_info(uint8_t index);
s_tip712_calldata_info *get_current_calldata_info(void);
bool all_calldata_info_processed(void);
void calldata_info_set_state(uint8_t index, e_eip712_calldata_state state);
bool calldata_info_all_received(const s_tip712_calldata_info *calldata_info);
