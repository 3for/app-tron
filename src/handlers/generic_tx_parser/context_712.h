#pragma once

// ---------------------------------------------------------------------------
// GCS P1 STUB.
//
// In app-ethereum the generic_tx_parser can also drive EIP-712 clear-signing,
// where it tracks whether the message's embedded calldata has been fully
// received. tx_ctx.c references that state through context_712.h.
//
// P1 only handles TriggerSmartContract transactions (APP_STATE_SIGNING_TX); the
// TIP712/EIP712 code paths in tx_ctx.c are never entered. This stub exists only
// so those paths compile. To be replaced if/when TIP712 is routed through the
// generic_tx_parser.
// ---------------------------------------------------------------------------

#include <stdbool.h>

typedef struct {
    bool processed;
} s_eip712_calldata_info;

s_eip712_calldata_info *get_current_calldata_info(void);
bool calldata_info_all_received(const s_eip712_calldata_info *info);
