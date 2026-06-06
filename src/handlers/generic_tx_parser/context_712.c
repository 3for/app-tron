#include <stddef.h>
#include "context_712.h"

// GCS P1 STUB - see context_712.h. Never reached in APP_STATE_SIGNING_TX mode.

static s_eip712_calldata_info g_dummy_calldata_info;

s_eip712_calldata_info *get_current_calldata_info(void) {
    return &g_dummy_calldata_info;
}

bool calldata_info_all_received(const s_eip712_calldata_info *info) {
    (void) info;
    return false;
}
