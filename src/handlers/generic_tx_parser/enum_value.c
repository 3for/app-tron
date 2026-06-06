#include <stddef.h>
#include "enum_value.h"

// GCS P1 STUB - see enum_value.h.

const s_enum_value_entry *get_matching_enum(const uint64_t *chain_id,
                                            const uint8_t *contract_addr,
                                            const uint8_t *selector,
                                            uint8_t id,
                                            uint8_t value) {
    (void) chain_id;
    (void) contract_addr;
    (void) selector;
    (void) id;
    (void) value;
    return NULL;
}

void enum_value_cleanup(void) {
}
