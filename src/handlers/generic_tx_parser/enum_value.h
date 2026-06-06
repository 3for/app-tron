#pragma once

// ---------------------------------------------------------------------------
// GCS P1 STUB.
//
// app-ethereum maps opaque enum byte values to human-readable names via signed
// descriptors (INS_PROVIDE_ENUM_VALUE, 0x24). The generic_tx_parser ENUM field
// formatter calls get_matching_enum() to resolve them.
//
// Tron does not implement 0x24 yet, so this stub keeps app-ethereum's
// s_enum_value_entry layout and get_matching_enum() signature but never finds a
// match. To be replaced when enum-value support lands.
// ---------------------------------------------------------------------------

#include <stdint.h>
#include "lists.h"         // flist_node_t
#include "common_utils.h"  // ADDRESS_LENGTH
#include "plugin_utils.h"  // SELECTOR_SIZE

#define MAX_ENUM_NAME_SIZE 21

typedef struct {
    flist_node_t _list;
    uint64_t chain_id;
    uint8_t contract_addr[ADDRESS_LENGTH];
    uint8_t selector[SELECTOR_SIZE];
    uint8_t id;
    uint8_t value;
    char name[MAX_ENUM_NAME_SIZE];
} s_enum_value_entry;

// Returns the matching enum entry, or NULL when none is known (always NULL in
// the P1 stub).
const s_enum_value_entry *get_matching_enum(const uint64_t *chain_id,
                                            const uint8_t *contract_addr,
                                            const uint8_t *selector,
                                            uint8_t id,
                                            uint8_t value);

void enum_value_cleanup(void);
