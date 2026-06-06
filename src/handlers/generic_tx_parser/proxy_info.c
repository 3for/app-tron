#include "proxy_info.h"

// GCS P1 STUB - see proxy_info.h.

const uint8_t *get_implem_contract(const uint64_t *chain_id,
                                   const uint8_t *addr,
                                   const uint8_t *selector) {
    (void) chain_id;
    (void) addr;
    (void) selector;
    return NULL;
}

const uint8_t *get_proxy_contract(const uint64_t *chain_id,
                                  const uint8_t *addr,
                                  const uint8_t *selector) {
    (void) chain_id;
    (void) addr;
    (void) selector;
    return NULL;
}

void proxy_cleanup(void) {
}
