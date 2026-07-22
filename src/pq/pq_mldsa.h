#pragma once

#ifdef HAVE_MLDSA_POC

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(API_LEVEL) || API_LEVEL < 26
#error "ML-DSA PoC requires Ledger SDK API level 26 or later"
#endif

#include "lcx_mldsa.h"

#define TRON_PQ_PROTOCOL_VERSION       1U
#define TRON_PQ_SCHEME_ML_DSA_44      2U
#define TRON_PQ_PUBLIC_KEY_SIZE        MLDSA44_PUBLICKEYBYTES
#define TRON_PQ_PRIVATE_KEY_SIZE       MLDSA44_SECRETKEYBYTES
#define TRON_PQ_SIGNATURE_SIZE         MLDSA44_SIGBYTES
#define TRON_PQ_ADDRESS_SIZE           21U
#define TRON_PQ_PUBLIC_KEY_FINGERPRINT 32U

typedef enum {
    PQ_RESULT_PUBLIC_KEY = 1,
    PQ_RESULT_SIGNATURE = 2,
    PQ_RESULT_SELFTEST_MESSAGE = 3,
} pq_result_object_t;

typedef struct {
    uint8_t *public_key;
    uint8_t *private_key;
    uint8_t *signature;
    uint8_t address[TRON_PQ_ADDRESS_SIZE];
    uint8_t public_key_fingerprint[TRON_PQ_PUBLIC_KEY_FINGERPRINT];
    uint8_t selftest_message[32];
    uint32_t session_id;
    uint16_t signature_length;
    bool key_initialized;
    bool selftest_ready;
} pq_mldsa_context_t;

extern pq_mldsa_context_t pq_mldsa_context;

bool pq_mldsa_has_key(void);
uint32_t pq_mldsa_session_id(void);
const uint8_t *pq_mldsa_address(void);

bool pq_mldsa_generate_key(void);
bool pq_mldsa_sign_hash(const uint8_t hash[static 32]);
bool pq_mldsa_run_selftest(void);

bool pq_mldsa_get_result(pq_result_object_t object,
                         const uint8_t **data,
                         uint16_t *data_length);

void pq_mldsa_result_cleanup(void);
void pq_mldsa_full_cleanup(void);

#endif  // HAVE_MLDSA_POC
