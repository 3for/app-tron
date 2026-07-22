#ifdef HAVE_MLDSA_POC

#include <string.h>

#include "app_mem_utils.h"
#include "cx.h"
#include "helpers.h"
#include "os.h"
#include "pq_mldsa.h"

pq_mldsa_context_t pq_mldsa_context;

static void derive_pq_address(const uint8_t public_key[static TRON_PQ_PUBLIC_KEY_SIZE],
                              uint8_t address[static TRON_PQ_ADDRESS_SIZE]) {
    uint8_t digest[32];
    cx_sha3_t keccak;

    CX_ASSERT(cx_keccak_init_no_throw(&keccak, 256));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &keccak,
                               CX_LAST,
                               public_key,
                               TRON_PQ_PUBLIC_KEY_SIZE,
                               digest,
                               sizeof(digest)));

    address[0] = ADD_PRE_FIX_BYTE_MAINNET;
    memcpy(address + 1, digest + 12, 20);
    explicit_bzero(digest, sizeof(digest));
}

static void fingerprint_public_key(
    const uint8_t public_key[static TRON_PQ_PUBLIC_KEY_SIZE],
    uint8_t fingerprint[static TRON_PQ_PUBLIC_KEY_FINGERPRINT]) {
    cx_hash_sha256(public_key,
                   TRON_PQ_PUBLIC_KEY_SIZE,
                   fingerprint,
                   TRON_PQ_PUBLIC_KEY_FINGERPRINT);
}

bool pq_mldsa_has_key(void) {
    return pq_mldsa_context.key_initialized && pq_mldsa_context.public_key != NULL &&
           pq_mldsa_context.private_key != NULL;
}

uint32_t pq_mldsa_session_id(void) {
    return pq_mldsa_context.session_id;
}

const uint8_t *pq_mldsa_address(void) {
    return pq_mldsa_context.address;
}

void pq_mldsa_result_cleanup(void) {
    if (pq_mldsa_context.signature != NULL) {
        explicit_bzero(pq_mldsa_context.signature, TRON_PQ_SIGNATURE_SIZE);
        APP_MEM_FREE_AND_NULL((void **) &pq_mldsa_context.signature);
    }
    pq_mldsa_context.signature_length = 0;
    pq_mldsa_context.selftest_ready = false;
    explicit_bzero(pq_mldsa_context.selftest_message,
                   sizeof(pq_mldsa_context.selftest_message));
}

void pq_mldsa_full_cleanup(void) {
    pq_mldsa_result_cleanup();

    if (pq_mldsa_context.private_key != NULL) {
        explicit_bzero(pq_mldsa_context.private_key, TRON_PQ_PRIVATE_KEY_SIZE);
        APP_MEM_FREE_AND_NULL((void **) &pq_mldsa_context.private_key);
    }
    if (pq_mldsa_context.public_key != NULL) {
        explicit_bzero(pq_mldsa_context.public_key, TRON_PQ_PUBLIC_KEY_SIZE);
        APP_MEM_FREE_AND_NULL((void **) &pq_mldsa_context.public_key);
    }

    explicit_bzero(&pq_mldsa_context, sizeof(pq_mldsa_context));
}

bool pq_mldsa_generate_key(void) {
    cx_err_t error;

    pq_mldsa_full_cleanup();

    pq_mldsa_context.public_key = APP_MEM_ALLOC(TRON_PQ_PUBLIC_KEY_SIZE);
    pq_mldsa_context.private_key = APP_MEM_ALLOC(TRON_PQ_PRIVATE_KEY_SIZE);
    if (pq_mldsa_context.public_key == NULL || pq_mldsa_context.private_key == NULL) {
        pq_mldsa_full_cleanup();
        return false;
    }

    io_seproxyhal_io_heartbeat();
    error = MLDSA_keygen(pq_mldsa_context.public_key,
                         TRON_PQ_PUBLIC_KEY_SIZE,
                         pq_mldsa_context.private_key,
                         TRON_PQ_PRIVATE_KEY_SIZE,
                         MLDSA_44);
    io_seproxyhal_io_heartbeat();
    if (error != CX_OK) {
        pq_mldsa_full_cleanup();
        return false;
    }

    derive_pq_address(pq_mldsa_context.public_key, pq_mldsa_context.address);
    fingerprint_public_key(pq_mldsa_context.public_key,
                           pq_mldsa_context.public_key_fingerprint);
    cx_rng_no_throw((uint8_t *) &pq_mldsa_context.session_id,
                    sizeof(pq_mldsa_context.session_id));
    if (pq_mldsa_context.session_id == 0) {
        pq_mldsa_context.session_id = 1;
    }
    pq_mldsa_context.key_initialized = true;
    return true;
}

bool pq_mldsa_sign_hash(const uint8_t hash[static 32]) {
    cx_err_t error;
    size_t actual_length = 0;

    if (!pq_mldsa_has_key() || hash == NULL) {
        return false;
    }

    pq_mldsa_result_cleanup();
    pq_mldsa_context.signature = APP_MEM_ALLOC(TRON_PQ_SIGNATURE_SIZE);
    if (pq_mldsa_context.signature == NULL) {
        return false;
    }

    io_seproxyhal_io_heartbeat();
    error = MLDSA_sign(pq_mldsa_context.signature,
                       TRON_PQ_SIGNATURE_SIZE,
                       &actual_length,
                       hash,
                       32,
                       NULL,
                       0,
                       pq_mldsa_context.private_key,
                       TRON_PQ_PRIVATE_KEY_SIZE,
                       MLDSA_44);
    io_seproxyhal_io_heartbeat();
    if (error != CX_OK || actual_length != TRON_PQ_SIGNATURE_SIZE) {
        pq_mldsa_result_cleanup();
        return false;
    }

    error = MLDSA_verify(pq_mldsa_context.signature,
                         actual_length,
                         hash,
                         32,
                         NULL,
                         0,
                         pq_mldsa_context.public_key,
                         TRON_PQ_PUBLIC_KEY_SIZE,
                         MLDSA_44);
    if (error != CX_OK) {
        pq_mldsa_result_cleanup();
        return false;
    }

    pq_mldsa_context.signature_length = (uint16_t) actual_length;
    return true;
}

bool pq_mldsa_run_selftest(void) {
    static const uint8_t SELFTEST_MESSAGE[32] = {
        0x8e, 0x93, 0x40, 0xa7, 0x17, 0x9c, 0xb6, 0x78,
        0x35, 0x9f, 0x90, 0xd4, 0x66, 0xc7, 0x19, 0xba,
        0x44, 0x42, 0x8f, 0x55, 0xd3, 0x5f, 0x22, 0x43,
        0x6f, 0x10, 0x74, 0x78, 0x18, 0x0b, 0xde, 0x9f,
    };

    if (!pq_mldsa_generate_key()) {
        return false;
    }
    if (!pq_mldsa_sign_hash(SELFTEST_MESSAGE)) {
        pq_mldsa_full_cleanup();
        return false;
    }

    memcpy(pq_mldsa_context.selftest_message,
           SELFTEST_MESSAGE,
           sizeof(SELFTEST_MESSAGE));
    pq_mldsa_context.selftest_ready = true;
    return true;
}

bool pq_mldsa_get_result(pq_result_object_t object,
                         const uint8_t **data,
                         uint16_t *data_length) {
    if (data == NULL || data_length == NULL || !pq_mldsa_context.key_initialized) {
        return false;
    }

    switch (object) {
        case PQ_RESULT_PUBLIC_KEY:
            *data = pq_mldsa_context.public_key;
            *data_length = TRON_PQ_PUBLIC_KEY_SIZE;
            return *data != NULL;
        case PQ_RESULT_SIGNATURE:
            *data = pq_mldsa_context.signature;
            *data_length = pq_mldsa_context.signature_length;
            return *data != NULL && *data_length == TRON_PQ_SIGNATURE_SIZE;
        case PQ_RESULT_SELFTEST_MESSAGE:
            *data = pq_mldsa_context.selftest_message;
            *data_length = sizeof(pq_mldsa_context.selftest_message);
            return pq_mldsa_context.selftest_ready;
        default:
            return false;
    }
}

#endif  // HAVE_MLDSA_POC
