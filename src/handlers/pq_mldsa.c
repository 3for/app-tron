#ifdef HAVE_MLDSA_POC

#include <string.h>

#include "apdu_constants.h"
#include "app_errors.h"
#include "helpers.h"
#include "io.h"
#include "os.h"
#include "pq_mldsa.h"
#include "shared_context.h"
#include "ui_globals.h"
#include "ui_review_menu.h"

#define PQ_RESULT_REQUEST_SIZE 8U
#define PQ_RESULT_MAX_CHUNK    220U

int sendPqSessionMetadata(bool include_signature) {
    uint32_t tx = 0;
    uint16_t signature_length = include_signature ? pq_mldsa_context.signature_length : 0;

    if (!pq_mldsa_has_key() ||
        (include_signature && signature_length != TRON_PQ_SIGNATURE_SIZE)) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    G_io_apdu_buffer[tx++] = TRON_PQ_PROTOCOL_VERSION;
    G_io_apdu_buffer[tx++] = TRON_PQ_SCHEME_ML_DSA_44;
    U4BE_ENCODE(G_io_apdu_buffer, tx, pq_mldsa_session_id());
    tx += 4;
    memcpy(G_io_apdu_buffer + tx, pq_mldsa_address(), TRON_PQ_ADDRESS_SIZE);
    tx += TRON_PQ_ADDRESS_SIZE;
    U2BE_ENCODE(G_io_apdu_buffer, tx, TRON_PQ_PUBLIC_KEY_SIZE);
    tx += 2;
    U2BE_ENCODE(G_io_apdu_buffer, tx, signature_length);
    tx += 2;
    memcpy(G_io_apdu_buffer + tx,
           pq_mldsa_context.public_key_fingerprint,
           TRON_PQ_PUBLIC_KEY_FINGERPRINT);
    tx += TRON_PQ_PUBLIC_KEY_FINGERPRINT;

    return io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
}

int handleGetPqCapabilities(uint8_t p1,
                            uint8_t p2,
                            const uint8_t *data,
                            uint16_t data_length) {
    uint32_t tx = 0;
    (void) data;

    if (p1 != 0 || p2 != 0 || data_length != 0) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    G_io_apdu_buffer[tx++] = TRON_PQ_PROTOCOL_VERSION;
    G_io_apdu_buffer[tx++] = TRON_PQ_SCHEME_ML_DSA_44;
    U2BE_ENCODE(G_io_apdu_buffer, tx, TRON_PQ_PUBLIC_KEY_SIZE);
    tx += 2;
    U2BE_ENCODE(G_io_apdu_buffer, tx, TRON_PQ_SIGNATURE_SIZE);
    tx += 2;
    // Bit 0: ephemeral RAM-only key; bit 1: chunked output; bit 2: pure ML-DSA.
    G_io_apdu_buffer[tx++] = 0x07;
    return io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
}

int handleGeneratePqKey(uint8_t p1,
                        uint8_t p2,
                        const uint8_t *data,
                        uint16_t data_length) {
    (void) data;

    if ((p1 != P1_CONFIRM && p1 != P1_NON_CONFIRM) ||
        p2 != TRON_PQ_SCHEME_ML_DSA_44 || data_length != 0) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    if (!pq_mldsa_generate_key()) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }
    if (p1 == P1_NON_CONFIRM) {
        // Retained for the automated PoC probes. Hardware account workflows
        // must use P1_CONFIRM so the address is verified on-device before it
        // receives funds.
        appState = APP_STATE_PQ_KEY_READY;
        return sendPqSessionMetadata(false);
    }

    getBase58FromAddress(pq_mldsa_address(), strings.common.toAddress);
    appState = APP_STATE_PQ_ADDRESS_REVIEW;
    ux_flow_display(APPROVAL_VERIFY_ADDRESS, false);
    return 0;
}

int handleMldsaSelftest(uint8_t p1,
                        uint8_t p2,
                        const uint8_t *data,
                        uint16_t data_length) {
    (void) data;

    if (p1 != 0 || p2 != 0 || data_length != 0) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    if (!pq_mldsa_run_selftest()) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }
    appState = APP_STATE_PQ_RESULT_READY;
    return sendPqSessionMetadata(true);
}

int handleGetPqResult(uint8_t p1,
                      uint8_t p2,
                      const uint8_t *data,
                      uint16_t data_length) {
    const uint8_t *result;
    uint16_t result_length;
    uint32_t session_id;
    uint16_t offset;
    uint16_t requested;
    uint16_t chunk_length;
    uint32_t tx = 0;
    pq_result_object_t object;

    if (p1 != 0 || p2 != 0 || data == NULL || data_length != PQ_RESULT_REQUEST_SIZE) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    session_id = U4BE(data, 0);
    object = (pq_result_object_t) data[4];
    offset = U2BE(data, 5);
    requested = data[7];
    if (session_id != pq_mldsa_session_id() ||
        !pq_mldsa_get_result(object, &result, &result_length) || offset > result_length) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (requested == 0 || requested > PQ_RESULT_MAX_CHUNK) {
        requested = PQ_RESULT_MAX_CHUNK;
    }
    chunk_length = result_length - offset;
    if (chunk_length > requested) {
        chunk_length = requested;
    }

    G_io_apdu_buffer[tx++] = TRON_PQ_PROTOCOL_VERSION;
    G_io_apdu_buffer[tx++] = TRON_PQ_SCHEME_ML_DSA_44;
    U4BE_ENCODE(G_io_apdu_buffer, tx, session_id);
    tx += 4;
    G_io_apdu_buffer[tx++] = (uint8_t) object;
    U2BE_ENCODE(G_io_apdu_buffer, tx, offset);
    tx += 2;
    U2BE_ENCODE(G_io_apdu_buffer, tx, result_length);
    tx += 2;
    G_io_apdu_buffer[tx++] = ((uint32_t) offset + chunk_length == result_length) ? 1 : 0;
    G_io_apdu_buffer[tx++] = (uint8_t) chunk_length;
    memcpy(G_io_apdu_buffer + tx, result + offset, chunk_length);
    tx += chunk_length;

    return io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
}

int handleDeletePqKey(uint8_t p1,
                      uint8_t p2,
                      const uint8_t *data,
                      uint16_t data_length) {
    uint32_t session_id;

    if (p1 != 0 || p2 != 0 || data == NULL || data_length != 4) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    session_id = U4BE(data, 0);
    if (!pq_mldsa_has_key() || session_id != pq_mldsa_session_id()) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    pq_mldsa_full_cleanup();
    appState = APP_STATE_IDLE;
    return io_send_sw(E_OK);
}

int handleClosePqResult(uint8_t p1,
                        uint8_t p2,
                        const uint8_t *data,
                        uint16_t data_length) {
    uint32_t session_id;

    if (p1 != 0 || p2 != 0 || data == NULL || data_length != 4) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    session_id = U4BE(data, 0);
    if (!pq_mldsa_has_key() || session_id != pq_mldsa_session_id()) {
        return io_send_sw(E_INCORRECT_DATA);
    }

    pq_mldsa_result_cleanup();
    appState = APP_STATE_PQ_KEY_READY;
    return io_send_sw(E_OK);
}

#endif  // HAVE_MLDSA_POC
