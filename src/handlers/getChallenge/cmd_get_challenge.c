#include <os.h>
#include <os_io.h>
#include <cx.h>
// #include "apdu_constants.h"
#include "challenge.h"
#include "app_errors.h"

static uint32_t challenge;

/**
 * Generate a new challenge from the Random Number Generator
 */
void roll_challenge(void) {
#ifdef HAVE_CHALLENGE_NO_CHECK
    challenge = 0x12345678;
#else
    challenge = cx_rng_u32();
#endif
}

/**
 * Get the current challenge
 *
 * @return challenge
 */
uint32_t get_challenge(void) {
    return challenge;
}

/**
 * Check the challenge
 *
 * @return whether the received challenge matches the current one
 */
bool check_challenge(uint32_t received_challenge) {
    UNUSED(received_challenge);
#ifndef HAVE_CHALLENGE_NO_CHECK
    if (received_challenge != challenge) {
        PRINTF("Error: challenge mismatch!\n");
        return false;
    }
#endif
    return true;
}

/**
 * Send back the current challenge
 */
uint16_t handle_get_challenge(uint8_t p1, uint8_t p2, const uint8_t *data, uint8_t length) {
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(data);
    UNUSED(length);
    PRINTF("New challenge -> %u\n", get_challenge());
    U4BE_ENCODE(G_io_apdu_buffer, 0, get_challenge());
    uint32_t tx = 4;

    G_io_apdu_buffer[tx] = (APDU_RESPONSE_OK >> 8) & 0xff;
    G_io_apdu_buffer[tx + 1] = APDU_RESPONSE_OK & 0xff;

    tx += 2;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);

    return 0;
}
