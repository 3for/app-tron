#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "helpers.h"

void getAddressFromPublicKey(const uint8_t *public_key, uint8_t address[static ADDRESS_SIZE]) {
    for (size_t i = 0; i < ADDRESS_SIZE; i++) {
        address[i] = public_key[i % PUBLIC_KEY_SIZE];
    }
    address[0] = 0x41U;
}

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out) {
    static const char hex[] = "0123456789abcdef";

    for (size_t i = 0; i < BASE58CHECK_ADDRESS_SIZE; i++) {
        out[i] = hex[address[i % ADDRESS_SIZE] & 0x0FU];
    }
    out[BASE58CHECK_ADDRESS_SIZE] = '\0';
}

__attribute__((weak)) off_t read_bip32_path(const uint8_t *buffer,
                                            size_t length,
                                            bip32_path_t *path) {
    if ((length == 0U) || (buffer[0] > MAX_BIP32_PATH) ||
        (length < 1U + ((size_t) buffer[0] * 4U))) {
        return -1;
    }

    path->length = buffer[0];
    for (size_t i = 0; i < path->length; i++) {
        const size_t offset = 1U + i * 4U;
        path->indices[i] = ((uint32_t) buffer[offset] << 24U) |
                           ((uint32_t) buffer[offset + 1U] << 16U) |
                           ((uint32_t) buffer[offset + 2U] << 8U) |
                           (uint32_t) buffer[offset + 3U];
    }
    return (off_t) (1U + ((size_t) path->length * 4U));
}
