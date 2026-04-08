#include "helpers.h"

#include "bip32_path_parser.h"

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712) {
    if (ctx_712 == NULL) {
        return -1;
    }

    return read_bip32_path_words(buffer,
                                 length,
                                 &ctx_712->pathLength,
                                 ctx_712->bip32Path,
                                 MAX_BIP32_PATH);
}
