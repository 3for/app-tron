#pragma once

#include <sys/types.h>
#include "parse.h"

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t address[static ADDRESS_SIZE]);
void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out);

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path);

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712);

int initPublicKeyContext(bip32_path_t *bip32_path,
                         char *address58,
                         publicKeyContext_t *public_key_ctx);
