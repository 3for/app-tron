#pragma once

#include <sys/types.h>
#include "parse.h"

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t address[static ADDRESS_SIZE]);
void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out, bool truncate);
bool getAddressFromBase58(const char *in, size_t in_len, uint8_t out[static ADDRESS_SIZE]);

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path);

off_t read_bip32_path_712(const uint8_t *buffer,
                          uint16_t length,
                          messageSigningContext712_t *ctx_712);
