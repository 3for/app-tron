#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t starts;
    uint32_t signs;
    uint32_t approves;
    uint32_t rejects;
    uint32_t idles;
    uint32_t blind_signing_errors;
} tip712_fuzz_ui_stats_t;

void init_tip712_fuzz_environment(void);
void fuzz_set_tip712_environment(uint8_t bits);
tip712_fuzz_ui_stats_t fuzz_get_tip712_ui_stats(void);
