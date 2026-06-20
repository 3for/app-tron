#pragma once

// Host-side mock of src/nbgl/ui_utils.h. The real header pulls in the full NBGL
// stack (nbgl_use_case.h); the standalone fuzz build only needs the tag/value
// pair scratch structures and the alloc/cleanup helpers that the TIP-712 / GCS
// code drives. Only the fields the host-compiled code touches are modelled.

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    const char *item;
    const char *value;
    union {
        const void *valueIcon;
        const void *extension;
    };
    int8_t forcePageStart : 1;
    int8_t centeredInfo : 1;
    int8_t aliasValue : 1;
} nbgl_contentTagValue_t;

typedef struct {
    const nbgl_contentTagValue_t *pairs;
    uint8_t nbPairs;
    bool wrapping;
} nbgl_contentTagValueList_t;

extern nbgl_contentTagValue_t *g_pairs;
extern nbgl_contentTagValueList_t *g_pairsList;

extern char *g_titleMsg;
extern char *g_subTitleMsg;
extern char *g_finishMsg;

void ui_all_cleanup(void);

bool ui_pairs_init(uint8_t nbPairs);
void ui_pairs_cleanup(void);

bool ui_buffers_init(uint8_t title_len, uint8_t subtitle_len, uint8_t finish_len);
void ui_buffers_cleanup(void);
