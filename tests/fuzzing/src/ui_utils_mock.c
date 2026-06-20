// Host-side stub of src/nbgl/ui_utils.c. Mirrors the real allocation/cleanup
// behaviour (so the TIP-712 push-model UI can fill g_pairs[] without overflow)
// but drops the NBGL/io_seproxyhal dependencies: on allocation failure it simply
// reports failure to the caller instead of sending a device status word.

#include "ui_utils.h"
#include "app_mem_utils.h"

nbgl_contentTagValue_t *g_pairs = NULL;
nbgl_contentTagValueList_t *g_pairsList = NULL;

char *g_titleMsg = NULL;
char *g_subTitleMsg = NULL;
char *g_finishMsg = NULL;

void ui_pairs_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_pairs);
    APP_MEM_FREE_AND_NULL((void **) &g_pairsList);
}

void ui_buffers_cleanup(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_titleMsg);
    APP_MEM_FREE_AND_NULL((void **) &g_subTitleMsg);
    APP_MEM_FREE_AND_NULL((void **) &g_finishMsg);
}

void ui_all_cleanup(void) {
    ui_pairs_cleanup();
    ui_buffers_cleanup();
}

bool ui_pairs_init(uint8_t nbPairs) {
    ui_pairs_cleanup();
    if (!APP_MEM_CALLOC((void **) &g_pairsList, sizeof(nbgl_contentTagValueList_t))) {
        goto error;
    }
    if (!APP_MEM_CALLOC((void **) &g_pairs, (size_t) nbPairs * sizeof(nbgl_contentTagValue_t))) {
        goto error;
    }
    g_pairsList->nbPairs = nbPairs;
    g_pairsList->pairs = g_pairs;
    g_pairsList->wrapping = true;
    return true;
error:
    ui_all_cleanup();
    return false;
}

bool ui_buffers_init(uint8_t title_len, uint8_t subtitle_len, uint8_t finish_len) {
    ui_buffers_cleanup();
    if ((title_len > 0) && !APP_MEM_CALLOC((void **) &g_titleMsg, title_len)) {
        goto error;
    }
    if ((subtitle_len > 0) && !APP_MEM_CALLOC((void **) &g_subTitleMsg, subtitle_len)) {
        goto error;
    }
    if ((finish_len > 0) && !APP_MEM_CALLOC((void **) &g_finishMsg, finish_len)) {
        goto error;
    }
    return true;
error:
    ui_all_cleanup();
    return false;
}
