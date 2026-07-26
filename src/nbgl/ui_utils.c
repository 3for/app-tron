#include "nbgl_use_case.h"
#include "app_mem_utils.h"
#include "ui_callbacks.h"
#include "ui_utils.h"
#include "gcs_memory.h"
#include "mem_utils.h"

nbgl_contentTagValue_t *g_pairs = NULL;
nbgl_contentTagValueList_t *g_pairsList = NULL;

char *g_titleMsg = NULL;
char *g_subTitleMsg = NULL;
char *g_finishMsg = NULL;

/*
 * ui_utils is shared by TIP-712 and GCS. Only GCS has an active session
 * budget, so adding an eight-byte tracked-allocation header to every TIP-712
 * UI object needlessly reduces the already tight Nano S+ review heap. Record
 * the allocator used by each object instead: this preserves exact alloc/free
 * symmetry even if cleanup happens after the active phase changes, while GCS
 * allocations remain fully charged until reset_app_context() ends the budget.
 */
static bool g_pairs_tracked;
static bool g_pairs_list_tracked;
static bool g_title_tracked;
static bool g_subtitle_tracked;
static bool g_finish_tracked;

static bool ui_mem_calloc(void **buffer, size_t size, bool *tracked) {
    if ((buffer == NULL) || (tracked == NULL)) {
        return false;
    }
    *buffer = NULL;
    *tracked = gcs_budget_is_active();
    if (*tracked) {
        if (!gcs_mem_calloc_into(buffer, size, GCS_MEM_UI)) {
            *tracked = false;
            return false;
        }
        return true;
    }
    return APP_MEM_CALLOC(buffer, size);
}

static void ui_mem_free_and_null(void **buffer, bool *tracked) {
    if ((buffer == NULL) || (tracked == NULL)) {
        return;
    }
    if (*buffer != NULL) {
        if (*tracked) {
            gcs_mem_free(*buffer);
        } else {
            APP_MEM_FREE(*buffer);
        }
        *buffer = NULL;
    }
    *tracked = false;
}

/**
 * Internal cleanup for partially initialized UI buffers. The caller owns the
 * APDU status and signing-state reset, avoiding duplicate asynchronous replies.
 */
static void _cleanup(void) {
    ui_all_cleanup();
}

void ui_pairs_cleanup(void) {
    ui_mem_free_and_null((void **) &g_pairs, &g_pairs_tracked);
    ui_mem_free_and_null((void **) &g_pairsList, &g_pairs_list_tracked);
}

void ui_buffers_cleanup(void) {
    ui_mem_free_and_null((void **) &g_titleMsg, &g_title_tracked);
    ui_mem_free_and_null((void **) &g_subTitleMsg, &g_subtitle_tracked);
    ui_mem_free_and_null((void **) &g_finishMsg, &g_finish_tracked);
}

void ui_all_cleanup(void) {
    ui_pairs_cleanup();
    ui_buffers_cleanup();
}

/**
 * Initialize the buffers
 *
 * @return whether the initialization was successful
 */
bool ui_pairs_init(uint8_t nbPairs) {
    ui_pairs_cleanup();
    // Allocate the pairsList memory
    if (!ui_mem_calloc((void **) &g_pairsList,
                       sizeof(nbgl_contentTagValueList_t),
                       &g_pairs_list_tracked)) {
        goto error;
    }

    // Allocate the pairs memory
    if (!ui_mem_calloc((void **) &g_pairs,
                       (size_t) nbPairs * sizeof(nbgl_contentTagValue_t),
                       &g_pairs_tracked)) {
        goto error;
    }
    g_pairsList->nbPairs = nbPairs;
    g_pairsList->pairs = g_pairs;
    g_pairsList->wrapping = true;
    return true;
error:
    _cleanup();
    return false;
}

/**
 * Initialize the buffers
 *
 * @param title_len Length of the Title message buffer
 * @param subtitle_len Length of the SubTitle message buffer
 * @param finish_len Length of the Finish message buffer
 * @return whether the initialization was successful
 */
bool ui_buffers_init(uint8_t title_len, uint8_t subtitle_len, uint8_t finish_len) {
    ui_buffers_cleanup();
    if (title_len > 0) {
        // Allocate the Title message buffer
        if (!ui_mem_calloc((void **) &g_titleMsg, title_len, &g_title_tracked)) {
            goto error;
        }
    }
    if (subtitle_len > 0) {
        // Allocate the SubTitle message buffer
        if (!ui_mem_calloc((void **) &g_subTitleMsg,
                           subtitle_len,
                           &g_subtitle_tracked)) {
            goto error;
        }
    }
    if (finish_len > 0) {
        // Allocate the Finish message buffer
        if (!ui_mem_calloc((void **) &g_finishMsg, finish_len, &g_finish_tracked)) {
            goto error;
        }
    }

    return true;
error:
    _cleanup();
    return false;
}
