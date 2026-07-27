#include "context_712.h"
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "sol_typenames.h"
#include "path.h"
#include "field_hash.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "app_errors.h"      // APDU response codes
#include "shared_context.h"  // reset_app_context
#include "common_ui.h"       // ui_idle
#include "gcs_memory.h"

e_struct_init struct_state = NOT_INITIALIZED;
s_tip712_context *tip712_context = NULL;
static tip712_phase_t tip712_phase = TIP712_PHASE_NONE;

/**
 * Initialize the TIP712 context
 *
 * @return a boolean indicating if the initialization was successful or not
 */
bool tip712_context_init(void) {
    /* A full TIP-712 definition is itself a signing session, even before its
     * first UI page changes appState. Never create it on top of another owner
     * of tmpCtx/UI memory, and never replace an existing definition in place. */
    if ((tip712_context != NULL) || (tip712_phase != TIP712_PHASE_NONE) ||
        (appState != APP_STATE_IDLE)) {
        apdu_response_code = SWO_CONDITIONS_NOT_SATISFIED;
        return false;
    }
    if (!gcs_budget_begin()) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    // init global variables
    tip712_context = gcs_mem_calloc(sizeof(*tip712_context), GCS_MEM_GENERIC);
    if (tip712_context == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        goto error;
    }

    if (sol_typenames_init() == false) {
        goto error;
    }

    if (path_init() == false) {
        goto error;
    }

    if (field_hash_init() == false) {
        goto error;
    }

    if (ui_712_init() == false) {
        goto error;
    }

    if (typed_data_init() == false) {
        goto error;
    }

    tip712_context->go_home_on_failure = true;
    // A missing domain chainId historically maps to zero. If a chainId is
    // received later, field_hash_domain_special_fields() updates this flag
    // after checking whether its numeric value can safely back u64 metadata.
    tip712_context->chain_id_fits_u64 = true;

    struct_state = NOT_INITIALIZED;
    tip712_phase = TIP712_PHASE_FULL_BUILDING;

    return true;
error:
    tip712_context_cleanup();
    (void) gcs_budget_end();
    return false;
}

/**
 * De-initialize the TIP712 context
 */
void tip712_context_cleanup(void) {
    /* The legacy hash-only flow has no heap-backed context. Its phase must
     * still be cleared by the common reset path. */
    tip712_phase = TIP712_PHASE_NONE;
    struct_state = NOT_INITIALIZED;
    if (tip712_context != NULL) {
        typed_data_deinit();
        path_deinit();
        field_hash_deinit();
        ui_712_deinit();
        sol_typenames_deinit();
        gcs_mem_free_and_null((void **) &tip712_context);
    }
}

void tip712_context_deinit(void) {
    tip712_context_cleanup();
    reset_app_context();
}

tip712_phase_t tip712_get_phase(void) {
    return tip712_phase;
}

bool tip712_full_session_in_progress(void) {
    return (tip712_phase == TIP712_PHASE_FULL_BUILDING) ||
           (tip712_phase == TIP712_PHASE_FULL_REVIEW);
}

bool tip712_review_in_progress(void) {
    return (tip712_phase == TIP712_PHASE_FULL_REVIEW) ||
           (tip712_phase == TIP712_PHASE_LEGACY_REVIEW);
}

bool tip712_mark_reviewing(void) {
    if ((tip712_context != NULL) &&
        (tip712_phase == TIP712_PHASE_FULL_BUILDING)) {
        tip712_phase = TIP712_PHASE_FULL_REVIEW;
        return true;
    }
    return false;
}

bool tip712_mark_legacy_reviewing(void) {
    if ((tip712_context != NULL) || (tip712_phase != TIP712_PHASE_NONE) ||
        (appState != APP_STATE_IDLE)) {
        return false;
    }
    tip712_phase = TIP712_PHASE_LEGACY_REVIEW;
    return true;
}
