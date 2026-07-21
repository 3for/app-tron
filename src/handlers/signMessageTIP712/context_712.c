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

e_struct_init struct_state = NOT_INITIALIZED;
s_tip712_context *tip712_context = NULL;

/**
 * Initialize the TIP712 context
 *
 * @return a boolean indicating if the initialization was successful or not
 */
bool tip712_context_init(void) {
    if (tip712_context != NULL) {
        tip712_context_deinit();
        return false;
    }

    // init global variables
    if (APP_MEM_CALLOC((void **) &tip712_context, sizeof(*tip712_context)) == false) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    if (sol_typenames_init() == false) {
        return false;
    }

    if (path_init() == false) {
        return false;
    }

    if (field_hash_init() == false) {
        return false;
    }

    if (ui_712_init() == false) {
        return false;
    }

    if (typed_data_init() == false) {
        return false;
    }

    tip712_context->go_home_on_failure = true;

    struct_state = NOT_INITIALIZED;

    return true;
}

/**
 * De-initialize the TIP712 context
 */
void tip712_context_cleanup(void) {
    if (tip712_context == NULL) {
        return;
    }
    typed_data_deinit();
    path_deinit();
    field_hash_deinit();
    ui_712_deinit();
    sol_typenames_deinit();
    APP_MEM_FREE_AND_NULL((void **) &tip712_context);
}

void tip712_context_deinit(void) {
    tip712_context_cleanup();
    reset_app_context();
}
