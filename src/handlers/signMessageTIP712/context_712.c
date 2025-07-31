#include <string.h>
#include <stdint.h>
#include "context_712.h"
#include "mem_utils.h"
#include "mem.h"
#include "sol_typenames.h"
#include "path.h"
#include "field_hash.h"
#include "ui_logic.h"
#include "typed_data.h"
#include "commands_712.h"
#include "app_errors.h"

extern void reset_app_context();

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
    if ((tip712_context = app_mem_alloc(sizeof(*tip712_context))) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    explicit_bzero(tip712_context, sizeof(*tip712_context));

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
void tip712_context_deinit(void) {
    typed_data_deinit();
    path_deinit();
    field_hash_deinit();
    ui_712_deinit();
    sol_typenames_deinit();
    if (tip712_context != NULL) {
        app_mem_free(tip712_context);
        tip712_context = NULL;
    }
    reset_app_context();
}
