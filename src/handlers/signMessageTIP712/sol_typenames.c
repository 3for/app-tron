#include <string.h>

#include "app_errors.h"
#include "os_pic.h"
#include "sol_typenames.h"
#include "typed_data.h"
#include "ui_globals.h"

bool sol_typenames_init(void) {
    return true;
}

void sol_typenames_deinit(void) {}

const char *get_struct_field_sol_typename(const void *ptr, uint8_t *length) {
    e_type field_type = struct_field_type(ptr);
    const char *name = NULL;

    switch (field_type) {
        case TYPE_SOL_INT:
            name = "int";
            break;
        case TYPE_SOL_UINT:
            name = "uint";
            break;
        case TYPE_SOL_ADDRESS:
            name = "address";
            break;
        case TYPE_SOL_BOOL:
            name = "bool";
            break;
        case TYPE_SOL_STRING:
            name = "string";
            break;
        case TYPE_SOL_BYTES_FIX:
        case TYPE_SOL_BYTES_DYN:
            name = "bytes";
            break;
        case TYPE_SOL_TRCTOKEN:
            name = "trcToken";
            break;
        default:
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return NULL;
    }
    name = PIC(name);
    if (length != NULL) {
        *length = (uint8_t) strlen(name);
    }
    return name;
}
