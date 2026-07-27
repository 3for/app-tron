#include "sol_typenames.h"
#include "app_mem_utils.h"
#include "mem_utils.h"
#include "os_pic.h"
#include "app_errors.h"  // APDU response codes
#include "parse.h"       // apdu_response_code
#include "typed_data.h"
#include "common_utils.h"  // ARRAY_SIZE
#include "gcs_memory.h"

typedef struct {
    char *name;
    e_type value;
} s_sol_type;

static s_sol_type *g_sol_types = NULL;

/**
 * Initialize solidity typenames in memory
 *
 * @return whether the initialization went well or not
 */
bool sol_typenames_init(void) {
    uint8_t count = TYPES_COUNT - 1;  // because 0 is custom (so not solidity)

    if (g_sol_types != NULL) {
        sol_typenames_deinit();
        return false;
    }
    g_sol_types = gcs_mem_calloc(sizeof(*g_sol_types) * count, GCS_MEM_GENERIC);
    if (g_sol_types == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    for (int i = 0; i < count; ++i) {
        g_sol_types[i].value = i + 1;
        switch (g_sol_types[i].value) {
            case TYPE_SOL_INT:
                g_sol_types[i].name = gcs_mem_strdup("int", GCS_MEM_GENERIC);
                break;
            case TYPE_SOL_UINT:
                g_sol_types[i].name = gcs_mem_strdup("uint", GCS_MEM_GENERIC);
                break;
            case TYPE_SOL_ADDRESS:
                g_sol_types[i].name = gcs_mem_strdup("address", GCS_MEM_GENERIC);
                break;
            case TYPE_SOL_BOOL:
                g_sol_types[i].name = gcs_mem_strdup("bool", GCS_MEM_GENERIC);
                break;
            case TYPE_SOL_STRING:
                g_sol_types[i].name = gcs_mem_strdup("string", GCS_MEM_GENERIC);
                break;
            case TYPE_SOL_BYTES_FIX:
            case TYPE_SOL_BYTES_DYN:
                g_sol_types[i].name = gcs_mem_strdup("bytes", GCS_MEM_GENERIC);
                break;
            case TYPE_SOL_TRCTOKEN:
                g_sol_types[i].name = gcs_mem_strdup("trcToken", GCS_MEM_GENERIC);
                break;
            default:
                apdu_response_code = SWO_INCORRECT_DATA;
                sol_typenames_deinit();
                return false;
        }
        if (g_sol_types[i].name == NULL) {
            apdu_response_code = SWO_INSUFFICIENT_MEMORY;
            sol_typenames_deinit();
            return false;
        }
    }
    return true;
}

void sol_typenames_deinit(void) {
    if (g_sol_types != NULL) {
        for (int i = 0; i < (TYPES_COUNT - 1); ++i) {
            gcs_mem_free(g_sol_types[i].name);
        }
        gcs_mem_free_and_null((void **) &g_sol_types);
    }
}

/**
 * Get typename from a given field
 *
 * @param[in] field_ptr pointer to a struct field
 * @return typename or \ref NULL in case it wasn't found
 */
const char *get_struct_field_sol_typename(const s_struct_712_field *field_ptr) {
    for (int i = 0; i < (TYPES_COUNT - 1); ++i) {
        if (field_ptr->type == g_sol_types[i].value) {
            return g_sol_types[i].name;
        }
    }
    apdu_response_code = SWO_INCORRECT_DATA;
    return NULL;  // Not found
}
