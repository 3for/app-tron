#include <string.h>

#include "app_mem_utils.h"
#include "app_errors.h"
#include "mem_utils.h"
#include "type_hash.h"
#include "format_hash_field_type.h"
#include "hash_bytes.h"
#include "typed_data.h"
#include "ui_globals.h"
#include "lists.h"
#include "gcs_memory.h"

/**
 * Encode & hash the given structure field
 *
 * @param[in] field_ptr pointer to the struct field
 * @return \ref true it finished correctly, \ref false if it didn't (memory allocation)
 */
static bool encode_and_hash_field(const s_struct_712_field *field_ptr) {
    const char *name;

    if (!format_hash_field_type(field_ptr, (cx_hash_t *) &global_sha3)) {
        return false;
    }
    // space between field type name and field name
    if (!hash_byte_no_throw(' ', (cx_hash_t *) &global_sha3)) {
        return false;
    }

    // field name
    name = field_ptr->key_name;
    return hash_nbytes_no_throw((const uint8_t *) name,
                                strlen(name),
                                (cx_hash_t *) &global_sha3);
}

/**
 * Encode and hash a given structure type into the active Keccak context
 *
 * @param[in] struct_ptr pointer to the structure we want the typestring of
 * @return \ref true on success, \ref false on error
 */
static bool encode_and_hash_type(const s_struct_712 *struct_ptr) {
    const char *struct_name;
    const s_struct_712_field *field_ptr;

    // struct name
    struct_name = struct_ptr->name;
    if (!hash_nbytes_no_throw((const uint8_t *) struct_name,
                              strlen(struct_name),
                              (cx_hash_t *) &global_sha3)) {
        return false;
    }

    // opening struct parentheses
    if (!hash_byte_no_throw('(', (cx_hash_t *) &global_sha3)) {
        return false;
    }

    for (field_ptr = struct_ptr->fields; field_ptr != NULL;
         field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
        // comma separating struct fields
        if (field_ptr != struct_ptr->fields) {
            if (!hash_byte_no_throw(',', (cx_hash_t *) &global_sha3)) {
                return false;
            }
        }

        if (encode_and_hash_field(field_ptr) == false) {
            return false;
        }
    }
    // closing struct parentheses
    return hash_byte_no_throw(')', (cx_hash_t *) &global_sha3);
}

typedef struct struct_dep {
    flist_node_t _list;
    const s_struct_712 *s;
} s_struct_dep;

/**
 * Find all the dependencies from a given structure
 *
 * @param[out] deps_count count of how many struct dependency pointers
 * @param[in] first_dep pointer to the first dependency pointer
 * @param[in] struct_ptr pointer to the struct we are getting the dependencies of
 * @return pointer to the first found dependency, \ref NULL otherwise
 */
static bool get_struct_dependencies(s_struct_dep **first_dep, const s_struct_712 *struct_ptr) {
    const s_struct_712_field *field_ptr;
    const char *arg_structname;
    const s_struct_712 *arg_struct_ptr;
    s_struct_dep *tmp;
    s_struct_dep *new_dep;
    s_struct_dep *next_dep = NULL;
    const s_struct_712 *current = struct_ptr;

    while (current != NULL) {
        for (field_ptr = current->fields; field_ptr != NULL;
             field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
            if (field_ptr->type != TYPE_CUSTOM) {
                continue;
            }
            // get struct name
            arg_structname = get_struct_field_typename(field_ptr);
            // from its name, get the pointer to its definition
            if ((arg_structname == NULL) ||
                ((arg_struct_ptr = get_structn(arg_structname, strlen(arg_structname))) == NULL)) {
                PRINTF("Error: could not find TIP-712 dependency struct \"");
                for (int i = 0; (arg_structname != NULL) && (i < (int) strlen(arg_structname));
                     ++i) {
                    PRINTF("%c", arg_structname[i]);
                }
                PRINTF("\" during type_hash\n");
                return false;
            }

            // check if it is not already present in the dependencies array
            for (tmp = *first_dep; tmp != NULL;
                 tmp = (s_struct_dep *) ((flist_node_t *) tmp)->next) {
                // it's a match!
                if (tmp->s == arg_struct_ptr) {
                    break;
                }
            }
            // If it is not present, append it. The outer loop walks this list
            // iteratively, avoiding host-controlled recursion depth.
            if (tmp == NULL) {
                new_dep = gcs_mem_calloc(sizeof(*new_dep), GCS_MEM_TEMPORARY);
                if (new_dep == NULL) {
                    apdu_response_code = SWO_INSUFFICIENT_MEMORY;
                    return false;
                }
                new_dep->s = arg_struct_ptr;
                flist_push_back((flist_node_t **) first_dep, (flist_node_t *) new_dep);
            }
        }
        if (next_dep == NULL) {
            next_dep = *first_dep;
        } else {
            next_dep = (s_struct_dep *) ((flist_node_t *) next_dep)->next;
        }
        current = (next_dep == NULL) ? NULL : next_dep->s;
    }
    return true;
}

static bool compare_struct_deps(const s_struct_dep *a, const s_struct_dep *b) {
    const char *name1, *name2;
    size_t namelen1, namelen2;
    int str_cmp_result;

    name1 = a->s->name;
    namelen1 = strlen(name1);
    name2 = b->s->name;
    namelen2 = strlen(name2);

    str_cmp_result = strncmp(name1, name2, MIN(namelen1, namelen2));
    if ((str_cmp_result > 0) || ((str_cmp_result == 0) && (namelen1 > namelen2))) {
        return false;
    }
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_struct_dep(s_struct_dep *sdep) {
    gcs_mem_free(sdep);
}

/**
 * Encode the structure's type and hash it
 *
 * @param[in] struct_name name of the given struct
 * @param[in] struct_name_length length of the name of the given struct
 * @param[out] hash_buf buffer containing the resulting type_hash
 * @return whether the type_hash was successful or not
 */
bool type_hash(const char *struct_name, const uint8_t struct_name_length, uint8_t *hash_buf) {
    const void *struct_ptr;
    s_struct_dep *deps;

    if ((struct_ptr = get_structn(struct_name, struct_name_length)) == NULL) {
        PRINTF("Error: could not find TIP-712 struct \"");
        for (int i = 0; i < struct_name_length; ++i) {
            PRINTF("%c", struct_name[i]);
        }
        PRINTF("\" for type_hash\n");
        return false;
    }
    if (cx_keccak_init_no_throw(&global_sha3, 256) != CX_OK) {
        return false;
    }
    deps = NULL;
    if (!get_struct_dependencies(&deps, struct_ptr)) {
        flist_clear((flist_node_t **) &deps, (f_list_node_del) &delete_struct_dep);
        return false;
    }
    flist_sort((flist_node_t **) &deps, (f_list_node_cmp) &compare_struct_deps);
    if (encode_and_hash_type(struct_ptr) == false) {
        flist_clear((flist_node_t **) &deps, (f_list_node_del) &delete_struct_dep);
        return false;
    }
    // loop over each struct and generate string
    for (const s_struct_dep *tmp = deps; tmp != NULL;
         tmp = (s_struct_dep *) ((flist_node_t *) tmp)->next) {
        if (encode_and_hash_type(tmp->s) == false) {
            flist_clear((flist_node_t **) &deps, (f_list_node_del) &delete_struct_dep);
            return false;
        }
    }
    flist_clear((flist_node_t **) &deps, (f_list_node_del) &delete_struct_dep);

    // copy hash into memory
    if (finalize_hash((cx_hash_t *) &global_sha3, hash_buf, KECCAK256_HASH_BYTESIZE) != true) {
        return false;
    }
    return true;
}
