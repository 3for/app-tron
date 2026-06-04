#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "app_mem_utils.h"
#include "app_errors.h"
#include "format_hash_field_type.h"
#include "hash_bytes.h"
#include "typed_data.h"
#include "type_hash.h"
#include "ui_globals.h"

typedef struct struct_dep_s {
    struct struct_dep_s *next;
    const s_struct_712 *item;
} s_struct_dep;

static bool encode_and_hash_field(const s_struct_712_field *field_ptr) {
    const char *name;

    if (!format_hash_field_type(field_ptr, (cx_hash_t *) &global_sha3)) {
        return false;
    }
    hash_byte(' ', (cx_hash_t *) &global_sha3);

    name = field_ptr->key_name;
    hash_nbytes((uint8_t *) name, strlen(name), (cx_hash_t *) &global_sha3);
    return true;
}

static bool encode_and_hash_type(const s_struct_712 *struct_ptr) {
    const s_struct_712_field *field_ptr;
    const char *struct_name;

    struct_name = struct_ptr->name;
    hash_nbytes((uint8_t *) struct_name, strlen(struct_name), (cx_hash_t *) &global_sha3);
    hash_byte('(', (cx_hash_t *) &global_sha3);

    for (field_ptr = struct_ptr->fields; field_ptr != NULL;
         field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
        if (field_ptr != struct_ptr->fields) {
            hash_byte(',', (cx_hash_t *) &global_sha3);
        }
        if (!encode_and_hash_field(field_ptr)) {
            return false;
        }
    }
    hash_byte(')', (cx_hash_t *) &global_sha3);
    return true;
}

static bool dep_exists(const s_struct_dep *deps, const s_struct_712 *item) {
    while (deps != NULL) {
        if (deps->item == item) {
            return true;
        }
        deps = deps->next;
    }
    return false;
}

static bool dep_push(s_struct_dep **deps, const s_struct_712 *item) {
    s_struct_dep *new_dep = NULL;
    s_struct_dep *tail;

    if (APP_MEM_CALLOC((void **) &new_dep, sizeof(*new_dep)) == false) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    new_dep->item = item;
    if (*deps == NULL) {
        *deps = new_dep;
    } else {
        for (tail = *deps; tail->next != NULL; tail = tail->next)
            ;
        tail->next = new_dep;
    }
    return true;
}

static void dep_clear(s_struct_dep **deps) {
    while (*deps != NULL) {
        s_struct_dep *next = (*deps)->next;

        APP_MEM_FREE(*deps);
        *deps = next;
    }
}

static bool get_struct_dependencies(s_struct_dep **deps, const s_struct_712 *struct_ptr) {
    const s_struct_712_field *field_ptr;
    const char *arg_structname;
    const s_struct_712 *arg_struct_ptr;

    for (field_ptr = struct_ptr->fields; field_ptr != NULL;
         field_ptr = (s_struct_712_field *) ((flist_node_t *) field_ptr)->next) {
        if (field_ptr->type != TYPE_CUSTOM) {
            continue;
        }
        arg_structname = get_struct_field_typename(field_ptr);
        if (arg_structname == NULL) {
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return false;
        }
        arg_struct_ptr = get_structn(arg_structname, strlen(arg_structname));
        if (arg_struct_ptr == NULL) {
            PRINTF("Error: could not find TIP-712 dependency struct \"");
            for (int i = 0; i < (int) strlen(arg_structname); ++i) {
                PRINTF("%c", arg_structname[i]);
            }
            PRINTF("\" during type_hash\n");
            return false;
        }
        if (!dep_exists(*deps, arg_struct_ptr)) {
            if (!dep_push(deps, arg_struct_ptr)) {
                return false;
            }
            if (!get_struct_dependencies(deps, arg_struct_ptr)) {
                return false;
            }
        }
    }
    return true;
}

static bool dep_less_or_equal(const s_struct_dep *a, const s_struct_dep *b) {
    const char *name1 = a->item->name;
    const char *name2 = b->item->name;
    size_t namelen1 = strlen(name1);
    size_t namelen2 = strlen(name2);
    int str_cmp_result = strncmp(name1, name2, MIN(namelen1, namelen2));

    return (str_cmp_result < 0) || ((str_cmp_result == 0) && (namelen1 <= namelen2));
}

static void dep_sort(s_struct_dep **deps) {
    bool changed;

    if ((deps == NULL) || (*deps == NULL)) {
        return;
    }
    do {
        s_struct_dep **cursor = deps;

        changed = false;
        while (((*cursor) != NULL) && ((*cursor)->next != NULL)) {
            s_struct_dep *a = *cursor;
            s_struct_dep *b = a->next;

            if (!dep_less_or_equal(a, b)) {
                a->next = b->next;
                b->next = a;
                *cursor = b;
                changed = true;
            }
            cursor = &((*cursor)->next);
        }
    } while (changed);
}

bool type_hash(const char *const struct_name, const uint8_t struct_name_length, uint8_t *hash_buf) {
    const s_struct_712 *struct_ptr;
    s_struct_dep *deps = NULL;
    cx_err_t error = CX_INTERNAL_ERROR;

    if ((struct_ptr = get_structn(struct_name, struct_name_length)) == NULL) {
        PRINTF("Error: could not find TIP-712 struct \"");
        for (int i = 0; i < struct_name_length; ++i) {
            PRINTF("%c", struct_name[i]);
        }
        PRINTF("\" for type_hash\n");
        return false;
    }
    CX_CHECK(cx_keccak_init_no_throw(&global_sha3, 256));
    if (!get_struct_dependencies(&deps, struct_ptr)) {
        dep_clear(&deps);
        return false;
    }
    dep_sort(&deps);
    if (!encode_and_hash_type(struct_ptr)) {
        dep_clear(&deps);
        return false;
    }
    for (const s_struct_dep *dep = deps; dep != NULL; dep = dep->next) {
        if (!encode_and_hash_type(dep->item)) {
            dep_clear(&deps);
            return false;
        }
    }
    dep_clear(&deps);

    CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha3,
                              CX_LAST,
                              NULL,
                              0,
                              hash_buf,
                              KECCAK256_HASH_BYTESIZE));
    return true;
end:
    dep_clear(&deps);
    return false;
}
