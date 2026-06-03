#include <stdlib.h>
#include <string.h>

#include "app_mem_utils.h"
#include "app_errors.h"
#include "context_712.h"
#include "sol_typenames.h"
#include "typed_data.h"

static s_struct_712 *g_structs = NULL;

static uint8_t list_count_fields(const s_struct_712_field *field) {
    uint8_t count = 0;

    while (field != NULL) {
        if (count == UINT8_MAX) {
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return 0;
        }
        count++;
        field = field->next;
    }
    return count;
}

static uint8_t list_count_structs(const s_struct_712 *item) {
    uint8_t count = 0;

    while (item != NULL) {
        if (count == UINT8_MAX) {
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return 0;
        }
        count++;
        item = item->next;
    }
    return count;
}

static void free_field(s_struct_712_field *field) {
    if (field == NULL) {
        return;
    }
    APP_MEM_FREE(field->type_name);
    APP_MEM_FREE(field->array_levels);
    APP_MEM_FREE(field->key_name);
    APP_MEM_FREE(field);
}

static void free_fields(s_struct_712_field *field) {
    while (field != NULL) {
        s_struct_712_field *next = field->next;

        free_field(field);
        field = next;
    }
}

static void free_struct(s_struct_712 *item) {
    if (item == NULL) {
        return;
    }
    APP_MEM_FREE(item->name);
    free_fields(item->fields);
    APP_MEM_FREE(item);
}

bool typed_data_init(void) {
    if (g_structs != NULL) {
        typed_data_deinit();
        return false;
    }
    return true;
}

void typed_data_deinit(void) {
    while (g_structs != NULL) {
        s_struct_712 *next = g_structs->next;

        free_struct(g_structs);
        g_structs = next;
    }
}

const void *get_array_in_mem(const void *ptr, uint8_t *array_size) {
    if (ptr == NULL) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return NULL;
    }
    if (array_size != NULL) {
        *array_size = *(const uint8_t *) ptr;
    }
    return (const uint8_t *) ptr + sizeof(uint8_t);
}

const char *get_string_in_mem(const uint8_t *ptr, uint8_t *string_length) {
    return (const char *) get_array_in_mem(ptr, string_length);
}

bool struct_field_is_array(const void *ptr) {
    const s_struct_712_field *field = ptr;

    return (field != NULL) && field->type_is_array;
}

bool struct_field_has_typesize(const void *ptr) {
    const s_struct_712_field *field = ptr;

    return (field != NULL) && field->type_has_size;
}

e_type struct_field_type(const void *ptr) {
    const s_struct_712_field *field = ptr;

    if (field == NULL) {
        return TYPE_CUSTOM;
    }
    return field->type;
}

uint8_t get_struct_field_typesize(const void *ptr) {
    const s_struct_712_field *field = ptr;

    if (field == NULL) {
        return 0;
    }
    return field->type_size;
}

const char *get_struct_field_custom_typename(const void *ptr, uint8_t *length) {
    const s_struct_712_field *field = ptr;

    if ((field == NULL) || (field->type_name == NULL)) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    if (length != NULL) {
        *length = (uint8_t) strlen(field->type_name);
    }
    return field->type_name;
}

const char *get_struct_field_typename(const void *ptr, uint8_t *length) {
    const s_struct_712_field *field = ptr;
    const char *name;

    if (field == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    if (field->type == TYPE_CUSTOM) {
        return get_struct_field_custom_typename(field, length);
    }
    name = get_struct_field_sol_typename(field, length);
    if (name == NULL) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
    }
    return name;
}

e_array_type struct_field_array_depth(const void *ptr, uint8_t *array_size) {
    const s_struct_712_field_array_level *array_level = ptr;

    if (array_level == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return ARRAY_DYNAMIC;
    }
    if ((array_level->type == ARRAY_FIXED_SIZE) && (array_size != NULL)) {
        *array_size = array_level->size;
    }
    return array_level->type;
}

const void *get_next_struct_field_array_lvl(const void *ptr) {
    const s_struct_712_field_array_level *array_level = ptr;

    if (array_level == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    return array_level + 1;
}

const void *get_struct_field_array_lvls_array(const void *ptr, uint8_t *length) {
    const s_struct_712_field *field = ptr;

    if (field == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    if (length != NULL) {
        *length = field->array_level_count;
    }
    return field->array_levels;
}

const char *get_struct_field_keyname(const void *ptr, uint8_t *length) {
    const s_struct_712_field *field = ptr;

    if ((field == NULL) || (field->key_name == NULL)) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    if (length != NULL) {
        *length = (uint8_t) strlen(field->key_name);
    }
    return field->key_name;
}

const void *get_next_struct_field(const void *ptr) {
    const s_struct_712_field *field = ptr;

    if (field == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    return field->next;
}

const char *get_struct_name(const void *ptr, uint8_t *length) {
    const s_struct_712 *item = ptr;

    if ((item == NULL) || (item->name == NULL)) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    if (length != NULL) {
        *length = (uint8_t) strlen(item->name);
    }
    return item->name;
}

const void *get_struct_fields_array(const void *ptr, uint8_t *length) {
    const s_struct_712 *item = ptr;

    if (item == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    if (length != NULL) {
        *length = list_count_fields(item->fields);
    }
    return item->fields;
}

const void *get_next_struct(const void *ptr) {
    const s_struct_712 *item = ptr;

    if (item == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    return item->next;
}

const void *get_structs_array(uint8_t *length) {
    if (length != NULL) {
        *length = list_count_structs(g_structs);
    }
    return g_structs;
}

const s_struct_712 *get_struct_list(void) {
    return g_structs;
}

const s_struct_712 *get_structn(const char *name, uint8_t length) {
    const s_struct_712 *item;

    if (name == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return NULL;
    }
    for (item = g_structs; item != NULL; item = item->next) {
        if ((item->name != NULL) && (length == strlen(item->name)) &&
            (memcmp(name, item->name, length) == 0)) {
            return item;
        }
    }
    apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
    return NULL;
}

bool set_struct_name(uint8_t length, const uint8_t *name) {
    s_struct_712 *new_struct = NULL;
    s_struct_712 *tail;

    if ((name == NULL) || (length == 0)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    if (APP_MEM_CALLOC((void **) &new_struct, sizeof(*new_struct)) == false) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    if ((new_struct->name = APP_MEM_ALLOC((size_t) length + 1U)) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        free_struct(new_struct);
        return false;
    }
    memcpy(new_struct->name, name, length);
    new_struct->name[length] = '\0';

    if (g_structs == NULL) {
        g_structs = new_struct;
    } else {
        for (tail = g_structs; tail->next != NULL; tail = tail->next)
            ;
        tail->next = new_struct;
    }
    struct_state = INITIALIZED;
    return true;
}

static bool set_struct_field_typedesc(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    uint8_t typedesc;

    if ((*data_idx + sizeof(typedesc)) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    typedesc = data[(*data_idx)++];
    field->type_is_array = (typedesc & ARRAY_MASK) != 0;
    field->type_has_size = (typedesc & TYPESIZE_MASK) != 0;
    field->type = typedesc & TYPE_MASK;
    if (field->type >= TYPES_COUNT) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    return true;
}

static bool set_struct_field_custom_typename(s_struct_712_field *field,
                                             const uint8_t *data,
                                             uint8_t *data_idx,
                                             uint8_t length) {
    uint8_t typename_len;

    if ((*data_idx + sizeof(typename_len)) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    typename_len = data[(*data_idx)++];
    if ((*data_idx + typename_len) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    if ((field->type_name = APP_MEM_ALLOC((size_t) typename_len + 1U)) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    memcpy(field->type_name, &data[*data_idx], typename_len);
    field->type_name[typename_len] = '\0';
    *data_idx += typename_len;
    return true;
}

static bool set_struct_field_array(s_struct_712_field *field,
                                   const uint8_t *data,
                                   uint8_t *data_idx,
                                   uint8_t length) {
    if ((*data_idx + sizeof(field->array_level_count)) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    field->array_level_count = data[(*data_idx)++];
    if (field->array_level_count == 0) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    field->array_levels =
        APP_MEM_ALLOC(sizeof(*field->array_levels) * field->array_level_count);
    if (field->array_levels == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    for (uint8_t idx = 0; idx < field->array_level_count; ++idx) {
        if ((*data_idx + sizeof(uint8_t)) > length) {
            apdu_response_code = APDU_RESPONSE_INVALID_DATA;
            return false;
        }
        field->array_levels[idx].type = data[(*data_idx)++];
        switch (field->array_levels[idx].type) {
            case ARRAY_DYNAMIC:
                field->array_levels[idx].size = 0;
                break;
            case ARRAY_FIXED_SIZE:
                if ((*data_idx + sizeof(field->array_levels[idx].size)) > length) {
                    apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                    return false;
                }
                field->array_levels[idx].size = data[(*data_idx)++];
                break;
            default:
                apdu_response_code = APDU_RESPONSE_INVALID_DATA;
                return false;
        }
    }
    return true;
}

static bool set_struct_field_typesize(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    if ((*data_idx + sizeof(field->type_size)) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    field->type_size = data[(*data_idx)++];
    return true;
}

static bool set_struct_field_keyname(s_struct_712_field *field,
                                     const uint8_t *data,
                                     uint8_t *data_idx,
                                     uint8_t length) {
    uint8_t keyname_len;

    if ((*data_idx + sizeof(keyname_len)) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    keyname_len = data[(*data_idx)++];
    if ((*data_idx + keyname_len) > length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    }
    if ((field->key_name = APP_MEM_ALLOC((size_t) keyname_len + 1U)) == NULL) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    memcpy(field->key_name, &data[*data_idx], keyname_len);
    field->key_name[keyname_len] = '\0';
    *data_idx += keyname_len;
    return true;
}

bool set_struct_field(uint8_t length, const uint8_t *data) {
    uint8_t data_idx = 0;
    s_struct_712 *tail;
    s_struct_712_field *new_field = NULL;
    s_struct_712_field *field_tail;

    if ((data == NULL) || (length == 0)) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        return false;
    } else if (g_structs == NULL) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }
    if (struct_state == NOT_INITIALIZED) {
        apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
        return false;
    }
    if (APP_MEM_CALLOC((void **) &new_field, sizeof(*new_field)) == false) {
        apdu_response_code = APDU_RESPONSE_INSUFFICIENT_MEMORY;
        return false;
    }
    if (!set_struct_field_typedesc(new_field, data, &data_idx, length)) {
        goto cleanup;
    }
    if (new_field->type_has_size) {
        if (new_field->type == TYPE_CUSTOM) {
            apdu_response_code = APDU_RESPONSE_CONDITION_NOT_SATISFIED;
            goto cleanup;
        }
        if (!set_struct_field_typesize(new_field, data, &data_idx, length)) {
            goto cleanup;
        }
    } else if (new_field->type == TYPE_CUSTOM) {
        if (!set_struct_field_custom_typename(new_field, data, &data_idx, length)) {
            goto cleanup;
        }
    }
    if (new_field->type_is_array &&
        !set_struct_field_array(new_field, data, &data_idx, length)) {
        goto cleanup;
    }
    if (!set_struct_field_keyname(new_field, data, &data_idx, length)) {
        goto cleanup;
    }
    if (data_idx != length) {
        apdu_response_code = APDU_RESPONSE_INVALID_DATA;
        goto cleanup;
    }

    for (tail = g_structs; tail->next != NULL; tail = tail->next)
        ;
    if (tail->fields == NULL) {
        tail->fields = new_field;
    } else {
        for (field_tail = tail->fields; field_tail->next != NULL; field_tail = field_tail->next)
            ;
        field_tail->next = new_field;
    }
    return true;

cleanup:
    free_field(new_field);
    return false;
}
