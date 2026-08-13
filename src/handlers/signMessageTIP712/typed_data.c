#include <string.h>
#include "typed_data.h"
#include "sol_typenames.h"
#include "context_712.h"
#include "app_mem_utils.h"
#include "app_errors.h"  // APDU response codes
#include "parse.h"       // apdu_response_code
#include "tip712_limits.h"
#include "gcs_memory.h"

static s_struct_712 *g_structs = NULL;
static size_t g_struct_count;
static size_t g_field_count;
static size_t g_array_level_count;

static bool is_solidity_identifier(const uint8_t *name, size_t length) {
    if ((name == NULL) || (length == 0U) ||
        (length > TIP712_MAX_IDENTIFIER_LENGTH)) {
        return false;
    }
    if (!(((name[0] >= 'A') && (name[0] <= 'Z')) ||
          ((name[0] >= 'a') && (name[0] <= 'z')) || (name[0] == '_') ||
          (name[0] == '$'))) {
        return false;
    }
    for (size_t i = 1U; i < length; i++) {
        if (!(((name[i] >= 'A') && (name[i] <= 'Z')) ||
              ((name[i] >= 'a') && (name[i] <= 'z')) ||
              ((name[i] >= '0') && (name[i] <= '9')) || (name[i] == '_') ||
              (name[i] == '$'))) {
            return false;
        }
    }
    return true;
}

/**
 * Initialize the typed data context
 *
 * @return whether the memory allocation was successful
 */
bool typed_data_init(void) {
    if (g_structs != NULL) {
        typed_data_deinit();
        return false;
    }
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_field(s_struct_712_field *f) {
    gcs_mem_free(f->type_name);
    gcs_mem_free(f->array_levels);
    gcs_mem_free(f->key_name);
    gcs_mem_free(f);
}

// to be used as a \ref f_list_node_del
static void delete_struct(s_struct_712 *s) {
    gcs_mem_free(s->name);
    flist_clear((flist_node_t **) &s->fields, (f_list_node_del) &delete_field);
    gcs_mem_free(s);
}

void typed_data_deinit(void) {
    flist_clear((flist_node_t **) &g_structs, (f_list_node_del) &delete_struct);
    g_struct_count = 0U;
    g_field_count = 0U;
    g_array_level_count = 0U;
}

/**
 * Get type name from a struct field
 *
 * @param[in] field_ptr struct field pointer
 * @return type name pointer
 */
const char *get_struct_field_typename(const s_struct_712_field *field_ptr) {
    if (field_ptr == NULL) {
        return NULL;
    }
    if (field_ptr->type == TYPE_CUSTOM) {
        return field_ptr->type_name;
    }
    return get_struct_field_sol_typename(field_ptr);
}

const s_struct_712 *get_struct_list(void) {
    return g_structs;
}

/**
 * Find struct with a given name
 *
 * @param[in] name struct name
 * @param[in] length name length
 * @return pointer to struct
 */
const s_struct_712 *get_structn(const char *name, uint8_t length) {
    const s_struct_712 *struct_ptr;

    if (name == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return NULL;
    }
    for (struct_ptr = get_struct_list(); struct_ptr != NULL;
         struct_ptr = (s_struct_712 *) ((flist_node_t *) struct_ptr)->next) {
        if (struct_ptr->name != NULL) {
            if ((length == strlen(struct_ptr->name)) &&
                (memcmp(name, struct_ptr->name, length) == 0)) {
                return struct_ptr;
            }
        }
    }
    apdu_response_code = SWO_INCORRECT_DATA;
    return NULL;
}

_Static_assert(TIP712_MAX_STRUCTS <= 16U,
               "TIP712 dependency bitmask only supports 16 structs");

bool typed_data_schema_is_acyclic(void) {
    const s_struct_712 *structs[TIP712_MAX_STRUCTS];
    uint16_t dependencies[TIP712_MAX_STRUCTS] = {0};
    size_t count = 0U;

    for (const s_struct_712 *current = g_structs; current != NULL;
         current = (const s_struct_712 *) ((const flist_node_t *) current)->next) {
        if (count >= TIP712_MAX_STRUCTS) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        structs[count++] = current;
    }

    for (size_t i = 0U; i < count; i++) {
        for (const s_struct_712_field *field = structs[i]->fields;
             field != NULL;
             field = (const s_struct_712_field *)
                         ((const flist_node_t *) field)->next) {
            bool found = false;

            if (field->type != TYPE_CUSTOM) {
                continue;
            }
            for (size_t j = 0U; j < count; j++) {
                if (strcmp(field->type_name, structs[j]->name) == 0) {
                    dependencies[i] |= (uint16_t) (UINT16_C(1) << j);
                    found = true;
                    break;
                }
            }
            if (!found) {
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
            }
        }
    }

    /* The schema is tiny (at most 16 structs), so transitive closure gives a
     * bounded, allocation-free cycle check. Recursive schemas are rejected at
     * filtering activation instead of failing midway through value parsing. */
    for (size_t k = 0U; k < count; k++) {
        for (size_t i = 0U; i < count; i++) {
            if ((dependencies[i] & (uint16_t) (UINT16_C(1) << k)) != 0U) {
                dependencies[i] |= dependencies[k];
            }
        }
    }
    for (size_t i = 0U; i < count; i++) {
        if ((dependencies[i] & (uint16_t) (UINT16_C(1) << i)) != 0U) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
    }
    return true;
}

/**
 * Set struct name
 *
 * @param[in] length name length
 * @param[in] name name
 * @return whether it was successful
 */
bool set_struct_name(uint8_t length, const uint8_t *name) {
    s_struct_712 *new_struct;

    if (!is_solidity_identifier(name, length) ||
        (g_struct_count >= TIP712_MAX_STRUCTS)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    for (const s_struct_712 *cur = g_structs; cur != NULL;
         cur = (const s_struct_712 *) ((const flist_node_t *) cur)->next) {
        if ((strlen(cur->name) == length) &&
            (memcmp(cur->name, name, length) == 0)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
    }

    new_struct = gcs_mem_calloc(sizeof(*new_struct), GCS_MEM_GENERIC);
    if (new_struct == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    if ((new_struct->name = gcs_mem_alloc(length + 1U, GCS_MEM_GENERIC)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        gcs_mem_free(new_struct);
        return false;
    }
    new_struct->name[length] = '\0';
    memmove(new_struct->name, name, length);
    struct_state = INITIALIZED;

    flist_push_back((flist_node_t **) &g_structs, (flist_node_t *) new_struct);
    g_struct_count++;
    return true;
}

/**
 * Set struct field TypeDesc
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful or not
 */
static bool set_struct_field_typedesc(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    uint8_t typedesc;

    // copy TypeDesc
    if ((*data_idx + sizeof(typedesc)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    typedesc = data[(*data_idx)++];
    field->type_is_array = typedesc & ARRAY_MASK;
    field->type_has_size = typedesc & TYPESIZE_MASK;
    field->type = typedesc & TYPE_MASK;
    return true;
}

/**
 * Set struct field custom typename
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_custom_typename(s_struct_712_field *field,
                                             const uint8_t *data,
                                             uint8_t *data_idx,
                                             uint8_t length) {
    uint8_t typename_len;

    // copy custom struct name length
    if ((*data_idx + sizeof(typename_len)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    typename_len = data[(*data_idx)++];

    // copy name
    if ((*data_idx + typename_len) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (!is_solidity_identifier(&data[*data_idx], typename_len)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if ((field->type_name = gcs_mem_alloc(typename_len + 1U, GCS_MEM_GENERIC)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    field->type_name[typename_len] = '\0';
    memmove(field->type_name, &data[*data_idx], typename_len);
    *data_idx += typename_len;
    return true;
}

/**
 * Set struct field's array levels
 *
 * @param[in] data the field data
 * @param[in] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_array(s_struct_712_field *field,
                                   const uint8_t *data,
                                   uint8_t *data_idx,
                                   uint8_t length) {
    if ((*data_idx + sizeof(field->array_level_count)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    field->array_level_count = data[(*data_idx)++];
    if ((field->array_level_count == 0) ||
        (field->array_level_count > TIP712_MAX_ARRAY_LEVELS_PER_FIELD) ||
        (g_array_level_count >
         (TIP712_MAX_ARRAY_LEVELS - field->array_level_count))) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if ((field->array_levels =
             gcs_mem_alloc(sizeof(*field->array_levels) * field->array_level_count,
                           GCS_MEM_GENERIC)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    for (int idx = 0; idx < field->array_level_count; ++idx) {
        if ((*data_idx + sizeof(field->array_levels[idx].type)) > length)  // check buffer bound
        {
            apdu_response_code = SWO_INCORRECT_DATA;
            return false;
        }
        field->array_levels[idx].type = data[(*data_idx)++];
        switch (field->array_levels[idx].type) {
            case ARRAY_DYNAMIC:  // nothing to do
                break;
            case ARRAY_FIXED_SIZE:
                if ((*data_idx + sizeof(field->array_levels[idx].size)) >
                    length)  // check buffer bound
                {
                    apdu_response_code = SWO_INCORRECT_DATA;
                    return false;
                }
                field->array_levels[idx].size = data[(*data_idx)++];
                if (field->array_levels[idx].size == 0U) {
                    apdu_response_code = SWO_INCORRECT_DATA;
                    return false;
                }
                break;
            default:
                // should not be in here :^)
                apdu_response_code = SWO_INCORRECT_DATA;
                return false;
        }
    }
    return true;
}

/**
 * Set struct field's type size
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_typesize(s_struct_712_field *field,
                                      const uint8_t *data,
                                      uint8_t *data_idx,
                                      uint8_t length) {
    // copy TypeSize
    if ((*data_idx + sizeof(field->type_size)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    field->type_size = data[(*data_idx)++];
    if ((field->type_size == 0U) || (field->type_size > INT256_LENGTH)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    return true;
}

/**
 * Set struct field's key name
 *
 * @param[in] data the field data
 * @param[in,out] data_idx the data index
 * @return whether it was successful
 */
static bool set_struct_field_keyname(s_struct_712_field *field,
                                     const uint8_t *data,
                                     uint8_t *data_idx,
                                     uint8_t length) {
    uint8_t keyname_len;

    // copy length
    if ((*data_idx + sizeof(keyname_len)) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    keyname_len = data[(*data_idx)++];

    // copy name
    if ((*data_idx + keyname_len) > length)  // check buffer bound
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }
    if (!is_solidity_identifier(&data[*data_idx], keyname_len)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if ((field->key_name = gcs_mem_alloc(keyname_len + 1U, GCS_MEM_GENERIC)) == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }
    field->key_name[keyname_len] = '\0';
    memmove(field->key_name, &data[*data_idx], keyname_len);
    *data_idx += keyname_len;
    return true;
}

/**
 * Set struct field
 *
 * @param[in] length data length
 * @param[in] data the field data
 * @return whether it was successful
 */
bool set_struct_field(uint8_t length, const uint8_t *data) {
    uint8_t data_idx = 0;

    if ((data == NULL) || (length == 0)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    } else if (g_structs == NULL) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    if ((struct_state == NOT_INITIALIZED) ||
        (g_field_count >= TIP712_MAX_FIELDS)) {
        apdu_response_code = SWO_INCORRECT_DATA;
        return false;
    }

    s_struct_712_field *new_field = NULL;
    new_field = gcs_mem_calloc(sizeof(*new_field), GCS_MEM_GENERIC);
    if (new_field == NULL) {
        apdu_response_code = SWO_INSUFFICIENT_MEMORY;
        return false;
    }

    if (!set_struct_field_typedesc(new_field, data, &data_idx, length)) {
        goto cleanup;
    }
    if (new_field->type >= TYPES_COUNT) {
        apdu_response_code = SWO_INCORRECT_DATA;
        goto cleanup;
    }

    // check TypeSize flag in TypeDesc
    if (new_field->type_has_size) {
        // TYPESIZE and TYPE_CUSTOM are mutually exclusive
        if (new_field->type == TYPE_CUSTOM) {
            apdu_response_code = SWO_INCORRECT_DATA;
            goto cleanup;
        }

        if (set_struct_field_typesize(new_field, data, &data_idx, length) == false) {
            goto cleanup;
        }

    } else if (new_field->type == TYPE_CUSTOM) {
        if (set_struct_field_custom_typename(new_field, data, &data_idx, length) == false) {
            goto cleanup;
        }
    }

    /* Enforce canonical Solidity type-size combinations. Bare int/uint are
     * valid aliases for 256-bit values; fixed bytes always need bytes1..32. */
    if (new_field->type_has_size) {
        if ((new_field->type != TYPE_SOL_INT) &&
            (new_field->type != TYPE_SOL_UINT) &&
            (new_field->type != TYPE_SOL_BYTES_FIX)) {
            apdu_response_code = SWO_INCORRECT_DATA;
            goto cleanup;
        }
    } else if (new_field->type == TYPE_SOL_BYTES_FIX) {
        apdu_response_code = SWO_INCORRECT_DATA;
        goto cleanup;
    }
    if (new_field->type_is_array) {
        if (set_struct_field_array(new_field, data, &data_idx, length) == false) {
            goto cleanup;
        }
    }

    if (set_struct_field_keyname(new_field, data, &data_idx, length) == false) {
        goto cleanup;
    }

    if (data_idx != length)  // check that there is no more
    {
        apdu_response_code = SWO_INCORRECT_DATA;
        goto cleanup;
    }

    // get last struct
    s_struct_712 *s = g_structs;
    while ((s_struct_712 *) ((flist_node_t *) s)->next != NULL) {
        s = (s_struct_712 *) ((flist_node_t *) s)->next;
    }

    for (const s_struct_712_field *cur = s->fields; cur != NULL;
         cur = (const s_struct_712_field *) ((const flist_node_t *) cur)->next) {
        if (strcmp(cur->key_name, new_field->key_name) == 0) {
            apdu_response_code = SWO_INCORRECT_DATA;
            goto cleanup;
        }
    }

    flist_push_back((flist_node_t **) &s->fields, (flist_node_t *) new_field);
    g_field_count++;
    g_array_level_count += new_field->array_level_count;
    return true;
cleanup:
    if (new_field != NULL) {
        gcs_mem_free(new_field->key_name);
        gcs_mem_free(new_field->array_levels);
        gcs_mem_free(new_field->type_name);
        gcs_mem_free(new_field);
    }
    return false;
}
