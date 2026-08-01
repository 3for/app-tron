#include <string.h>
#include "os_print.h"
#include "gtp_field_table.h"
#include "gcs_memory.h"
#include "lists.h"
#include "shared_context.h"  // appState
#include "ui_logic.h"
#include "tx_ctx.h"
#include "gcs_limits.h"

typedef struct {
    flist_node_t _list;
    s_field_table_entry field;
} s_field_table_node;

static s_field_table_node *g_table = NULL;

bool field_table_init(void) {
    if (g_table != NULL) {
        field_table_cleanup();
        return false;
    }
    return true;
}

// to be used as a \ref f_list_node_del
static void delete_table_node(s_field_table_node *node) {
    gcs_mem_free(node->field.key);
    gcs_mem_free(node->field.value);
    if (node->field.owns_extra_data) {
        gcs_mem_free((void *) node->field.extra_data);
    }
    gcs_mem_free(node);
}

void field_table_cleanup(void) {
    flist_clear((flist_node_t **) &g_table, (f_list_node_del) &delete_table_node);
}

static bool add_to_field_table_internal(e_param_type type,
                                        const char *key,
                                        const char *value,
                                        const void *extra_data,
                                        size_t extra_data_size) {
    size_t key_len;
    size_t value_len;
    s_field_table_node *node;

    if ((key == NULL) || (value == NULL) ||
        ((extra_data_size != 0U) && (extra_data == NULL))) {
        PRINTF("Error: NULL key/value!\n");
        return false;
    }
    if ((appState == APP_STATE_SIGNING_TX) &&
        (field_table_size() >= GCS_MAX_RENDERED_FIELDS)) {
        PRINTF("Error: too many rendered fields!\n");
        return false;
    }
    PRINTF(">>> \"%s\": \"%s\"\n", key, value);
    if (appState == APP_STATE_SIGNING_EIP712) {
        if ((type == PARAM_TYPE_INTENT) && (txContext.current_batch_size > 1)) {
            // Special handling for intent in TIP712 mode
            if (!ui_712_set_intent()) return false;
            PRINTF("[Intent] Start\n");
        }
        return ui_712_set_title(key, strlen(key)) &&
               ui_712_set_value(value, strlen(value));
    }
    node = gcs_mem_calloc(sizeof(*node), GCS_MEM_FIELD);
    if (node == NULL) {
        return false;
    }
    if (__builtin_add_overflow(strlen(key), 1U, &key_len) ||
        __builtin_add_overflow(strlen(value), 1U, &value_len)) {
        gcs_mem_free(node);
        return false;
    }
    if ((node->field.key = gcs_mem_alloc(key_len, GCS_MEM_FIELD)) == NULL) {
        gcs_mem_free(node);
        return false;
    }
    if ((node->field.value = gcs_mem_alloc(value_len, GCS_MEM_FIELD)) == NULL) {
        gcs_mem_free(node->field.key);
        gcs_mem_free(node);
        return false;
    }
    if (extra_data_size != 0U) {
        node->field.extra_data = gcs_mem_alloc(extra_data_size, GCS_MEM_FIELD);
        if (node->field.extra_data == NULL) {
            gcs_mem_free(node->field.value);
            gcs_mem_free(node->field.key);
            gcs_mem_free(node);
            return false;
        }
        memcpy((void *) node->field.extra_data, extra_data, extra_data_size);
        node->field.owns_extra_data = true;
    } else {
        node->field.extra_data = extra_data;
    }
    if (type == PARAM_TYPE_INTENT) {
        // Special handling for intent
        node->field.start_intent = true;
        type = PARAM_TYPE_RAW;  // store as raw
        PRINTF("[Intent] Start\n");
    } else {
        node->field.end_intent = validate_instruction_hash();
        if (node->field.end_intent) {
            PRINTF("[Intent] End\n");
        }
    }

    node->field.type = type;
    memcpy(node->field.key, key, key_len);
    memcpy(node->field.value, value, value_len);

    flist_push_back((flist_node_t **) &g_table, (flist_node_t *) node);
    return true;
}

bool add_to_field_table(e_param_type type,
                        const char *key,
                        const char *value,
                        const void *extra_data) {
    return add_to_field_table_internal(type, key, value, extra_data, 0U);
}

bool add_to_field_table_with_extra_data_copy(e_param_type type,
                                             const char *key,
                                             const char *value,
                                             const void *extra_data,
                                             size_t extra_data_size) {
    if (extra_data_size == 0U) {
        return false;
    }
    return add_to_field_table_internal(type,
                                       key,
                                       value,
                                       extra_data,
                                       extra_data_size);
}

bool set_intent_field(const char *value) {
    e_param_type type = PARAM_TYPE_INTENT;

    if (txContext.current_batch_size == 1) {
        // Only one transaction in the batch, no need to mark as intent
        type = PARAM_TYPE_RAW;
    }
    return add_to_field_table(type, "Transaction type", value, NULL);
}

size_t field_table_size(void) {
    return flist_size((flist_node_t **) &g_table);
}

const s_field_table_entry *get_from_field_table(int index) {
    const s_field_table_node *node = g_table;

    if (index < 0) {
        return NULL;
    }

    for (int i = 0; i < index; ++i) {
        if (node == NULL) return NULL;
        node = (s_field_table_node *) ((flist_node_t *) node)->next;
    }
    return (node == NULL) ? NULL : &node->field;
}
