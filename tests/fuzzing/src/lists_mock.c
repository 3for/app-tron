// Host-side mock implementation of the Ledger SDK intrusive list helpers.
// See include/lists.h for the rationale. Each delete callback owns freeing its
// node, so every helper that drops a node captures the neighbour links first.

#include "lists.h"

// ---- Singly-linked forward list -------------------------------------------

void flist_push_front(flist_node_t **list, flist_node_t *node) {
    if (list == NULL || node == NULL) {
        return;
    }
    node->next = *list;
    *list = node;
}

void flist_push_back(flist_node_t **list, flist_node_t *node) {
    if (list == NULL || node == NULL) {
        return;
    }
    node->next = NULL;
    if (*list == NULL) {
        *list = node;
        return;
    }
    flist_node_t *cur = *list;
    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = node;
}

void flist_pop_front(flist_node_t **list, f_list_node_del cb) {
    if (list == NULL || *list == NULL) {
        return;
    }
    flist_node_t *node = *list;
    *list = node->next;
    if (cb != NULL) {
        cb((flist_node_t *) node);
    }
}

void flist_pop_back(flist_node_t **list, f_list_node_del cb) {
    if (list == NULL || *list == NULL) {
        return;
    }
    flist_node_t *prev = NULL;
    flist_node_t *cur = *list;
    while (cur->next != NULL) {
        prev = cur;
        cur = cur->next;
    }
    if (prev == NULL) {
        *list = NULL;
    } else {
        prev->next = NULL;
    }
    if (cb != NULL) {
        cb((flist_node_t *) cur);
    }
}

void flist_remove(flist_node_t **list, flist_node_t *node, f_list_node_del cb) {
    if (list == NULL || node == NULL) {
        return;
    }
    flist_node_t *prev = NULL;
    flist_node_t *cur = *list;
    while (cur != NULL) {
        if (cur == node) {
            if (prev == NULL) {
                *list = cur->next;
            } else {
                prev->next = cur->next;
            }
            if (cb != NULL) {
                cb((flist_node_t *) cur);
            }
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}

size_t flist_size(flist_node_t **list) {
    size_t count = 0;
    if (list == NULL) {
        return 0;
    }
    for (flist_node_t *cur = *list; cur != NULL; cur = cur->next) {
        count += 1;
    }
    return count;
}

void flist_clear(flist_node_t **list, f_list_node_del cb) {
    if (list == NULL) {
        return;
    }
    flist_node_t *cur = *list;
    while (cur != NULL) {
        flist_node_t *next = cur->next;  // capture before cb frees the node
        if (cb != NULL) {
            cb((flist_node_t *) cur);
        }
        cur = next;
    }
    *list = NULL;
}

void flist_sort(flist_node_t **list, f_list_node_cmp cmp) {
    if (list == NULL || *list == NULL || cmp == NULL) {
        return;
    }
    // Bubble sort over the linked list. The comparator returns true when the
    // pair (a, b) is already in order; false means they must be swapped. This
    // matches the SDK contract used by the TIP-712 dependency sort.
    bool swapped = true;
    while (swapped) {
        swapped = false;
        flist_node_t *prev = NULL;
        flist_node_t *cur = *list;
        while (cur->next != NULL) {
            flist_node_t *next = cur->next;
            if (!cmp(cur, next)) {
                cur->next = next->next;
                next->next = cur;
                if (prev == NULL) {
                    *list = next;
                } else {
                    prev->next = next;
                }
                prev = next;
                swapped = true;
            } else {
                prev = cur;
                cur = cur->next;
            }
        }
    }
}

// ---- Doubly-linked list ----------------------------------------------------

void list_push_front(list_node_t **list, list_node_t *node) {
    if (list == NULL || node == NULL) {
        return;
    }
    node->prev = NULL;
    node->next = *list;
    if (*list != NULL) {
        (*list)->prev = node;
    }
    *list = node;
}

void list_push_back(list_node_t **list, list_node_t *node) {
    if (list == NULL || node == NULL) {
        return;
    }
    node->next = NULL;
    if (*list == NULL) {
        node->prev = NULL;
        *list = node;
        return;
    }
    list_node_t *cur = *list;
    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = node;
    node->prev = cur;
}

static void list_unlink(list_node_t **list, list_node_t *node) {
    if (node->prev != NULL) {
        node->prev->next = node->next;
    } else {
        *list = node->next;
    }
    if (node->next != NULL) {
        node->next->prev = node->prev;
    }
}

void list_pop_front(list_node_t **list, f_list_node_del cb) {
    if (list == NULL || *list == NULL) {
        return;
    }
    list_node_t *node = *list;
    list_unlink(list, node);
    if (cb != NULL) {
        cb((flist_node_t *) node);
    }
}

void list_pop_back(list_node_t **list, f_list_node_del cb) {
    if (list == NULL || *list == NULL) {
        return;
    }
    list_node_t *cur = *list;
    while (cur->next != NULL) {
        cur = cur->next;
    }
    list_unlink(list, cur);
    if (cb != NULL) {
        cb((flist_node_t *) cur);
    }
}

void list_remove(list_node_t **list, list_node_t *node, f_list_node_del cb) {
    if (list == NULL || node == NULL) {
        return;
    }
    list_unlink(list, node);
    if (cb != NULL) {
        cb((flist_node_t *) node);
    }
}

size_t list_size(list_node_t **list) {
    size_t count = 0;
    if (list == NULL) {
        return 0;
    }
    for (list_node_t *cur = *list; cur != NULL; cur = cur->next) {
        count += 1;
    }
    return count;
}

void list_clear(list_node_t **list, f_list_node_del cb) {
    if (list == NULL) {
        return;
    }
    list_node_t *cur = *list;
    while (cur != NULL) {
        list_node_t *next = cur->next;  // capture before cb frees the node
        if (cb != NULL) {
            cb((flist_node_t *) cur);
        }
        cur = next;
    }
    *list = NULL;
}
