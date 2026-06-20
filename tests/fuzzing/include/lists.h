#pragma once

#include <stddef.h>
#include <stdbool.h>

// Host-side mock of the Ledger SDK (lib_standard_app) intrusive list helpers.
//
// app-tron's TIP-712 code embeds a list node as the FIRST member of its node
// structs and drives them through these helpers:
//   - signMessageTIP712/typed_data.c, type_hash.c, ui_logic.c use the
//     singly-linked `flist_*` API (flist_node_t).
//   - signMessageTIP712/path.c uses the doubly-linked `list_*` API
//     (list_node_t, which also exposes `prev`).
//
// The standalone fuzz build has no BOLOS_SDK, so this reproduces the SDK
// semantics. The important contract: the per-node delete callback is what frees
// the node, so the helpers capture the neighbour links BEFORE invoking it.

// ---- Singly-linked forward list -------------------------------------------
typedef struct flist_node_s {
    struct flist_node_s *next;
} flist_node_t;

// Node callbacks, shared by both list flavours. The SDK types them in terms of
// flist_node_t*; callers either pass a flist-typed callback directly (GCS) or
// cast their concrete (struct *) callback at the call site (TIP-712, path.c).
typedef void (*f_list_node_del)(flist_node_t *node);
typedef bool (*f_list_node_cmp)(const flist_node_t *a, const flist_node_t *b);

void flist_push_front(flist_node_t **list, flist_node_t *node);
void flist_push_back(flist_node_t **list, flist_node_t *node);
void flist_pop_front(flist_node_t **list, f_list_node_del cb);
void flist_pop_back(flist_node_t **list, f_list_node_del cb);
void flist_remove(flist_node_t **list, flist_node_t *node, f_list_node_del cb);
size_t flist_size(flist_node_t **list);
void flist_clear(flist_node_t **list, f_list_node_del cb);
void flist_sort(flist_node_t **list, f_list_node_cmp cmp);

// ---- Doubly-linked list ----------------------------------------------------
typedef struct list_node_s {
    struct list_node_s *next;
    struct list_node_s *prev;
} list_node_t;

void list_push_front(list_node_t **list, list_node_t *node);
void list_push_back(list_node_t **list, list_node_t *node);
void list_pop_front(list_node_t **list, f_list_node_del cb);
void list_pop_back(list_node_t **list, f_list_node_del cb);
void list_remove(list_node_t **list, list_node_t *node, f_list_node_del cb);
size_t list_size(list_node_t **list);
void list_clear(list_node_t **list, f_list_node_del cb);
