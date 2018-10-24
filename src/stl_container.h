/*
 * stl_container.h
 * 		A wrapper of stl tree/vector/list etc. because gdb is a c program
 */
#ifndef _STL_CONTAINER_H
#define _STL_CONTAINER_H

#include "x_type.h"

struct CA_SET;
struct CA_LIST;

#ifndef __cplusplus
#ifdef _SPLAY_TREE_H
#define CA_USE_SPLAY_TREE
#endif
#endif

#ifdef CA_USE_SPLAY_TREE
typedef int (*CA_CompareFunctionType) (splay_tree_key, splay_tree_key);
bool ca_set_insert_key_and_val(struct CA_SET* iset, void* key, void* val);
#else
typedef bool (*CA_CompareFunctionType)(void *, void *);
bool ca_set_insert(struct CA_SET*, void*);
#endif

struct CA_SET* ca_set_new(CA_CompareFunctionType comp);
void ca_set_delete(struct CA_SET*);
void* ca_set_find(struct CA_SET*, void*);
void  ca_set_clear(struct CA_SET*);
void  ca_set_traverse_start(struct CA_SET*);
void* ca_set_traverse_next(struct CA_SET*);

void  ca_list_traverse_start(struct CA_LIST*);
void* ca_list_traverse_next(struct CA_LIST*);
void* ca_list_find(struct CA_LIST*, void*);
void  ca_list_clear(struct CA_LIST*);
void  ca_list_push_front(struct CA_LIST*, void*);
void  ca_list_push_back(struct CA_LIST*, void*);
void* ca_list_pop_front(struct CA_LIST*);
struct CA_LIST* ca_list_new(void);
void ca_list_delete(struct CA_LIST*);
bool ca_list_empty(struct CA_LIST*);
size_t ca_list_size(struct CA_LIST*);

#endif // _STL_CONTAINER_H
