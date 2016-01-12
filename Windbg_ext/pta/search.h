/*
 * search.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */

#ifndef SEARCH_H_
#define SEARCH_H_

#include "ref.h"

/*
 * Exposed functions
 */
extern CA_BOOL find_object_type(address_t addr);

extern CA_BOOL find_object_refs(address_t addr, size_t size, unsigned int iLevel);
extern struct CA_LIST* search_object_refs(address_t addr, size_t size, unsigned int iLevel, enum storage_type stype);
extern void set_max_indirection_level(unsigned int);

extern CA_BOOL find_object_refs_on_threads(address_t addr, size_t size, unsigned int depth);

extern CA_BOOL  search_cplusplus_objects_and_references(const char* exp);
extern struct CA_LIST* search_cplusplus_objects_with_vptr(const char* exp);

extern CA_BOOL find_shared_objects_by_threads(struct CA_LIST* threads);
extern struct CA_LIST* search_shared_objects_by_threads(struct CA_LIST* threads);
extern void set_shared_objects_indirection_level(unsigned int);

extern void print_memory_pattern(address_t lo, address_t hi);

extern void print_ref(const struct object_reference*, unsigned int, CA_BOOL, CA_BOOL);

extern void fill_ref_location(struct object_reference*);

extern CA_BOOL g_skip_free;
extern CA_BOOL g_skip_unknown;

#endif /* SEARCH_H_ */
