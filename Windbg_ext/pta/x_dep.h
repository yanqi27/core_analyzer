/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_DEP_H_
#define X_DEP_H_

#include "x_type.h"

#define CA_VERSION_MAJOR 2
#define CA_VERSION_MINOR 16
#define CA_VERSION_STRING "2.16"

struct object_reference;
struct reg_value;
struct ca_segment;
struct CA_LIST;

struct ca_debug_context
{
	int tid;
	int frame_level;
	address_t sp;
	struct ca_segment* segment;
};

extern CA_BOOL update_memory_segments_and_heaps(void);

extern CA_BOOL inferior_memory_read (address_t addr, void* buffer, size_t sz);

extern void print_register_ref(const struct object_reference* ref);
extern void print_stack_ref(const struct object_reference* ref);
extern void print_global_ref(const struct object_reference* ref);
extern void print_heap_ref(const struct object_reference* ref);

extern CA_BOOL known_global_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz);
extern CA_BOOL known_stack_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz);

extern address_t get_var_addr_by_name(const char*, CA_BOOL);

extern void print_func_locals (void);
extern void print_type_layout (char*);

extern CA_BOOL get_vtable_from_exp(const char*, struct CA_LIST*, char*, size_t, size_t*);

extern CA_BOOL user_request_break(void);

extern CA_BOOL g_debug_core;

extern unsigned int g_ptr_bit;

extern struct ca_debug_context g_debug_context;

#define MAX_NUM_OPTIONS 32
extern int ca_parse_options(char* arg, char** out);

extern void calc_heap_usage(char *expr);

extern void init_progress_bar(unsigned long total);
extern void set_current_progress(unsigned long);
extern void end_progress_bar(void);

extern char ca_help_msg[];

extern address_t ca_eval_address(const char*);

extern CA_BOOL heap_command_impl(char* args);
extern CA_BOOL ref_command_impl(char* args);
extern CA_BOOL segment_command_impl(char* args);
extern CA_BOOL pattern_command_impl(char* args);

#endif // X_DEP_H_
