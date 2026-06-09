/*
 * x_common.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_COMMON_H_
#define X_COMMON_H_

#include <ctype.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <list>

#include "defs.h"
//#include "gdb_string.h"
#include "frame.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "value.h"
#include "language.h"
#include "expression.h"
#include "gdbcore.h"
#include "top.h"
#include "target.h"
#include "breakpoint.h"
#include "demangle.h"
#include "valprint.h"
#include "annotate.h"
#include "symfile.h"		/* for overlay functions */
#include "objfiles.h"		/* ditto */
#include "completer.h"		/* for completion functions */
#include "ui-out.h"
#include "gdbsupport/gdb_assert.h"
#include "block.h"
#include "stack.h"
#include "dictionary.h"
#include "exceptions.h"
#include "disasm.h"
#include "gdbthread.h"
#include "inferior.h"
#include "regcache.h"
#include "elf-bfd.h"
#include "arch-utils.h"
#include "amd64-tdep.h"
#include "cp-abi.h"
#include "user-regs.h"
#include "splay-tree.h"

#define CA_VERSION_MAJOR 2
#define CA_VERSION_MINOR 23
#define CA_VERSION_STRING "2.23"

typedef CORE_ADDR address_t;
struct object_reference;
struct reg_value;
struct ca_segment;

struct ca_debug_context
{
	int tid;
	int frame_level;
	address_t sp;
	struct ca_segment* segment;
};

#ifndef CA_PRINT
#define CA_PRINT(format,args...) \
	gdb_printf(_(format), ##args)
#endif

#define PRINT_FORMAT_POINTER "0x%lx"
#define PRINT_FORMAT_SIZE    "%ld"

#define MAX_NUM_OPTIONS 32

// global variables
extern bool g_debug_core;
extern unsigned int g_ptr_bit;
extern struct ca_debug_context g_debug_context;

// print functions
extern void print_op_value_context(size_t op_value, int op_size, address_t loc, int offset, int lea);
extern void print_type_name(struct type*, const char*, const char*, const char*);
extern void print_register_ref(const struct object_reference* ref);
extern void print_stack_ref(const struct object_reference* ref);
extern void print_global_ref(const struct object_reference* ref);
extern void print_heap_ref(const struct object_reference* ref);
extern void print_func_locals (void);
extern void print_type_layout (char*);
extern void print_build_ids(void);
extern bool display_object_stats(void);

// symbol/type lookup functions
extern struct symbol* get_stack_sym(const struct object_reference*, address_t*, size_t*);
extern struct symbol* get_global_sym(const struct object_reference*, address_t*, size_t*);
extern struct type*   get_heap_object_type(const struct object_reference*);
extern struct type* get_struct_field_type_and_name(struct type*, size_t, int, char*, size_t, int*);
extern struct type *ca_type(struct symbol *sym);
extern enum type_code ca_code(struct type *type);
extern const char *ca_name(struct type *type);
extern struct type *ca_field_type(struct type *type, int i);
extern int ca_num_fields(struct type *type);
extern const char *ca_field_name(struct type *type, int i);
extern bool get_gv_value(const char *varname, char *buf, size_t bufsz);
extern bool ca_get_field_value(struct value *, const char *, size_t *, bool);
extern bool ca_memcpy_field_value(struct value *, const char *, char *, size_t);
extern struct value *ca_get_field_gdb_value(struct value *, const char *);
extern bool known_global_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz);
extern bool known_stack_sym(const struct object_reference* ref, address_t* sym_addr, size_t* sym_sz);
extern bool known_heap_block(const struct object_reference* ref);
extern bool global_text_ref(const struct object_reference* ref);
extern address_t get_var_addr_by_name(const char*, bool);
extern bool get_vtable_from_exp(const char*, std::list<struct object_range*>&, char*, size_t, size_t*);

// target query/extraction functions
extern bool update_memory_segments_and_heaps(void);
extern bool inferior_memory_read (address_t addr, void* buffer, size_t sz);
extern void ca_switch_to_thread(struct thread_info *info);
extern bool user_request_break(void);

// utility functions
extern void search_types_by_size(size_t, size_t);
extern int ca_parse_options(char* arg, char** out);
extern void calc_heap_usage(char *expr);
extern void init_progress_bar(unsigned long total);
extern void set_current_progress(unsigned long);
extern void end_progress_bar(void);
extern address_t ca_eval_address(const char*);

// command implementations
extern bool heap_command_impl(char* args);
extern bool ref_command_impl(char* args);
extern bool segment_command_impl(char* args);
extern bool pattern_command_impl(char* args);
extern void ca_initialize_heapcmd();

// misc functions
extern bool get_tcmalloc_version(address_t func_addr, int *major, int *minor);

#endif // X_COMMON_H_
