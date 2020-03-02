/*
 * x_dep.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef X_TYPE_H_
#define X_TYPE_H_

#include <ctype.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>

#include "defs.h"
//#include "gdb_string.h"
#include "frame.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "value.h"
#include "language.h"
#include "expression.h"
#include "gdbcore.h"
#include "gdbcmd.h"
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
#include "solist.h"
#include "gdbthread.h"
#include "inferior.h"
#include "regcache.h"
#include "elf-bfd.h"
#include "arch-utils.h"
#include "solist.h"
#include "amd64-tdep.h"
#include "cp-abi.h"
#include "user-regs.h"
#include "splay-tree.h"

typedef CORE_ADDR address_t;

#define CA_PRINT(format,args...) \
	printf_filtered(_(format), ##args)

#define PRINT_FORMAT_POINTER "0x%lx"
#define PRINT_FORMAT_SIZE    "%ld"

extern void print_op_value_context(size_t op_value, int op_size, address_t loc, int offset, int lea);
extern void print_type_name(struct type*, const char*, const char*, const char*);
struct object_reference;

extern struct symbol* get_stack_sym(const struct object_reference*, address_t*, size_t*);
extern struct symbol* get_global_sym(address_t, address_t*, size_t*);
extern struct type*   get_heap_object_type(const struct object_reference*);
extern struct type* get_struct_field_type_and_name(struct type*, size_t, int, char*, size_t, int*);

#endif // X_TYPE_H_
