/*
 * ref.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef REF_H_
#define REF_H_

#include "x_dep.h"

#define ALIGN(x,s) ( ((x) + (s) - 1) & (~((s) - 1)) )
#define NAME_BUF_SZ 1024
/*
 * Data structures for reference
 */
enum storage_type
{
	ENUM_UNKNOWN     = 0x00,
	ENUM_REGISTER    = 0x01,
	ENUM_STACK       = 0x02,
	ENUM_MODULE_TEXT = 0x04,
	ENUM_MODULE_DATA = 0x08,
	ENUM_HEAP        = 0x10,
	ENUM_ALL         = 0xffffffff
};

// Heap memory block info is provided by specific memory manager
struct heap_block
{
	address_t addr;
	size_t    size;
	bool   inuse;
};

struct reg_ref
{
	int tid;
	int reg_num;
	const char* name;
};

struct stack_ref
{
	//ptid_t ptid;	// "Actual process id";
	int tid;		// thread id used by debugger
	int frame;
	int offset;
};

struct module_ref
{
	address_t base;
	size_t    size;
	const char* name;
};

struct heap_ref
{
	address_t addr;
	size_t    size;
	int       inuse;
};

struct anon_ref
{
	size_t size;
};

struct object_reference
{
	// data members
	int       level;		// 0 is referenced, 1 means direct ref, 2 stands for 2nd level indirect ref, and so on
	int       target_index;	// I am a reference to the object in this slot
	enum storage_type  storage_type;
	address_t vaddr;	// the address that references
	address_t value;	// the value at the above address, i.e. the the referenced
	union
	{
		struct reg_ref       reg;
		struct stack_ref     stack;
		struct module_ref    module;
		struct heap_ref      heap;
		struct anon_ref      target;
	} where;
};

struct object_range
{
	address_t low;
	address_t high;
};

struct ca_segment;

struct reg_value
{
	int reg_num;
	int reg_width;		// in bytes
	address_t value;
};

struct CA_LIST;

/////////////////////////////////////////////////////////////////////////
// Import functions (required from heap parser, x_dep, etc.)
/////////////////////////////////////////////////////////////////////////
extern bool is_heap_object_with_vptr(const struct object_reference*, char*, size_t);
extern bool search_registers(const struct ca_segment*, struct CA_LIST*, struct CA_LIST*);
extern int read_registers(const struct ca_segment*, struct reg_value*, int);
extern int get_frame_number(const struct ca_segment*, address_t, int*);
extern int get_thread_id(const struct ca_segment*);
extern address_t get_rsp(const struct ca_segment*);
extern void clear_addr_type_map(void);

#endif // REF_H_
