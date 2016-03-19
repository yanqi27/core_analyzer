/*
 * segment.h
 *		data structure representing segments of process image
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef SEGMENT_H_
#define SEGMENT_H_

#include "ref.h"

struct ca_thread
{
	int    tid;
	long   lwp;
	void*  context;
};

struct ca_segment
{
	address_t m_vaddr;	// virtual address in the target process
	size_t    m_vsize;	// size of the virtual memory segment
	char*     m_faddr;	// mmapped address in the host process (core_ananlyzer)
	size_t    m_fsize;	// corresponding size in the core file
	enum storage_type m_type;
	unsigned int m_bitvec_ready:1;	// indicating the bit vector is initialized
	unsigned int m_read:1;
	unsigned int m_write:1;
	unsigned int m_exec:1;
	unsigned int m_reserved:28;
	unsigned int* m_ptr_bitvec;		// bit vector of addressable pointers
	struct ca_thread m_thread;
	const char*   m_module_name;
};

/*
 * Exposed functions, global variables
 */
extern struct ca_segment*
add_one_segment(address_t vaddr, size_t size, CA_BOOL read, CA_BOOL write, CA_BOOL exec);

extern CA_BOOL release_all_segments(void);

extern CA_BOOL alloc_bit_vec(void);

extern CA_BOOL test_segments(CA_BOOL verbose);

extern struct ca_segment* get_segment(address_t addr, size_t len);

extern CA_BOOL set_addressable_bit_vec(struct ca_segment*);

extern CA_BOOL read_memory_wrapper (struct ca_segment*, address_t, void*, size_t);

extern void* core_to_mmap_addr(address_t vaddr);

extern void set_value (address_t addr, address_t value);

extern void unset_value (address_t addr);

extern void print_set_values (void);

extern struct ca_segment* g_segments;
extern unsigned int g_segment_count;

#endif /* SEGMENT_H_ */
