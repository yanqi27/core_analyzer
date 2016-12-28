/*
 * search.c
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "search.h"
#include "segment.h"
#include "heap.h"
#include "stl_container.h"

/////////////////////////////////////////////////////
// Data Structures used for implementation
/////////////////////////////////////////////////////
struct shared_object
{
	address_t start;
	address_t end;
	struct CA_LIST* thread_owners;	// list of thread references
	struct CA_LIST* parent_shrobjs;	// list of shared_objects that point to me
};

/////////////////////////////////////////////////////
// global variables
/////////////////////////////////////////////////////
bool g_skip_free = true;
bool g_skip_unknown = false;
unsigned int g_max_indirection_level = 16;
#define MAX_INDIRECTION_LEVEL 64

static unsigned int g_shrobj_level = 1;
static const unsigned int MAX_SHROBJ_LEVEL = 16;

static void* gp_mem_buf = NULL;
static size_t g_mem_buf_sz = 0;

static int g_nregs = 0;
static struct reg_value* g_regs_buf = NULL;

static const int min_chars = 4;

static unsigned int g_output_count = 0;

static struct CA_SET* g_shared_objects = NULL;

/////////////////////////////////////////////////////
// forward declarations.
/////////////////////////////////////////////////////
static size_t is_string(address_t, int, bool*);
static void print_string(address_t str);
static void print_wstring(address_t str);
static void print_ref_chain (struct CA_LIST*);
static void init_shared_objects(void);
static void empty_shared_objects(void);
static void print_shared_objects_by_threads(void);
static struct shared_object* add_one_shared_object(address_t, bool, unsigned int);
static bool has_multiple_thread_owners(struct shared_object* shrobj);

/***************************************************************************
* Search functions
***************************************************************************/
/*
 * Params:
 * 		next_bit_index represents the i_th pointers in this segment
 * 		searched-for value is in the range of [target_low, target_high)
 * Return:
 * 		true if the 1st match is found, false otherwise
 * 		next_bit_index is updated
 */
static bool
search_value_by_range(struct ca_segment* segment,
		size_t* next_bit_index,
		struct object_range** targets,
		int target_is_ptr,
		address_t* found_val,
		address_t* found_vaddr)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	size_t max_bit_index  = segment->m_fsize / ptr_sz;

	if (!segment->m_bitvec_ready)
		set_addressable_bit_vec(segment);

	// find next addressable pointer
	while (*next_bit_index < max_bit_index)
	{
		unsigned int target_index;
		// The bit vector of addressable can speed up search significantly
		if (target_is_ptr)
		{
			unsigned int i;
			unsigned int uint_bit;
			size_t uint_index = *next_bit_index >> 5;
			unsigned int bits = segment->m_ptr_bitvec[uint_index];

			if (bits == 0)
			{
				// There are no addressable ptrs in the next chunk of memory (32 ptrs)
				// Also account for unaligned next_bit_index
				*next_bit_index = (*next_bit_index & ~(size_t)0x1F) + 32;
				continue;
			}
			// consider the bit inside the uint
			uint_bit = *next_bit_index & (size_t)0x1F;
			bits &= ~( (1 << uint_bit) - 1);
			if (bits == 0)
			{
				*next_bit_index = (*next_bit_index & ~(size_t)0x1F) + 32;
				continue;
			}
			// find the non-zero bit
			bits = bits >> uint_bit;
			for (i=uint_bit; i<32; i++)
			{
				if (bits & 0x1)
				{
					// this is a valid ptr, check if it points to target object
					size_t offset = *next_bit_index * ptr_sz;
					const char* next_ref = segment->m_faddr + offset;
					address_t val;
					if (ptr_sz == 8)
					{
#ifdef sun
						// sparcv9 core aligns on 4-byte only. sigh..
						if ((address_t)next_ref & 0x7ul)
							memcpy(&val, next_ref, 8);
						else
#endif
							val = *(address_t*)next_ref;
					}
					else
						val = *(unsigned int*)next_ref;

					for (target_index=0; targets[target_index]; target_index++)
					{
						if (val >= targets[target_index]->low && val < targets[target_index]->high)
						{
							*found_val = val;
							*found_vaddr = segment->m_vaddr + offset;
							return true;
						}
					}
				}
				bits = bits >> 1;
				(*next_bit_index)++;
			}
		}
		else	// we have to scan raw data for arbitrary target
		{
			const char* start = segment->m_faddr;
			const char* next  = start + (*next_bit_index * ptr_sz);
			const char* end   = start + segment->m_fsize;
			while (next + ptr_sz <= end)
			{
				address_t val;
				if (ptr_sz == 8)
				{
#ifdef sun
					// sparcv9 core aligns on 4-byte only. sigh..
					if ((address_t)next & 0x7ul)
						memcpy(&val, next, 8);
					else
#endif
						val = *(address_t*)next;
				}
				else
					val = *(unsigned int*)next;

				for (target_index=0; targets[target_index]; target_index++)
				{
					if (val >= targets[target_index]->low && val < targets[target_index]->high)
					{
						*found_val = val;
						*found_vaddr = segment->m_vaddr + (next - start);
						return true;
					}
				}
				(*next_bit_index)++;
				next += ptr_sz;
			}
		}
	}

	return false;
}

/////////////////////////////////////////////////////////////////////////
// The work horse of value search
// Found references are inserted into output list.
// Return true if at least one is found
/////////////////////////////////////////////////////////////////////////
static bool
search_value_internal(struct CA_LIST* targets,
					bool target_is_ptr,
					enum storage_type stype,
					struct CA_LIST* refs)
{
	bool lbFound = false;
	unsigned int i;
	unsigned int num_targets = ca_list_size(targets);
	struct object_range** target_array = NULL;

	if (num_targets == 0)
		return false;
	else
	{
		struct object_range* target;
		// use an array terminated with NULL, for performance sake
		target_array = (struct object_range**) malloc (sizeof(struct object_range*) * (num_targets+1));
		i = 0;
		ca_list_traverse_start(targets);
		while ( (target = (struct object_range*) ca_list_traverse_next(targets)) )
		{
			target_array[i++] = target;
		}
		target_array[i++] = NULL;
		if (i != num_targets + 1)
		{
			CA_PRINT("Internal error: corrupted targets CA_LIST\n");
			free(target_array);
			return false;
		}
	}

	// search all threads' registers/stacks
	for (i=0; i<g_segment_count; i++)
	{
		struct ca_segment* segment = &g_segments[i];

		// registers are read if this is a thread stack
		if (segment->m_type == ENUM_STACK && (stype & ENUM_REGISTER))
		{
			if (search_registers(segment, targets, refs))
				lbFound = true;
		}

		// skip undesired setment
		if ( (segment->m_type & stype) == 0)
			continue;

		// This search may take long, bail out if user is impatient
		if (user_request_break())
		{
			CA_PRINT("Abort searching\n");
			break;
		}

		// search segment memory
		if (segment->m_fsize > 0)
		{
			size_t next_bit_index = 0;
			// if we are debugging core file, read memory from mmap-ed file
			// for live process, use a buffer to read in the whole segment
			if (!g_debug_core)
			{
				if (segment->m_fsize > g_mem_buf_sz)
				{
					if (gp_mem_buf)
						free(gp_mem_buf);
					gp_mem_buf = malloc(segment->m_fsize);
					g_mem_buf_sz = segment->m_fsize;
				}
				if (!read_memory_wrapper(segment, segment->m_vaddr, gp_mem_buf, segment->m_fsize) )
				{
					// can't read the segment's data, something is broken
					continue;
				}
				else
					segment->m_faddr = (char*) gp_mem_buf;
			}
			// begin to scan memory, pointed by segment->m_faddr
			while (1)
			{
				address_t val   = 0xdeadbeef;
				address_t vaddr = 0xdeadbeef;

				if(search_value_by_range(segment, &next_bit_index, target_array, target_is_ptr, &val, &vaddr))
				{
					// find a match in this segment
					bool valid_ref = false;
					struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
					ref->storage_type = segment->m_type;
					ref->vaddr        = vaddr;
					ref->value        = val;

					// detail for various storage class
					if (segment->m_type == ENUM_STACK)
					{
						ref->where.stack.tid = segment->m_thread.tid;
						ref->where.stack.frame = get_frame_number(segment, vaddr, &ref->where.stack.offset);
						if (ref->where.stack.frame >= 0 || !g_skip_free)
							valid_ref = true;
					}
					else if (segment->m_type == ENUM_MODULE_TEXT || segment->m_type == ENUM_MODULE_DATA)
					{
						// it belongs to a module's .text or .data
						valid_ref = true;
						ref->where.module.name = segment->m_module_name;
						ref->where.module.base = segment->m_vaddr;
						ref->where.module.size = segment->m_vsize;
					}
					else if (segment->m_type == ENUM_HEAP)
					{
						if (is_heap_block(vaddr))
						{
							// otherwise, it is on heap
							struct heap_block blk;
							get_heap_block_info(vaddr, &blk);
							// we generally don't care about free heap memory
							if (blk.inuse || !g_skip_free)
							{
								valid_ref = true;
								ref->where.heap.addr = blk.addr;
								ref->where.heap.size = blk.size;
								ref->where.heap.inuse = blk.inuse;
							}
						}
						else	// it is in heap segment, but not recognized by allocator
							ref->storage_type = ENUM_UNKNOWN;
					}
					// keep meaningful ref, and throw away undesired one
					if (valid_ref || (!g_skip_unknown && ref->storage_type == ENUM_UNKNOWN))
					{
						ca_list_push_back(refs, ref);
						lbFound = true;
						// avoid exceedingly too many refs for any human being to read
						if (ca_list_size(refs) > 16 * 1024)
							break;
					}
					else
						free(ref);
					next_bit_index++;
				}
				else
					break;
			}
			// remove reference to the global buffer, for the sake of peace mind
			if (!g_debug_core)
				segment->m_faddr = NULL;
		}
	}

	// cleanup
	if (target_array)
		free(target_array);

	return lbFound;
}

// Given an address (ref->vaddr), figure out its proper storage type
void
fill_ref_location(struct object_reference* ref)
{
	struct heap_block blockinfo;
	address_t addr = ref->vaddr;

	// the target address must be in process address space
	struct ca_segment* segment = get_segment(addr, 1);
	if (!segment)
	{
		ref->storage_type = ENUM_UNKNOWN;
		return;
	}

	// analyze target's storage type
	if (segment->m_type == ENUM_STACK)
	{
		// stack address, that's it.
		ref->storage_type = ENUM_STACK;
		ref->where.stack.tid = segment->m_thread.tid;
		ref->where.stack.frame = get_frame_number(segment, addr, &ref->where.stack.offset);
	}
	else if (segment->m_type == ENUM_MODULE_DATA || segment->m_type == ENUM_MODULE_TEXT)
	{
		// A module's .text/.data address, that's it.
		ref->storage_type = segment->m_type;
		ref->where.module.base = segment->m_vaddr;
		ref->where.module.size = segment->m_vsize;
		ref->where.module.name = segment->m_module_name;
	}
	else if (is_heap_block(addr)
			&& get_heap_block_info(addr, &blockinfo) )
	{
		// heap address
		ref->vaddr = addr;
		ref->storage_type = ENUM_HEAP;
		ref->where.heap.addr = blockinfo.addr;
		ref->where.heap.size = blockinfo.size;
		ref->where.heap.inuse = blockinfo.inuse;
	}
	else
	{
		ref->storage_type = ENUM_UNKNOWN;
		//an unknown memory object
		//ref->where.target.size = 1;
	}
}

/////////////////////////////////////////////////////////////////////////
// Given an object, check whether its data member references the target
/////////////////////////////////////////////////////////////////////////
static bool search_object_tree (struct CA_LIST* refs, address_t obj_vaddr, size_t obj_sz, size_t iLevel)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	bool rc = false;
	struct object_reference* ref;
	struct ca_segment* segment;
	address_t sym_addr;
	size_t    sym_sz;
	address_t cursor = 0;
	address_t end = 0;
	struct object_reference new_ref;

	ca_list_traverse_start(refs);
	ref = (struct object_reference*) ca_list_traverse_next(refs);

	segment = get_segment (ref->value, ptr_sz);
	if (!segment)
		return false;

	// go deeper if the referenced value points to a global variable or an in-use heap block
	if (segment->m_type == ENUM_MODULE_DATA && known_global_sym(ref, &sym_addr, &sym_sz))
	{
		cursor = sym_addr;
		end    = sym_addr + sym_sz;
	}
	else if (segment->m_type == ENUM_HEAP && is_heap_block(ref->value))
	{
		struct heap_block blk;
		get_heap_block_info(ref->value, &blk);
		// we generally don't care about free heap memory
		if (blk.inuse || !g_skip_free)
		{
			cursor = blk.addr;
			end    = blk.addr + blk.size;
			new_ref.where.heap.addr = blk.addr;
			new_ref.where.heap.inuse = blk.inuse;
			new_ref.where.heap.size = blk.size;
		}
	}

	if (cursor && end)
	{
		new_ref.level = ref->level + 1;
		new_ref.storage_type = segment->m_type;
		// check each pointer/ref of the memory block
		while (cursor + ptr_sz <= end)
		{
			address_t val = 0;
			if (!read_memory_wrapper(segment, cursor, (void*)&val, ptr_sz))
				break;
			if (val >= obj_vaddr && val < obj_vaddr + obj_sz)
			{
				// find one match
				rc = true;
				new_ref.vaddr = cursor;
				new_ref.value = val;
				ca_list_push_front(refs, &new_ref);
				print_ref_chain (refs);
				ca_list_pop_front(refs);
			}
			else if (iLevel > 1 && val)
			{
				// user wants to dig deeper
				new_ref.vaddr = cursor;
				new_ref.value = val;
				ca_list_push_front(refs, &new_ref);
				if (search_object_tree (refs, obj_vaddr, obj_sz, iLevel - 1))
					rc = true;
				ca_list_pop_front(refs);
			}
			cursor += ptr_sz;
		}
	}

	return rc;
}

/////////////////////////////////////////////////////////////////////////
// Same as find_object_refs, except only thread stack memory is searched
//     including registers of thread context
/////////////////////////////////////////////////////////////////////////
bool find_object_refs_on_threads(address_t obj_vaddr, size_t obj_sz, unsigned int iLevel)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	unsigned int i;
	bool rc = false;

	if (iLevel <= 0 || iLevel > g_max_indirection_level)
	{
		CA_PRINT("The indirecton level %d is too high\n", iLevel);
		return false;
	}

	// static buffer for all register values
	if (g_nregs == 0)
	{
		g_nregs = read_registers (NULL, NULL, 0);
		g_regs_buf = (struct reg_value*) malloc(g_nregs * sizeof(struct reg_value));
	}

	g_output_count = 0;
	// search all threads' registers/stacks
	for (i=0; i<g_segment_count; i++)
	{
		struct ca_segment* segment = &g_segments[i];
		if (user_request_break())
		{
			CA_PRINT("Abort searching references\n");
			break;
		}
		if (segment->m_type == ENUM_STACK)
		{
			int k;
			struct object_reference ref;
			// read register values of this thread context
			int nread = read_registers (segment, g_regs_buf, g_nregs);

			memset(&ref, 0, sizeof(ref));
			for (k=0; k<nread; k++)
			{
				if (g_regs_buf[k].reg_width == ptr_sz
					&& g_regs_buf[k].value >= obj_vaddr && g_regs_buf[k].value < obj_vaddr + obj_sz)
				{
					rc = true;
					ref.storage_type = ENUM_REGISTER;
					ref.where.reg.tid = get_thread_id (segment);
					ref.where.reg.reg_num = k;
					ref.value = g_regs_buf[k].value;
					CA_PRINT("------------------------ %d ------------------------\n", ++g_output_count);
					print_ref(&ref, 0, false, true);
					CA_PRINT("\n");
				}
			}
			// stack memory
			{
				address_t cursor = segment->m_vaddr;
				address_t end    = segment->m_vaddr + segment->m_fsize;
				if (g_skip_free)
				{
					address_t rsp = get_rsp(segment);
					if (rsp > segment->m_vaddr)
						cursor = rsp;
				}
				ref.storage_type = ENUM_STACK;
				ref.where.stack.tid = get_thread_id (segment);
				ref.level = 1;
				while (cursor + ptr_sz <= end)
				{
					address_t val = 0;
					if (!read_memory_wrapper(segment, cursor, (void*)&val, ptr_sz))
						break;
					ref.vaddr = cursor;
					ref.value = val;
					if (val >= obj_vaddr && val < obj_vaddr + obj_sz)
					{
						rc = true;
						ref.where.stack.frame = get_frame_number(segment, cursor, &ref.where.stack.offset);
						CA_PRINT("------------------------ %d ------------------------\n", ++g_output_count);
						print_ref (&ref, 0, false, true);
						CA_PRINT("\n");
					}
					else if (iLevel > 1 && val)
					{
						struct CA_LIST* refs = ca_list_new();
						ca_list_push_front(refs, &ref);
						if (search_object_tree (refs, obj_vaddr, obj_sz, iLevel - 1))
							rc = true;
						ca_list_delete(refs);
					}
					cursor += ptr_sz;
				}
			}
		}
	}
	return rc;
}

/////////////////////////////////////////////////////////////////////////
// Return a list of references to the input object
//   parameter iLevel is ignored for now
/////////////////////////////////////////////////////////////////////////
struct CA_LIST* search_object_refs(address_t obj_vaddr, size_t obj_sz, unsigned int iLevel, enum storage_type stype)
{
	struct CA_LIST* ref_list;
	struct CA_LIST* targets;
	struct CA_LIST* result_list = NULL;
	struct object_range target;

	// set up search target
	target.low = obj_vaddr;
	target.high = target.low + obj_sz;
	targets = ca_list_new();
	ca_list_push_front(targets, &target);

	ref_list = ca_list_new();
	// invoke full-core memory search
	if (search_value_internal(targets, false, stype, ref_list) )
	{
		struct object_reference* ref;
		// References are found, eliminate unwanted and save the rest into result
		result_list = ca_list_new();
		ca_list_traverse_start(ref_list);
		while ( (ref = (struct object_reference*) ca_list_traverse_next(ref_list)) )
		{
			// remove self/circular-reference heap block
			bool dup_heap_block = false;
			if (ref->storage_type == ENUM_HEAP)
			{
				const struct object_reference* cursor;
				ca_list_traverse_start(result_list);
				while ( (cursor = (struct object_reference*) ca_list_traverse_next(result_list)) )
				{
					if (cursor->storage_type == ENUM_HEAP && cursor->where.heap.addr == ref->where.heap.addr)
					{
						dup_heap_block = true;
						break;
					}
				}
			}
			if (!dup_heap_block)
				ca_list_push_front(result_list, ref);
			else
				free (ref);
		}
	}
	ca_list_delete(ref_list);
	ca_list_delete(targets);

	return result_list;
}

/////////////////////////////////////////////////////////////////////////
// Horizontal search.
//     direct and indirect references to an object up to iLevel
/////////////////////////////////////////////////////////////////////////
bool find_object_refs(address_t obj_vaddr, size_t obj_sz, unsigned int iLevel)
{
	unsigned int i, n;
	struct object_reference* ref;
	struct CA_LIST* ref_list;

	// references are placed in an array
	unsigned int ref_cnt = 0;
	unsigned int ref_buf_sz = 64;
	struct object_reference** refs = (struct object_reference**) malloc(sizeof(struct object_reference*)*ref_buf_sz);

	// the 1st element is the searched target
	refs[0] = (struct object_reference*) malloc(sizeof(struct object_reference));
	ref = refs[0];
	ref->level = 0;
	ref->target_index = -1;
	ref->storage_type = ENUM_UNKNOWN;
	ref->vaddr        = obj_vaddr;
	ref->value        = 0;
	ref->where.target.size = obj_sz;
	ref_cnt++;

	//fill_ref_location(ref);
	ref_list = ca_list_new();
	// search references and put in the vector flat out
	for (n=0; n<iLevel; n++)
	{
		unsigned int vec_sz = ref_cnt;
		for (i=0; i<vec_sz; i++)
		{
			ref = refs[i];
			if (ref->level == n && ref->storage_type != ENUM_REGISTER)
			{
				bool target_is_ptr = true;
				struct CA_LIST* targets = ca_list_new();
				struct object_range target;
				target.low = ref->vaddr;
				target.high = target.low + 1;
				// default search scope is the exact address
				if (ref->target_index < 0)
				{
					target_is_ptr = false;
					target.high = target.low + obj_sz;
				}
				else if (ref->storage_type == ENUM_HEAP)
				{
					target.low = ref->where.heap.addr;
					target.high = target.low + ref->where.heap.size;
				}
				ca_list_push_front(targets, &target);
				// invoke full-core memory search
				// ref_list shall be empty at this point
				if (search_value_internal(targets, target_is_ptr, ENUM_UNKNOWN, ref_list) )
				{
					struct object_reference* aref;
					ca_list_traverse_start(ref_list);
					while ( (aref = (struct object_reference*) ca_list_traverse_next(ref_list)) )
					{
						// remove self/circular-reference heap block
						int dup_heap_block = false;
						if (aref->storage_type == ENUM_HEAP)
						{
							int k;
							for (k=ref_cnt-1; k>=0; k--)
							{
								const struct object_reference* cursor = refs[k];
								if (cursor->storage_type == ENUM_HEAP && cursor->where.heap.addr == aref->where.heap.addr)
								{
									dup_heap_block = true;
									break;
								}
							}
						}
						if (!dup_heap_block)
						{
							// append the newly found reference
							aref->level = n + 1;
							aref->target_index = i;
							if (ref_cnt >= ref_buf_sz)
							{
								refs = (struct object_reference**) realloc(refs, ref_buf_sz*2*sizeof(struct object_reference*));
								ref_buf_sz *= 2;
							}
							refs[ref_cnt] = aref;
							ref_cnt++;
						}
						else
							free(aref);
					}
					ca_list_clear(ref_list);
				}
				ca_list_delete(targets);
			}
		}
	}
	ca_list_delete(ref_list);

	// display the result
	if (ref_cnt > 1)
	{
		int ref_cursor = ref_cnt - 1;
		int cur_level = iLevel;
		int indent = 0;
		int prev_target = refs[ref_cursor]->target_index;
		CA_PRINT("------------------------- Level %d -------------------------\n", cur_level);
		clear_addr_type_map();
		while (ref_cursor>0 && cur_level>0)
		{
			struct object_reference* ref = refs[ref_cursor];
			if (ref->level == cur_level)
			{
				int next_referenced;
				// no arrow, verbose
				print_ref(ref, indent, false, true);
				ref_cursor--;
				next_referenced = (refs[ref_cursor])->target_index;
				if (next_referenced != prev_target)
				{
					if (prev_target == 0)
					{
						int k;
						for (k=0; k<indent; k++)
							CA_PRINT("    ");
						CA_PRINT("|--> searched target ["PRINT_FORMAT_POINTER", "PRINT_FORMAT_POINTER")\n", obj_vaddr, obj_vaddr+obj_sz);
					}
					else
						print_ref(refs[prev_target], indent, true, false); // arrow/no verbose
					prev_target = next_referenced;
					CA_PRINT("\n");
					//clear_addr_type_map();
				}
			}
			else
			{
				cur_level--;
				if (cur_level > 0)
				{
					indent++;
					CA_PRINT("------------------------- Level %d -------------------------\n", cur_level);
					//clear_addr_type_map();
				}
			}
		}
		clear_addr_type_map();
	}

	// clean up
	for (i=0; i<ref_cnt; i++)
		free(refs[i]);
	free(refs);

	if (ref_cnt > 1)
		return true;
	return false;
}

/////////////////////////////////////////////////////////////////////////
// Vertical search.
//     Find a recognizable object to identify the type associated with
//     the memory.
/////////////////////////////////////////////////////////////////////////
bool find_object_type(address_t obj_vaddr)
{
	bool lbFound = false;
	int i;
	unsigned int n;
	struct object_reference* ref;
	struct CA_LIST* ref_list;

	// references are placed in an array
	unsigned int k, ref_cnt = 0;
	unsigned int ref_buf_sz = 64;
	struct object_reference** refs;

	// sanity check
	if (!get_segment(obj_vaddr, 1))
	{
		CA_PRINT("[Error] Address "PRINT_FORMAT_POINTER" is not in target's address space\n", obj_vaddr);
		return false;
	}

	refs = (struct object_reference**) malloc(sizeof(struct object_reference*)*ref_buf_sz);
	// the 1st element is the searched target
	refs[0] = (struct object_reference*) malloc(sizeof(struct object_reference));
	ref = refs[0];
	ref->level = 0;
	ref->target_index = -1;
	ref->storage_type = ENUM_UNKNOWN;
	ref->vaddr        = obj_vaddr;
	ref->value        = 0;
	ref->where.target.size = 1;
	ref_cnt++;

	fill_ref_location(ref);
	if (ref->storage_type == ENUM_HEAP)
	{
		if (ref->where.heap.inuse)
		{
			CA_PRINT("Address "PRINT_FORMAT_POINTER" belongs to heap block ["PRINT_FORMAT_POINTER", "PRINT_FORMAT_POINTER"] size="PRINT_FORMAT_SIZE"\n",
				ref->vaddr, ref->where.heap.addr, ref->where.heap.addr+ref->where.heap.size, ref->where.heap.size);
		}
		else
		{
			CA_PRINT("Address "PRINT_FORMAT_POINTER" belongs to a FREE memory block ["PRINT_FORMAT_POINTER", "PRINT_FORMAT_POINTER") size="PRINT_FORMAT_SIZE"\n",
				obj_vaddr, ref->where.heap.addr, ref->where.heap.addr + ref->where.heap.size, ref->where.heap.size);
		}
	}
	// There is no need to dig deeper for free heap block, or
	// if the target is a heap object w/ _vptr
	if (ref->storage_type == ENUM_REGISTER
			|| ref->storage_type == ENUM_STACK
			|| ref->storage_type == ENUM_MODULE_TEXT
			|| ref->storage_type == ENUM_MODULE_DATA
			|| (ref->storage_type == ENUM_HEAP && ref->where.heap.inuse && is_heap_object_with_vptr(ref, NULL, 0)))
		lbFound = true;
	else if (ref->storage_type == ENUM_HEAP && !ref->where.heap.inuse)
		lbFound = false;
	else
	{
		ref_list = ca_list_new();
		// Deep search of heap objects
		for (n=0; !lbFound && n<g_max_indirection_level; n++)
		{
			int vec_sz = ref_cnt;
			if (refs[vec_sz-1]->level != n)	// no more candidate to search
				break;

			for (i=vec_sz-1; !lbFound && i>=0 && refs[i]->level==n; i--)
			{
				bool target_is_ptr = true;
				struct CA_LIST* targets = ca_list_new();
				struct object_range target;
				target.low = ref->vaddr;
				target.high = target.low + 1;
				// searched target can only be heap block or unknown
				ref = refs[i];
				if (ref->storage_type == ENUM_HEAP)
				{
					target.low = ref->where.heap.addr;
					target.high = target.low + ref->where.heap.size;
				}
				else if (ref->target_index < 0)
				{
					target_is_ptr = false;
					target.high = target.low + ref->where.target.size;
				}
				ca_list_push_front(targets, &target);

				// invoke full-core memory search
				if (search_value_internal(targets, target_is_ptr, ENUM_UNKNOWN, ref_list) )
				{
					struct object_reference* aref;
					// first scan for success, global/stack/heap w/o _vptr
					ca_list_traverse_start(ref_list);
					while ( (aref = (struct object_reference*) ca_list_traverse_next(ref_list)) )
					{
						int remove_heap_block = false;
						if ( (aref->storage_type == ENUM_STACK && aref->where.stack.frame >= 0)
							|| aref->storage_type == ENUM_REGISTER
							|| aref->storage_type == ENUM_MODULE_DATA
							|| (aref->storage_type==ENUM_HEAP && aref->where.heap.inuse && is_heap_object_with_vptr(aref, NULL, 0)) )
						{
							lbFound = true;
						}
						// remove self-reference or free heap block
						if (!lbFound && aref->storage_type == ENUM_HEAP)
						{
							if (aref->where.heap.inuse)
							{
								int k;
								for (k=ref_cnt-1; k>=0; k--)
								{
									const struct object_reference* cursor = refs[k];
									if (cursor->storage_type == ENUM_HEAP && cursor->where.heap.addr == aref->where.heap.addr)
									{
										remove_heap_block = true;
										break;
									}
								}
							}
							else
								remove_heap_block = true;
						}
						if (remove_heap_block)
							free(aref);
						else
						{
							// append the newly found reference
							aref->level = n + 1;
							aref->target_index = i;
							if (ref_cnt >= ref_buf_sz)
							{
								refs = (struct object_reference**) realloc(refs, ref_buf_sz*2*sizeof(struct object_reference*));
								ref_buf_sz *= 2;
							}
							refs[ref_cnt] = aref;
							ref_cnt++;
						}
					}
				}
				ca_list_clear(ref_list);
				ca_list_delete(targets);
			}
		}
		ca_list_delete(ref_list);

		if (n == g_max_indirection_level)
			CA_PRINT("Warning: max levels of indirection %d has been reached\n", g_max_indirection_level);
	}

	// display the result
	clear_addr_type_map();
	if (lbFound)
	{
		int count;
		n = refs[ref_cnt-1]->level;
		for (i=ref_cnt-1, count=1; i>=0 && refs[i]->level==n; i--)
		{
			ref = refs[i];
			if ( (ref->storage_type == ENUM_STACK && ref->where.stack.frame >= 0)
				|| ref->storage_type == ENUM_REGISTER
				|| ref->storage_type == ENUM_MODULE_DATA
				|| ref->storage_type == ENUM_MODULE_TEXT
				|| (ref->storage_type==ENUM_HEAP && is_heap_object_with_vptr(ref, NULL, 0)) )
			{
				int indent = 0;
				int next_ref_index = i;
				CA_PRINT("------------------------- %d -------------------------\n", count);
				count++;
				clear_addr_type_map();
				while (next_ref_index >= 0)
				{
					ref = refs[next_ref_index];
					print_ref(ref, indent, indent>0, true);	// verbose
					next_ref_index = ref->target_index;
					indent++;
				}
				CA_PRINT("\n");
			}
		}
	}
	clear_addr_type_map();

	// clean up
	for (k=0; k<ref_cnt; k++)
		free(refs[k]);
	free(refs);

	return lbFound;
}

#ifdef CA_USE_SPLAY_TREE
static int address_comp_func(splay_tree_key a, splay_tree_key b)
{
	if (a > b)
		return 1;
	else if (a == b)
		return 0;
	else
		return -1;
}
#else
static bool address_comp_func(void *lhs, void *rhs)
{
	if ((address_t)lhs < (address_t)rhs)
		return true;
	else
		return false;
}
#endif

/////////////////////////////////////////////////////////////////////////
// Return a list of C++ objects with _vptr to the type of the input expression
//   the caller is responsible to release the list and its elements
/////////////////////////////////////////////////////////////////////////
struct CA_LIST* search_cplusplus_objects_with_vptr(const char* exp)
{
	struct CA_LIST* vtables;
	char type_name[NAME_BUF_SZ];
	size_t type_sz;
	struct object_range* target;
	struct CA_LIST* result_list = NULL;

	vtables = ca_list_new();
	if (get_vtable_from_exp(exp, vtables, type_name, NAME_BUF_SZ, &type_sz))
	{
		struct CA_LIST*	ref_list;

		ref_list = ca_list_new();
    	if (search_value_internal(vtables, true, ENUM_UNKNOWN, ref_list) )
    	{
    		struct object_reference* ref;
    		struct CA_SET* unique_refs = ca_set_new(address_comp_func);

    		result_list = ca_list_new();
    		// go through all found objects
    		ca_list_traverse_start(ref_list);
    		while ( (ref = (struct object_reference*) ca_list_traverse_next(ref_list)) )
    		{
				address_t obj_addr;
    			bool delete_ref = true;
				// avoid slicing of heap object
				if (ref->storage_type == ENUM_HEAP)
					obj_addr = ref->where.heap.addr;
				else
					obj_addr = ref->vaddr;

				if (!ca_set_find(unique_refs, (void*)obj_addr))
				{
					address_t var_addr;
					size_t    var_size;

#ifdef CA_USE_SPLAY_TREE
					ca_set_insert_key_and_val(unique_refs, (void*)obj_addr, (void*)obj_addr);
#else
					ca_set_insert(unique_refs, (void*)obj_addr);
#endif
					// ignore register object
					if (ref->storage_type == ENUM_REGISTER)
					{
					}
					// ignore unknown global (it may be reference from linker generated objects, like import/export items)
					/*else if ( ((ref->storage_type == ENUM_MODULE_TEXT || ref->storage_type == ENUM_MODULE_DATA)
							&& !known_global_sym(ref, NULL, NULL)) )
					{
					}*/
					else if (ref->storage_type == ENUM_MODULE_TEXT || ref->storage_type == ENUM_MODULE_DATA)
					{
					}
					// skip known stack variable which is not a pointer type
					else if (ref->storage_type == ENUM_STACK
							&& (!known_stack_sym(ref, &var_addr, &var_size) || var_size != type_sz))
					{
					}
					else
					{
	    				ref->value = 0;
						ca_list_push_front(result_list, ref);
						delete_ref = false;
					}
				}
    			if (delete_ref)
    				free (ref);
    		}
    		// clean up temporary containers
    		ca_set_delete(unique_refs);
    	}
		ca_list_delete(ref_list);
	}

	// clean up vtables
	ca_list_traverse_start(vtables);
	while ((target = (struct object_range*) ca_list_traverse_next(vtables)) )
		free (target);
	ca_list_delete(vtables);

	return result_list;
}

/////////////////////////////////////////////////////////////////////////
// search C++ objects and references to them by the type of the input expression
/////////////////////////////////////////////////////////////////////////
bool search_cplusplus_objects_and_references(const char* exp, bool thread_scope)
{
	bool lbFound = false;
	struct CA_LIST* vtables = ca_list_new();
	char type_name[NAME_BUF_SZ];
	size_t type_sz;

	if (get_vtable_from_exp(exp, vtables, type_name, NAME_BUF_SZ, &type_sz))
	{
		struct CA_LIST* ref_list;
		struct object_range* target;

		ca_list_traverse_start(vtables);
		target = (struct object_range*) ca_list_traverse_next(vtables);
		CA_PRINT ("Searching objects of type=\"%s\" size=%ld ",	type_name, type_sz);
		if (ca_list_size(vtables) == 1)
			CA_PRINT ("(vtable 0x%lx--0x%lx)\n", target->low, target->high);
		else
		{
			CA_PRINT ("\n");
			while ( (target = (struct object_range*) ca_list_traverse_next(vtables)) )
			{
				CA_PRINT ("\tvtable 0x%lx--0x%lx\n", target->low, target->high);
			}
			CA_PRINT ("\n");
		}

		ref_list = ca_list_new();
    	if (search_value_internal(vtables, true, ENUM_UNKNOWN, ref_list) )
    	{
    		struct object_reference* ref;
    		struct CA_LIST* ref_targets = ca_list_new();
    		struct CA_SET* unique_refs = ca_set_new(address_comp_func);
    		// show found objects
    		ca_list_traverse_start(ref_list);
    		while ( (ref = (struct object_reference*) ca_list_traverse_next(ref_list)) )
    		{
				address_t var_addr = 0;
				size_t    var_size = 0;
				address_t obj_addr;

				// avoid duplicate
				if (ref->storage_type == ENUM_HEAP)
					obj_addr = ref->where.heap.addr;
				else
					obj_addr = ref->vaddr;
				if (ca_set_find(unique_refs, (void*)obj_addr))
					continue;
				else
#ifdef CA_USE_SPLAY_TREE
					ca_set_insert_key_and_val(unique_refs, (void*)obj_addr, (void*)obj_addr);
#else
					ca_set_insert(unique_refs, (void*)obj_addr);
#endif

				// ignore register object
    			if (ref->storage_type == ENUM_REGISTER)
    			{
    			}
    			// ignore unknown global (it may be reference from linker generated objects, like import/export items)
    			/*else if ( ((ref->storage_type == ENUM_MODULE_TEXT || ref->storage_type == ENUM_MODULE_DATA)
    					&& !known_global_sym(ref, NULL, NULL)) )
    			{
    			}*/
    			// ignore all globals to avoid red herrings, e.g. gcc compiler generates global object of "VTT for some_class"
    			else if (ref->storage_type == ENUM_MODULE_TEXT || ref->storage_type == ENUM_MODULE_DATA)
    			{
    			}
    			// skip known stack variable which is not a pointer type
    			else if (ref->storage_type == ENUM_STACK
    					&& (!known_stack_sym(ref, &var_addr, &var_size) || var_size != type_sz))
    			{
    			}
    			else
    			{
					// print out object
    				ref->value = 0;
					print_ref(ref, 1, false, false);
					// put object as the target for the search of its reference
					target = (struct object_range*) malloc (sizeof(struct object_range));
					target->low = ref->vaddr;
					target->high = target->low + type_sz;
					if (ref->storage_type == ENUM_HEAP
							&& target->high > ref->where.heap.addr + ref->where.heap.size)
						target->high = ref->where.heap.addr + ref->where.heap.size;
					ca_list_push_front(ref_targets, target);
    			}
    			// release this found item and move on to the next
    			free (ref);
    		}
    		ca_set_delete(unique_refs);
    		ca_list_clear(ref_list);

    		if (!ca_list_empty(ref_targets))
    		{
				// Search the references to found objects
				CA_PRINT ("\nSearching references to above objects\n");
				if (search_value_internal(ref_targets, true, ENUM_UNKNOWN, ref_list))
				{
		    		ca_list_traverse_start(ref_list);
		    		while ( (ref = (struct object_reference*) ca_list_traverse_next(ref_list)) )
					{
						// print out reference
						print_ref(ref, 1, false, true);
						// release this reference
						free (ref);
					}
		    		ca_list_clear(ref_list);
				}
				// clean up
				ca_list_traverse_start(ref_targets);
				while ( (target = (struct object_range*) ca_list_traverse_next(ref_targets)) )
				{
					free (target);
				}
    		}
    		ca_list_delete(ref_targets);
    	}
    	else
    		CA_PRINT ("No objects are found\n");
    	// clean up vtable targets
    	ca_list_traverse_start(vtables);
    	while ((target = (struct object_range*) ca_list_traverse_next(vtables)) )
    	{
    		free (target);
    	}
	}
    else
    {
    	CA_PRINT ("Failed to resolve the type of expression \"%s\"\n", exp);
    	CA_PRINT ("Only C++ object with virtual table is currently supported\n");
    }

	ca_list_delete(vtables);

	return lbFound;
}

static void
find_shared_objects_one_thread(struct ca_segment* segment, bool ignore_new_shrobj)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	int k, nread;
	struct shared_object* shrobj;
	struct object_reference* aref;
	address_t cursor, end;

	// static buffer for all register values
	if (g_nregs == 0)
	{
		g_nregs = read_registers (NULL, NULL, 0);
		g_regs_buf = (struct reg_value*) malloc(g_nregs * sizeof(struct reg_value));
	}

	// read register values of this thread context
	nread = read_registers (segment, g_regs_buf, g_nregs);
	for (k=0; k<nread; k++)
	{
		if (g_regs_buf[k].reg_width == ptr_sz && g_regs_buf[k].value)
		{
			shrobj = add_one_shared_object(g_regs_buf[k].value, ignore_new_shrobj, 1);
			if (shrobj)
			{
				aref = (struct object_reference*) malloc(sizeof(struct object_reference));
				memset(aref, 0, sizeof(struct object_reference));
				aref->value = g_regs_buf[k].value;
				aref->storage_type = ENUM_REGISTER;
				aref->where.reg.tid = segment->m_thread.tid;
				aref->where.reg.reg_num = k;
				ca_list_push_front(shrobj->thread_owners, aref);
			}
		}
	}

	// stack memory
	cursor = get_rsp(segment);
	end    = segment->m_vaddr + segment->m_fsize;
	if (cursor < segment->m_vaddr || cursor >= segment->m_vaddr + segment->m_vsize)
		cursor = segment->m_vaddr;
	while (cursor + ptr_sz <= end)
	{
		address_t value = 0;
		if (!read_memory_wrapper(segment, cursor, (void*)&value, ptr_sz))
			break;
		if (value)
		{
			shrobj = add_one_shared_object(value, ignore_new_shrobj, 1);
			if (shrobj)
			{
				address_t var_addr = 0;
				size_t    var_size = 0;

				aref = (struct object_reference*) malloc(sizeof(struct object_reference));
				memset(aref, 0, sizeof(struct object_reference));
				aref->storage_type = ENUM_STACK;
				aref->vaddr = cursor;
				aref->value = value;
				aref->where.stack.tid = segment->m_thread.tid;
				aref->where.stack.frame = get_frame_number(segment, cursor, &aref->where.stack.offset);

				if (!known_stack_sym(aref, &var_addr, &var_size)
					|| var_size >= ptr_sz)
				{
					ca_list_push_front(shrobj->thread_owners, aref);
				}
				else
					free (aref);
			}
		}
		cursor += ptr_sz;
	}
}

void set_shared_objects_indirection_level(unsigned int level)
{
	if (level==0 || level>MAX_SHROBJ_LEVEL)
		CA_PRINT("Current indirection level of shared-object search is %d\n", g_shrobj_level);
	else
	{
		g_shrobj_level = level;
		CA_PRINT("Current indirection level of shared-object search is set to %d\n", g_shrobj_level);
	}
}

void set_max_indirection_level(unsigned int level)
{
    if (level == 0)
    	CA_PRINT("Current max levels of indirection is %d\n", g_max_indirection_level);
    else if (level > 0 && level <= MAX_INDIRECTION_LEVEL)
    {
    	g_max_indirection_level = level;
    	CA_PRINT("Current max levels of indirection is set to %d\n", g_max_indirection_level);
    }
    else
    	CA_PRINT("Invalid parameter %d, allowed range [1 ... %d]\n", level, MAX_INDIRECTION_LEVEL);
}

/////////////////////////////////////////////////////////////////////////
// Shared objects that currently referenced from multiple threads
//		threads is a list of threads that we are interested in
// Return true or false
/////////////////////////////////////////////////////////////////////////
static bool shared_objects_internal(struct CA_LIST* threads, bool verbose)
{
	unsigned int i;
	struct ca_segment* segment;
	char* input_tid_map = NULL;
	int max_tid = 0;

	// check whether the thread list contains valid thread IDs
	for (i=0; i<g_segment_count; i++)
	{
		segment = &g_segments[i];
		if (segment->m_type == ENUM_STACK)
		{
			if (segment->m_thread.tid < 0)
			{
				if (verbose)
					CA_PRINT("internal error: tid is negative %d\n", segment->m_thread.tid);
				return false;
			}
			else if (max_tid < segment->m_thread.tid)
				max_tid = segment->m_thread.tid;
		}
	}
	if (max_tid > 64*1024)
	{
		if (verbose)
			CA_PRINT("internal error: tid %d is too big to handle\n", max_tid);
		return false;
	}
	// convert the thread list into an array indexed by thread id
	input_tid_map = (char*) malloc (max_tid + 1);
	if (!ca_list_empty(threads))
	{
		void* p;

		memset(input_tid_map, 0, max_tid + 1);

		ca_list_traverse_start(threads);
		while ( (p = ca_list_traverse_next(threads)))
		{
			int tid = *(int*) p;
			if (tid >=0 && tid <= max_tid)
				input_tid_map[tid] = 1;
			else
			{
				if (verbose)
					CA_PRINT("Input thread id is out of range %d\n", tid);
				free (input_tid_map);
				return false;
			}
		}
	}
	else
		memset(input_tid_map, 1, max_tid + 1);	// empty thread list means all threads

	// set shared object repository to initial state
	init_shared_objects ();

	// First search all input threads' registers/stacks, record all found shared objects
	for (i=0; i<g_segment_count; i++)
	{
		if (user_request_break())
		{
			if (verbose)
				CA_PRINT("Abort searching shared objects\n");
			break;
		}

		segment = &g_segments[i];
		if (segment->m_type == ENUM_STACK && input_tid_map[segment->m_thread.tid])
			find_shared_objects_one_thread (segment, false);
	}
	// Second search all other threads' registers/stacks,
	// ignore all new shared objects, and append owner for previously found shared objects
	for (i=0; i<g_segment_count; i++)
	{
		if (user_request_break())
		{
			if (verbose)
				CA_PRINT("Abort searching shared objects\n");
			break;
		}

		segment = &g_segments[i];
		if (segment->m_type == ENUM_STACK && !input_tid_map[segment->m_thread.tid])
			find_shared_objects_one_thread (segment, true);
	}

	// clean up
	free(input_tid_map);

	return true;
}

/////////////////////////////////////////////////////////////////////////
// Return a list of objects that currently referenced from multiple threads
//		threads is a list of threads that we are interested in
/////////////////////////////////////////////////////////////////////////
struct CA_LIST* search_shared_objects_by_threads(struct CA_LIST* threads)
{
	if (shared_objects_internal(threads, false))
	{
		// Prepare result
		struct shared_object* shrobj;
		struct CA_LIST* result = ca_list_new();

		ca_set_traverse_start(g_shared_objects);
		while ( (shrobj = (struct shared_object*)ca_set_traverse_next(g_shared_objects)) )
		{
			// there might be no owner because we know the stack variable are not of pointer type
			if (ca_list_empty(shrobj->thread_owners) && ca_list_empty(shrobj->parent_shrobjs))
				continue;
			else if (has_multiple_thread_owners(shrobj))
			{
				struct object_reference* ref = (struct object_reference*) malloc(sizeof(struct object_reference));
				ref->vaddr = shrobj->start;
				ref->value = 0;
				ref->target_index = -1;
				ref->level = 0;
				fill_ref_location(ref);
				ca_list_push_front(result, ref);
			}
		}
		return result;
	}
	else
		return NULL;
}

/////////////////////////////////////////////////////////////////////////
// Find objects that currently referenced from multiple threads
//		threads is a list of threads that we are interested in, i.e. any shared object referenced by them
//		depth is the max level of indirect reference
/////////////////////////////////////////////////////////////////////////
bool find_shared_objects_by_threads(struct CA_LIST* threads)
{

	if (shared_objects_internal(threads, true))
	{
		// Display result
		print_shared_objects_by_threads();
		return true;
	}
	else
		return false;
}

/////////////////////////////////////////////////////////////////////////
// Display a reference
/////////////////////////////////////////////////////////////////////////
void print_ref
(const struct object_reference* ref, unsigned int indent, bool print_arrow, bool verbose)
{
	unsigned int i;
	for (i=0; i<indent; i++)
		CA_PRINT("    ");
	if (print_arrow)
		CA_PRINT("|--> ");

	if (ref->storage_type == ENUM_REGISTER)
	{
		CA_PRINT("[register]");
		print_register_ref(ref);
	}
	else if (ref->storage_type == ENUM_STACK)
	{
		CA_PRINT("[stack]");
		print_stack_ref(ref);
	}
	else if (ref->storage_type == ENUM_MODULE_TEXT || ref->storage_type == ENUM_MODULE_DATA)
	{
		if (ref->storage_type == ENUM_MODULE_TEXT)
			CA_PRINT("[.text/.rodata]");
		else
			CA_PRINT("[.data/.bss]");
		print_global_ref(ref);
	}
	else if (ref->storage_type == ENUM_HEAP)
	{
		CA_PRINT("[heap block] "PRINT_FORMAT_POINTER"--"PRINT_FORMAT_POINTER" size="PRINT_FORMAT_SIZE,
			ref->where.heap.addr, ref->where.heap.addr+ref->where.heap.size, ref->where.heap.size);
		if (verbose)
		{
			print_heap_ref(ref);
			if (ref->target_index >= 0 || ref->vaddr != ref->where.heap.addr)
			{
				CA_PRINT(" @+"PRINT_FORMAT_SIZE"", ref->vaddr - ref->where.heap.addr);
				if (ref->value)
					CA_PRINT(": "PRINT_FORMAT_POINTER"", ref->value);
			}
		}
	}
	else
	{
		CA_PRINT("[unknown] "PRINT_FORMAT_POINTER"", ref->vaddr);
		if (ref->value)
			CA_PRINT(": "PRINT_FORMAT_POINTER"", ref->value);
	}
	CA_PRINT("\n");
}

/////////////////////////////////////////////////////////////////////////
// Given a singly-linked list of refs w/ the referenced as the head
/////////////////////////////////////////////////////////////////////////
static void print_ref_chain (struct CA_LIST* refs)
{
	int levels, i;
	struct object_reference* ref;
	struct object_reference* ref_chain[MAX_INDIRECTION_LEVEL];

	CA_PRINT("------------------------ %d ------------------------\n", ++g_output_count);
	levels = ca_list_size(refs);
	// reverse the link list into array
	ca_list_traverse_start(refs);
	for (i=0; i<levels; i++)
	{
		ref = (struct object_reference*) ca_list_traverse_next(refs);
		ref_chain[levels - i - 1] = ref;
	}
	// print out all objects on the list
	clear_addr_type_map();
	for (i=0; i<levels; i++)
	{
		ref = ref_chain[i];
		if (ref->storage_type == ENUM_STACK)
		{
			struct ca_segment* segment = get_segment (ref->vaddr, 1);
			ref->where.stack.frame = get_frame_number(segment, ref->vaddr, &ref->where.stack.offset);
		}
		else if (ref->storage_type == ENUM_REGISTER)
		{
		}
		print_ref(ref, i, true, true);
	}
	CA_PRINT("\n");
}

void print_memory_pattern(address_t lo, address_t hi)
{
	int ptr_bit = g_ptr_bit;
	size_t ptr_sz = ptr_bit >> 3;
	address_t next;

	CA_PRINT("memory pattern ["PRINT_FORMAT_POINTER", "PRINT_FORMAT_POINTER"]:\n", lo, hi);
	for (next = ALIGN(lo,ptr_sz); next+ptr_sz <= hi; next += ptr_sz)
	{
		size_t value = 0;
		int lbSearchString = true;
		int lbIsPointer = false;
		struct object_reference ref;

		if (!read_memory_wrapper(NULL, next, (void*)&value, ptr_sz))
		{
			CA_PRINT("inaccessible memory "PRINT_FORMAT_POINTER"\n", next);
			break;
		}

		/* Skip 0 assuming the memory region contains sparse data */
		if (value == 0)
		{
			CA_PRINT(PRINT_FORMAT_POINTER": 0\n", next);
			continue;
		}

		ref.level        = 0;
		ref.target_index = -1;
		ref.storage_type = ENUM_UNKNOWN;
		ref.vaddr        = value;
		ref.value        = 0;
		ref.where.target.size = 1;
		fill_ref_location(&ref);

		CA_PRINT(PRINT_FORMAT_POINTER": "PRINT_FORMAT_POINTER, next, value); // assuming 64bit or 16 hex digits
		if (ref.storage_type == ENUM_STACK
			|| ref.storage_type == ENUM_MODULE_DATA
			|| ref.storage_type == ENUM_MODULE_TEXT)
			lbSearchString = false;

		if (ref.storage_type == ENUM_STACK
			|| ref.storage_type == ENUM_MODULE_DATA
			|| ref.storage_type == ENUM_MODULE_TEXT
			|| ref.storage_type == ENUM_HEAP)
		{
			lbIsPointer = true;
			CA_PRINT(" => ");
			print_ref(&ref, 0, false, true);	// no indent, no arrow decoration, verbose
		}
		else
			CA_PRINT("\n");

		if (!lbSearchString)
			continue;

		/* check char[] if this is not a pointer */
		if (!lbIsPointer)
		{
			address_t next2;
			address_t prev_printed = next;
			for (next2=next; next2<next+ptr_sz; next2++)
			{
				bool lbWString;
				long lStrLen;
				lStrLen = is_string(next2, min_chars, &lbWString);
				if (lStrLen)
				{
					// compute "next" so it is the last 8-bytes of the found string
					next = next2 + lStrLen + (lbWString ? sizeof(wchar_t) : sizeof(char));
					next = ALIGN(next,ptr_sz) - ptr_sz;
					if (next > prev_printed)
					{
						value = 0;
						if (read_memory_wrapper(NULL, next, (void*)&value, ptr_sz))
						{
							CA_PRINT("...\n");
							if (ptr_bit == 64)
								CA_PRINT(PRINT_FORMAT_POINTER": 0x%016lx\n", next, value);
							else
								CA_PRINT(PRINT_FORMAT_POINTER": 0x%08lx\n", next, value);
						}
					}
					if (lbWString)
					{
						CA_PRINT("\t\twchar_t[] => L\"");
						print_wstring(next2);
					}
					else
					{
						CA_PRINT("\t\tchar[] => \"");
						print_string(next2);
					}
					CA_PRINT("\"\n");
					break;
				}
			}
		}
		else	// Otherwise, check if this is a pointer to a string
		{
			address_t addr = value;
			bool lbWString;
			long lStrLen = is_string(addr, min_chars, &lbWString);
			if (lStrLen)
			{
				if (lbWString)
				{
					CA_PRINT("\t\t(wchar_t*) => L\"");
					print_wstring(addr);
				}
				else
				{
					CA_PRINT("\t\t(char*) => \"");
					print_string(addr);
				}
				CA_PRINT("\"\n");
			}
		}
	}
}

/*
 * Given a string of command options, end each option with '\0',
 * 		and store in an array
 * Return number of options
 */
int ca_parse_options(char* arg, char** out)
{
	int count = 0;
	char* cursor = arg;
	char* end    = arg + strlen(arg);
	while (cursor < end && *cursor)
	{
		if (*cursor == ' ' || *cursor == '\t')
			cursor++;
		else
		{
			char* next = cursor + 1;
			// push this option to the back of the array
			out[count] = cursor;
			count++;
			if (count > MAX_NUM_OPTIONS)
			{
				CA_PRINT ("Warning: Too many options > %d\n", MAX_NUM_OPTIONS);
				return count;
			}
			// end this option with '\0'
			// find the end of this argument
			while (*next && *next != ' ' && *next != '\t')
				next++;
			*next = '\0';
			cursor = next + 1;
		}
	}
	return count;
}

/***************************************************************************
* Memory pattern helpers
***************************************************************************/

// addr is the place to search string
// return string len in bytes if found
static size_t
is_string(address_t addr, int min_chars, bool* orbWString)
{
	// search char[]
	size_t len;
	address_t str_addr;
	{
		char c;
		len = 0;
		for (str_addr = addr; ; str_addr++)
		{
			if (!read_memory_wrapper(NULL, str_addr, (void*)&c, sizeof(c)))
				break;
			if (isprint(c))
				len++;
			else
				break;
		}
		if (len >= min_chars)
		{
			*orbWString = false;
			return len;
		}
	}
	// search wchar_t[]
	// assume addr is aligned on wchar_t
	//if ((addr % sizeof(wchar_t)) == 0)
	{
		wchar_t wc;
		len = 0;
		for (str_addr = addr; ; str_addr += sizeof(wchar_t))
		{
			if (!read_memory_wrapper(NULL, str_addr, (void*)&wc, sizeof(wc)))
				break;
			wc &= 0xff;
			if (isprint(wc))
				len ++;
			else
				break;
		}
		if (len >= min_chars)
		{
			*orbWString = true;
			return len * sizeof(wchar_t);
		}
	}

	return 0;
}

static void
print_string(address_t str)
{
	char c;
	if (!str)
		return;

	do
	{
		c = 0;
		if (read_memory_wrapper(NULL, str, (void*)&c, sizeof(c)))
		{
			if (c)
			{
				CA_PRINT("%c", c);
				str += sizeof(c);
			}
		}
		else
			break;
	} while (c);
}

static void
print_wstring(address_t str)
{
	wchar_t wc;

	if (!str)
		return;

	do
	{
		wc = 0;
		if (read_memory_wrapper(NULL, str, (void*)&wc, sizeof(wc)))
		{
			if (wc)
			{
				//wprintf(L"%lc", wc);
				CA_PRINT("%c", wc);
				str += sizeof(wc);
			}
		}
		else
			break;
	} while (wc);
}

/***************************************************************************
* Helper functions for shared objects
***************************************************************************/
#ifdef CA_USE_SPLAY_TREE
#define shared_object_comp_func address_comp_func
#else
static bool shared_object_comp_func(void *lhs, void *rhs)
{
	struct shared_object* shrobj1 = (struct shared_object*)lhs;
	struct shared_object* shrobj2 = (struct shared_object*)rhs;
	if (shrobj1->start < shrobj2->start)
		return true;
	else
		return false;
}
#endif

static void empty_shared_objects(void)
{
	struct shared_object* shrobj;

	if (!g_shared_objects)
		return;

	// free shared objects one by one
	ca_set_traverse_start (g_shared_objects);
	while ( (shrobj = (struct shared_object*)ca_set_traverse_next(g_shared_objects)) )
	{
		struct object_reference* ref;
		struct CA_LIST* owners = shrobj->thread_owners;
		// cleanup owners
		ca_list_traverse_start(owners);
		while ( (ref = (struct object_reference*) ca_list_traverse_next(owners)) )
			free(ref);
		ca_list_delete(owners);
		ca_list_delete(shrobj->parent_shrobjs);
		// free shared object itself
		free(shrobj);
	}
	// remove all nodes
	ca_set_delete(g_shared_objects);
	g_shared_objects = NULL;
}

static void init_shared_objects(void)
{
	empty_shared_objects ();
	g_shared_objects = ca_set_new (shared_object_comp_func);
}

/*
 * if the object is first time seen, create an entry for it
 * Return a new reference, which is attached to the object's owner list
 */
static struct shared_object*
find_or_insert_object(address_t obj_start, size_t obj_size, bool ignore_new_shrobj)
{
	/* search previously found shared objects */
	struct shared_object  anobj;
	struct shared_object* shrobj;

	anobj.start = obj_start;
	anobj.end   = obj_start + obj_size;
#ifdef CA_USE_SPLAY_TREE
	shrobj = (struct shared_object* ) ca_set_find (g_shared_objects, (void*)obj_start);
#else
	shrobj = (struct shared_object* ) ca_set_find (g_shared_objects, &anobj);
#endif
	if (!shrobj && !ignore_new_shrobj)
	{
		// This is a new shared object
		shrobj = (struct shared_object*) malloc(sizeof(struct shared_object));
		shrobj->start = anobj.start;
		shrobj->end   = anobj.end;
		shrobj->thread_owners = ca_list_new();
		shrobj->parent_shrobjs = ca_list_new();
#ifdef CA_USE_SPLAY_TREE
		ca_set_insert_key_and_val(g_shared_objects, (void*)shrobj->start, shrobj);
#else
		ca_set_insert (g_shared_objects, shrobj);
#endif
	}

	return shrobj;
}

static void
get_all_parents(struct CA_SET* parents, struct shared_object* shrobj, unsigned int level)
{
	if (level < g_shrobj_level)
	{
		struct shared_object* parent = NULL;
		ca_list_traverse_start(shrobj->parent_shrobjs);
		while ( (parent = (struct shared_object*) ca_list_traverse_next(shrobj->parent_shrobjs) ) )
		{
#ifdef CA_USE_SPLAY_TREE
			ca_set_insert_key_and_val(parents, (void*)parent->start, parent);
#else
			ca_set_insert(parents, parent);
#endif
			if (level+1 < g_shrobj_level)
				get_all_parents(parents, parent, level+1);
		}
	}
}

static bool has_multiple_thread_owners(struct shared_object* shrobj)
{
	int tid;
	int first_seen_tid = -1;
	struct object_reference* ref;
	bool rc = false;

	// first check all thread owners
	ca_list_traverse_start(shrobj->thread_owners);
	while ( (ref = (struct object_reference*) ca_list_traverse_next(shrobj->thread_owners) ) )
	{
		tid = (ref->storage_type == ENUM_STACK) ? ref->where.stack.tid : ref->where.reg.tid;
		// if this thread is first seen
		if (first_seen_tid >= 0)
		{
			if (first_seen_tid != tid)
				return true;
		}
		else
			first_seen_tid = tid;
	}

	// At this point, there is no or only one thread owner of this shared object
	// if this is a child object, check parental shared objects
	if (g_shrobj_level > 1 && !ca_list_empty(shrobj->parent_shrobjs))
	{
		struct shared_object* obj;
		struct CA_SET* parents;

		parents = ca_set_new(shared_object_comp_func);
		get_all_parents(parents, shrobj, 1);

		ca_set_traverse_start(parents);
		while ( rc == false && (obj = (struct shared_object*) ca_set_traverse_next(parents)) )
		{
			ca_list_traverse_start(obj->thread_owners);
			while ( (ref = (struct object_reference*) ca_list_traverse_next(obj->thread_owners) ) )
			{
				tid = (ref->storage_type == ENUM_STACK) ? ref->where.stack.tid : ref->where.reg.tid;
				// if this thread is first seen
				if (first_seen_tid >= 0)
				{
					if (first_seen_tid != tid)
					{
						rc = true;
						break;
					}
				}
				else
					first_seen_tid = tid;
			}
		}
		ca_set_delete(parents);
	}

	return rc;
}

static void
print_one_shared_object(struct shared_object* shrobj, struct CA_LIST* child_chain)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct object_reference* ref;
	struct shared_object* child;
	int level;
	address_t parent_obj_start, parent_obj_end;

	// first all thread owners
	ca_list_traverse_start(shrobj->thread_owners);
	while ( (ref = (struct object_reference*) ca_list_traverse_next(shrobj->thread_owners) ) )
		print_ref(ref, 1, false, true);

	// print the parent chain reaching this shared object
	level = 1;
	parent_obj_start = shrobj->start;
	parent_obj_end   = shrobj->end;
	ca_list_traverse_start(child_chain);
	while ( (child = (struct shared_object*) ca_list_traverse_next(child_chain) ) )
	{
		struct object_reference aref;
		bool lbfound = false;
		address_t val = 0;
		address_t cursor;
		for (cursor = parent_obj_start; cursor + ptr_sz <= parent_obj_end; cursor += ptr_sz)
		{
			if (!read_memory_wrapper(NULL, cursor, (void*)&val, ptr_sz))
			{
				CA_PRINT("internal error: failed to read core memory at "PRINT_FORMAT_POINTER"\n", cursor);
				break;
			}
			if (val >= child->start && val < child->end)
			{
				lbfound = true;
				aref.vaddr = cursor;
				aref.value = val;
				aref.target_index = -1;
				aref.level = 0;
			}
		}
		level++;
		if (lbfound)
		{
			fill_ref_location(&aref);
			print_ref(&aref, level, true, true);
		}
		else
			CA_PRINT("internal error: impossible switch\n");
		parent_obj_start = child->start;
		parent_obj_end   = child->end;
	}

	// if this is a child object, go to parental shared objects
	if (ca_list_size(child_chain)+1 < g_shrobj_level
		&& !ca_list_empty(shrobj->parent_shrobjs) )
	{
		CA_PRINT("    ...................................................\n");
		ca_list_push_front(child_chain, shrobj);
		ca_list_traverse_start(shrobj->parent_shrobjs);
		while ( (child = (struct shared_object*) ca_list_traverse_next(shrobj->parent_shrobjs) ) )
		{
			print_one_shared_object(child, child_chain);
		}
		ca_list_pop_front(child_chain);
	}
}

static void print_shared_objects_by_threads(void)
{
	int count = 0;
	struct shared_object* shrobj;
	struct CA_LIST* child_chain = ca_list_new();

	ca_set_traverse_start(g_shared_objects);
	while ( (shrobj = (struct shared_object*)ca_set_traverse_next(g_shared_objects)) )
	{
		// there might be no owner because we know the stack variable are not of pointer type
		if (ca_list_empty(shrobj->thread_owners) && ca_list_empty(shrobj->parent_shrobjs))
			continue;

		// We are only interested in shared object referenced by more than one thread
		// which is a candidate of race condition
		// Display all references to this object
		if (has_multiple_thread_owners(shrobj))
		{
			struct object_reference aref;

			CA_PRINT("------------------------ %d ------------------------\n", ++count);
			// print the shared object first
			aref.vaddr = shrobj->start;
			aref.value = 0;
			aref.target_index = -1;
			aref.level = 0;
			fill_ref_location(&aref);
			CA_PRINT("shared object: ");
			if (aref.storage_type == ENUM_MODULE_DATA)
			{
				struct ca_segment* segment = get_segment(aref.vaddr, 1);
				if (segment && !segment->m_write)
					CA_PRINT("(read-only) ");
			}
			print_ref(&aref, 0, false, true);
			// then print the thread references to the shared object
			ca_list_clear(child_chain);
			print_one_shared_object(shrobj, child_chain);
		}
	}

	ca_list_delete(child_chain);
}

static struct shared_object*
add_one_shared_object(address_t addr, bool ignore_new_shrobj, unsigned int level)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct ca_segment* segment = get_segment(addr, 8);
	struct shared_object* shrobj;
	address_t obj_addr = 0;
	size_t    obj_size = 0;

	if (!segment)
		return NULL;

	// figure out the addr/size of the object
	if (segment->m_type == ENUM_HEAP)
	{
		struct heap_block blockinfo;
		if (is_heap_block(addr)
			&& get_heap_block_info(addr, &blockinfo)
			&& blockinfo.inuse == true)
		{
			obj_addr = blockinfo.addr;
			obj_size = blockinfo.size;
		}
	}
	else if (segment->m_type == ENUM_MODULE_DATA)
	{
		struct object_reference obj_ref;
		obj_ref.storage_type = ENUM_MODULE_DATA;
		obj_ref.vaddr = addr;
		if (!known_global_sym(&obj_ref, &obj_addr, &obj_size))
		{
			obj_addr = addr;
			obj_size  = 1;
		}
	}

	if (obj_addr && obj_size)
	{
		shrobj = find_or_insert_object(obj_addr, obj_size, ignore_new_shrobj);
		// if deeper relationship is desired, call me recursively
		if (shrobj && level < g_shrobj_level)
		{
			address_t cursor;
			for(cursor = obj_addr;
				cursor + ptr_sz < obj_addr + obj_size;
				cursor += ptr_sz )
			{
				address_t value = 0;
				if (!read_memory_wrapper(NULL, cursor, (void*)&value, ptr_sz))
					break;
				else if (value)
				{
					struct shared_object* child_shrobj = add_one_shared_object(value, ignore_new_shrobj, level+1);
					if (child_shrobj && !ca_list_find(child_shrobj->parent_shrobjs, shrobj))
					{
						ca_list_push_front(child_shrobj->parent_shrobjs, shrobj);
					}
				}
			}
		}
	}
	else
		shrobj = NULL;

	return shrobj;
}
