/*
 * segment.c
 * 		Represent a process image in a set of segments
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "segment.h"


/***************************************************************************
* Global variables
***************************************************************************/
struct ca_segment* g_segments = NULL;
unsigned int g_segment_count = 0;

/***************************************************************************
* Internal representation of memory segments
* 	segment infos are sorted and cached in a buffer
***************************************************************************/
static unsigned int g_segment_buffer_size = 0;
#define INIT_SEG_BUFFER_SZ 256
static size_t g_bitvec_length = 0;

static void* sys_alloc(size_t sz);
static void  sys_free(void* p, size_t sz);
/////////////////////////////////////////////////////////
// Dismantle all segments previously built
// but keep the buffer for reuse
/////////////////////////////////////////////////////////
CA_BOOL release_all_segments(void)
{
	unsigned int i;
	struct ca_segment* segment;
	// release the bit vector, which is one monolithic region
	for (i=0; i<g_segment_count; i++)
	{
		segment = &g_segments[i];
		if (segment->m_ptr_bitvec)
		{
			sys_free(segment->m_ptr_bitvec, g_bitvec_length);
			break;
		}
	}
	// release module_name
	for (i=0; i<g_segment_count; i++)
	{
		segment = &g_segments[i];
		if ((segment->m_type == ENUM_MODULE_TEXT || segment->m_type == ENUM_MODULE_DATA)
			&& segment->m_module_name)
			free((void*)segment->m_module_name);
	}
	// Since all ca_segments are on a big buffer, simply ground the indexes
	g_segment_count = 0;

	return CA_TRUE;
}

// Expand buffer for at least "inc" slots
static void prepare_segment_buffer(unsigned int inc)
{
	if (!g_segments)
	{
		g_segments = (struct ca_segment*) malloc(sizeof(struct ca_segment)*INIT_SEG_BUFFER_SZ);
		g_segment_buffer_size = INIT_SEG_BUFFER_SZ;
	}
	else if (g_segment_count + inc > g_segment_buffer_size)
	{
		g_segment_buffer_size *= 2;
		g_segments = (struct ca_segment*) realloc(g_segments, sizeof(struct ca_segment)*g_segment_buffer_size);
	}
}

//  Split a segment into two parts at given address
static void split_segment(struct ca_segment* segment, address_t addr)
{
	unsigned int index;
	size_t old_vsize, old_fsize;
	struct ca_segment* next;

	// Sanity check
	if (addr < segment->m_vaddr || addr >= segment->m_vaddr + segment->m_vsize)
		return;

	// Move down segments after me
	index = segment - &g_segments[0];
	if (index < g_segment_count - 1)
	{
		unsigned int i;
		for (i = g_segment_count - 1; ; i--)
		{
			memcpy(&g_segments[i + 1], &g_segments[i], sizeof(struct ca_segment));
			if (i == index)
				break;
		}
	}
	g_segment_count++;
	// Adjust the first part
	old_vsize = segment->m_vsize;
	old_fsize = segment->m_fsize;
	segment->m_vsize = addr - segment->m_vaddr;
	if (segment->m_fsize > segment->m_vsize)
		segment->m_fsize = segment->m_vsize;
	// Adjust the second part
	next = segment + 1;
	next->m_vaddr = addr;
	next->m_vsize = old_vsize - segment->m_vsize;
	if (segment->m_faddr)
		next->m_faddr = segment->m_faddr + segment->m_vsize;
	if (old_fsize > segment->m_fsize)
		next->m_fsize = old_fsize - segment->m_fsize;
	if (segment->m_module_name)
		next->m_module_name = strdup(segment->m_module_name);
	if (next->m_ptr_bitvec)
	{
		if (next->m_fsize > 0)
		{
			size_t ptr_sz = g_ptr_bit >> 3;
			next->m_ptr_bitvec = (unsigned int*)((char*)segment->m_ptr_bitvec + (segment->m_fsize/ptr_sz >> 3));
		}
		else
			next->m_ptr_bitvec = NULL;
	}
}

/////////////////////////////////////////////////////////////////////
// [1] Append a new segment to the end of the array of
//        segments in my previous collection.
// [2] If the new segment is a subset of an existing segment, split it
/////////////////////////////////////////////////////////////////////
struct ca_segment*
add_one_segment(address_t vaddr, size_t size,
		       CA_BOOL read, CA_BOOL write, CA_BOOL exec)
{
	struct ca_segment* segment = NULL;

	// We need no more than two more slots in the buffer
	prepare_segment_buffer(2);

	segment = &g_segments[g_segment_count-1];
	if (g_segment_count == 0 || vaddr >= segment->m_vaddr + segment->m_vsize)
	{
		// In most case, new segment's address is higher
		segment = &g_segments[g_segment_count++];
		segment->m_vaddr = vaddr;
		segment->m_vsize = size;
		segment->m_faddr = NULL;
		if (!read || g_debug_core)
			segment->m_fsize = 0;
		else
			segment->m_fsize = size;
		segment->m_type = ENUM_UNKNOWN;
		segment->m_bitvec_ready = 0;
		segment->m_read  = read ? 1:0;
		segment->m_write = write ? 1:0;
		segment->m_exec  = exec ? 1:0;
		segment->m_reserved = 0;
		segment->m_thread.tid = -1;
		segment->m_module_name = NULL;
		segment->m_ptr_bitvec = NULL;
	}
	else
	{
		size_t ptr_sz = g_ptr_bit >> 3;
		size_t ptr_mask = ptr_sz - 1;
		// round up addr/size
		vaddr = (vaddr + ptr_mask) & (~ptr_mask);
		size = (size + ptr_mask) & (~ptr_mask);
		segment = get_segment(vaddr, size);
		if (segment)
		{
			// an existing segment fully consists of the new one
			// check the head
			if (segment->m_vaddr < vaddr)
			{
				split_segment(segment, vaddr);	// permission bits should be the same
				segment++;
			}
			// check the foot, segment->m_vaddr should be vaddr at this point
			if (segment->m_vsize > size)
			{
				split_segment(segment, vaddr + size);
			}
		}
		else
			CA_PRINT("Error: add_one_segment("PRINT_FORMAT_POINTER", "PRINT_FORMAT_POINTER") segment is added in wrong order\n",
					vaddr, vaddr + size);
	}

	if (g_segments[g_segment_count-1].m_vaddr == 0)
	{
		CA_PRINT("Internal error: g_segment_count %d\n", g_segment_count);
	}
	return segment;
}

//////////////////////////////////////////////////////////////
// Return the segment containing the given memory range
// use binary search since segments are sorted by vaddr
//////////////////////////////////////////////////////////////
struct ca_segment* get_segment(address_t addr, size_t len)
{
	unsigned int l_index = 0;
	unsigned int u_index = g_segment_count;
	address_t target_end;

	if (len == 0)
		len = 1;
	target_end = addr + len;
	// bail out for out of bound addr
	if (addr < g_segments[0].m_vaddr
		|| target_end > g_segments[u_index-1].m_vaddr+g_segments[u_index-1].m_vsize)
		return NULL;

	while (l_index < u_index)
	{
		unsigned int m_index = (l_index + u_index) / 2;
		struct ca_segment* segment = &g_segments[m_index];
		if (target_end <= segment->m_vaddr)
			u_index = m_index;
		else if (addr >= segment->m_vaddr + segment->m_vsize)
			l_index = m_index + 1;
		else
			return segment;
	}
	return NULL;
}

CA_BOOL alloc_bit_vec(void)
{
	unsigned int i;
	char* buffer;
	size_t ptr_sz = g_ptr_bit >> 3;

	g_bitvec_length = 0;
	for (i=0; i<g_segment_count; i++)
	{
		struct ca_segment* segment = &g_segments[i];
		size_t seg_bits = segment->m_fsize/ptr_sz;
		g_bitvec_length += ALIGN(seg_bits, 32) >> 5;
	}
	// Carve the buffer into pieces for each segment's bit vector
	g_bitvec_length *= sizeof(unsigned int);
	buffer = (char*) sys_alloc(g_bitvec_length);
	for (i=0; i<g_segment_count; i++)
	{
		struct ca_segment* segment = &g_segments[i];
		if (segment->m_fsize > 0)
		{
			size_t seg_bits = segment->m_fsize/ptr_sz;
			segment->m_ptr_bitvec = (unsigned int*) buffer;
			buffer += ALIGN(seg_bits, 32) >> 3;
		}
	}
	return CA_TRUE;
}

CA_BOOL test_segments(CA_BOOL verbose)
{
	unsigned int i, len;
	struct ca_segment* seg;
	struct ca_segment* seg1;
	struct ca_segment* seg2;

	if (g_segment_count <= 0)
	{
		if (verbose)
			CA_PRINT("There is not segments to test\n");
		return CA_FALSE;
	}
	// make sure all segments are properly sorted by address and there is no overlap
	for (i=0; i<g_segment_count-1; i++)
	{
		seg1 = &g_segments[i];
		seg2 = &g_segments[i+1];
		if (seg1->m_vaddr + seg1->m_vsize > seg2->m_vaddr)
		{
			if (verbose)
			{
				CA_PRINT("The following segments are in wrong order:\n");
				CA_PRINT("\t[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i, seg1->m_vaddr, seg1->m_vaddr + seg1->m_vsize);
				CA_PRINT("\t[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i+1, seg2->m_vaddr, seg2->m_vaddr + seg2->m_vsize);
			}
			return CA_FALSE;
		}
	}
	// make sure query segment function works well
	for (len=0; len<2; len++)
	{
		// low address
		seg = &g_segments[0];
		if (get_segment(seg->m_vaddr - 1, len) != NULL)
		{
			if (verbose)
			{
				CA_PRINT("An address less than the 1st segment returns a valid segment\n");
				CA_PRINT("[0] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
			}
			return CA_FALSE;
		}
		// high address
		seg = &g_segments[g_segment_count-1];
		if (get_segment(seg->m_vaddr + seg->m_vsize, len) != NULL)
		{
			if (verbose)
			{
				CA_PRINT("An address higher than the last segment returns a valid segment\n");
				CA_PRINT("[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", g_segment_count-1, seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
			}
			return CA_FALSE;
		}
		for (i=0; i<g_segment_count; i++)
		{
			seg = &g_segments[i];
			// Segment's beginning address
			if (get_segment(seg->m_vaddr, len) != seg)
			{
				if (verbose)
				{
					CA_PRINT("Segment's start address doesn't return this segment\n");
					CA_PRINT("[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i, seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
				}
				return CA_FALSE;
			}
			// segment's end address
			if (get_segment(seg->m_vaddr + seg->m_vsize, len) == seg)
			{
				if (verbose)
				{
					CA_PRINT("Segment's end address returns this segment\n");
					CA_PRINT("[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i, seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
				}
				return CA_FALSE;
			}
			if (get_segment(seg->m_vaddr + seg->m_vsize - 8, 8) != seg)
			{
				if (verbose)
				{
					CA_PRINT("Segment's last block doesn't return this segment\n");
					CA_PRINT("[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i, seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
				}
				return CA_FALSE;
			}
			// segment's mid address
			if (get_segment(seg->m_vaddr + seg->m_vsize/2, len) != seg)
			{
				if (verbose)
				{
					CA_PRINT("Segment's middle address doesn't return this segment\n");
					CA_PRINT("[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i, seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
				}
				return CA_FALSE;
			}
			// segments' gap
			if (i < g_segment_count - 1)
			{
				seg2 = &g_segments[i+1];
				if (seg->m_vaddr + seg->m_vsize < seg2->m_vaddr
					&& get_segment(seg->m_vaddr + seg->m_vsize, len) != NULL)
				{
					if (verbose)
					{
						CA_PRINT("An address "PRINT_FORMAT_POINTER" len=%d between two segments should return no segment:\n", seg->m_vaddr + seg->m_vsize, len);
						CA_PRINT("\t[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i, seg->m_vaddr, seg->m_vaddr + seg->m_vsize);
						CA_PRINT("\t[%d] "PRINT_FORMAT_POINTER" -- "PRINT_FORMAT_POINTER"\n", i+1, seg2->m_vaddr, seg2->m_vaddr + seg2->m_vsize);
					}
					return CA_FALSE;
				}
			}
		}
	}
	return CA_TRUE;
}

//////////////////////////////////////////////////////////////
// Optimization for repeated reference searches
//		use a bitvec to indicate whether a data in target's
//		address space is a pointer or not.
//////////////////////////////////////////////////////////////
CA_BOOL set_addressable_bit_vec(struct ca_segment* segment)
{
	if (segment->m_fsize>0 && !segment->m_bitvec_ready)
	{
		size_t ptr_sz = g_ptr_bit >> 3;
		const char* start = segment->m_faddr;
		const char* next  = start;
		const char* end   = start + segment->m_fsize;

		while (next + ptr_sz <= end)
		{
			address_t val = 0;
			if (ptr_sz == 8)
			{
#ifdef sun
				// data in sparcv9 core file aligns on 4-byte only. sigh..
				if ((address_t)next & 0x7ul)
					memcpy(&val, next, 8);
				else
#endif
					val = *(address_t*)next;
			}
			else
				val = *(unsigned int*)next;
			// Assuming bitvec is sparse,
			// Get its buffer by mmap therefore initial values are zero
			// We only need to set the bits of addressable pointers
			if (val)
			{
				// there is a good chance that a valid ptr points to its own segment where the ptr is
				if ( (val >= segment->m_vaddr && val < segment->m_vaddr + segment->m_vsize)
					|| get_segment(val, 1) )
				{
					size_t offset = (next - start) / ptr_sz;
					unsigned int bit = 1 << (offset & (size_t)0x1F);
					segment->m_ptr_bitvec[offset>>5] |= bit;
				}
			}
			next += ptr_sz;
		}
		// done
		segment->m_bitvec_ready = 1;
	}
	return CA_TRUE;
}

//////////////////////////////////////////////////////////////
// A simple implementation to remember user's choice of fake
// data values
//////////////////////////////////////////////////////////////
struct temp_value
{
	struct temp_value* next;
	address_t addr;
	address_t value;
};

static struct temp_value* g_set_values = NULL;

void set_value (address_t addr, address_t value)
{
	struct temp_value* pval = (struct temp_value*) malloc(sizeof(struct temp_value));
	pval->next = g_set_values;
	pval->addr = addr;
	pval->value = value;
	g_set_values = pval;
}

void unset_value (address_t addr)
{
	struct temp_value* pval = g_set_values;
	struct temp_value* previous = NULL;
	while (pval)
	{
		if (pval->addr == addr)
		{
			if (previous)
				previous->next = pval->next;
			else
				g_set_values = pval->next;
			free (pval);
			return;
		}
		previous = pval;
	}
}

void print_set_values (void)
{
	struct temp_value* pval = g_set_values;
	if (!pval)
	{
		CA_PRINT("No value is set\n");
		return;
	}

	while (pval)
	{
		CA_PRINT(PRINT_FORMAT_POINTER": "PRINT_FORMAT_POINTER"\n", pval->addr, pval->value);
		pval = pval->next;
	}
}

static CA_BOOL get_preset_value (address_t addr, void* buffer, size_t sz)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	struct temp_value* pval = g_set_values;
	while (pval)
	{
		if (pval->addr >= addr && pval->addr + ptr_sz <= addr + sz)
		{
			if (ptr_sz == 8)
				*(address_t*)((char*)buffer + (pval->addr - addr)) = pval->value;
			else
				*(unsigned int*)((char*)buffer + (pval->addr - addr)) = pval->value;
		}
		pval = pval->next;
	}
	return CA_TRUE;
}

//////////////////////////////////////////////////////////////
// segment may be cached by for better performance
//////////////////////////////////////////////////////////////
CA_BOOL read_memory_wrapper (struct ca_segment* segment, address_t addr, void* buffer, size_t sz)
{
	size_t ptr_sz = g_ptr_bit >> 3;
	CA_BOOL rc = CA_FALSE;
	if (g_debug_core && g_segment_count)
	{
		char* mapped_addr;
		static struct ca_segment* last_seg  = NULL;
		// use caller provided segment
		if (segment && addr >= segment->m_vaddr && addr+sz <= segment->m_vaddr+segment->m_fsize)
		{
			mapped_addr = (char*)(segment->m_faddr + (addr - segment->m_vaddr));
#if !defined(sun)
			if (sz == ptr_sz)	// fast path for pointer/ref
			{
				if (ptr_sz == 8)
					*(address_t*)buffer = *(address_t*)mapped_addr;
				else
					*(unsigned int*)buffer = *(unsigned int*)mapped_addr;
			}
			else
#endif
				memcpy(buffer, mapped_addr, sz);
			rc = CA_TRUE;
		}
		// Otherwise, find the belonging segment and cache it
		else if (!last_seg || addr < last_seg->m_vaddr || addr+sz > last_seg->m_vaddr+last_seg->m_fsize)
			last_seg = get_segment(addr, sz);

		if (!rc && last_seg && addr >= last_seg->m_vaddr && addr+sz <= last_seg->m_vaddr+last_seg->m_fsize)
		{
			mapped_addr = (char*)(last_seg->m_faddr + (addr - last_seg->m_vaddr));
#if !defined(sun)
			if (sz == ptr_sz)	// fast path for pointer/ref
			{
				if (ptr_sz == 8)
					*(address_t*)buffer = *(address_t*)mapped_addr;
				else
					*(unsigned int*)buffer = *(unsigned int*)mapped_addr;
			}
			else
#endif
				memcpy(buffer, mapped_addr, sz);
			rc = CA_TRUE;
		}
#if defined(__MACH__)
		if (!rc)
		{
			// MacOS's heap data structure crosses segments' boundary
			segment = get_segment(addr, 1);
			if (segment && addr + sz > segment->m_vaddr + segment->m_vsize && segment->m_vsize == segment->m_fsize)
			{
				struct ca_segment* next_segment = get_segment(segment->m_vaddr + segment->m_vsize, (addr + sz) - (segment->m_vaddr + segment->m_vsize));
				if (next_segment)
				{
					size_t copy_sz = segment->m_vaddr + segment->m_vsize - addr;
					mapped_addr = (char*)(segment->m_faddr + (addr - segment->m_vaddr));
					memcpy(buffer, mapped_addr, copy_sz);
					memcpy((char*)buffer + copy_sz, next_segment->m_faddr, sz - copy_sz);
					rc = CA_TRUE;
				}
			}
		}
#endif
	}
	else
		rc = inferior_memory_read(addr, buffer, sz);
	// if user preset values within the range, use it
	if (rc && g_set_values)
		get_preset_value(addr, buffer, sz);

	return rc;
}

//////////////////////////////////////////////////////////////
// virtual address to mmaped-file address
//////////////////////////////////////////////////////////////
void* core_to_mmap_addr(address_t vaddr)
{
	struct ca_segment* segment = get_segment(vaddr, 1);
	if (segment && vaddr >= segment->m_vaddr && vaddr <= segment->m_vaddr + segment->m_vsize
		&& segment->m_fsize >= vaddr - segment->m_vaddr)
	{
		return segment->m_faddr + (vaddr - segment->m_vaddr);
	}

	return NULL;
}

static void* sys_alloc(size_t sz)
{
	void* result;
#ifdef WIN32
	result = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
	if (!result)
#elif defined(__MACH__)
	result = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	if(result == (void*)-1)
#else
	result = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(result == (void*)-1)
#endif
	{
		CA_PRINT("Fatal: failed to allocate "PRINT_FORMAT_SIZE" bytes from kernel\n", sz);
		return NULL;
	}

	return result;
}

static void  sys_free(void* p, size_t sz)
{
#ifdef WIN32
	VirtualFree (p, 0, MEM_RELEASE);
#else
	munmap ((char*)p, sz);
#endif
}
