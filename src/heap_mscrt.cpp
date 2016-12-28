/*
 * heap_mscrt.cpp
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include "segment.h"
#include "heap_mscrt.h"

enum MSCRT_VER
{
	MSCRT_WIN_UNKNOWN,
	MSCRT_WIN_2003,
	MSCRT_WIN_2008
};

/////////////////////////////////////////////////////
// Global Vars
/////////////////////////////////////////////////////
size_t g_align = sizeof(double); // 8 byte

static const size_t g_page_sz = 4096;
static address_t g_peb_vaddr = 0;		// virual address of PEB
static address_t g_heaps_vaddr = 0;		// PEB.ProcessHeaps
static bool   g_dbgheap = false;	// flag for debug heap
static enum MSCRT_VER g_mscrt_ver = MSCRT_WIN_UNKNOWN;	// runtime type

/////////////////////////////////////////////////////
// Forwarded functions
/////////////////////////////////////////////////////
static bool
page_walk(address_t, bool, struct heap_block*, size_t*, size_t*);
static bool
page_walk_internal_2003(HEAP_SEGMENT_2003*, address_t, bool, struct heap_block*, size_t*, size_t*, unsigned long*, unsigned long*);
static bool
page_walk_internal_2008(HEAP_2008*, HEAP_SEGMENT_2008*, address_t, address_t, bool, struct heap_block*, size_t*, size_t*, unsigned long*, unsigned long*);
static bool
page_walk_internal_2008_32(HEAP_2008_32*, HEAP_SEGMENT_2008_32*, address_t, address_t, bool, struct heap_block*, size_t*, size_t*, unsigned long*, unsigned long*);

static bool
page_walk_2003(address_t, bool,	struct heap_block*,	size_t*, size_t*);
static bool
page_walk_2008(address_t, bool,	struct heap_block*,	size_t*, size_t*);
static bool
page_walk_2008_32(address_t, bool,	struct heap_block*,	size_t*, size_t*);

static bool heap_walk_internal(bool ibDryRun, bool verbose);
static bool heap_walk_2003(bool ibDryRun, bool verbose);
static bool heap_walk_2008(bool ibDryRun, bool verbose);
static bool heap_walk_2008_32(bool ibDryRun, bool verbose);

static bool walk_inuse_blocks_2003(struct inuse_block*, unsigned long*);
static bool walk_inuse_blocks_2008(struct inuse_block*, unsigned long*);
static bool walk_inuse_blocks_2008_32(struct inuse_block*, unsigned long*);

static bool get_biggest_blocks_2003(struct heap_block* blks, unsigned int num);
static bool get_biggest_blocks_2008(struct heap_block* blks, unsigned int num);
static bool get_biggest_blocks_in_heap_segment_2003(HEAP_SEGMENT_2003*, struct heap_block* blks, unsigned int num);
static bool get_biggest_blocks_in_heap_segment_2008(HEAP_2008*, HEAP_SEGMENT_2008*, address_t, struct heap_block* blks, unsigned int num);
static bool get_biggest_blocks_2008_32(struct heap_block* blks, unsigned int num);
static bool get_biggest_blocks_in_heap_segment_2008_32(HEAP_2008_32*, HEAP_SEGMENT_2008_32*, address_t, struct heap_block* blks, unsigned int num);

static void add_one_big_block(struct heap_block* blks, unsigned int num, struct heap_block* blk);

/////////////////////////////////////////////////////
// Exported functions
/////////////////////////////////////////////////////
bool init_heap()
{
	int ptr_bit = g_ptr_bit;
	int ptr_sz = ptr_bit == 64 ? 8 : 4;

	g_peb_vaddr = get_var_addr_by_name("peb", true);
	if (!g_peb_vaddr)
		return false;
	// get the PEB structure
	if (ptr_bit == 64)
	{
		PEB peb;
		if (!read_memory_wrapper(NULL, g_peb_vaddr, &peb, sizeof(peb)))
			return false;
		g_heaps_vaddr = (address_t) peb.ProcessHeaps;
		// Read the first _HEAP structure to determine whether target is win 2003 or 2008
		address_t heap_vaddr;
		if (!read_memory_wrapper(NULL, g_heaps_vaddr, &heap_vaddr, sizeof(heap_vaddr))
			|| heap_vaddr == 0)
			return false;
		HEAP_2008 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;
		if ((address_t)heap.Heap == heap_vaddr)
			g_mscrt_ver = MSCRT_WIN_2008;
		else
			g_mscrt_ver = MSCRT_WIN_2003;
	}
	else if (ptr_bit == 32)
	{
		PEB_32 peb;
		HEAP_2008_32 heap;
		if (!read_memory_wrapper(NULL, g_peb_vaddr, &peb, sizeof(peb)))
			return false;
		g_heaps_vaddr = (address_t) peb.ProcessHeaps;
		// Read the first _HEAP structure to determine whether target is win 2003 or 2008
		ptr_t_32 heap_vaddr;
		if (read_memory_wrapper(NULL, g_heaps_vaddr, &heap_vaddr, sizeof(heap_vaddr))
			&& read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap))
			&& heap.Heap == heap_vaddr)
		{
			g_mscrt_ver = MSCRT_WIN_2008;
		}
		else
		{
			// 2003 32bit has different structures
			CA_PRINT("Warning: only windows 2008 is supported for 32-bit program dump\n");
			return false;
		}
	}
	else
		return false;

	// decide if heap is debug version by runtime dll name
	for (unsigned int i=0; i<g_segment_count; i++)
	{
		struct ca_segment* segment = &g_segments[i];
		const char* mod_name;
		if (segment->m_type == ENUM_MODULE_TEXT && segment->m_module_name
			&& ((mod_name=strstr(segment->m_module_name, "msvcr")) || (mod_name=strstr(segment->m_module_name, "MSVCR"))) )
		{
			if (strstr(mod_name, "0d.dll") || strstr(mod_name, "0D.dll")
					|| strstr(mod_name, "0d.DLL") || strstr(mod_name, "0D.DLL") )
				g_dbgheap = true;
			break;
		}
	}

	// Fixup segments that belongs to heaps
	if (!heap_walk_internal(true, false))
		return false;

	return true;
}

bool get_heap_block_info(address_t addr, struct heap_block* blk)
{
	return page_walk(addr, false, blk, NULL, NULL);
}

bool is_heap_block(address_t addr)
{
	if (addr == 0)
		return false;

	heap_block blk_info;
	bool rc = page_walk(addr, false, &blk_info, NULL, NULL);
	//if (blk_info.addr != 0)
	//	return true;
	return rc;
}

bool heap_walk(address_t addr, bool verbose)
{
	if (addr)
		return page_walk(addr, true, NULL, NULL, NULL);
	else
		return heap_walk_internal(false, verbose);
}

// Assuming the input buffer is already zeroed, num is non-zero
bool get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	if (g_ptr_bit == 64)
	{
		if (g_mscrt_ver == MSCRT_WIN_2003)
			return get_biggest_blocks_2003(blks, num);
		else if (g_mscrt_ver == MSCRT_WIN_2008)
			return get_biggest_blocks_2008(blks, num);
	}
	else if (g_ptr_bit == 32)
	{
		if (g_mscrt_ver == MSCRT_WIN_2008)
			return get_biggest_blocks_2008_32(blks, num);
	}

	return false;
}

static int compare_block_info( const void *arg1, const void *arg2 )
{
	struct inuse_block* left = (struct inuse_block*) arg1;
	struct inuse_block* right = (struct inuse_block*) arg2;
	if (left->addr < right->addr)
		return -1;
	else
		return 1;
}

bool walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
	bool rc = false;

	if (g_ptr_bit == 64)
	{
		if (g_mscrt_ver == MSCRT_WIN_2003)
			rc = walk_inuse_blocks_2003(opBlocks, opCount);
		else if (g_mscrt_ver == MSCRT_WIN_2008)
			rc = walk_inuse_blocks_2008(opBlocks, opCount);
	}
	else if (g_ptr_bit == 32)
	{
		if (g_mscrt_ver == MSCRT_WIN_2008)
			rc = walk_inuse_blocks_2008_32(opBlocks, opCount);
	}

	// sort the array if necessary
	if (rc && opBlocks && *opCount)
		qsort(opBlocks, *opCount, sizeof(struct inuse_block), compare_block_info);

	return rc;
}

/////////////////////////////////////////////////////
// Implementation of heap walk
/////////////////////////////////////////////////////
static bool heap_walk_internal(bool ibDryRun, bool verbose)
{
	bool rc = false;

	if (verbose)
		init_mem_histogram(16);

	if (g_ptr_bit == 64)
	{
		if (g_mscrt_ver == MSCRT_WIN_2003)
			rc = heap_walk_2003(ibDryRun, verbose);
		else if (g_mscrt_ver == MSCRT_WIN_2008)
			rc = heap_walk_2008(ibDryRun, verbose);
	}
	else if (g_ptr_bit == 32)
	{
		if (g_mscrt_ver == MSCRT_WIN_2008)
			rc = heap_walk_2008_32(ibDryRun, verbose);
	}

	if (verbose && rc)
	{
		CA_PRINT("\n");
		display_mem_histogram("");
	}

	return rc;
}

static bool
page_walk(address_t addr,			// input heap addr
			bool bVerbose,				// print detail info or not
			struct heap_block* opBlock,	// output the block containing the addr
			size_t* opInuseBytes,		// output page in-use bytes
			size_t* opFreeBytes)		// output page free bytes
{
	if (g_ptr_bit == 64)
	{
		if (g_mscrt_ver == MSCRT_WIN_2003)
			return page_walk_2003(addr, bVerbose, opBlock, opInuseBytes, opFreeBytes);
		else if (g_mscrt_ver == MSCRT_WIN_2008)
			return page_walk_2008(addr, bVerbose, opBlock, opInuseBytes, opFreeBytes);
	}
	else if (g_ptr_bit == 32)
	{
		if (g_mscrt_ver == MSCRT_WIN_2008)
			return page_walk_2008_32(addr, bVerbose, opBlock, opInuseBytes, opFreeBytes);
	}
	return false;
}

/////////////////////////////////////////////////////
// Version specific implementation
/////////////////////////////////////////////////////
static bool
page_walk_2008(address_t addr,			// input heap addr
			bool bVerbose,				// print detail info or not
			struct heap_block* opBlock,	// output the block containing the addr
			size_t* opInuseBytes,		// output page in-use bytes
			size_t* opFreeBytes)		// output page free bytes
{
	bool rc = false;
	size_t inuse_bytes = 0, free_bytes = 0;
	unsigned long num_inuse = 0, num_free = 0;
	// loop through all heaps
	int heap_cnt;
	bool bailout = false;
	for (heap_cnt = 0; !bailout; heap_cnt++)
	{
		address_t heap_vaddr;
		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		HEAP_2008 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;
		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		address_t sentinel = (address_t) &((HEAP_2008*)heap_vaddr)->SegmentList;
		address_t next_list_entry_addr = (address_t) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			address_t seg_start, seg_end;
			HEAP_SEGMENT_2008 heap_seg;
			address_t seg_addr = next_list_entry_addr - (address_t) &((HEAP_2008*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				return false;

			seg_start = (address_t) heap_seg.BaseAddress;
			seg_end   = seg_start + heap_seg.NumberOfPages * g_page_sz;
			if (addr && addr >= seg_start && addr < seg_end)
			{
				bailout = true;
				rc = page_walk_internal_2008(&heap, &heap_seg, seg_addr, addr, bVerbose, opBlock, &inuse_bytes, &free_bytes, &num_inuse, &num_free);
				break;
			}
			next_list_entry_addr = (address_t) heap_seg.SegmentListEntry.Flink;
		}
	}

	if (bVerbose)
	{
		CA_PRINT("Total %ld inuse blocks of "PRINT_FORMAT_SIZE" bytes\n", num_inuse, inuse_bytes);
		CA_PRINT("Total %ld free blocks of "PRINT_FORMAT_SIZE" bytes\n", num_free, free_bytes);
	}
	if (rc && opInuseBytes && opFreeBytes)
	{
		*opInuseBytes = inuse_bytes;
		*opFreeBytes = free_bytes;
	}

	return rc;
}

static bool
page_walk_2008_32(address_t addr,			// input heap addr
			bool bVerbose,				// print detail info or not
			struct heap_block* opBlock,	// output the block containing the addr
			size_t* opInuseBytes,		// output page in-use bytes
			size_t* opFreeBytes)		// output page free bytes
{
	bool rc = false;
	size_t inuse_bytes = 0, free_bytes = 0;
	unsigned long num_inuse = 0, num_free = 0;
	// loop through all heaps
	int heap_cnt;
	bool bailout = false;
	for (heap_cnt = 0; !bailout; heap_cnt++)
	{
		ptr_t_32 heap_vaddr;
		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		HEAP_2008_32 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;
		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		ptr_t_32 sentinel = (ptr_t_32) &((HEAP_2008_32*)heap_vaddr)->SegmentList;
		ptr_t_32 next_list_entry_addr = (ptr_t_32) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			ptr_t_32 seg_start, seg_end;
			HEAP_SEGMENT_2008_32 heap_seg;
			ptr_t_32 seg_addr = next_list_entry_addr - (ptr_t_32) &((HEAP_2008_32*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				return false;

			seg_start = (ptr_t_32) heap_seg.BaseAddress;
			seg_end   = seg_start + heap_seg.NumberOfPages * g_page_sz;
			if (addr && addr >= seg_start && addr < seg_end)
			{
				bailout = true;
				rc = page_walk_internal_2008_32(&heap, &heap_seg, seg_addr, addr, bVerbose, opBlock, &inuse_bytes, &free_bytes, &num_inuse, &num_free);
				break;
			}
			next_list_entry_addr = (ptr_t_32) heap_seg.SegmentListEntry.Flink;
		}
	}

	if (bVerbose)
	{
		CA_PRINT("Total %ld inuse blocks of %ld bytes\n", num_inuse, inuse_bytes);
		CA_PRINT("Total %ld free blocks of %ld bytes\n", num_free, free_bytes);
	}
	if (rc && opInuseBytes && opFreeBytes)
	{
		*opInuseBytes = inuse_bytes;
		*opFreeBytes = free_bytes;
	}

	return rc;
}

static bool
page_walk_2003(address_t addr,			// input heap addr
			bool bVerbose,			// print detail info or not
			struct heap_block* opBlock,	// output the block containing the addr
			size_t* opInuseBytes,		// output page in-use bytes
			size_t* opFreeBytes)		// output page free bytes
{
	bool rc = false;
	size_t inuse_bytes = 0, free_bytes = 0;
	unsigned long num_inuse = 0, num_free = 0;
	// loop through all heaps
	int heap_cnt;
	bool bailout = false;
	for (heap_cnt = 0; !bailout; heap_cnt++)
	{
		address_t heap_vaddr;
		// peb.ProcessHeaps points to an array of _HEAP
		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		// there are up to 64 segments per heap
		HEAP_2003 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;
		for (int i=0; i<64 && heap.Segments[i]; i++)
		{
			HEAP_SEGMENT_2003 heap_seg;
			address_t seg_end;
			if (!read_memory_wrapper(NULL, (address_t)heap.Segments[i], &heap_seg, sizeof(heap_seg)) )
				return false;
			seg_end = (address_t)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;
			if (addr && addr >= (address_t)heap_seg.BaseAddress && addr < seg_end)
			{
				bailout = true;
				rc = page_walk_internal_2003(&heap_seg, addr, bVerbose, opBlock, &inuse_bytes, &free_bytes, &num_inuse, &num_free);
				break;
			}
		}
	}

	if (bVerbose)
	{
		CA_PRINT("Total %ld inuse blocks of "PRINT_FORMAT_SIZE" bytes\n", num_inuse, inuse_bytes);
		CA_PRINT("Total %ld free blocks of "PRINT_FORMAT_SIZE" bytes\n", num_free, free_bytes);
	}
	if (rc && opInuseBytes && opFreeBytes)
	{
		*opInuseBytes = inuse_bytes;
		*opFreeBytes = free_bytes;
	}

	return rc;
}

static bool heap_walk_2008(bool ibDryRun, bool verbose)
{
	size_t total_inuse_bytes = 0, total_free_bytes = 0;
	unsigned long total_num_inuse = 0, total_num_free = 0;
	unsigned long err_count = 0;

	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		address_t heap_vaddr;
		HEAP_2008 heap;
		address_t sentinel, next_list_entry_addr;

		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		if (!ibDryRun)
			CA_PRINT("\theap "PRINT_FORMAT_POINTER" ...\n", heap_vaddr);
		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		sentinel = (address_t) &((HEAP_2008*)heap_vaddr)->SegmentList;
		next_list_entry_addr = (address_t) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			address_t seg_end;
			HEAP_SEGMENT_2008 heap_seg;
			address_t seg_addr = next_list_entry_addr - (address_t) &((HEAP_2008*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				return false;
			seg_end = (address_t)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;

			if (ibDryRun)
			{
				// Simply walk through all pages and fixup the ca_segment's storage type
				address_t cursor = (address_t)heap_seg.BaseAddress;
				while (cursor < seg_end)
				{
					ca_segment* segment = get_segment(cursor, 1);
					if (segment && segment->m_type == ENUM_UNKNOWN)
						segment->m_type = ENUM_HEAP;
					cursor += g_page_sz;
				}
			}
			else
			{
				size_t inuse_bytes = 0, free_bytes = 0;
				unsigned long num_inuse = 0, num_free = 0;

				CA_PRINT("\t\tsegment "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" ",
						(address_t)heap_seg.BaseAddress, seg_end);
				if (!page_walk_internal_2008(&heap, &heap_seg, seg_addr, 0, false, NULL, &inuse_bytes, &free_bytes, &num_inuse, &num_free))
				{
					err_count++;
					CA_PRINT("==> Error found in this segment (!heap "PRINT_FORMAT_POINTER" for more detail) <==\n",
							(address_t)heap_seg.BaseAddress);
					//break;
				}
				else
				{
					print_size(seg_end - (address_t)heap_seg.BaseAddress);
					CA_PRINT(" in-use %ld(", num_inuse);
					print_size(inuse_bytes);
					CA_PRINT(") free %ld(", num_free);
					print_size(free_bytes);
					CA_PRINT(")");
				}
				CA_PRINT("\n");
				total_num_inuse += num_inuse;
				total_num_free  += num_free;
				total_inuse_bytes += inuse_bytes;
				total_free_bytes  += free_bytes;
			}
			next_list_entry_addr = (address_t) heap_seg.SegmentListEntry.Flink;
		}
	}
	if (err_count > 0)
		CA_PRINT("Find %d heap errors\n", err_count);
	else if (!ibDryRun)
	{
		CA_PRINT("\n");
		CA_PRINT("There are %d heaps\n", heap_cnt);
		CA_PRINT("Total %ld busy blocks of ", total_num_inuse);
		print_size(total_inuse_bytes);
		CA_PRINT("\n");
		CA_PRINT("Total %ld free blocks of ", total_num_free);
		print_size(total_free_bytes);
		CA_PRINT("\n");
	}

	return true;
}

static bool walk_inuse_blocks_2008(struct inuse_block* opBlocks, unsigned long* opCount)
{
	*opCount = 0;
	struct inuse_block* pBlockinfo = opBlocks;
	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		address_t heap_vaddr;
		HEAP_2008 heap;
		address_t sentinel, next_list_entry_addr;

		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			break;
		if (heap_vaddr == 0)
			break;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			continue;

		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		sentinel = (address_t) &((HEAP_2008*)heap_vaddr)->SegmentList;
		next_list_entry_addr = (address_t) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			address_t entry_vaddr;
			address_t seg_end;
			HEAP_SEGMENT_2008 heap_seg;
			address_t seg_addr = next_list_entry_addr - (address_t) &((HEAP_2008*)0)->SegmentListEntry;

			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				break;
			seg_end = (address_t)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;

			// Start walking heap segment
			entry_vaddr = (address_t) heap_seg.FirstEntry;
			while (entry_vaddr < seg_end)
			{
				address_t user_addr;
				size_t entry_sz, user_sz;
				HEAP_ENTRY_2008 entry;
				bool lbUncommitted = false;

				// there are multiple uncommitted ranges, which might be readable or unreadable
				// they are on a doubly-linked list and they are NOT necessarily sorted by address
				// 		_HEAP_SEGMENT_2008::NumberOfUnCommittedRanges is also the list size + 1 (sentinel)
				// 		_HEAP_SEGMENT_2003::UCRSegmentList is the sentinel
				if (heap_seg.NumberOfUnCommittedRanges > 0)
				{
					address_t ucr_sentinel, ucr_next;
					HEAP_UCR_DESCRIPTOR ucr_descriptor;

					ucr_sentinel = seg_addr + (address_t) &((HEAP_SEGMENT_2008*)0)->UCRSegmentList;
					ucr_next = (address_t)heap_seg.UCRSegmentList.Flink;
					while (ucr_next != ucr_sentinel)
					{
						ucr_next -= (address_t) &((HEAP_UCR_DESCRIPTOR*)0)->SegmentEntry;
						if (!read_memory_wrapper(NULL, ucr_next, &ucr_descriptor, sizeof(ucr_descriptor)))
							break;
						else if (entry_vaddr >= (address_t)ucr_descriptor.Address && entry_vaddr < (address_t)ucr_descriptor.Address + ucr_descriptor.Size)
						{
							// we run into one of the uncommitted ranges
							// treat the whole range as a free entry
							lbUncommitted = true;
							entry_vaddr = (address_t)ucr_descriptor.Address + ucr_descriptor.Size;
							break;
						}
						// Get the next uncommitted range on the list
						ucr_next = (address_t) ucr_descriptor.SegmentEntry.Flink;
					}
				}
				if (lbUncommitted)
					continue;

				// The normal block starts with HEAP_ENTRY
				if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
					break;
				else	// We have read HEAP_ENTRY successfully
				{
					// Encoding of the HEAP_ENTRY
					if (heap.EncodeFlagMask)
					{
						UCHAR* bytes = (UCHAR*) &entry.Size;
						*(DWORD*)bytes ^= *(DWORD*)(&heap.Encoding.Size);
						// check the encoding byte
						if (entry.SmallTagIndex != (bytes[0] ^ bytes[1] ^ bytes[2]) )
							break;
					}
					entry_sz = entry.Size * sizeof(entry);
					// HEAP_ENTRY::Size tag is often the victim of memory overrun
					if (entry_sz == 0
						|| entry_vaddr + entry_sz > (address_t) heap_seg.LastValidEntry
						|| entry_vaddr + entry_sz > seg_end)
						break;
					// HEAP_ENTRY::UnusedBytes
					user_addr = entry_vaddr + sizeof(entry);
					if (entry_sz > entry.UnusedBytes && entry.UnusedBytes >= sizeof(entry))
						user_sz = entry_sz - entry.UnusedBytes;
					else
						user_sz = entry_sz - sizeof(entry);
					// HEAP_ENTRY::Flags, busy block only
					if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
					{
						// A free chunk doesn't have _CrtMemBlockHeader. If an uncommitted page
						// follows, we can't even read enough bytes sizeof(_CrtMemBlockHeader)
						if (g_dbgheap && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader))
						{
							_CrtMemBlockHeader pHead;
							if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
								return false;
							/* gap is filled with _bNoMansLandFill or 0xfd */
							if (*(int*)&pHead.gap == 0xfdfdfdfd)
							{
								user_addr += sizeof(_CrtMemBlockHeader);
								user_sz = pHead.nDataSize;
							}
						}
						// Now we know this block
						(*opCount)++;
						if (pBlockinfo)
						{
							pBlockinfo->addr = user_addr;
							pBlockinfo->size = user_sz;
							pBlockinfo++;
						}
					}
					// calc the next block
					entry_vaddr = entry_vaddr + entry_sz;
				}
			}
			next_list_entry_addr = (address_t) heap_seg.SegmentListEntry.Flink;
		}
	}

	return true;
}

static bool heap_walk_2008_32(bool ibDryRun, bool verbose)
{
	size_t total_inuse_bytes = 0, total_free_bytes = 0;
	unsigned long total_num_inuse = 0, total_num_free = 0;
	unsigned int err_count = 0;

	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		ptr_t_32 heap_vaddr;
		HEAP_2008_32 heap;
		ptr_t_32 sentinel, next_list_entry_addr;

		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		if (!ibDryRun)
			CA_PRINT("\theap 0x%lx ...\n", heap_vaddr);
		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		sentinel = (ptr_t_32) &((HEAP_2008_32*)heap_vaddr)->SegmentList;
		next_list_entry_addr = (ptr_t_32) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			ptr_t_32 seg_end;
			HEAP_SEGMENT_2008_32 heap_seg;
			ptr_t_32 seg_addr = next_list_entry_addr - (ptr_t_32) &((HEAP_2008_32*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				return false;
			seg_end = (ptr_t_32)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;

			if (ibDryRun)
			{
				// Simply walk through all pages and fixup the ca_segment's storage type
				ptr_t_32 cursor = (ptr_t_32)heap_seg.BaseAddress;
				while (cursor < seg_end)
				{
					ca_segment* segment = get_segment(cursor, 1);
					if (segment && segment->m_type == ENUM_UNKNOWN)
						segment->m_type = ENUM_HEAP;
					cursor += g_page_sz;
				}
			}
			else
			{
				size_t inuse_bytes = 0, free_bytes = 0;
				unsigned long num_inuse = 0, num_free = 0;

				CA_PRINT("\t\tsegment 0x%lx - 0x%lx ",
						(ptr_t_32)heap_seg.BaseAddress, seg_end);
				if (!page_walk_internal_2008_32(&heap, &heap_seg, seg_addr, 0, false, NULL, &inuse_bytes, &free_bytes, &num_inuse, &num_free))
				{
					err_count++;
					CA_PRINT("==> Error found in this segment (!heap 0x%lx for more detail) <==\n",
							(ptr_t_32)heap_seg.BaseAddress);
					//break;
				}
				else
				{
					print_size(seg_end - (address_t)heap_seg.BaseAddress);
					CA_PRINT(" in-use %d(", num_inuse);
					print_size(inuse_bytes);
					CA_PRINT(") free %d(", num_free);
					print_size(free_bytes);
					CA_PRINT(")");
				}
				CA_PRINT("\n");
				total_num_inuse += num_inuse;
				total_num_free  += num_free;
				total_inuse_bytes += inuse_bytes;
				total_free_bytes  += free_bytes;
			}
			next_list_entry_addr = (ptr_t_32) heap_seg.SegmentListEntry.Flink;
		}
	}
	if (err_count > 0)
		CA_PRINT("Find %d heap errors\n", err_count);
	else if (!ibDryRun)
	{
		CA_PRINT("\n");
		CA_PRINT("There are %d heaps\n", heap_cnt);
		CA_PRINT("Total %ld busy blocks of ", total_num_inuse);
		print_size(total_inuse_bytes);
		CA_PRINT("\n");
		CA_PRINT("Total %ld free blocks of ", total_num_free);
		print_size(total_free_bytes);
		CA_PRINT("\n");
	}

	return true;
}

static bool walk_inuse_blocks_2008_32(struct inuse_block* opBlocks, unsigned long* opCount)
{
	*opCount = 0;
	struct inuse_block* pBlockinfo = opBlocks;
	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		ptr_t_32 heap_vaddr;
		HEAP_2008_32 heap;
		ptr_t_32 sentinel, next_list_entry_addr;

		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			break;
		if (heap_vaddr == 0)
			break;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			continue;

		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		sentinel = (ptr_t_32) &((HEAP_2008_32*)heap_vaddr)->SegmentList;
		next_list_entry_addr = (ptr_t_32) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			ptr_t_32 entry_vaddr;
			ptr_t_32 seg_end;
			HEAP_SEGMENT_2008_32 heap_seg;
			ptr_t_32 seg_addr = next_list_entry_addr - (ptr_t_32) &((HEAP_2008_32*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				break;
			seg_end = (ptr_t_32)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;

			// Start walking heap segment
			entry_vaddr = (ptr_t_32) heap_seg.FirstEntry;
			while (entry_vaddr < seg_end)
			{
				ptr_t_32 user_addr;
				unsigned int entry_sz, user_sz;
				HEAP_ENTRY_2008_32 entry;
				bool lbUncommitted = false;

				// there are multiple uncommitted ranges, which might be readable or unreadable
				// they are on a doubly-linked list and they are NOT necessarily sorted by address
				// 		_HEAP_SEGMENT_2008::NumberOfUnCommittedRanges is also the list size + 1 (sentinel)
				// 		_HEAP_SEGMENT_2003::UCRSegmentList is the sentinel
				if (heap_seg.NumberOfUnCommittedRanges > 0)
				{
					ptr_t_32 ucr_sentinel, ucr_next;
					HEAP_UCR_DESCRIPTOR_32 ucr_descriptor;

					ucr_sentinel = seg_addr + (ptr_t_32) &((HEAP_SEGMENT_2008_32*)0)->UCRSegmentList;
					ucr_next = (ptr_t_32)heap_seg.UCRSegmentList.Flink;
					while (ucr_next != ucr_sentinel)
					{
						ucr_next -= (ptr_t_32) &((HEAP_UCR_DESCRIPTOR_32*)0)->SegmentEntry;
						if (!read_memory_wrapper(NULL, ucr_next, &ucr_descriptor, sizeof(ucr_descriptor)))
							break;
						else if (entry_vaddr >= (ptr_t_32)ucr_descriptor.Address && entry_vaddr < (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size)
						{
							// we run into one of the uncommitted ranges
							// treat the whole range as a free entry
							lbUncommitted = true;
							entry_vaddr = (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size;
							break;
						}
						// Get the next uncommitted range on the list
						ucr_next = (ptr_t_32) ucr_descriptor.SegmentEntry.Flink;
					}
				}
				if (lbUncommitted)
					continue;

				// The normal block starts with HEAP_ENTRY
				if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
					break;
				else	// We have read HEAP_ENTRY successfully
				{
					// Encoding of the HEAP_ENTRY
					if (heap.EncodeFlagMask)
					{
						UCHAR* bytes = (UCHAR*) &entry.Size;
						*(DWORD*)bytes ^= *(DWORD*)(&heap.Encoding.Size);
						// check the encoding byte
						if (entry.SmallTagIndex != (bytes[0] ^ bytes[1] ^ bytes[2]) )
							break;
					}
					entry_sz = entry.Size * sizeof(entry);
					// HEAP_ENTRY::Size tag is often the victim of memory overrun
					if (entry_sz == 0
						|| entry_vaddr + entry_sz > (ptr_t_32) heap_seg.LastValidEntry
						|| entry_vaddr + entry_sz > seg_end)
						break;
					// HEAP_ENTRY::UnusedBytes
					user_addr = entry_vaddr + sizeof(entry);
					if (entry_sz > entry.UnusedBytes && entry.UnusedBytes >= sizeof(entry))
						user_sz = entry_sz - entry.UnusedBytes;
					else
						user_sz = entry_sz - sizeof(entry);
					// HEAP_ENTRY::Flags, busy block only
					if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
					{
						// A free chunk doesn't have _CrtMemBlockHeader. If an uncommitted page
						// follows, we can't even read enough bytes sizeof(_CrtMemBlockHeader)
						if (g_dbgheap && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader_32))
						{
							_CrtMemBlockHeader_32 pHead;
							if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
								break;
							/* gap is filled with _bNoMansLandFill or 0xfd */
							if (*(int*)&pHead.gap == 0xfdfdfdfd)
							{
								user_addr += sizeof(_CrtMemBlockHeader_32);
								user_sz = pHead.nDataSize;
							}
						}
						// Now we know this block
						(*opCount)++;
						if (pBlockinfo)
						{
							pBlockinfo->addr = user_addr;
							pBlockinfo->size = user_sz;
							pBlockinfo++;
						}
					}
					// calc the next block
					entry_vaddr = entry_vaddr + entry_sz;
				}
			}
			next_list_entry_addr = (ptr_t_32) heap_seg.SegmentListEntry.Flink;
		}
	}

	return true;
}

static bool get_biggest_blocks_2008(struct heap_block* blks, unsigned int num)
{
	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		address_t heap_vaddr;
		HEAP_2008 heap;
		address_t sentinel, next_list_entry_addr;

		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		sentinel = (address_t) &((HEAP_2008*)heap_vaddr)->SegmentList;
		next_list_entry_addr = (address_t) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			address_t seg_end;
			HEAP_SEGMENT_2008 heap_seg;
			address_t seg_addr = next_list_entry_addr - (address_t) &((HEAP_2008*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				break;
			seg_end = (address_t)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;
			// Ignore errors
			get_biggest_blocks_in_heap_segment_2008(&heap, &heap_seg, seg_addr, blks, num);
			next_list_entry_addr = (address_t) heap_seg.SegmentListEntry.Flink;
		}
	}

	return true;
}

static bool get_biggest_blocks_2008_32(struct heap_block* blks, unsigned int num)
{
	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		ptr_t_32 heap_vaddr;
		HEAP_2008_32 heap;
		ptr_t_32 sentinel, next_list_entry_addr;

		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		if (heap_vaddr == 0)
			break;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		// segments are on a doubly-linked list
		// _HEAP.SegmentList is the sentinel LIST_ENTRY
		sentinel = (ptr_t_32) &((HEAP_2008_32*)heap_vaddr)->SegmentList;
		next_list_entry_addr = (ptr_t_32) heap.SegmentList.Flink;
		while (next_list_entry_addr != sentinel)
		{
			ptr_t_32 seg_end;
			HEAP_SEGMENT_2008_32 heap_seg;
			ptr_t_32 seg_addr = next_list_entry_addr - (ptr_t_32) &((HEAP_2008_32*)0)->SegmentListEntry;
			if (!read_memory_wrapper(NULL, seg_addr, &heap_seg, sizeof(heap_seg)))
				break;
			seg_end = (ptr_t_32)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;
			// Ignore errors
			get_biggest_blocks_in_heap_segment_2008_32(&heap, &heap_seg, seg_addr, blks, num);
			next_list_entry_addr = (ptr_t_32) heap_seg.SegmentListEntry.Flink;
		}
	}

	return true;
}

static bool heap_walk_2003(bool ibDryRun, bool verbose)
{
	size_t total_inuse_bytes = 0, total_free_bytes = 0;
	unsigned long total_num_inuse = 0, total_num_free = 0;
	unsigned long err_count = 0;

	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		address_t heap_vaddr;
		// g_heaps_vaddr is the beginning of an array of heap addresses.
		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		// The array ends with address 0
		if (heap_vaddr == 0)
			break;

		HEAP_2003 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		if (!ibDryRun)
			CA_PRINT("\theap "PRINT_FORMAT_POINTER" ...\n", heap_vaddr);
		// loop through all segments(up to 64) for each heap
		for (int i=0; i<64 && heap.Segments[i]; i++)
		{
			HEAP_SEGMENT_2003 heap_seg;
			address_t seg_end;
			if (!read_memory_wrapper(NULL, (address_t)heap.Segments[i], &heap_seg, sizeof(heap_seg)) )
				break;
			seg_end = (address_t)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;

			if (ibDryRun)
			{
				// Simply walk through all pages and fixup the ca_segment's storage type
				address_t cursor = (address_t)heap_seg.BaseAddress;
				while (cursor < seg_end)
				{
					ca_segment* segment = get_segment(cursor, 1);
					if (segment && segment->m_type == ENUM_UNKNOWN)
						segment->m_type = ENUM_HEAP;
					cursor += g_page_sz;
				}
			}
			else
			{
				unsigned long num_inuse = 0, num_free = 0;
				size_t inuse_bytes = 0, free_bytes = 0;

				CA_PRINT("\t\tsegment "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" ",
					heap_seg.BaseAddress, seg_end);
				if (!page_walk_internal_2003(&heap_seg, 0, false, NULL, &inuse_bytes, &free_bytes, &num_inuse, &num_free))
				{
					err_count++;
					CA_PRINT("==> Error found in this segment (!heap "PRINT_FORMAT_POINTER" for more detail) <==\n",
							heap_seg.FirstEntry);
					//break;
				}
				else
				{
					print_size(seg_end - (address_t)heap_seg.BaseAddress);
					CA_PRINT(" in-use %d(", num_inuse);
					print_size(inuse_bytes);
					CA_PRINT(") free %d(", num_free);
					print_size(free_bytes);
					CA_PRINT(")");
				}
				CA_PRINT("\n");
				total_num_inuse += num_inuse;
				total_num_free  += num_free;
				total_inuse_bytes += inuse_bytes;
				total_free_bytes  += free_bytes;
			}
		}
	}
	if (err_count > 0)
		CA_PRINT("Find %d heap errors\n", err_count);
	else if (!ibDryRun)
	{
		CA_PRINT("\n");
		CA_PRINT("There are %d heaps\n", heap_cnt);
		CA_PRINT("Total %ld busy blocks of ", total_num_inuse);
		print_size(total_inuse_bytes);
		CA_PRINT("\n");
		CA_PRINT("Total %ld free blocks of ", total_num_inuse);
		print_size(total_free_bytes);
		CA_PRINT("\n");
	}

	return true;
}

static bool walk_inuse_blocks_2003(struct inuse_block* opBlocks, unsigned long* opCount)
{
	*opCount = 0;
	struct inuse_block* pBlockinfo = opBlocks;
	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		address_t heap_vaddr;
		// g_heaps_vaddr is the beginning of an array of heap addresses.
		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			return false;
		// The array ends with address 0
		if (heap_vaddr == 0)
			break;

		HEAP_2003 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		// loop through all segments(up to 64) for each heap
		for (int i=0; i<64 && heap.Segments[i]; i++)
		{
			HEAP_SEGMENT_2003 heap_seg;
			address_t seg_end;
			address_t entry_vaddr;
			address_t range_vaddr;
			HEAP_UNCOMMMTTED_RANGE range;

			if (!read_memory_wrapper(NULL, (address_t)heap.Segments[i], &heap_seg, sizeof(heap_seg)) )
				continue;
			seg_end = (address_t)heap_seg.BaseAddress + heap_seg.NumberOfPages * g_page_sz;
			// there may be multiple uncommitted ranges
			// they are sorted by address, and on a singly-linked list (last one is grounded)
			// 		_HEAP_SEGMENT_2003::NumberOfUnCommittedRanges is also the list size
			// 		_HEAP_SEGMENT_2003::UnCommittedRanges is the list head
			if (heap_seg.NumberOfUnCommittedRanges > 0)
			{
				range_vaddr = (address_t) heap_seg.UnCommittedRanges;
				if (!read_memory_wrapper(NULL, range_vaddr, &range, sizeof(range)))
					continue;
			}
			else
			{
				range.Address = (PVOID)seg_end;
				range.Size = 0;
			}

			// Start walking heap segment
			entry_vaddr = (address_t) heap_seg.FirstEntry;
			while (entry_vaddr < seg_end)
			{
				address_t user_addr;
				size_t entry_sz, user_sz;
				HEAP_ENTRY_2003 entry;

				// is the next entry falls in an uncommitted range?
				if (entry_vaddr >= (address_t)range.Address)
				{
					if (entry_vaddr >= (address_t)range.Address + range.Size)
						break;
					// treat the whole range as a free entry
					entry_vaddr = (address_t)range.Address + range.Size;
					// Get the next uncommitted range on the list
					range_vaddr = (address_t) range.next;
					if (range_vaddr)
					{
						if (!read_memory_wrapper(NULL, range_vaddr, &range, sizeof(range)))
							break;
					}
					else
					{
						range.Address = (PVOID)seg_end;
						range.Size = 0;
					}
				}
				else
				{
					// The block starts with HEAP_ENTRY
					if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
						break;
					entry_sz = entry.Size * sizeof(entry);
					// HEAP_ENTRY::Size tag is often the victim of memory overrun
					if (entry_vaddr + entry_sz > seg_end)
						break;
					// HEAP_ENTRY::UnusedBytes
					user_addr = entry_vaddr + sizeof(entry);
					if (entry_sz > entry.UnusedBytes)
						user_sz = entry_sz - entry.UnusedBytes;
					else
						user_sz = entry_sz - sizeof(entry);
					// HEAP_ENTRY::Flags
					// check for busy flag
					if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
					{
						// An in-use chunk could have no _CrtMemBlockHeader either.
						// If an uncommitted page follows, we can't read enough bytes sizeof(_CrtMemBlockHeader)
						if (g_dbgheap && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader))
						{
							_CrtMemBlockHeader pHead;
							if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
								break;
							/* gap is filled with _bNoMansLandFill or 0xfd */
							if (*(int*)&pHead.gap == 0xfdfdfdfd)
							{
								user_addr += sizeof(_CrtMemBlockHeader);
								user_sz = pHead.nDataSize;
							}
						}
						// Now we know this block
						(*opCount)++;
						if (pBlockinfo)
						{
							pBlockinfo->addr = user_addr;
							pBlockinfo->size = user_sz;
							pBlockinfo++;
						}
					}
					// calc the next block
					entry_vaddr = entry_vaddr + entry_sz;
				}
			}
		}
	}

	return true;
}

static bool get_biggest_blocks_2003(struct heap_block* blks, unsigned int num)
{
	// loop through all heaps
	int heap_cnt;
	for (heap_cnt = 0; ; heap_cnt++)
	{
		address_t heap_vaddr;
		// g_heaps_vaddr is the beginning of an array of heap addresses.
		if (!read_memory_wrapper(NULL, g_heaps_vaddr + heap_cnt * sizeof(heap_vaddr), &heap_vaddr, sizeof(heap_vaddr)))
			continue;
		// The array ends with address 0
		if (heap_vaddr == 0)
			break;

		HEAP_2003 heap;
		if (!read_memory_wrapper(NULL, heap_vaddr, &heap, sizeof(heap)))
			return false;

		// loop through all segments(up to 64) for each heap
		for (int i=0; i<64 && heap.Segments[i]; i++)
		{
			HEAP_SEGMENT_2003 heap_seg;
			if (!read_memory_wrapper(NULL, (address_t)heap.Segments[i], &heap_seg, sizeof(heap_seg)) )
				break;
			// Ignore errors
			get_biggest_blocks_in_heap_segment_2003(&heap_seg, blks, num);
		}
	}

	return true;
}

static bool
page_walk_internal_2008(HEAP_2008* heap,			// in => heap
					HEAP_SEGMENT_2008* heap_seg,	// in => heap segment
					address_t seg_addr,				// in => heap segment address
					address_t addr,					// input heap addr
					bool bVerbose,				// print detail info or not
					struct heap_block* opBlock,		// output the block containing the addr
					size_t* opInuseBytes,			// output page in-use bytes
					size_t* opFreeBytes,			// output page free bytes
					unsigned long* opNumInuse,		// output number inuse blocks
					unsigned long* opNumFree)		// output number of free blocks
{
	address_t entry_vaddr;
	address_t seg_end = (address_t)heap_seg->BaseAddress + heap_seg->NumberOfPages * g_page_sz;

	// Sanity check
	if (addr)
	{
		if (addr < (address_t)heap_seg->BaseAddress	|| addr >= seg_end)
		{
			CA_PRINT("[Error] Unexpected page walk with input address "PRINT_FORMAT_POINTER"\n", addr);
			return false;
		}
		else if (opBlock && addr<(address_t)heap_seg->FirstEntry)
		{
			opBlock->addr = (address_t)heap_seg->BaseAddress;
			opBlock->inuse = false;
			opBlock->size = (address_t)heap_seg->FirstEntry - (address_t)heap_seg->BaseAddress;
			return true;
		}

	}

	// Start walking heap segment
	entry_vaddr = (address_t) heap_seg->FirstEntry;
	while (entry_vaddr < seg_end)
	{
		address_t user_addr;
		bool busy;
		size_t entry_sz, user_sz;
		HEAP_ENTRY_2008 entry;
		bool lbUncommitted = false;

		// there are multiple uncommitted ranges, which might be readable or unreadable
		// they are on a doubly-linked list and they are NOT necessarily sorted by address
		// 		_HEAP_SEGMENT_2008::NumberOfUnCommittedRanges is also the list size + 1 (sentinel)
		// 		_HEAP_SEGMENT_2003::UCRSegmentList is the sentinel
		// !FIXME! It is slow to do this for every block traversed.
		if (heap_seg->NumberOfUnCommittedRanges > 0)
		{
			address_t ucr_sentinel, ucr_next;
			HEAP_UCR_DESCRIPTOR ucr_descriptor;

			ucr_sentinel = seg_addr + (address_t) &((HEAP_SEGMENT_2008*)0)->UCRSegmentList;
			ucr_next = (address_t)heap_seg->UCRSegmentList.Flink;
			/*if ((address_t)heap_seg->UCRSegmentList.Flink == ucr_sentinel)
			{
				CA_PRINT("[Error] Heap Segment "PRINT_FORMAT_POINTER" UCRSegmentList is empty, but NumberOfUnCommittedRanges is %d\n",
						seg_addr, heap_seg->NumberOfUnCommittedRanges);
				return false;
			}*/
			while (ucr_next != ucr_sentinel)
			{
				ucr_next -= (address_t) &((HEAP_UCR_DESCRIPTOR*)0)->SegmentEntry;
				if (!read_memory_wrapper(NULL, ucr_next, &ucr_descriptor, sizeof(ucr_descriptor)))
				{
					CA_PRINT("[Error] Fail to read UCRSegmentList "PRINT_FORMAT_POINTER"\n", ucr_next);
					return false;
				}
				else if (entry_vaddr >= (address_t)ucr_descriptor.Address && entry_vaddr < (address_t)ucr_descriptor.Address + ucr_descriptor.Size)
				{
					// we run into one of the uncommitted ranges
					// treat the whole range as a free entry
					lbUncommitted = true;
					entry_vaddr = (address_t)ucr_descriptor.Address + ucr_descriptor.Size;
					if (opBlock
						&& addr >= (address_t)ucr_descriptor.Address
						&& addr < (address_t)ucr_descriptor.Address + ucr_descriptor.Size)
					{
						opBlock->addr = (address_t)ucr_descriptor.Address;
						opBlock->inuse = false;
						opBlock->size = ucr_descriptor.Size;
						return true;
					}
					if (bVerbose)
					{
						CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [Uncommitted Range]\n",
								ucr_descriptor.Address, (address_t)ucr_descriptor.Address + ucr_descriptor.Size);
					}
					if (opFreeBytes)
						*opFreeBytes += ucr_descriptor.Size;
					add_block_mem_histogram(ucr_descriptor.Size, false, 1);
					break;
				}
				// Get the next uncommitted range on the list
				ucr_next = (address_t) ucr_descriptor.SegmentEntry.Flink;
			}
		}
		if (lbUncommitted)
			continue;

		// The normal block starts with HEAP_ENTRY
		if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
		{
			CA_PRINT("[Error] Failed to read HEAP_ENTRY at "PRINT_FORMAT_POINTER"\n", entry_vaddr);
			return false;
		}
		else	// We have read HEAP_ENTRY successfully
		{
			// Encoding of the HEAP_ENTRY
			if (heap->EncodeFlagMask)
			{
				UCHAR* bytes = (UCHAR*) &entry.Size;
				*(DWORD*)bytes ^= *(DWORD*)(&heap->Encoding.Size);
				// check the encoding byte
				if (entry.SmallTagIndex != (bytes[0] ^ bytes[1] ^ bytes[2]) )
				{
					CA_PRINT("[Error] Encoding is invalid/corrupted at HEAP_ENTRY "PRINT_FORMAT_POINTER"\n", entry_vaddr);
					return false;
				}
			}
			entry_sz = entry.Size * sizeof(entry);
			// HEAP_ENTRY::Size tag is often the victim of memory overrun
			if (entry_sz == 0
				|| entry_vaddr + entry_sz > (address_t) heap_seg->LastValidEntry
				|| entry_vaddr + entry_sz > seg_end)
			{
				CA_PRINT("[Error] HEAP_ENTRY at "PRINT_FORMAT_POINTER" has an invalid/corrupted size value %d\n",
						entry_vaddr, entry.Size);
				return false;
			}
			// HEAP_ENTRY::UnusedBytes
			user_addr = entry_vaddr + sizeof(entry);
			if (entry_sz > entry.UnusedBytes && entry.UnusedBytes >= sizeof(entry))
				user_sz = entry_sz - entry.UnusedBytes;
			else
				user_sz = entry_sz - sizeof(entry);
			// HEAP_ENTRY::Flags
			if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
				busy = true;
			else
				busy = false;
			if (bVerbose)
				CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [struct HEAP_ENTRY]\n",
						entry_vaddr, user_addr);
			// A free chunk doesn't have _CrtMemBlockHeader. If an uncommitted page
			// follows, we can't even read enough bytes sizeof(_CrtMemBlockHeader)
			if (g_dbgheap && busy && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader))
			{
				_CrtMemBlockHeader pHead;
				if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
					return false;
				/* gap is filled with _bNoMansLandFill or 0xfd */
				if (*(int*)&pHead.gap == 0xfdfdfdfd)
				{
					user_addr += sizeof(_CrtMemBlockHeader);
					user_sz = pHead.nDataSize;
					if (bVerbose)
						CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [struct _CrtMemBlockHeader]\n",
								entry_vaddr + sizeof(entry), user_addr);
				}
			}

			if (bVerbose)
			{
				if (busy)
					CA_PRINT("\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size="PRINT_FORMAT_SIZE" busy [USER SPACE]\n",
						user_addr, user_addr+user_sz, user_sz);
				else
					CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size="PRINT_FORMAT_SIZE" free [USER SPACE]\n",
						user_addr, user_addr+user_sz, user_sz);
				if (user_addr+user_sz < entry_vaddr+entry_sz)
					CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [Unused Bytes]\n",
							user_addr+user_sz, entry_vaddr+entry_sz);
			}
			if (addr && opBlock
				&& addr >= entry_vaddr && addr < entry_vaddr + entry_sz)
			{
				if (addr >= user_addr && addr < user_addr + user_sz)
				{
					// Input address is within user space
					opBlock->addr = user_addr;
					opBlock->inuse = busy;
					opBlock->size = user_sz;
				}
				else
				{
					// Input address is heap data
					opBlock->inuse = false;
					if (addr < user_addr)
					{
						opBlock->addr = entry_vaddr;
						opBlock->size = user_addr - entry_vaddr;
					}
					else
					{
						opBlock->addr = user_addr + user_sz;
						opBlock->size = entry_vaddr + entry_sz - opBlock->addr;
					}
				}
				break;
			}
			if (opInuseBytes && opFreeBytes && opNumInuse && opNumFree)
			{
				if (busy)
				{
					*opInuseBytes += user_sz;
					(*opNumInuse)++;
				}
				else
				{
					*opFreeBytes += user_sz;
					(*opNumFree)++;
				}
			}
			add_block_mem_histogram(user_sz, busy, 1);
			// calc the next block
			entry_vaddr = entry_vaddr + entry_sz;
		}
	}

	return true;
}

static bool
page_walk_internal_2008_32(HEAP_2008_32* heap,			// in => heap
					HEAP_SEGMENT_2008_32* heap_seg,	// in => heap segment
					address_t seg_addr,				// in => heap segment address
					address_t addr,					// input heap addr
					bool bVerbose,				// print detail info or not
					struct heap_block* opBlock,		// output the block containing the addr
					size_t* opInuseBytes,			// output page in-use bytes
					size_t* opFreeBytes,			// output page free bytes
					unsigned long* opNumInuse,		// output number inuse blocks
					unsigned long* opNumFree)		// output number of free blocks
{
	ptr_t_32 entry_vaddr;
	ptr_t_32 seg_end = (ptr_t_32)heap_seg->BaseAddress + heap_seg->NumberOfPages * g_page_sz;;

	// Sanity check
	if (addr)
	{
		if (addr < (ptr_t_32)heap_seg->BaseAddress	|| addr >= seg_end)
		{
			CA_PRINT("[Error] Unexpected page walk with input address 0x%lx\n", addr);
			return false;
		}
		else if (opBlock && addr<(ptr_t_32)heap_seg->FirstEntry)
		{
			opBlock->addr = (ptr_t_32)heap_seg->BaseAddress;
			opBlock->inuse = false;
			opBlock->size = (ptr_t_32)heap_seg->FirstEntry - (ptr_t_32)heap_seg->BaseAddress;
			return true;
		}

	}

	// Start walking heap segment
	entry_vaddr = (ptr_t_32) heap_seg->FirstEntry;
	while (entry_vaddr < seg_end)
	{
		ptr_t_32 user_addr;
		bool busy;
		unsigned int entry_sz, user_sz;
		HEAP_ENTRY_2008_32 entry;
		bool lbUncommitted = false;

		// there are multiple uncommitted ranges, which might be readable or unreadable
		// they are on a doubly-linked list and they are NOT necessarily sorted by address
		// 		_HEAP_SEGMENT_2008::NumberOfUnCommittedRanges is also the list size + 1 (sentinel)
		// 		_HEAP_SEGMENT_2003::UCRSegmentList is the sentinel
		// !FIXME! It is slow to do this for every block traversed.
		if (heap_seg->NumberOfUnCommittedRanges > 0)
		{
			ptr_t_32 ucr_sentinel, ucr_next;
			HEAP_UCR_DESCRIPTOR_32 ucr_descriptor;

			ucr_sentinel = seg_addr + (ptr_t_32) &((HEAP_SEGMENT_2008_32*)0)->UCRSegmentList;
			ucr_next = (ptr_t_32)heap_seg->UCRSegmentList.Flink;
			while (ucr_next != ucr_sentinel)
			{
				ucr_next -= (ptr_t_32) &((HEAP_UCR_DESCRIPTOR_32*)0)->SegmentEntry;
				if (!read_memory_wrapper(NULL, ucr_next, &ucr_descriptor, sizeof(ucr_descriptor)))
				{
					CA_PRINT("[Error] Fail to read UCRSegmentList 0x%lx\n", ucr_next);
					return false;
				}
				else if (entry_vaddr >= (ptr_t_32)ucr_descriptor.Address && entry_vaddr < (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size)
				{
					// we run into one of the uncommitted ranges
					// treat the whole range as a free entry
					lbUncommitted = true;
					entry_vaddr = (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size;
					if (opBlock
						&& addr >= (ptr_t_32)ucr_descriptor.Address
						&& addr < (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size)
					{
						opBlock->addr = (ptr_t_32)ucr_descriptor.Address;
						opBlock->inuse = false;
						opBlock->size = ucr_descriptor.Size;
						return true;
					}
					if (bVerbose)
					{
						CA_PRINT("\t0x%lx - 0x%lx [Uncommitted Range]\n",
								ucr_descriptor.Address, (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size);
					}
					if (opFreeBytes)
						*opFreeBytes += ucr_descriptor.Size;
					add_block_mem_histogram(ucr_descriptor.Size, false, 1);
					break;
				}
				// Get the next uncommitted range on the list
				ucr_next = (ptr_t_32) ucr_descriptor.SegmentEntry.Flink;
			}
		}
		if (lbUncommitted)
			continue;

		// The normal block starts with HEAP_ENTRY
		if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
		{
			CA_PRINT("[Error] Failed to read HEAP_ENTRY at 0x%lx\n", entry_vaddr);
			return false;
		}
		else	// We have read HEAP_ENTRY successfully
		{
			// Encoding of the HEAP_ENTRY
			if (heap->EncodeFlagMask)
			{
				UCHAR* bytes = (UCHAR*) &entry.Size;
				*(DWORD*)bytes ^= *(DWORD*)(&heap->Encoding.Size);
				// check the encoding byte
				if (entry.SmallTagIndex != (bytes[0] ^ bytes[1] ^ bytes[2]) )
				{
					CA_PRINT("[Error] Encoding is invalid/corrupted at HEAP_ENTRY 0x%lx\n", entry_vaddr);
					return false;
				}
			}
			entry_sz = entry.Size * sizeof(entry);
			// HEAP_ENTRY::Size tag is often the victim of memory overrun
			if (entry_sz == 0
				|| entry_vaddr + entry_sz > (ptr_t_32) heap_seg->LastValidEntry
				|| entry_vaddr + entry_sz > seg_end)
			{
				CA_PRINT("[Error] HEAP_ENTRY at 0x%lx has an invalid/corrupted size value %d\n",
						entry_vaddr, entry.Size);
				return false;
			}
			// HEAP_ENTRY::UnusedBytes
			user_addr = entry_vaddr + sizeof(entry);
			if (entry_sz > entry.UnusedBytes && entry.UnusedBytes >= sizeof(entry))
				user_sz = entry_sz - entry.UnusedBytes;
			else
				user_sz = entry_sz - sizeof(entry);
			// HEAP_ENTRY::Flags
			if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
				busy = true;
			else
				busy = false;
			if (bVerbose)
				CA_PRINT("\t0x%lx - 0x%lx [struct HEAP_ENTRY]\n",
						entry_vaddr, user_addr);
			// A free chunk doesn't have _CrtMemBlockHeader. If an uncommitted page
			// follows, we can't even read enough bytes sizeof(_CrtMemBlockHeader)
			if (g_dbgheap && busy && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader_32))
			{
				_CrtMemBlockHeader_32 pHead;
				if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
					return false;
				/* gap is filled with _bNoMansLandFill or 0xfd */
				if (*(int*)&pHead.gap == 0xfdfdfdfd)
				{
					user_addr += sizeof(_CrtMemBlockHeader_32);
					user_sz = pHead.nDataSize;
					if (bVerbose)
						CA_PRINT("\t0x%lx - 0x%lx [struct _CrtMemBlockHeader]\n",
								entry_vaddr + sizeof(entry), user_addr);
				}
			}

			if (bVerbose)
			{
				if (busy)
					CA_PRINT("\t\t0x%lx - 0x%lx size=%ld busy [USER SPACE]\n",
						user_addr, user_addr+user_sz, user_sz);
				else
					CA_PRINT("\t0x%lx - 0x%lx size=%ld free [USER SPACE]\n",
						user_addr, user_addr+user_sz, user_sz);
				if (user_addr+user_sz < entry_vaddr+entry_sz)
					CA_PRINT("\t0x%lx - 0x%lx [Unused Bytes]\n",
							user_addr+user_sz, entry_vaddr+entry_sz);
			}
			if (addr && opBlock
				&& addr >= entry_vaddr && addr < entry_vaddr + entry_sz)
			{
				if (addr >= user_addr && addr < user_addr + user_sz)
				{
					// Input address is within user space
					opBlock->addr = user_addr;
					opBlock->inuse = busy;
					opBlock->size = user_sz;
				}
				else
				{
					// Input address is heap data
					opBlock->inuse = false;
					if (addr < user_addr)
					{
						opBlock->addr = entry_vaddr;
						opBlock->size = user_addr - entry_vaddr;
					}
					else
					{
						opBlock->addr = user_addr + user_sz;
						opBlock->size = entry_vaddr + entry_sz - opBlock->addr;
					}
				}
				break;
			}
			if (opInuseBytes && opFreeBytes && opNumInuse && opNumFree)
			{
				if (busy)
				{
					*opInuseBytes += user_sz;
					(*opNumInuse)++;
				}
				else
				{
					*opFreeBytes += user_sz;
					(*opNumFree)++;
				}
			}
			add_block_mem_histogram(user_sz, busy, 1);
			// calc the next block
			entry_vaddr = entry_vaddr + entry_sz;
		}
	}

	return true;
}

static bool
get_biggest_blocks_in_heap_segment_2008(HEAP_2008* heap,
										HEAP_SEGMENT_2008* heap_seg,
										address_t seg_addr,
										struct heap_block* blks,
										unsigned int num)
{
	address_t entry_vaddr = (address_t) heap_seg->FirstEntry;
	address_t seg_end = (address_t)heap_seg->BaseAddress + heap_seg->NumberOfPages * g_page_sz;;
	struct heap_block* smallest = &blks[num - 1];

	if (smallest->size > seg_end - entry_vaddr)
		return true;

	// Start walking heap segment
	while (entry_vaddr < seg_end)
	{
		address_t user_addr;
		bool busy;
		size_t entry_sz, user_sz;
		HEAP_ENTRY_2008 entry;
		bool lbUncommitted = false;

		// there are multiple uncommitted ranges, which might be readable or unreadable
		// they are on a doubly-linked list and they are NOT necessarily sorted by address
		// 		_HEAP_SEGMENT_2008::NumberOfUnCommittedRanges is also the list size + 1 (sentinel)
		// 		_HEAP_SEGMENT_2003::UCRSegmentList is the sentinel
		// !FIXME! It is slow to do this for every block traversed.
		if (heap_seg->NumberOfUnCommittedRanges > 0)
		{
			address_t ucr_sentinel, ucr_next;
			HEAP_UCR_DESCRIPTOR ucr_descriptor;

			ucr_sentinel = seg_addr + (address_t) &((HEAP_SEGMENT_2008*)0)->UCRSegmentList;
			ucr_next = (address_t)heap_seg->UCRSegmentList.Flink;
			while (ucr_next != ucr_sentinel)
			{
				ucr_next -= (address_t) &((HEAP_UCR_DESCRIPTOR*)0)->SegmentEntry;
				if (!read_memory_wrapper(NULL, ucr_next, &ucr_descriptor, sizeof(ucr_descriptor)))
					return false;
				else if (entry_vaddr >= (address_t)ucr_descriptor.Address && entry_vaddr < (address_t)ucr_descriptor.Address + ucr_descriptor.Size)
				{
					// we run into one of the uncommitted ranges
					// treat the whole range as a free entry
					lbUncommitted = true;
					entry_vaddr = (address_t)ucr_descriptor.Address + ucr_descriptor.Size;
					break;
				}
				// Get the next uncommitted range on the list
				ucr_next = (address_t) ucr_descriptor.SegmentEntry.Flink;
			}
		}
		if (lbUncommitted)
			continue;

		// The normal block starts with HEAP_ENTRY
		if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
			return false;
		else	// We have read HEAP_ENTRY successfully
		{
			// Encoding of the HEAP_ENTRY
			if (heap->EncodeFlagMask)
			{
				UCHAR* bytes = (UCHAR*) &entry.Size;
				*(DWORD*)bytes ^= *(DWORD*)(&heap->Encoding.Size);
				// check the encoding byte
				if (entry.SmallTagIndex != (bytes[0] ^ bytes[1] ^ bytes[2]) )
					return false;
			}
			entry_sz = entry.Size * sizeof(entry);
			// HEAP_ENTRY::Size tag is often the victim of memory overrun
			if (entry_sz == 0
				|| entry_vaddr + entry_sz > (address_t) heap_seg->LastValidEntry
				|| entry_vaddr + entry_sz > seg_end)
				return false;
			// HEAP_ENTRY::UnusedBytes
			user_addr = entry_vaddr + sizeof(entry);
			if (entry_sz > entry.UnusedBytes && entry.UnusedBytes >= sizeof(entry))
				user_sz = entry_sz - entry.UnusedBytes;
			else
				user_sz = entry_sz - sizeof(entry);
			// HEAP_ENTRY::Flags
			if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
				busy = true;
			else
				busy = false;
			// A free chunk doesn't have _CrtMemBlockHeader. If an uncommitted page
			// follows, we can't even read enough bytes sizeof(_CrtMemBlockHeader)
			if (g_dbgheap && busy && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader))
			{
				_CrtMemBlockHeader pHead;
				if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
					return false;
				/* gap is filled with _bNoMansLandFill or 0xfd */
				if (*(int*)&pHead.gap == 0xfdfdfdfd)
				{
					user_addr += sizeof(_CrtMemBlockHeader);
					user_sz = pHead.nDataSize;
				}
			}

			if (busy && user_sz > smallest->size)
			{
				struct heap_block blk;
				blk.addr = user_addr;
				blk.inuse = true;
				blk.size = user_sz;
				add_one_big_block(blks, num, &blk);
			}
			entry_vaddr = entry_vaddr + entry_sz;
		}
	}

	return true;
}

static bool
get_biggest_blocks_in_heap_segment_2008_32(HEAP_2008_32* heap,
										HEAP_SEGMENT_2008_32* heap_seg,
										address_t seg_addr,
										struct heap_block* blks,
										unsigned int num)
{
	ptr_t_32 entry_vaddr = (ptr_t_32) heap_seg->FirstEntry;
	ptr_t_32 seg_end = (ptr_t_32)heap_seg->BaseAddress + heap_seg->NumberOfPages * g_page_sz;;
	struct heap_block* smallest = &blks[num - 1];

	if (smallest->size > seg_end - entry_vaddr)
		return true;

	// Start walking heap segment
	while (entry_vaddr < seg_end)
	{
		ptr_t_32 user_addr;
		bool busy;
		DWORD entry_sz, user_sz;
		HEAP_ENTRY_2008_32 entry;
		bool lbUncommitted = false;

		// there are multiple uncommitted ranges, which might be readable or unreadable
		// they are on a doubly-linked list and they are NOT necessarily sorted by address
		// 		_HEAP_SEGMENT_2008::NumberOfUnCommittedRanges is also the list size + 1 (sentinel)
		// 		_HEAP_SEGMENT_2003::UCRSegmentList is the sentinel
		// !FIXME! It is slow to do this for every block traversed.
		if (heap_seg->NumberOfUnCommittedRanges > 0)
		{
			ptr_t_32 ucr_sentinel, ucr_next;
			HEAP_UCR_DESCRIPTOR_32 ucr_descriptor;

			ucr_sentinel = seg_addr + (ptr_t_32) &((HEAP_SEGMENT_2008_32*)0)->UCRSegmentList;
			ucr_next = (ptr_t_32)heap_seg->UCRSegmentList.Flink;
			while (ucr_next != ucr_sentinel)
			{
				ucr_next -= (ptr_t_32) &((HEAP_UCR_DESCRIPTOR_32*)0)->SegmentEntry;
				if (!read_memory_wrapper(NULL, ucr_next, &ucr_descriptor, sizeof(ucr_descriptor)))
					return false;
				else if (entry_vaddr >= (ptr_t_32)ucr_descriptor.Address && entry_vaddr < (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size)
				{
					// we run into one of the uncommitted ranges
					// treat the whole range as a free entry
					lbUncommitted = true;
					entry_vaddr = (ptr_t_32)ucr_descriptor.Address + ucr_descriptor.Size;
					break;
				}
				// Get the next uncommitted range on the list
				ucr_next = (ptr_t_32) ucr_descriptor.SegmentEntry.Flink;
			}
		}
		if (lbUncommitted)
			continue;

		// The normal block starts with HEAP_ENTRY
		if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
			return false;
		else	// We have read HEAP_ENTRY successfully
		{
			// Encoding of the HEAP_ENTRY
			if (heap->EncodeFlagMask)
			{
				UCHAR* bytes = (UCHAR*) &entry.Size;
				*(DWORD*)bytes ^= *(DWORD*)(&heap->Encoding.Size);
				// check the encoding byte
				if (entry.SmallTagIndex != (bytes[0] ^ bytes[1] ^ bytes[2]) )
					return false;
			}
			entry_sz = entry.Size * sizeof(entry);
			// HEAP_ENTRY::Size tag is often the victim of memory overrun
			if (entry_sz == 0
				|| entry_vaddr + entry_sz > (ptr_t_32) heap_seg->LastValidEntry
				|| entry_vaddr + entry_sz > seg_end)
				return false;
			// HEAP_ENTRY::UnusedBytes
			user_addr = entry_vaddr + sizeof(entry);
			if (entry_sz > entry.UnusedBytes && entry.UnusedBytes >= sizeof(entry))
				user_sz = entry_sz - entry.UnusedBytes;
			else
				user_sz = entry_sz - sizeof(entry);
			// HEAP_ENTRY::Flags
			if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
				busy = true;
			else
				busy = false;
			// A free chunk doesn't have _CrtMemBlockHeader. If an uncommitted page
			// follows, we can't even read enough bytes sizeof(_CrtMemBlockHeader)
			if (g_dbgheap && busy && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader_32))
			{
				_CrtMemBlockHeader_32 pHead;
				if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
					return false;
				/* gap is filled with _bNoMansLandFill or 0xfd */
				if (*(int*)&pHead.gap == 0xfdfdfdfd)
				{
					user_addr += sizeof(_CrtMemBlockHeader_32);
					user_sz = pHead.nDataSize;
				}
			}

			if (busy && user_sz > smallest->size)
			{
				struct heap_block blk;
				blk.addr = user_addr;
				blk.inuse = true;
				blk.size = user_sz;
				add_one_big_block(blks, num, &blk);
			}
			entry_vaddr = entry_vaddr + entry_sz;
		}
	}

	return true;
}

static bool
page_walk_internal_2003(HEAP_SEGMENT_2003* heap_seg,// in => heap segment
					address_t addr,					// input heap addr
					bool bVerbose,				// print detail info or not
					struct heap_block* opBlock,		// output the block containing the addr
					size_t* opInuseBytes,			// output page in-use bytes
					size_t* opFreeBytes,			// output page free bytes
					unsigned long* opNumInuse,		// outpout number of inuse blocks
					unsigned long* opNumFree)		// output number of free blocks
{
	address_t entry_vaddr;
	address_t seg_end = (address_t)heap_seg->BaseAddress + heap_seg->NumberOfPages * g_page_sz;
	address_t range_vaddr;
	HEAP_UNCOMMMTTED_RANGE range;

	// Sanity check
	if (addr)
	{
		if (addr < (address_t)heap_seg->BaseAddress	|| addr >= seg_end)
		{
			CA_PRINT("[Error] Unexpected page walk with input address "PRINT_FORMAT_POINTER"\n", addr);
			return false;
		}
		else if (opBlock && addr<(address_t)heap_seg->FirstEntry)
		{
			opBlock->addr = (address_t)heap_seg->BaseAddress;
			opBlock->inuse = false;
			opBlock->size = (address_t)heap_seg->FirstEntry - (address_t)heap_seg->BaseAddress;
			return true;
		}

	}

	// there may be multiple uncommitted ranges
	// they are sorted by address, and on a singly-linked list (last one is grounded)
	// 		_HEAP_SEGMENT_2003::NumberOfUnCommittedRanges is also the list size
	// 		_HEAP_SEGMENT_2003::UnCommittedRanges is the list head
	if (heap_seg->NumberOfUnCommittedRanges > 0)
	{
		range_vaddr = (address_t) heap_seg->UnCommittedRanges;
		if (!read_memory_wrapper(NULL, range_vaddr, &range, sizeof(range)))
		{
			CA_PRINT("[Error] Failed to read _HEAP_SEGMENT::UnCommittedRanges "PRINT_FORMAT_POINTER"\n", range_vaddr);
			return false;
		}
	}
	else
	{
		range.Address = (PVOID)seg_end;
		range.Size = 0;
	}

	// Start walking heap segment
	entry_vaddr = (address_t) heap_seg->FirstEntry;
	while (entry_vaddr < seg_end)
	{
		address_t user_addr;
		bool busy;
		size_t entry_sz, user_sz;
		HEAP_ENTRY_2003 entry;

		// is the next entry falls in an uncommitted range?
		if (entry_vaddr >= (address_t)range.Address)
		{
			if (entry_vaddr >= (address_t)range.Address + range.Size)
			{
				CA_PRINT("[Error] Unexpected: uncommitted range "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" is missed\n",
						range.Address, (address_t)range.Address + range.Size);
				return false;
			}
			// treat the whole range as a free entry
			entry_vaddr = (address_t)range.Address + range.Size;
			if (opBlock
				&& addr >= (address_t)range.Address
				&& addr < (address_t)range.Address+range.Size)
			{
				opBlock->addr = (address_t)range.Address;
				opBlock->inuse = false;
				opBlock->size = range.Size;
				return true;
			}
			if (bVerbose)
			{
				CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [Uncommitted Range]\n",
					range.Address, (address_t)range.Address + range.Size);
			}
			if (opFreeBytes)
				*opFreeBytes += range.Size;
			add_block_mem_histogram(range.Size, false, 1);
			// Get the next uncommitted range on the list
			range_vaddr = (address_t) range.next;
			if (range_vaddr)
			{
				if (!read_memory_wrapper(NULL, range_vaddr, &range, sizeof(range)))
				{
					CA_PRINT("[Error] Failed to read _HEAP_SEGMENT::UnCommittedRanges "PRINT_FORMAT_POINTER"\n", range_vaddr);
					return false;
				}
			}
			else
			{
				range.Address = (PVOID)seg_end;
				range.Size = 0;
			}
		}
		else
		{
			// The block starts with HEAP_ENTRY
			if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
			{
				CA_PRINT("[Error] Failed to read _HEAP_Entry "PRINT_FORMAT_POINTER"\n", entry_vaddr);
				return false;
			}
			entry_sz = entry.Size * sizeof(entry);
			// HEAP_ENTRY::Size tag is often the victim of memory overrun
			if (entry_vaddr + entry_sz > seg_end)
			{
				CA_PRINT("[Error] HEAP_ENTRY at "PRINT_FORMAT_POINTER" has an invalid/corrupted size value %d\n",
						entry_vaddr, entry.Size);
				return false;
			}
			// HEAP_ENTRY::UnusedBytes
			user_addr = entry_vaddr + sizeof(entry);
			if (entry_sz > entry.UnusedBytes)
				user_sz = entry_sz - entry.UnusedBytes;
			else
				user_sz = entry_sz - sizeof(entry);
			// HEAP_ENTRY::Flags
			if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
				busy = true;
			else
				busy = false;

			if (bVerbose)
				CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [struct HEAP_ENTRY]\n",
						entry_vaddr, user_addr);
			// A free chunk doesn't have _CrtMemBlockHeader.
			// An in-use chunk could have no _CrtMemBlockHeader either.
			// If an uncommitted page follows, we can't read enough bytes sizeof(_CrtMemBlockHeader)
			if (g_dbgheap && busy && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader))
			{
				_CrtMemBlockHeader pHead;
				if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
				{
					CA_PRINT("[Error] Failed to read _CrtMemBlockHeader "PRINT_FORMAT_POINTER"\n", user_addr);
					return false;
				}
				/* gap is filled with _bNoMansLandFill or 0xfd */
				if (*(int*)&pHead.gap == 0xfdfdfdfd)
				{
					user_addr += sizeof(_CrtMemBlockHeader);
					user_sz = pHead.nDataSize;
					if (bVerbose)
						CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [struct _CrtMemBlockHeader]\n",
								entry_vaddr + sizeof(entry), user_addr);
				}
			}

			if (bVerbose)
			{
				if (busy)
					CA_PRINT("\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size="PRINT_FORMAT_SIZE" busy [USER SPACE]\n",
						user_addr, user_addr+user_sz, user_sz);
				else
					CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size="PRINT_FORMAT_SIZE" free [USER SPACE]\n",
						user_addr, user_addr+user_sz, user_sz);
				if (user_addr+user_sz < entry_vaddr+entry_sz)
					CA_PRINT("\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" [Unused Bytes]\n",
							user_addr+user_sz, entry_vaddr+entry_sz);
			}
			if (addr && opBlock
				&& addr >= entry_vaddr && addr < entry_vaddr + entry_sz)
			{
				if (addr >= user_addr && addr < user_addr + user_sz)
				{
					// Input address is within user space
					opBlock->addr = user_addr;
					opBlock->inuse = busy;
					opBlock->size = user_sz;
				}
				else
				{
					// Input address is heap data
					opBlock->inuse = false;
					if (addr < user_addr)
					{
						opBlock->addr = entry_vaddr;
						opBlock->size = user_addr - entry_vaddr;
					}
					else
					{
						opBlock->addr = user_addr + user_sz;
						opBlock->size = entry_vaddr + entry_sz - opBlock->addr;
					}
				}
				return true;
			}
			if (opInuseBytes && opFreeBytes && opNumInuse && opNumFree)
			{
				if (busy)
				{
					*opInuseBytes += user_sz;
					(*opNumInuse)++;
				}
				else
				{
					*opFreeBytes += user_sz;
					(*opNumFree)++;
				}
			}
			add_block_mem_histogram(user_sz, busy, 1);
			// calc the next block
			entry_vaddr = entry_vaddr + entry_sz;
		}
	}

	return true;
}

static bool get_biggest_blocks_in_heap_segment_2003(HEAP_SEGMENT_2003*heap_seg, struct heap_block* blks, unsigned int num)
{
	address_t entry_vaddr = (address_t) heap_seg->FirstEntry;
	address_t seg_end = (address_t)heap_seg->BaseAddress + heap_seg->NumberOfPages * g_page_sz;
	address_t range_vaddr;
	HEAP_UNCOMMMTTED_RANGE range;
	struct heap_block* smallest = &blks[num - 1];

	// there may be multiple uncommitted ranges
	// they are sorted by address, and on a singly-linked list (last one is grounded)
	// 		_HEAP_SEGMENT_2003::NumberOfUnCommittedRanges is also the list size
	// 		_HEAP_SEGMENT_2003::UnCommittedRanges is the list head
	if (heap_seg->NumberOfUnCommittedRanges > 0)
	{
		range_vaddr = (address_t) heap_seg->UnCommittedRanges;
		if (!read_memory_wrapper(NULL, range_vaddr, &range, sizeof(range)))
			return false;
	}
	else
	{
		range.Address = (PVOID)seg_end;
		range.Size = 0;
	}

	if (smallest->size > seg_end - entry_vaddr)
		return true;

	// Start walking heap segment
	while (entry_vaddr < seg_end)
	{
		address_t user_addr;
		bool busy;
		size_t entry_sz, user_sz;
		HEAP_ENTRY_2003 entry;

		// is the next entry falls in an uncommitted range?
		if (entry_vaddr >= (address_t)range.Address)
		{
			if (entry_vaddr >= (address_t)range.Address + range.Size)
				return false;
			// treat the whole range as a free entry
			entry_vaddr = (address_t)range.Address + range.Size;
			// Get the next uncommitted range on the list
			range_vaddr = (address_t) range.next;
			if (range_vaddr)
			{
				if (!read_memory_wrapper(NULL, range_vaddr, &range, sizeof(range)))
					return false;
			}
			else
			{
				range.Address = (PVOID)seg_end;
				range.Size = 0;
			}
		}
		else
		{
			// The block starts with HEAP_ENTRY
			if (!read_memory_wrapper(NULL, entry_vaddr, &entry, sizeof(entry)))
				return false;
			entry_sz = entry.Size * sizeof(entry);
			// HEAP_ENTRY::Size tag is often the victim of memory overrun
			if (entry_vaddr + entry_sz > seg_end)
				return false;
			// HEAP_ENTRY::UnusedBytes
			user_addr = entry_vaddr + sizeof(entry);
			if (entry_sz > entry.UnusedBytes)
				user_sz = entry_sz - entry.UnusedBytes;
			else
				user_sz = entry_sz - sizeof(entry);
			// HEAP_ENTRY::Flags
			if ( (entry.Flags & PROCESS_HEAP_REGION) || (entry.Flags & PROCESS_HEAP_ENTRY_BUSY) )
				busy = true;
			else
				busy = false;

			// A free chunk doesn't have _CrtMemBlockHeader.
			// An in-use chunk could have no _CrtMemBlockHeader either.
			// If an uncommitted page follows, we can't read enough bytes sizeof(_CrtMemBlockHeader)
			if (g_dbgheap && busy && entry_sz - sizeof(entry) >= sizeof(_CrtMemBlockHeader))
			{
				_CrtMemBlockHeader pHead;
				if (!read_memory_wrapper(NULL, user_addr, &pHead, sizeof(pHead)))
					return false;
				/* gap is filled with _bNoMansLandFill or 0xfd */
				if (*(int*)&pHead.gap == 0xfdfdfdfd)
				{
					user_addr += sizeof(_CrtMemBlockHeader);
					user_sz = pHead.nDataSize;
				}
			}

			if (busy && user_sz > smallest->size)
			{
				struct heap_block blk;
				blk.addr = user_addr;
				blk.inuse = true;
				blk.size = user_sz;
				add_one_big_block(blks, num, &blk);
			}
			entry_vaddr = entry_vaddr + entry_sz;
		}
	}

	return true;
}

// The input array blks is assumed to be sorted by size already
static void add_one_big_block(struct heap_block* blks, unsigned int num, struct heap_block* blk)
{
	unsigned int i;
	for (i=0; i<num; i++)
	{
		if (blk->size > blks[i].size)
		{
			int k;
			// Insert blk->blks[i]
			// Move blks[i]->blks[i+1], .., blks[num-2]->blks[num-1]
			for (k= ((int)num)-2; k>=(int)i; k--)
				blks[k+1] = blks[k];
			blks[i] = *blk;
			break;
		}
	}
}
