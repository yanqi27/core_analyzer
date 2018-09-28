/*
 * heap_ptmalloc.c
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#include <gnu/libc-version.h>
#include <assert.h>

#include "segment.h"
#include "heap_ptmalloc.h"

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

/***************************************************************************
* Implementation specific data structures
***************************************************************************/

/*
 * Uniformed data structure to hide the differences across ptmalloc versions
 */
struct ca_malloc_par
{
  INTERNAL_SIZE_T  mmap_threshold;
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;
  unsigned int     pagesize;
  INTERNAL_SIZE_T  mmapped_mem;
  INTERNAL_SIZE_T  max_total_mem;
  char*            sbrk_base;
};

struct ca_malloc_state {
  int flags;
  int nfastbins;
  mfastbinptr      fastbins[NFASTBINS_GLIBC_2_5]; /* ver 2.5 has bigger NFASTBINS than other versions */
  mchunkptr        top;
  mchunkptr        last_remainder;
  mchunkptr        bins[NBINS * 2];
  unsigned int     binmap[BINMAPSIZE];
  void *next;
  void *next_free;
  INTERNAL_SIZE_T system_mem;
};

union malloc_state
{
	struct malloc_state_GLIBC_2_3 mstate_2_3;
	struct malloc_state_GLIBC_2_4 mstate_2_4;
	struct malloc_state_GLIBC_2_5 mstate_2_5;
	struct malloc_state_GLIBC_2_12 mstate_2_12;
	struct malloc_state_GLIBC_2_22 mstate_2_22;
};

struct heap_info {
  char* ar_ptr;				/* Arena for this heap. */
  struct heap_info*  prev;	/* Previous heap. */
  size_t size;				/* Current size in bytes. */
  size_t mprotect_size;		/* pad in glibc 2.3 */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];	/* this is 0 for 64bit */
};

#define heap_for_ptr(ptr) \
	((struct heap_info *)((unsigned long)(ptr) & ~(g_HEAP_MAX_SIZE-1)))

/*
** The purpose of arena is manage a group of heaps to serve a thread or a set of threads
**     A heap is a contiguous memory region, which belongs to an arena
*/
enum HEAP_TYPE
{
	ENUM_HEAP_UNDEFINED,
	ENUM_HEAP_MAIN,
	ENUM_HEAP_DYNAMIC,
	ENUM_HEAP_MMAP_BLOCK
};

struct ca_heap
{
	struct ca_arena*     mArena;
	struct ca_heap*      mpNext;		// next heap on list
	struct ca_segment*   mSegment;		// heap is part or whole of the segment
	address_t            mStartAddr;	// core's addr space
	address_t            mEndAddr;		// core's addr space
	address_t*           mChunks;		// sorted addresses of blocks belonging to this heap
	unsigned int         mNumChunks;	// the size of previous array of addresses
	unsigned int         mCorrupted:1;
	unsigned int         mResearved:31;
};

struct ca_arena
{
	enum HEAP_TYPE          mType;
	struct ca_heap*         mpHeap;		// singly-linked list of heaps
	address_t               mArenaAddr;	// core's addr space
	struct ca_malloc_state  mpState;	// point to struct malloc_state
};

#define COPY_MALLOC_PAR(pars) \
	do { \
		mparams.mmap_threshold = pars.mmap_threshold; \
		mparams.n_mmaps        = pars.n_mmaps; \
		mparams.n_mmaps_max    = pars.n_mmaps_max; \
		mparams.max_total_mem  = pars.max_total_mem; \
		mparams.max_n_mmaps    = pars.max_n_mmaps; \
		mparams.pagesize       = pars.pagesize; \
		mparams.mmapped_mem    = pars.mmapped_mem; \
		mparams.sbrk_base      = (char*) pars.sbrk_base; \
	} while(0)

#define COPY_MALLOC_PAR_WITHOUT_PAGESIZE(pars) \
	do { \
		mparams.mmap_threshold = pars.mmap_threshold; \
		mparams.n_mmaps        = pars.n_mmaps; \
		mparams.n_mmaps_max    = pars.n_mmaps_max; \
		mparams.max_total_mem  = pars.max_total_mem; \
		mparams.max_n_mmaps    = pars.max_n_mmaps; \
		mparams.pagesize       = 4096; \
		mparams.mmapped_mem    = pars.mmapped_mem; \
		mparams.sbrk_base      = (char*) pars.sbrk_base; \
	} while(0)

#define copy_mstate(arena, orig)								\
	do {												\
		(arena)->flags = 0; /* (orig)->flags; for 2.4 and later */			\
		(arena)->nfastbins = sizeof((orig)->fastbins)/sizeof((orig)->fastbins[0]);	\
		memcpy((arena)->fastbins, (orig)->fastbins, sizeof((orig)->fastbins));		\
		(arena)->top = (orig)->top;							\
		(arena)->last_remainder = (orig)->last_remainder;				\
		memcpy((arena)->bins, (orig)->bins, sizeof((orig)->bins));			\
		memcpy((arena)->binmap, (orig)->binmap, sizeof((orig)->binmap));		\
		(arena)->next = (orig)->next;							\
		(arena)->next_free = NULL; /* (orig)->next_free; for 2.5 and later */		\
		(arena)->system_mem = (orig)->system_mem;					\
	} while(0)

#define read_mp(v)									\
	do {										\
		struct malloc_par_GLIBC_2_##v pars;					\
		g_HEAP_MAX_SIZE = HEAP_MAX_SIZE_GLIBC_2_##v;				\
		g_MAX_FAST_SIZE = MAX_FAST_SIZE_GLIBC_2_##v;				\
		rc = read_memory_wrapper(NULL, mparams_vaddr, &pars, sizeof(pars));	\
		if (rc)									\
			COPY_MALLOC_PAR_WITHOUT_PAGESIZE(pars);				\
	} while (0)


/*
 * Global variables
 */
static int glibc_ver_major = 0;
static int glibc_ver_minor = 0;

static unsigned long g_HEAP_MAX_SIZE;
static size_t g_MAX_FAST_SIZE;
static struct ca_malloc_par mparams;

static bool g_heap_ready = false;
static struct ca_arena* g_arenas = NULL;
static unsigned int g_arena_cnt = 0;
static unsigned int g_arena_buf_sz = 0;

static struct ca_heap** g_sorted_heaps = NULL;	// heaps sorted by virtual address
static unsigned int g_heap_cnt = 0;

/*
 * Forward declaration
 */
static bool traverse_heap_blocks(struct ca_heap*, bool, size_t*, size_t*, unsigned long*, unsigned long*);

static bool build_heaps(void);
static bool get_glibc_version(void);

static bool build_sorted_heaps(void);
static void release_sorted_heaps(void);
static struct ca_heap* search_sorted_heaps(address_t);

static bool build_heap_chunks(struct ca_heap*);
static address_t search_chunk(struct ca_heap*, address_t);
static bool fill_heap_block(struct ca_heap*, address_t, struct heap_block*);

static bool in_fastbins_or_remainder(struct ca_malloc_state*, mchunkptr, size_t);

static size_t get_mstate_size(void);

/***************************************************************************
* Exposed functions
***************************************************************************/
const char *
heap_version(void)
{
	return "Ptmalloc 2.7";
}

bool init_heap(void)
{
	bool rc = build_heaps();

	return rc;
}

/*
 * Return true and detail info if the input addr belongs to a heap memory block
 */
bool get_heap_block_info(address_t addr, struct heap_block* blk)
{
	struct ca_heap* heap;

	if (!g_heap_ready)
		return false;

	heap = search_sorted_heaps(addr);
	if (heap)
		return fill_heap_block(heap, addr, blk);
	else
		return false;
}

/*
 * Return true and detail info of the heap block after the input addr
 */
bool get_next_heap_block(address_t addr, struct heap_block* blk)
{
	struct ca_heap* heap = NULL;
	address_t next_addr = 0;
	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);

	if (!g_heap_ready || g_heap_cnt == 0)
		return false;

	if (addr)
	{
		// If an address is given, it must belong to a heap block
		// otherwise, there is no sense of its next
		heap = search_sorted_heaps(addr);
		if (heap && fill_heap_block(heap, addr, blk))
		{
			next_addr = blk->addr + blk->size + size_t_sz;
			if (next_addr >= heap->mEndAddr)
			{
				// the given address is the last heap block of its heap
				// move to the next heap if any
				unsigned int heap_index;
				for (heap_index = 0; heap_index < g_heap_cnt; heap_index++)
				{
					if (g_sorted_heaps[heap_index] == heap)
						break;
				}
				if (heap_index + 1 < g_heap_cnt)
				{
					heap = g_sorted_heaps[heap_index + 1];
					next_addr = heap->mStartAddr;
				}
				else
				{
					heap = NULL;
					next_addr = 0;
				}
			}
		}
		else
			return false;
	}
	else
	{
		heap = g_sorted_heaps[0];
		next_addr = heap->mStartAddr;
	}

	// Hopefully we have locate the next heap block's address by now
	if (heap && next_addr && fill_heap_block(heap, next_addr, blk) && blk->addr > addr)
		return true;
	else
		return false;
}

/* Return true if the block belongs to a heap */
bool is_heap_block(address_t addr)
{
	struct ca_heap* heap;

	if (!g_heap_ready)
		return false;

	heap = search_sorted_heaps(addr);
	if (heap)
		return true;
	else
		return false;
}

/*
 * Traverse all heaps unless a non-zero address is given, in which case the specific heap is used
 */
bool heap_walk(address_t heapaddr, bool verbose)
{
	size_t size_t_sz =  sizeof(INTERNAL_SIZE_T);
	bool rc = true;
	size_t totoal_free_bytes, totoal_inuse_bytes;
	unsigned long total_num_inuse, total_num_free;
	unsigned int num_mmap;
	unsigned int mmap_arena_cnt = 0;
	int i, num_error;
	struct ca_heap*  heap;

	if (!g_heap_ready)
		return false;
	else if (heapaddr)
	{
		heap = search_sorted_heaps(heapaddr);
		if (heap)
		{
			struct ca_arena* arena = heap->mArena;
			address_t heap_begin = heap->mStartAddr - size_t_sz;
			address_t heap_end   = heap->mEndAddr;
			if (arena->mType == ENUM_HEAP_MAIN)
				CA_PRINT("\tMain arena");
			else if (arena->mType == ENUM_HEAP_DYNAMIC)
				CA_PRINT("\tDynamic arena");
			else if (arena->mType == ENUM_HEAP_MMAP_BLOCK)
				CA_PRINT("\tmmap block");
			if (arena->mArenaAddr)
				CA_PRINT(" ("PRINT_FORMAT_POINTER"): ["PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"]\n",
					arena->mArenaAddr, heap_begin, heap_end);
			return traverse_heap_blocks(heap, true, NULL, NULL, NULL, NULL);
		}
		else
		{
			CA_PRINT("Failed to find heap region that contains address "PRINT_FORMAT_POINTER"\n", heapaddr);
			return false;
		}
	}

	// Tuning and stats info
	CA_PRINT("\tTuning params & stats:\n");
	CA_PRINT("\t\tmmap_threshold="PRINT_FORMAT_SIZE"\n", mparams.mmap_threshold);
	CA_PRINT("\t\tpagesize=%d\n", mparams.pagesize);
	CA_PRINT("\t\tn_mmaps=%d\n", mparams.n_mmaps);
	CA_PRINT("\t\tn_mmaps_max=%d\n", mparams.n_mmaps_max);
	CA_PRINT("\t\ttotal mmap regions created=%d\n", mparams.max_n_mmaps);
	CA_PRINT("\t\tmmapped_mem="PRINT_FORMAT_SIZE"\n", mparams.mmapped_mem);
	CA_PRINT("\t\tsbrk_base=%p\n", mparams.sbrk_base);

	if (verbose)
		init_mem_histogram(16);

	totoal_free_bytes = 0;
	totoal_inuse_bytes = 0;
	total_num_inuse = 0;
	total_num_free = 0;
	num_mmap = 0;
	num_error = 0;
	// walk the arena
	for (i=0; i<g_arena_cnt; i++)
	{
		size_t inuse_bytes, free_bytes;
		struct ca_arena* arena = &g_arenas[i];
		heap  = arena->mpHeap;

		if (arena->mType == ENUM_HEAP_MAIN)
		{
			CA_PRINT("\tMain arena ("PRINT_FORMAT_POINTER") owns regions:\n", arena->mArenaAddr);
		}
		else if (arena->mType == ENUM_HEAP_DYNAMIC)
		{
			CA_PRINT("\tDynamic arena ("PRINT_FORMAT_POINTER") owns regions:\n", arena->mArenaAddr);
		}
		else if (arena->mType == ENUM_HEAP_MMAP_BLOCK)
		{
			CA_PRINT("\tmmap-ed large memory blocks:\n");
			mmap_arena_cnt++;
		}
		else
		{
			CA_PRINT("Unexpected arena type %d\n", arena->mType);
			return false;
		}

		// Traverse the link list of heaps of this arena
		while (heap)
		{
			unsigned long num_inuse=0, num_free=0;
			// there might be too many mmap blocks to print
			if (arena->mType == ENUM_HEAP_MMAP_BLOCK)
				num_mmap++;

			CA_PRINT("\t\t["PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"] Total ",
					heap->mStartAddr + size_t_sz, heap->mEndAddr);
			print_size(heap->mEndAddr - heap->mStartAddr);

			if (traverse_heap_blocks(heap, false, &inuse_bytes, &free_bytes, &num_inuse, &num_free))
			{
				totoal_inuse_bytes += inuse_bytes;
				totoal_free_bytes  += free_bytes;
				total_num_inuse += num_inuse;
				total_num_free  += num_free;
				CA_PRINT(" in-use %ld(", num_inuse);
				print_size(inuse_bytes);
				CA_PRINT(") free %ld(", num_free);
				print_size(free_bytes);
				CA_PRINT(")");
			}
			else
			{
				num_error++;
				rc = false;
			}
			CA_PRINT("\n");
			heap = heap->mpNext;
		}
	}
	// There is so far no deterministic way to get all mmap blocks reliably
	if (num_mmap != mparams.n_mmaps)
	{
		CA_PRINT("\t\t%d mmap-ed large memory blocks are found, however, %d is recorded in mp_\n",
				num_mmap, mparams.n_mmaps);
	}
	// Total counters
	CA_PRINT("\n");
	if (rc)
	{
		CA_PRINT("\tThere are %d arenas", g_arena_cnt - mmap_arena_cnt);
		if (num_mmap > 0)
			CA_PRINT(" and %d mmap-ed memory blocks", num_mmap);
		CA_PRINT(" Total ");
		print_size(totoal_inuse_bytes + totoal_free_bytes);
		CA_PRINT("\n");

		CA_PRINT("\tTotal "PRINT_FORMAT_SIZE" blocks in-use of ", total_num_inuse);
		print_size(totoal_inuse_bytes);
		CA_PRINT("\n");

		CA_PRINT("\tTotal "PRINT_FORMAT_SIZE" blocks free of ",	total_num_free);
		print_size(totoal_free_bytes);
		CA_PRINT("\n\n");

		if (verbose)
			display_mem_histogram("\t");
	}
	else
		CA_PRINT("%d Errors encountered while walking the heap!\n", num_error);

	return rc;
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

bool get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	size_t mchunk_sz = sizeof(struct malloc_chunk);
	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);
	unsigned int i;
	struct ca_arena* arena;
	struct ca_heap*  heap;
	struct malloc_chunk achunk;
	struct heap_block blk;
	struct heap_block* smallest = &blks[num - 1];

	if (!g_heap_ready)
		return false;

	// mmap block should be bigger than any other block in arena
	for (i=0; i<g_arena_cnt; i++)
	{
		if (g_arenas[i].mType == ENUM_HEAP_MMAP_BLOCK)
		{
			arena = &g_arenas[i];
			heap  = arena->mpHeap;

			// Traverse the link list of heaps of this arena
			while (heap)
			{
				if (!read_memory_wrapper(NULL, heap->mStartAddr - size_t_sz, &achunk, mchunk_sz))
					break;
				blk.size = chunksize(&achunk) - size_t_sz * 2;
				if (blk.size > smallest->size)
				{
					blk.addr = heap->mStartAddr + size_t_sz;
					blk.inuse = true;
					add_one_big_block(blks, num, &blk);
				}
				heap = heap->mpNext;
			}
		}
	}
	if (smallest->size > 0)
		return true;

	// walk other arenas if there are fewer mmap blocks than the requested number of big blocks
	for (i=0; i<g_arena_cnt; i++)
	{
		if (g_arenas[i].mType != ENUM_HEAP_MMAP_BLOCK)
		{
			arena = &g_arenas[i];
			heap  = arena->mpHeap;
			// Traverse the link list of heaps of this arena
			while (heap)
			{
				unsigned int bi;
				// For regular heaps, build an array of sorted chunk address, then do a binary search
				if (!heap->mChunks)
					build_heap_chunks(heap);
				for (bi = 0; bi < heap->mNumChunks; bi++)
				{
					size_t chunksz;
					address_t chunk_addr = heap->mChunks[bi] - size_t_sz;
					if (!read_memory_wrapper(NULL, chunk_addr, &achunk, mchunk_sz))
						break;
					chunksz = chunksize(&achunk);
					if (chunk_addr + chunksz + mchunk_sz >= heap->mEndAddr)
					{
						// top pad is free memory block
					}
					else
					{
						// Get the next chunk which has the prev_inuse bit flag
						struct malloc_chunk next_chunk;
						if (!read_memory_wrapper(NULL, chunk_addr + chunksz, &next_chunk, mchunk_sz))
							break;

						if (prev_inuse(&next_chunk)
							&& (chunksz > g_MAX_FAST_SIZE || !in_fastbins_or_remainder(&heap->mArena->mpState, (mchunkptr)chunk_addr, chunksz)) )
						{
							// this is an in-use block
							blk.size = chunksz - size_t_sz;
							if (blk.size > smallest->size)
							{
								blk.addr = chunk_addr + size_t_sz * 2;
								blk.inuse = true;
								add_one_big_block(blks, num, &blk);
							}
						}
					}
				}
				heap = heap->mpNext;
			}
		}
	}
	return true;
}

bool walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
	unsigned int heap_index;
	struct inuse_block* pBlockinfo = opBlocks;

	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);
	size_t mchunk_sz = sizeof(struct malloc_chunk);

	if (!g_heap_ready)
		return false;

	*opCount = 0;
	for (heap_index = 0; heap_index < g_heap_cnt; heap_index++)
	{
		struct ca_heap* heap = g_sorted_heaps[heap_index];
		struct malloc_chunk achunk;

		// For mmap heap, there is only one block and in-use
		if (heap->mArena->mType == ENUM_HEAP_MMAP_BLOCK)
		{
			if (!read_memory_wrapper(NULL, heap->mStartAddr - size_t_sz, &achunk, mchunk_sz))
				continue;
			(*opCount)++;
			if (pBlockinfo)
			{
				pBlockinfo->addr = heap->mStartAddr + size_t_sz;
				pBlockinfo->size = chunksize(&achunk) - size_t_sz*2;
				pBlockinfo++;
			}
		}
		else
		{
			unsigned int chunk_index;
			// For regular heaps, use the sorted array of chunks
			if (!heap->mChunks)
				build_heap_chunks(heap);

			for (chunk_index = 0; chunk_index < heap->mNumChunks; chunk_index++)
			{
				address_t chunk_addr = heap->mChunks[chunk_index] - size_t_sz;
				size_t chunksz;
				// read current chunk's size tag
				if (!read_memory_wrapper(NULL, chunk_addr, &achunk, mchunk_sz))
					break;
				chunksz = chunksize(&achunk);
				// top pad
				if (chunk_addr + chunksz + mchunk_sz >= heap->mEndAddr)
					break;
				else
				{
					// Get the next chunk which has the prev_inuse bit flag
					struct malloc_chunk next_chunk;
					if (!read_memory_wrapper(NULL, chunk_addr + chunksz, &next_chunk, mchunk_sz))
						break;

					if (prev_inuse(&next_chunk)
						&& (chunksz > g_MAX_FAST_SIZE || !in_fastbins_or_remainder(&heap->mArena->mpState, (mchunkptr)chunk_addr, chunksz)) )
					{
						(*opCount)++;
						if (pBlockinfo)
						{
							pBlockinfo->addr = chunk_addr + size_t_sz*2;
							pBlockinfo->size = chunksz - size_t_sz;
							pBlockinfo++;
						}
					}
				}
			}
		}
	}
	return true;
}

/***************************************************************************
* Ptmalloc Helper Functions
***************************************************************************/

/*
 * compare two ca_heaps by their starting address
 */
static int compare_ca_heap(const void* lhs, const void* rhs)
{
	const struct ca_heap* heap1 = *(const struct ca_heap**) lhs;
	const struct ca_heap* heap2 = *(const struct ca_heap**) rhs;
	// they can't be equal
	if (heap1->mStartAddr < heap2->mStartAddr)
		return -1;
	else if (heap1->mStartAddr > heap2->mStartAddr)
		return 1;
	else
	{
		CA_PRINT("Internal error: two ca_heaps are of the same start address.\n");
		return 0;
	}
}

/*
 * Cleanup old array of sorted heaps
 */
static void release_sorted_heaps(void)
{
	if (g_sorted_heaps)
	{
		free(g_sorted_heaps);
		g_sorted_heaps = NULL;
	}
}

/*
 * All ca_heaps are sorted in an array for fast search
 */
static bool build_sorted_heaps(void)
{
	int i, k;
	struct ca_arena* arena;
	struct ca_heap*  heap_p;

	// First get the count of all heaps
	g_heap_cnt = 0;
	for (i=0; i<g_arena_cnt; i++)
	{
		arena = &g_arenas[i];
		heap_p = arena->mpHeap;
		while (heap_p)
		{
			g_heap_cnt++;
			heap_p = heap_p->mpNext;
		}
	}
	if (g_heap_cnt == 0)
		return false;

	// create an array and populate all heaps
	g_sorted_heaps = (struct ca_heap**) malloc(sizeof(struct ca_heap*) * (g_heap_cnt+1));
	k = 0;
	for (i=0; i<g_arena_cnt; i++)
	{
		arena = &g_arenas[i];
		heap_p = arena->mpHeap;
		while (heap_p)
		{
			g_sorted_heaps[k++] = heap_p;
			heap_p = heap_p->mpNext;
		}
	}
	g_sorted_heaps[g_heap_cnt] = NULL;	// seal the array with a NULL pointer
	// sort the array by heap's starting address
	qsort(g_sorted_heaps, g_heap_cnt, sizeof(g_sorted_heaps[0]), compare_ca_heap);

	return true;
}

/*
 * Given an address, return the ca_heap that contains the memory block
 */
static struct ca_heap* search_sorted_heaps(address_t addr)
{
	unsigned int l_index = 0;
	unsigned int u_index = g_heap_cnt;

	// sanity check
	if (!g_sorted_heaps || g_heap_cnt==0)
		return NULL;
	// bail out for out of bound addr
	if (addr < g_sorted_heaps[0]->mStartAddr || addr >= g_sorted_heaps[g_heap_cnt-1]->mEndAddr)
		return NULL;

	while (l_index < u_index)
	{
		unsigned int m_index = (l_index + u_index) / 2;
		struct ca_heap* heap = g_sorted_heaps[m_index];
		if (addr < heap->mStartAddr)
			u_index = m_index;
		else if (addr >= heap->mEndAddr)
			l_index = m_index + 1;
		else
			return heap;
	}
	return NULL;
}

/*
 * Add a heap to its arena
 */
static void add_ca_heap(struct ca_arena* arena, struct ca_heap* heap)
{
	heap->mArena = arena;
	// append the heap to the arena's link list of heaps
	if (arena->mpHeap)
	{
		struct ca_heap* prev, *tail;
		prev = arena->mpHeap;
		tail = prev->mpNext;
		while (tail)
		{
			prev = tail;
			tail = tail->mpNext;
		}
		prev->mpNext = heap;
	}
	else
		arena->mpHeap = heap;
	heap->mpNext = NULL;

	// fixup segment type
	if (heap->mSegment->m_type != ENUM_HEAP)
		heap->mSegment->m_type = ENUM_HEAP;

}

static struct ca_arena* alloc_ca_arena(void)
{
	struct ca_arena* arena;

	if (g_arena_cnt >= g_arena_buf_sz)
	{
		if (g_arena_buf_sz == 0)
			g_arena_buf_sz = 64;
		else
			g_arena_buf_sz *= 2;
		g_arenas = (struct ca_arena*) realloc(g_arenas, sizeof(struct ca_arena)*g_arena_buf_sz);
	}
	arena = &g_arenas[g_arena_cnt++];
	memset(arena, 0, sizeof(struct ca_arena));

	return arena;
}

/*
 * a special case handler
 */
static void release_ca_arena(struct ca_arena* arena)
{
	// The released one must be the last one
	if (arena == &g_arenas[g_arena_cnt-1])
	{
		g_arena_cnt--;
	}
}

/*
 * release a heap
 */
static void release_ca_heap(struct ca_heap* heap)
{
	if (heap->mChunks)
		free(heap->mChunks);
	memset(heap, 0xfd, sizeof(struct ca_heap));
	free(heap);
}

/*
 * struct ca_arena is placed on a buffer, which expands dynamically and never shrinks
 */
static void release_all_ca_arenas(void)
{
	unsigned int i;
	for (i=0; i<g_arena_cnt; i++)
	{
		struct ca_arena* arena = &g_arenas[i];
		struct ca_heap*  heap = arena->mpHeap;
		while (heap)
		{
			struct ca_heap* tmp_heap = heap;
			heap = heap->mpNext;
			release_ca_heap (tmp_heap);
		}
	}
	g_arena_cnt = 0;
	// sorted heaps are pointers to above released ones
	release_sorted_heaps();
}

static bool
read_malloc_state_by_symbol(address_t arena_vaddr, struct ca_malloc_state *state)
{
	struct type *ms_type = NULL;

	return true;
}

/*
 * Build an area and its belonging heaps
 */
static struct ca_arena* build_arena(address_t arena_vaddr, enum HEAP_TYPE type)
{
	struct malloc_chunk top_chunk;
	struct ca_segment* segment;
	struct ca_arena* arena;
	struct ca_heap*  heap;
	address_t cursor;
	struct malloc_chunk achunk;
	size_t chunksz, pgsize;
	address_t top_addr;
	size_t mchunk_sz = sizeof(struct malloc_chunk);
	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);
	size_t minsz = MINSIZE;

	arena = alloc_ca_arena();
	arena->mArenaAddr = arena_vaddr;
	arena->mType = type;

	if (type == ENUM_HEAP_MMAP_BLOCK)
	{
		memset(&arena->mpState, 0, sizeof(arena->mpState));
	}
	else
	{
		size_t mstate_size = get_mstate_size();
		union malloc_state arena_state;
		bool rc;

		// Parse arena's metadata by symbol if available
		rc = read_malloc_state_by_symbol(arena_vaddr, &arena->mpState);
		if (!rc) {
			// Read in arena's meta data, i.e. struct malloc_state
			rc = read_memory_wrapper(NULL, arena_vaddr, &arena_state, mstate_size);
			if (rc) {
				if (glibc_ver_minor == 3)
					copy_mstate(&arena->mpState, &arena_state.mstate_2_3);
				else if (glibc_ver_minor == 4)
					copy_mstate(&arena->mpState, &arena_state.mstate_2_4);
				else if (glibc_ver_minor == 5)
					copy_mstate(&arena->mpState, &arena_state.mstate_2_5);
				else if (glibc_ver_minor >= 12 && glibc_ver_minor <= 21)
					copy_mstate(&arena->mpState, &arena_state.mstate_2_12);
				else if (glibc_ver_minor >= 22 && glibc_ver_minor <= 27)
					copy_mstate(&arena->mpState, &arena_state.mstate_2_22);
				else {
					assert(0 && "internal error: glibc version not supported");
					return NULL;
				}
			} else {
				CA_PRINT("Failed to read arena at "PRINT_FORMAT_POINTER"\n", arena_vaddr);
				release_ca_arena(arena);
				return NULL;
			}
		}

		// A program may never allocate from main heap, only big memory blocks (128KB+)
		// handle this rare case
		if (arena->mpState.system_mem == 0)
		{
			release_ca_arena(arena);
			return NULL;
		}
		// top chunk is the last chunk of the arena
		top_addr = (address_t) arena->mpState.top;
		segment = get_segment(top_addr, mchunk_sz);
		if (!segment || !read_memory_wrapper(segment, top_addr, &top_chunk, mchunk_sz))
		{

			CA_PRINT("Failed to read arena's top chunk at "PRINT_FORMAT_POINTER"\n", top_addr);
			release_ca_arena(arena);
			return NULL;
		}
	}

	pgsize = mparams.pagesize;
	// Collect the heaps of this arena
	if (type == ENUM_HEAP_MAIN)
	{
		heap = (struct ca_heap*) malloc(sizeof(struct ca_heap));
		memset(heap, 0, sizeof(struct ca_heap));
		// main_arena
		if (contiguous(&arena->mpState))
		{
			heap->mEndAddr = (address_t)top_addr + chunksize(&top_chunk);
			heap->mStartAddr = heap->mEndAddr - arena->mpState.system_mem + size_t_sz;
			heap->mSegment = segment;
			add_ca_heap (arena, heap);
		}
		else
		{
			// non-contiguous main_arena, get the sbrk-ed heap
			bool find_fencepost = false;
			heap->mStartAddr = (address_t)mparams.sbrk_base + size_t_sz;
			segment = get_segment(heap->mStartAddr, 1);
			if (segment)
			{
				// find the double fencepost, which is the end of the sbrk-ed heap
				address_t seg_end = segment->m_vaddr + segment->m_fsize;
				heap->mSegment = segment;
				cursor = heap->mStartAddr - size_t_sz;
				while (cursor + mchunk_sz <= seg_end)
				{
					if (!read_memory_wrapper(segment, cursor, &achunk, mchunk_sz))
						break;
					chunksz = chunksize(&achunk);
					if (chunksz > 2*size_t_sz)
						cursor += chunksz;
					else if (chunksz == 2*size_t_sz)
					{
						cursor += 2*size_t_sz;
						// this might be the double fencepost
						if (cursor+2*size_t_sz <= seg_end)
						{
							if (read_memory_wrapper(segment, cursor, &achunk, 2*size_t_sz))
							{
								chunksz = chunksize(&achunk);
								if (chunksz == 2*size_t_sz)
								{
									// find it
									heap->mEndAddr = cursor - size_t_sz;
									add_ca_heap (arena, heap);
									find_fencepost = true;
								}
							}
						}
						break;
					}
					else
						break; // something wrong
				}
				if (!find_fencepost) // couldn't find the fencepost
				{
					heap->mEndAddr = segment->m_vaddr + segment->m_fsize;
					add_ca_heap (arena, heap);
				}
			}
			else
			{
				// we shouldn't get here, otherwise the core is seriously wrong
				CA_PRINT("Failed to find the segment of sbrk_base "PRINT_FORMAT_POINTER"\n", heap->mStartAddr);
				free (heap);
			}
			// then, get the heap of the top-chunk, which is mmap-ed due to failure of sbrk()
			segment = get_segment(top_addr, mchunk_sz);
			if (segment)
			{
				bool bailout = false;
				address_t start = segment->m_vaddr;
				while (!bailout && start < top_addr)
				{
					cursor = start;
					while (cursor < top_addr)
					{
						if (!read_memory_wrapper(NULL, cursor, &achunk, mchunk_sz))
							break;
						chunksz = chunksize(&achunk);
						if (chunksz < minsz)
							break;
						if (cursor + chunksz == top_addr)
						{
							heap = (struct ca_heap*) malloc(sizeof(struct ca_heap));
							memset(heap, 0, sizeof(struct ca_heap));
							heap->mSegment   = segment;
							heap->mStartAddr = start + size_t_sz;
							heap->mEndAddr = top_addr + chunksize(&top_chunk);
							add_ca_heap (arena, heap);
							bailout = true;
							break;
						}
						else
							cursor += chunksz;
					}
					start += pgsize;
				}
			}
		}
	}
	else if (type == ENUM_HEAP_DYNAMIC)
	{
		// dynamically created arena
		address_t h_vaddr = (address_t) heap_for_ptr(top_addr);
		size_t mstate_size = get_mstate_size();

		// It may have more than one heap
		while (h_vaddr)
		{
			address_t first_chunk;
			struct heap_info hinfo;
			size_t hinfo_sz = sizeof(struct heap_info);

			segment = get_segment(h_vaddr, hinfo_sz);
			if (!segment || !read_memory_wrapper(segment, h_vaddr, &hinfo, hinfo_sz))
			{
				CA_PRINT("Failed to read heap_info at "PRINT_FORMAT_POINTER"\n", h_vaddr);
				break;
			}
			heap = (struct ca_heap*) malloc(sizeof(struct ca_heap));
			memset(heap, 0, sizeof(struct ca_heap));
			heap->mSegment = segment;
			if ((address_t)(hinfo.ar_ptr) ==  h_vaddr + hinfo_sz)
				first_chunk = h_vaddr + hinfo_sz + mstate_size;
			else
				first_chunk = h_vaddr + hinfo_sz;
			// possible alignment requirement
			first_chunk = ((first_chunk + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK);
			heap->mStartAddr =  first_chunk + size_t_sz;
			heap->mEndAddr   = h_vaddr + hinfo.size;
			// remember this heap
			add_ca_heap(arena, heap);

			// previous mmap-ed region
			h_vaddr = (address_t)(hinfo.prev);
		}
	}
	else if (type == ENUM_HEAP_MMAP_BLOCK)
	{
		// mmap region is not tracked by the arena structure
		// heuristic search of such memory blocks
		unsigned int sindex;

		if ( (pgsize < 0x1000ul) || (pgsize & 0xffful) )
		{
			release_ca_arena(arena);
			return NULL;
		}

		for (sindex=0; sindex<g_segment_count; sindex++)
		{
			address_t hend;
			struct ca_segment* hseg = &g_segments[sindex];

			if (hseg->m_type == ENUM_MODULE_TEXT || hseg->m_type == ENUM_MODULE_DATA
				|| hseg->m_vsize != hseg->m_fsize)
				continue;
			if (!hseg->m_read || !hseg->m_write)
				continue;

			// check this segment for mmap region
			cursor = hseg->m_vaddr;
			hend   = hseg->m_vaddr + hseg->m_fsize;
			while (cursor + pgsize < hend)
			{
				unsigned int i;
				bool bailout = false;
				// No need to check known heaps
				for (i=0; i<g_arena_cnt && !bailout; i++)
				{
					struct ca_heap* next_heap = g_arenas[i].mpHeap;
					while (next_heap)
					{
						if (cursor >= next_heap->mStartAddr && cursor < next_heap->mEndAddr)
						{
							cursor = (next_heap->mEndAddr + (pgsize - 1)) & ~(pgsize - 1);
							bailout = true;
							break;
						}
						next_heap = next_heap->mpNext;
					}
				}

				if (cursor + pgsize < hend)
				{
					struct malloc_chunk mmap_chunk;
					if (!read_memory_wrapper(hseg, cursor, &mmap_chunk, mchunk_sz))
					{
						CA_PRINT("Failed to read memory at "PRINT_FORMAT_POINTER" while finding mmap blocks\n", cursor);
						break;
					}
					// such a block shall have
					// mmap bit is set and size is multiple of page size and chunk is within segment
					if (chunk_is_mmapped(&mmap_chunk)
						&& !prev_inuse(&mmap_chunk)
						//&& chunksize(&mmap_chunk) >= mparams.mmap_threshold // the threshold maybe changed
						&& chunksize(&mmap_chunk) > pgsize
						&& (chunksize(&mmap_chunk) & (pgsize - 1)) == 0
						&& chunksize(&mmap_chunk) <= hseg->m_vsize
						&& cursor + chunksize(&mmap_chunk) <= hend)
					{
						heap = (struct ca_heap*) malloc(sizeof(struct ca_heap));
						memset(heap, 0, sizeof(struct ca_heap));
						heap->mSegment = hseg;
						heap->mStartAddr = cursor + size_t_sz;
						heap->mEndAddr   = cursor + chunksize(&mmap_chunk);
						add_ca_heap(arena, heap);
						// move forward
						cursor += chunksize(&mmap_chunk);
						cursor = (cursor + (pgsize - 1)) & ~(pgsize - 1);
					}
					else
						cursor += pgsize;
				}
			}
		}
	}
	return arena;
}

static void version_warning(void)
{
	static int vw_once = 1;
	if (g_debug_core && vw_once)
	{
		CA_PRINT("==================================================================================\n");
		CA_PRINT("== The memory manager is assumed to be glibc %d.%d                                ==\n", glibc_ver_major, glibc_ver_minor);
		CA_PRINT("== If this is not true, please debug with another machine with matching glibc   ==\n");
		CA_PRINT("==================================================================================\n");
		vw_once = 0;
	}
}

static int
type_field_name2no(struct type *type, const char *field_name)
{
	int n;

	if (type == NULL)
		return -1;

	type = check_typedef (type);

	for (n = 0; n < TYPE_NFIELDS (type); n++) {
		if (strcmp (field_name, TYPE_FIELD_NAME (type, n)) == 0)
			return n;
	}
	return -1;
}

static bool
get_field_value(struct symbol *sym, struct value *val, const char *fieldname,
				size_t *data, bool optional)
{
	size_t r = 0;
	int fieldno;
	struct value *fieldval;

	*data = ULONG_MAX;
	fieldno = type_field_name2no(value_type(val), fieldname);
	if (fieldno < 0) {
		if (optional) {
			return true;
		} else {
			CA_PRINT("Failed to find member \"%s\"\n", fieldname);
			return false;
		}
	}
	fieldval = value_field(val, fieldno);
	*data = value_as_long(fieldval);
	return true;
}

static bool
read_mp_by_symbol(void)
{
	struct symbol *mp_;
	struct value *val;
	size_t data;
	/*
	 * Global var
	 * File malloc.c: static struct malloc_par mp_;
	 */
	mp_ = lookup_symbol("mp_", 0, VAR_DOMAIN, 0).symbol;
	if (mp_ == NULL) {
		CA_PRINT("Failed to lookup gv \"mp_\"\n");
		return false;
	}
	val = value_of_variable(mp_, 0);
	if(!get_field_value(mp_, val, "mmap_threshold", &data, false))
		return false;
	mparams.mmap_threshold = data;
	if (!get_field_value(mp_, val, "n_mmaps", &data, false))
		return false;
	mparams.n_mmaps = data;
	if (!get_field_value(mp_, val, "n_mmaps_max", &data, false))
		return false;
	mparams.n_mmaps_max = data;
	if (!get_field_value(mp_, val, "max_n_mmaps", &data, false))
		return false;
	mparams.max_n_mmaps = data;
	// pagesize is removed in glibc 2.27
	if (!get_field_value(mp_, val, "pagesize", &data, true))
		return false;
	if (data == ULONG_MAX)
		mparams.pagesize = 0x1000ul;
	else
		mparams.pagesize = data;
	if (!get_field_value(mp_, val, "mmapped_mem", &data, false))
		return false;
	mparams.mmapped_mem = data;
	if (!get_field_value(mp_, val, "sbrk_base", &data, false))
		return false;
	mparams.sbrk_base = (char *)data;

	return true;
}

static bool build_heaps_internal(address_t main_arena_vaddr, address_t mparams_vaddr)
{
	address_t arena_vaddr;
	struct ca_arena* arena;
	bool rc = false;

	// Read in the tuning parames
	if (glibc_ver_minor == 3)
		read_mp(3);
	else if (glibc_ver_minor == 4)
		read_mp(4);
	else if (glibc_ver_minor == 5)
	{
		read_mp(5);
		// My machine (rhel5.8) has glibc2.5 but its mp_ is of glibc2.12
		// !FIXME!
		if (mparams.pagesize != 0x1000ul)
		{
			struct malloc_par_GLIBC_2_12 pars;
			rc = read_memory_wrapper(NULL, mparams_vaddr, &pars, sizeof(pars));
			if (rc)
				COPY_MALLOC_PAR(pars);
			// pretend this is glibc 2.12
			if (mparams.pagesize == 0x1000ul)
			{
				g_HEAP_MAX_SIZE = HEAP_MAX_SIZE_GLIBC_2_12;
				g_MAX_FAST_SIZE = MAX_FAST_SIZE_GLIBC_2_12;
				glibc_ver_minor = 12;
			}
		}
	}
	else if (glibc_ver_minor >= 12 && glibc_ver_minor <= 16)
		read_mp(12);
	else if (glibc_ver_minor >= 17 && glibc_ver_minor <= 27)
		read_mp(17);

	if (!rc)
	{
		CA_PRINT("Failed to read global variable mp_ at "PRINT_FORMAT_POINTER"\n", mparams_vaddr);
		return false;
	}

	// Sanity check of heap parameters
	if (mparams.pagesize < 0x1000ul ||
		mparams.pagesize & 0xffful ||
		(size_t)mparams.sbrk_base & (size_t)0xffful ||
		get_segment((address_t)mparams.sbrk_base, 1) == NULL)
	{
		// We failed to extract heap metadata; try again with debug symbols
		rc = read_mp_by_symbol();
		if (!rc) {
			CA_PRINT("Failed to extract heap metadata from gv mp_ and main_arena\n");
			version_warning();
			return false;
		}
	}

	// start with main arena, which is always present
	arena_vaddr = main_arena_vaddr;
	do
	{
		enum HEAP_TYPE type;
		if (arena_vaddr == main_arena_vaddr)
			type = ENUM_HEAP_MAIN;
		else
			type = ENUM_HEAP_DYNAMIC;
		arena = build_arena(arena_vaddr, type);
		if (!arena)
			break;
		// move to the next arena
		arena_vaddr = (address_t) arena->mpState.next;
	} while (arena_vaddr != main_arena_vaddr);

	if (mparams.n_mmaps > 0)
	{
		int num_mmap = 0;
		arena = build_arena(0, ENUM_HEAP_MMAP_BLOCK);
		if (arena)
		{
			struct ca_heap* heap = arena->mpHeap;
			while (heap)
			{
				num_mmap++;
				heap = heap->mpNext;
			}
		}
		if (num_mmap != mparams.n_mmaps)
			CA_PRINT("Warning: %d mmap memory blocks were found while mp_ reports %d\n", num_mmap, mparams.n_mmaps);
	}

	return true;
}

/*
 * Core function to parse heap memory and build up meta data for various search functions
 *   Arena is a set of heaps (except main arena which has only one heap) serving one thread a time
 *   Heap is a contiguous region of memory, all blocks are linked in a list through struct malloc_chunk
 */
static bool build_heaps(void)
{
	address_t main_arena_vaddr, mparams_vaddr;
	bool rc;

	g_heap_ready = false;

	assert(NFASTBINS_GLIBC_2_5 >= NFASTBINS_GLIBC_2_12);

	if (glibc_ver_major != 2 && !get_glibc_version())
		return false;

	// Something has changed, discard the old info
	if (g_arena_cnt > 0)
		release_all_ca_arenas();

	// Support a subset of all glibc versions
	if (glibc_ver_minor != 3
		&& glibc_ver_minor != 4
		&& glibc_ver_minor != 5
		//&& glibc_ver_minor != 11
		&& (glibc_ver_minor < 12 || glibc_ver_minor > 27))
	{
		CA_PRINT("The memory manager of glibc %d.%d is not supported in this release\n",
				glibc_ver_major, glibc_ver_minor);
		return false;
	}

	main_arena_vaddr = get_var_addr_by_name("main_arena", true);
	mparams_vaddr    = get_var_addr_by_name("mp_", true); /* main_arena_vaddr + sizeof(struct malloc_state); */
	if (main_arena_vaddr == 0 || mparams_vaddr == 0)
	{
		CA_PRINT("Failed to get the addresses of global variables main_arena & mp_\n");
		return false;
	}

	rc = build_heaps_internal(main_arena_vaddr, mparams_vaddr);
	if (rc)
	{
		build_sorted_heaps();
		g_heap_ready = true;
	}

	return rc;
}

/*
 * Blocks in fastbins are free but their tags still indicate in-use.
 */
static bool in_fastbins_or_remainder(struct ca_malloc_state* mstate, mchunkptr chunk_p, size_t chunksz)
{
	int index;

	if (!mstate)
		return false;

	if (glibc_ver_minor == 3 || glibc_ver_minor == 4)
	{
		index = fastbin_index_GLIBC_2_3(chunksz);
	}
	else if (glibc_ver_minor == 5)
	{
		index = fastbin_index_GLIBC_2_5(chunksz);
	}
	else if (glibc_ver_minor >= 12 && glibc_ver_minor <= 27)
	{
		index = fastbin_index_GLIBC_2_12(chunksz);
	}
	else
		return false;

	// Fastbins
	if(index < mstate->nfastbins)
	{
		size_t mchunk_sz = sizeof(struct malloc_chunk);
		address_t chunk_vaddr = (address_t)mstate->fastbins[index];
		while (chunk_vaddr)
		{
			struct malloc_chunk fast_chunk;
			if (chunk_vaddr == (address_t)chunk_p)
				return true;
			else if (!read_memory_wrapper(NULL, chunk_vaddr, &fast_chunk, mchunk_sz))
				return false;
			/*
			if (chunk_vaddr == (address_t)fast_chunk.fd)
				break;
			*/
			if (chunksize(&fast_chunk) > g_MAX_FAST_SIZE)
				return false;
			chunk_vaddr = (address_t)(fast_chunk.fd);
		}
	}
	return false;
}

/*
 * Build up an array of addresses (in ascending order) of chunks of pass-in heap
 */
static bool build_heap_chunks(struct ca_heap* heap)
{
	unsigned int count;
	address_t cursor;
	struct malloc_chunk achunk;
	size_t chunksz;
	bool lbFencePost;
	size_t mchunk_sz = sizeof(struct malloc_chunk);
	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);

	// First pass, count the number of blocks
	count = 0;
	lbFencePost = false;
	cursor = heap->mStartAddr - size_t_sz;
	while (cursor < heap->mEndAddr)
	{
		count++;
		if (!read_memory_wrapper(NULL, cursor, &achunk, mchunk_sz))
			return false;

		// check if chunk size is within valid range
		chunksz = chunksize(&achunk);
		if (cursor > (address_t)(-chunksz)
			|| cursor+chunksz+mchunk_sz > heap->mEndAddr+0x100)
		{
			heap->mCorrupted = 1;
			break;
		}

		// top chunk is treated differently
		if (cursor + chunksz + mchunk_sz >= heap->mEndAddr)
		{
			// this is the top chunk of the arena.
			chunksz = heap->mEndAddr - cursor;
		}
		// detect double fence post
		else if (chunksz == 2*size_t_sz)
		{
			if (lbFencePost)	// 2nd fence post
				chunksz = heap->mEndAddr - cursor;
			else
				lbFencePost = true;	// 1st fence post
		}
		else
			lbFencePost = false;
		cursor += chunksz;
	}

	// Allocate memory for the array
	heap->mChunks = (address_t*) malloc((count + 1) * sizeof(address_t));
	heap->mNumChunks = count;

	// Second pass, fill the array with addresses of malloc_chunk
	count = 0;
	lbFencePost = false;
	cursor = heap->mStartAddr - size_t_sz;
	while (cursor < heap->mEndAddr)
	{
		heap->mChunks[count++] = cursor + size_t_sz;
		read_memory_wrapper(NULL, cursor, &achunk, mchunk_sz);
		// check if chunk size is within valid range
		chunksz = chunksize(&achunk);
		if (cursor > (address_t)(-chunksz)
			|| cursor+chunksz+mchunk_sz > heap->mEndAddr+0x100)
		{
			break;
		}

		// top chunk is treated differently
		if (cursor + chunksz + mchunk_sz >= heap->mEndAddr)
		{
			// this is the top chunk of the arena.
			chunksz = heap->mEndAddr - cursor;
		}
		// detect double fence post
		else if (chunksz == 2*size_t_sz)
		{
			if (lbFencePost)	// 2nd fence post
				chunksz = heap->mEndAddr - cursor;
			else
				lbFencePost = true;	// 1st fence post
		}
		else
			lbFencePost = false;
		cursor += chunksz;
	}
	// Seal the array with heap's end address
	heap->mChunks[count] = heap->mEndAddr;

	return true;
}

/*
 * Binary search of the malloc_chunk within a heap
 */
static address_t search_chunk(struct ca_heap* heap, address_t addr)
{
	unsigned int l_index = 0;
	unsigned int u_index = heap->mNumChunks;

	while (l_index < u_index)
	{
		unsigned int m_index = (l_index + u_index) / 2;
		address_t chunk = heap->mChunks[m_index];
		if (addr < chunk)
			u_index = m_index;
		else if (addr >= heap->mChunks[m_index+1])
			l_index = m_index + 1;
		else
			return chunk;
	}
	return 0;
}

/*
 * Locate the memory block containing addr
 * We have verified that "addr" falls within this heap's range
 */
static bool fill_heap_block(struct ca_heap* heap, address_t addr, struct heap_block* blk)
{
	address_t chunk_addr;
	struct malloc_chunk achunk;
	size_t chunksz;
	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);
	size_t mchunk_sz = sizeof(struct malloc_chunk);

	// For mmap heap, there is only one block and in-use
	if (heap->mArena->mType == ENUM_HEAP_MMAP_BLOCK)
	{
		if (!read_memory_wrapper(NULL, heap->mStartAddr - size_t_sz, &achunk, mchunk_sz))
			return false;
		blk->addr = heap->mStartAddr + size_t_sz;
		blk->size = chunksize(&achunk) - size_t_sz*2;
		blk->inuse = true;
		return true;
	}

	// For regular heaps, build an array of sorted chunk address, then do a binary search
	if (!heap->mChunks)
		build_heap_chunks(heap);
	chunk_addr = search_chunk(heap, addr) - size_t_sz;
	if (!read_memory_wrapper(NULL, chunk_addr, &achunk, mchunk_sz))
		return false;
	chunksz = chunksize(&achunk);
	blk->addr = chunk_addr + size_t_sz*2;
	// top pad
	if (chunk_addr + chunksz + mchunk_sz >= heap->mEndAddr)
	{
		blk->size = heap->mEndAddr - chunk_addr - size_t_sz*2;
		blk->inuse = false;
	}
	else
	{
		// Get the next chunk which has the prev_inuse bit flag
		struct malloc_chunk next_chunk;
		if (!read_memory_wrapper(NULL, chunk_addr + chunksz, &next_chunk, mchunk_sz))
			return false;

		if (prev_inuse(&next_chunk)
			&& (chunksz > g_MAX_FAST_SIZE || !in_fastbins_or_remainder(&heap->mArena->mpState, (mchunkptr)chunk_addr, chunksz)) )
		{
			blk->inuse = true;
		}
		else
			blk->inuse = false;
		blk->size = chunksz - size_t_sz;
	}
	return true;
}

/*
 * Bin and Fastbin are places to hold size-indexed link list of free memory blocks
 * Return false if the link list is damaged, a common consequence of memory corruption
 *
 * Implemented by Dave George
 */
static bool check_bin_and_fastbin(struct ca_arena* arena)
{
	bool rc = true;
	address_t amask = 7;

	// check fastbins
	int bi;
	int fbi;
	size_t mchunk_sz = sizeof(struct malloc_chunk);
	bool error_found;

	if (arena->mType == ENUM_HEAP_MMAP_BLOCK)
		return true;

	for (fbi = 0; fbi < arena->mpState.nfastbins; fbi++)
	{
		address_t chunk_vaddr = (address_t)arena->mpState.fastbins[fbi];
		address_t chunk_prev_vaddr = 0;
		error_found = false;
		while (chunk_vaddr)
		{
			struct malloc_chunk fast_chunk;
			if (chunk_vaddr & amask)
			{
				CA_PRINT("\nError: chunk at "PRINT_FORMAT_POINTER" in fastbin[%d] is misaligned\n",
						chunk_vaddr, fbi); /*T*/
				error_found = true;
			}
			else if (!read_memory_wrapper(NULL, chunk_vaddr, &fast_chunk, mchunk_sz))
			{
				CA_PRINT("\nFailed to get the chunk at "PRINT_FORMAT_POINTER" in fastbin[%d]\n",
						chunk_vaddr, fbi); /*T*/
				error_found = true;
			}
			if (error_found)
			{
				if (chunk_prev_vaddr)
				{
					if (read_memory_wrapper(NULL, chunk_prev_vaddr, &fast_chunk, mchunk_sz))
						CA_PRINT("\tChunk address comes from previous fastbin chunk at "PRINT_FORMAT_POINTER" with fd="PRINT_FORMAT_POINTER"\n",
								chunk_prev_vaddr, (address_t)(fast_chunk.fd));
				}
				else
					CA_PRINT("\tChunk address is the first chunk of this fastbin\n");
				rc = false;
				break;
			}
			chunk_prev_vaddr = chunk_vaddr;
			chunk_vaddr = (address_t)(fast_chunk.fd);
		}
	}

	// check bins
	for (bi = 1; bi < NBINS; bi++)
	{
		address_t chunk_vaddr = (address_t)arena->mpState.bins[bi];
		address_t chunk_next_vaddr = (address_t)arena->mpState.bins[bi+1];
		struct malloc_chunk chunk, chunk_first;

		error_found = false;
		//if (bDebug)
		//{
		//	if (bi < 2)
		//	{
		//		CA_PRINT("Bin[%d]="PRINT_FORMAT_POINTER"\n", bi, chunk_vaddr);
		//	}
		//}
		if (bi >= 2)
		{
			// List is empty
			if (chunk_vaddr == chunk_next_vaddr)
			{
				bi++;
				continue;
			}
			//if (bDebug)
			//{
			//	CA_PRINT("Bin[%d]="PRINT_FORMAT_POINTER", Bin[%d]="PRINT_FORMAT_POINTER"\n", bi, chunk_vaddr, bi+1, chunk_next_vaddr);
			//}
		}
		if (!read_memory_wrapper(NULL, chunk_vaddr, &chunk_first, mchunk_sz))
		{
			CA_PRINT("Failed to get the first chunk at "PRINT_FORMAT_POINTER" in bin[%d]\n",
					chunk_vaddr, bi); /*T*/
			rc = false;
		}
		else
		{
			address_t chunk_first_vaddr = chunk_vaddr;
			address_t chunk_prev_vaddr = 0;
			while (chunk_vaddr)
			{
				if (chunk_vaddr & amask)
				{
					CA_PRINT("\nError: chunk at "PRINT_FORMAT_POINTER" in bin[%d] is misaligned\n",
							chunk_vaddr, bi); /*T*/
					error_found = true;
				}
				else if (!read_memory_wrapper(NULL, chunk_vaddr, &chunk, mchunk_sz))
				{
					CA_PRINT("\nFailed to get the chunk at "PRINT_FORMAT_POINTER" in bin[%d]\n",
							chunk_vaddr, bi); /*T*/
					error_found = true;
				}
				else if (chunk_prev_vaddr && (address_t)(chunk.bk) != chunk_prev_vaddr)
				{
					CA_PRINT("\nError: chunk at "PRINT_FORMAT_POINTER" witch bk="PRINT_FORMAT_POINTER" that does not point to previous chunk\n",
							chunk_vaddr, (address_t)(chunk.bk));
					error_found = true;
				}
				else if ((address_t)(chunk.fd) == chunk_first_vaddr)
				{
					if ((address_t)(chunk_first.bk) != chunk_vaddr)
					{
						CA_PRINT("\nError: bk="PRINT_FORMAT_POINTER" of first chunk does not point to last chunk="PRINT_FORMAT_POINTER"\n",
								(address_t)(chunk_first.bk), chunk_vaddr);
						error_found = true;
					}
					if ((address_t)(chunk.fd) != chunk_first_vaddr)
					{
						CA_PRINT("\nError: fd="PRINT_FORMAT_POINTER" of last chunk does not point to first chunk="PRINT_FORMAT_POINTER"\n",
								(address_t)(chunk.fd), chunk_first_vaddr);
						error_found = true;
					}
				}
				if (error_found)
				{
					if (chunk_prev_vaddr)
					{
						if (read_memory_wrapper(NULL, chunk_prev_vaddr, &chunk, mchunk_sz))
							CA_PRINT("\tChunk address comes from previous bin[%d] chunk at "PRINT_FORMAT_POINTER" with {fd="PRINT_FORMAT_POINTER", bk="PRINT_FORMAT_POINTER"}\n",
									bi, chunk_prev_vaddr, (address_t)(chunk.fd), (address_t)(chunk.bk));
					}
					else
						CA_PRINT("\tChunk address is the first chunk of the bin[%d]\n", bi);
					rc = false;
					break;
				}
				chunk_prev_vaddr = chunk_vaddr;
				chunk_vaddr = (address_t)(chunk.fd);
				if (chunk_vaddr == chunk_first_vaddr)
				{
					chunk_vaddr = 0;
				}
			}
		}
		if (bi > 1)
			bi++;
	}
	return rc;
}

/*
 * Display all blocks in a heap
 */
static bool traverse_heap_blocks(struct ca_heap* heap,
							bool bDisplayBlocks,	// print detail info or not
							size_t* opInuseBytes,	// output page in-use bytes
							size_t* opFreeBytes,	// output page free bytes
							unsigned long* opNumInuse,	// output number of inuse blocks
							unsigned long* opNumFree)	// output number of free blocks
{
	size_t size_t_sz = sizeof(INTERNAL_SIZE_T);
	size_t mchunk_sz = sizeof(struct malloc_chunk);

	address_t cursor;
	struct malloc_chunk achunk;
	size_t totoal_free_bytes, num_free;
	size_t totoal_inuse_bytes, num_inuse;
	address_t heap_begin = heap->mStartAddr - size_t_sz;
	address_t heap_end   = heap->mEndAddr;
	struct ca_arena* arena = heap->mArena;

	// Arena walk starting with the first chunk
	cursor = heap_begin;
	if (!read_memory_wrapper(NULL, cursor, &achunk, mchunk_sz))
	{
		CA_PRINT("Failed to get the first chunk at "PRINT_FORMAT_POINTER"\n", cursor);
		return false;
	}

	// The loop to walk all blocks
	totoal_free_bytes  = num_free  = 0;
	totoal_inuse_bytes = num_inuse = 0;
	while (cursor < heap_end)
	{
		int lbFreeBlock, lbLastBlock;
		// check if chunk size is within valid range
		size_t chunksz = chunksize(&achunk);
		if (cursor > (address_t)(-chunksz) || cursor < heap_begin || cursor > heap_end
			|| cursor+chunksz+mchunk_sz > heap_end+0x100)
		{
			CA_PRINT("Failed to walk arena. The chunk at "PRINT_FORMAT_POINTER" may be corrupted. Its size tag is "PRINT_FORMAT_POINTER"\n",
					cursor, achunk.size);
			return false;
		}

		// top chunk is treated differently
		lbLastBlock = false;
		if (arena->mType == ENUM_HEAP_MMAP_BLOCK)
		{
			// mmap block is single block "heap"
			lbLastBlock = true;
			lbFreeBlock = false;
			chunksz -= size_t_sz;
			num_inuse = 1;
			totoal_inuse_bytes = chunksz - size_t_sz;
			add_block_mem_histogram(totoal_inuse_bytes, true, 1);
		}
		else if (cursor + chunksz + mchunk_sz >= heap_end)
		{
			// this is the top chunk of the arena. the LAST chunk, no next.
			lbLastBlock = true;
			chunksz = heap_end - cursor - size_t_sz;
			num_free++;
			totoal_free_bytes += chunksz - size_t_sz;
			//if (bVerbose)
			//	CA_PRINT("\t\t["PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"] fence post\n", cursor+size_t_sz*2, heap_end);
			lbFreeBlock = true;
			add_block_mem_histogram(chunksz - size_t_sz, false, 1);
		}
		else
		{
			// Get the next chunk
			struct malloc_chunk next_chunk;
			if (!read_memory_wrapper(NULL, cursor+chunksz, &next_chunk, mchunk_sz))
			{
				CA_PRINT("Failed to get chunk at "PRINT_FORMAT_POINTER"\n", cursor+chunksz);
				return false;
			}

			if (prev_inuse(&next_chunk)
				&& (chunksz > g_MAX_FAST_SIZE || !in_fastbins_or_remainder(&arena->mpState, (mchunkptr)cursor, chunksz)) )
			{
				lbFreeBlock = false;
				num_inuse++;
				totoal_inuse_bytes += chunksz - size_t_sz;
				add_block_mem_histogram(chunksz - size_t_sz, true, 1);
			}
			else
			{
				lbFreeBlock = true;
				num_free++;
				totoal_free_bytes += chunksz - size_t_sz;
				add_block_mem_histogram(chunksz - size_t_sz, false, 1);
			}
			// Special case of double fencepost for non-contiguous main_arena heaps
			if (chunksz == 2*size_t_sz && chunksize(&next_chunk) == 2*size_t_sz)
				lbLastBlock = true;
			achunk = next_chunk;
		}

		// print if desired
		if (bDisplayBlocks)
		{
			if (lbFreeBlock)
				CA_PRINT("\t\t["PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"] "PRINT_FORMAT_SIZE" bytes free\n",
						cursor+size_t_sz*2, cursor+chunksz+size_t_sz, chunksz-size_t_sz);
			else
				CA_PRINT("\t\t\t["PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"] "PRINT_FORMAT_SIZE" bytes inuse\n",
						cursor+size_t_sz*2, cursor+chunksz+size_t_sz, chunksz-size_t_sz);
		}

		// walk to next chunk
		if (lbLastBlock)
			break;
		else
			cursor += chunksz;
	} // arena walk loop

	// check free block link list in fastbins and bins
	if (!check_bin_and_fastbin(arena))
		return false;

	if (bDisplayBlocks)
	{
		CA_PRINT("\n");
		CA_PRINT("\tTotal inuse "PRINT_FORMAT_SIZE" blocks "PRINT_FORMAT_SIZE" bytes\n", num_inuse, totoal_inuse_bytes);
		CA_PRINT("\tTotal free "PRINT_FORMAT_SIZE" blocks "PRINT_FORMAT_SIZE" bytes\n", num_free, totoal_free_bytes);
	}

	if (opInuseBytes && opFreeBytes && opNumInuse && opNumFree)
	{
		*opInuseBytes = totoal_inuse_bytes;
		*opFreeBytes  = totoal_free_bytes;
		*opNumInuse = num_inuse;
		*opNumFree = num_free;
	}

	return true;
}

/*
 * Get the glibc version of the host machine.
 * Assume it is the same or compatible with the target machine.
 */
static bool get_glibc_version(void)
{
	const size_t bufsz = 64;
	char buf[bufsz];
	const char* version = gnu_get_libc_version();
	int len = strlen(version);
	int i;

	if (len >= bufsz)
		return false;

	strncpy(buf, version, len+1);
	for (i=0; i<len; i++)
	{
		if (buf[i] == '.')
		{
			buf[i] = '\0';
			glibc_ver_major = atoi(&buf[0]);
			glibc_ver_minor = atoi(&buf[i+1]);
			if (glibc_ver_major != 2)
			{
				CA_PRINT("This version of glibc %d.%d is not tested, please contact the owner\n",
						glibc_ver_major, glibc_ver_minor);
				return false;
			}
			return true;
		}
	}

	return false;
}

/*
 * Helper functions that depends on the glibc version
 *
 */
static size_t get_mstate_size(void)
{
	size_t mstate_size;
	if (glibc_ver_minor == 3)
		mstate_size = sizeof(struct malloc_state_GLIBC_2_3);
	else if (glibc_ver_minor == 4)
		mstate_size = sizeof(struct malloc_state_GLIBC_2_4);
	else if (glibc_ver_minor == 5)
		mstate_size = sizeof(struct malloc_state_GLIBC_2_5);
	else if (glibc_ver_minor >= 12 && glibc_ver_minor <= 21)
		mstate_size = sizeof(struct malloc_state_GLIBC_2_12);
	else if (glibc_ver_minor >= 22 && glibc_ver_minor <= 27)
		mstate_size = sizeof(struct malloc_state_GLIBC_2_22);
	else
		assert(0 && "internal error: glibc version not supported");

	return mstate_size;
}
