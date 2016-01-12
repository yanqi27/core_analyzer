/*
 * heap_darwin.h
 *  Mac OS X libc allocator data structure
 *
 *  Created on: July 8, 2013
 *      Author: myan
 */
#ifndef _MM_DARWIN_H
#define _MM_DARWIN_H

#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/boolean.h>
#include <mach/vm_types.h>

#include "heap.h"

#define CACHE_ALIGN __attribute__ ((aligned (128) )) /* Future-proofing at 128B */

#if !TARGET_OS_EMBEDDED
#define LARGE_CACHE			1
#else
#define LARGE_CACHE			0
#endif

#define vm_page_size			4096
#define vm_page_shift			12

typedef unsigned short msize_t;
typedef unsigned long  darwin_size_t;

typedef union {
    void	*p;
    uintptr_t	u;
} ptr_union;

typedef struct {
    ptr_union	previous;
    ptr_union	next;
} free_list_t;

typedef unsigned int grain_t; // N.B. wide enough to index all free slots

typedef int mag_index_t;

typedef unsigned char uint8_t;
typedef int pthread_lock_t;

typedef struct _malloc_zone_t {
    /* Only zone implementors should depend on the layout of this structure;
    Regular callers should use the access functions below */
    void	*reserved1;	/* RESERVED FOR CFAllocator DO NOT USE */
    void	*reserved2;	/* RESERVED FOR CFAllocator DO NOT USE */
    darwin_size_t 	(*size)(struct _malloc_zone_t *zone, const void *ptr); /* returns the size of a block or 0 if not in this zone; must be fast, especially for negative answers */
    void 	*(*malloc)(struct _malloc_zone_t *zone, darwin_size_t size);
    void 	*(*calloc)(struct _malloc_zone_t *zone, darwin_size_t num_items, darwin_size_t size); /* same as malloc, but block returned is set to zero */
    void 	*(*valloc)(struct _malloc_zone_t *zone, darwin_size_t size); /* same as malloc, but block returned is set to zero and is guaranteed to be page aligned */
    void 	(*free)(struct _malloc_zone_t *zone, void *ptr);
    void 	*(*realloc)(struct _malloc_zone_t *zone, void *ptr, darwin_size_t size);
    void 	(*destroy)(struct _malloc_zone_t *zone); /* zone is destroyed and all memory reclaimed */
    const char	*zone_name;

    /* Optional batch callbacks; these may be NULL */
    unsigned	(*batch_malloc)(struct _malloc_zone_t *zone, darwin_size_t size, void **results, unsigned num_requested); /* given a size, returns pointers capable of holding that size; returns the number of pointers allocated (maybe 0 or less than num_requested) */
    void	(*batch_free)(struct _malloc_zone_t *zone, void **to_be_freed, unsigned num_to_be_freed); /* frees all the pointers in to_be_freed; note that to_be_freed may be overwritten during the process */

    struct malloc_introspection_t	*introspect;
    unsigned	version;

    /* aligned memory allocation. The callback may be NULL. Present in version >= 5. */
    void *(*memalign)(struct _malloc_zone_t *zone, darwin_size_t alignment, darwin_size_t size);

    /* free a pointer known to be in zone and known to have the given size. The callback may be NULL. Present in version >= 6.*/
    void (*free_definite_size)(struct _malloc_zone_t *zone, void *ptr, darwin_size_t size);

    /* Empty out caches in the face of memory pressure. The callback may be NULL. Present in version >= 8. */
    darwin_size_t 	(*pressure_relief)(struct _malloc_zone_t *zone, darwin_size_t goal);
} malloc_zone_t;

typedef void * region_t;

#define HASHRING_REGION_DEALLOCATED	((region_t)-1) // Region at this slot reclaimed by OS

typedef struct region_hash_generation {
    darwin_size_t		num_regions_allocated;
    darwin_size_t		num_regions_allocated_shift; // log2(num_regions_allocated)
    region_t		*hashed_regions;  // hashed by location
    struct		region_hash_generation *nextgen;
} region_hash_generation_t;

typedef struct region_trailer
{
    struct region_trailer	*prev;
    struct region_trailer	*next;
    boolean_t			recirc_suitable;
    boolean_t			failedREUSE;
    volatile int		pinned_to_depot;
    unsigned			bytes_used;
    mag_index_t			mag_index;
} region_trailer_t;

/*
 * tiny
 */
#define SHIFT_TINY_QUANTUM		4	// Required for AltiVec
#define	TINY_QUANTUM			(1 << SHIFT_TINY_QUANTUM)

#define FOLLOWING_TINY_PTR(ptr,msize)	(((unsigned char *)(ptr)) + ((msize) << SHIFT_TINY_QUANTUM))

#ifdef __LP64__
#define NUM_TINY_SLOTS			64	// number of slots for free-lists
#else
#define NUM_TINY_SLOTS			32	// number of slots for free-lists
#endif

#define NUM_TINY_BLOCKS			64520
#define SHIFT_TINY_CEIL_BLOCKS	16 // ceil(log2(NUM_TINY_BLOCKS))
#define NUM_TINY_CEIL_BLOCKS	(1 << SHIFT_TINY_CEIL_BLOCKS)
#define TINY_BLOCKS_ALIGN		(SHIFT_TINY_CEIL_BLOCKS + SHIFT_TINY_QUANTUM) // 20

#define CEIL_NUM_TINY_BLOCKS_WORDS	(((NUM_TINY_BLOCKS + 31) & ~31) >> 5)

typedef uint32_t tiny_block_t[4];

#define TINY_METADATA_SIZE		(sizeof(region_trailer_t) + sizeof(tiny_header_inuse_pair_t) * CEIL_NUM_TINY_BLOCKS_WORDS)
#define TINY_REGION_SIZE							\
    ((NUM_TINY_BLOCKS * TINY_QUANTUM + TINY_METADATA_SIZE + vm_page_size - 1) & ~ (vm_page_size - 1))
#define TINY_METADATA_START		(NUM_TINY_BLOCKS * TINY_QUANTUM)

/*
 * Beginning and end pointers for a region's heap.
 */
#define TINY_REGION_ADDRESS(region)	((void *)(region))
#define TINY_REGION_END(region)		((void *)(((uintptr_t)(region)) + (NUM_TINY_BLOCKS * TINY_QUANTUM)))

/*
 * Locate the heap base for a pointer known to be within a tiny region.
 */
#define TINY_REGION_FOR_PTR(_p)		((tiny_region_t)((uintptr_t)(_p) & ~((1 << TINY_BLOCKS_ALIGN) - 1)))

/*
 * Convert between byte and msize units.
 */
#define TINY_BYTES_FOR_MSIZE(_m)	((_m) << SHIFT_TINY_QUANTUM)
#define TINY_MSIZE_FOR_BYTES(_b)	((_b) >> SHIFT_TINY_QUANTUM)

/*#ifdef __LP64__
# define TINY_FREE_SIZE(ptr)		(((msize_t *)(ptr))[8])
#else
# define TINY_FREE_SIZE(ptr)		(((msize_t *)(ptr))[4])
#endif
#define TINY_PREVIOUS_MSIZE(ptr)	((msize_t *)(ptr))[-1]*/


typedef struct tiny_header_inuse_pair
{
    uint32_t	header;
    uint32_t	inuse;
} tiny_header_inuse_pair_t;

/*
 * Layout of a tiny region
 */
typedef struct tiny_region
{
    tiny_block_t blocks[NUM_TINY_BLOCKS];

    region_trailer_t trailer;

    // The interleaved bit arrays comprising the header and inuse bitfields.
    // The unused bits of each component in the last pair will be initialized to sentinel values.
    tiny_header_inuse_pair_t pairs[CEIL_NUM_TINY_BLOCKS_WORDS];

    uint8_t pad[TINY_REGION_SIZE - (NUM_TINY_BLOCKS * sizeof(tiny_block_t)) - TINY_METADATA_SIZE];
} *tiny_region_t;

/*
 * Locate the block header for a pointer known to be within a tiny region.
 */
#define TINY_BLOCK_HEADER_FOR_PTR(_p)	((void *)&(((tiny_region_t)TINY_REGION_FOR_PTR(_p))->pairs))

/*
 * Locate the inuse map for a given block header pointer.
 */
#define TINY_INUSE_FOR_HEADER(_h)	((void *)&(((tiny_header_inuse_pair_t *)(_h))->inuse))

/*
 * Compute the bitmap index for a pointer known to be within a tiny region.
 */
#define TINY_INDEX_FOR_PTR(_p) 		(((uintptr_t)(_p) >> SHIFT_TINY_QUANTUM) & (NUM_TINY_CEIL_BLOCKS - 1))

typedef struct {			// vm_allocate()'d, so the array of magazines is page-aligned to begin with.
    // Take magazine_lock first,  Depot lock when needed for recirc, then szone->{tiny,small}_regions_lock when needed for alloc
    pthread_lock_t	magazine_lock; //CACHE_ALIGN;
    // Protection for the crtical section that does allocate_pages outside the magazine_lock
    volatile boolean_t	alloc_underway;

    // One element deep "death row", optimizes malloc/free/malloc for identical size.
    void		*mag_last_free; // low SHIFT_{TINY,SMALL}_QUANTUM bits indicate the msize
    region_t		mag_last_free_rgn; // holds the region for mag_last_free

    free_list_t		*mag_free_list[256]; // assert( 256 >= MAX( NUM_TINY_SLOTS, NUM_SMALL_SLOTS_LARGEMEM ))
    unsigned		mag_bitmap[8]; // assert( sizeof(mag_bitmap) << 3 >= sizeof(mag_free_list)/sizeof(free_list_t) )

    // the first and last free region in the last block are treated as big blocks in use that are not accounted for
    darwin_size_t		mag_bytes_free_at_end;
    darwin_size_t		mag_bytes_free_at_start;
    region_t		mag_last_region; // Valid iff mag_bytes_free_at_end || mag_bytes_free_at_start > 0

    // bean counting ...
    unsigned		mag_num_objects;
    darwin_size_t		mag_num_bytes_in_objects;
    darwin_size_t		num_bytes_in_magazine;

    // recirculation list -- invariant: all regions owned by this magazine that meet the emptiness criteria
    // are located nearer to the head of the list than any region that doesn't satisfy that criteria.
    // Doubly linked list for efficient extraction.
    unsigned		recirculation_entries;
    region_trailer_t	*firstNode;
    region_trailer_t	*lastNode;

#if __LP64__
    uint64_t		pad[48]; // So sizeof(magazine_t) is 2560 bytes. FIXME: assert this at compile time
#else
    uint32_t		pad[12]; // So sizeof(magazine_t) is 1280 bytes. FIXME: assert this at compile time
#endif
} magazine_t;

#if defined(__LP64__)
#define LARGE_ENTRY_CACHE_SIZE 16
#define LARGE_CACHE_SIZE_LIMIT ((vm_size_t)0x80000000) /* 2Gb */
#else
#error "Not supported yet"
#define LARGE_ENTRY_CACHE_SIZE 8
#define LARGE_CACHE_SIZE_LIMIT ((vm_size_t)0x02000000) /* 32Mb */
#endif

typedef struct {
    vm_address_t address;
    vm_size_t size;
    boolean_t did_madvise_reusable;
} large_entry_t;

#define INITIAL_NUM_REGIONS_SHIFT	6
#define INITIAL_NUM_REGIONS		(1 << INITIAL_NUM_REGIONS_SHIFT)

/*
 * small
 */
#define SMALL_IS_FREE			(1 << 15)

#define	SHIFT_SMALL_QUANTUM		(SHIFT_TINY_QUANTUM + 5)	// 9
#define	SMALL_QUANTUM			(1 << SHIFT_SMALL_QUANTUM)	// 512 bytes

#define FOLLOWING_SMALL_PTR(ptr,msize)	(((unsigned char *)(ptr)) + ((msize) << SHIFT_SMALL_QUANTUM))

/*
 * The number of slots in the free-list for small blocks.  To avoid going to
 * vm system as often on large memory machines, increase the number of free list
 * spots above some amount of RAM installed in the system.
 */
#define NUM_SMALL_SLOTS			32
#define NUM_SMALL_SLOTS_LARGEMEM	256
#define SMALL_BITMAP_WORDS		8

/*
 * We can only represent up to 1<<15 for msize; but we choose to stay even below that to avoid the
 * convention msize=0 => msize = (1<<15)
 */
#define NUM_SMALL_BLOCKS		16320
#define SHIFT_SMALL_CEIL_BLOCKS		14 // ceil(log2(NUM_SMALL_BLOCKs))
#define NUM_SMALL_CEIL_BLOCKS		(1 << SHIFT_SMALL_CEIL_BLOCKS)
#define SMALL_BLOCKS_ALIGN		(SHIFT_SMALL_CEIL_BLOCKS + SHIFT_SMALL_QUANTUM) // 23

#define SMALL_ENTROPY_BITS		13
#define SMALL_ENTROPY_MASK		((1 << SMALL_ENTROPY_BITS) - 1)

#define SMALL_METADATA_SIZE		(sizeof(region_trailer_t) + NUM_SMALL_BLOCKS * sizeof(msize_t))
#define SMALL_REGION_SIZE						\
    ((NUM_SMALL_BLOCKS * SMALL_QUANTUM + SMALL_METADATA_SIZE + vm_page_size - 1) & ~ (vm_page_size - 1))

#define SMALL_METADATA_START		(NUM_SMALL_BLOCKS * SMALL_QUANTUM)

/*
 * Beginning and end pointers for a region's heap.
 */
#define SMALL_REGION_ADDRESS(region)	((unsigned char *)region)
#define SMALL_REGION_END(region)	(SMALL_REGION_ADDRESS(region) + (NUM_SMALL_BLOCKS * SMALL_QUANTUM))

/*
 * Locate the heap base for a pointer known to be within a small region.
 */
#define SMALL_REGION_FOR_PTR(_p)	((void *)((uintptr_t)(_p) & ~((1 << SMALL_BLOCKS_ALIGN) - 1)))

/*
 * Convert between byte and msize units.
 */
#define SMALL_BYTES_FOR_MSIZE(_m)	((_m) << SHIFT_SMALL_QUANTUM)
#define SMALL_MSIZE_FOR_BYTES(_b)	((_b) >> SHIFT_SMALL_QUANTUM)

//#define SMALL_PREVIOUS_MSIZE(ptr)	((msize_t *)(ptr))[-1]

/*
 * Layout of a small region
 */
typedef uint32_t small_block_t[SMALL_QUANTUM/sizeof(uint32_t)];

typedef struct small_region
{
    small_block_t blocks[NUM_SMALL_BLOCKS];

    region_trailer_t trailer;

    msize_t small_meta_words[NUM_SMALL_BLOCKS];

    uint8_t pad[SMALL_REGION_SIZE - (NUM_SMALL_BLOCKS * sizeof(small_block_t)) - SMALL_METADATA_SIZE];
} *small_region_t;

/*
 * Per-region meta data for small allocator
 */
#define REGION_TRAILER_FOR_SMALL_REGION(r)	(&(((small_region_t)(r))->trailer))
//#define MAGAZINE_INDEX_FOR_SMALL_REGION(r)	(REGION_TRAILER_FOR_SMALL_REGION(r)->mag_index)
//#define BYTES_USED_FOR_SMALL_REGION(r)		(REGION_TRAILER_FOR_SMALL_REGION(r)->bytes_used)

/*
 * Locate the metadata base for a pointer known to be within a small region.
 */
//#define SMALL_META_HEADER_FOR_PTR(_p)	(((small_region_t)SMALL_REGION_FOR_PTR(_p))->small_meta_words)

/*
 * Compute the metadata index for a pointer known to be within a small region.
 */
#define SMALL_META_INDEX_FOR_PTR(_p)	(((uintptr_t)(_p) >> SHIFT_SMALL_QUANTUM) & (NUM_SMALL_CEIL_BLOCKS - 1))

/*
 * Find the metadata word for a pointer known to be within a small region.
 */
#define SMALL_METADATA_FOR_PTR(_p)	(SMALL_META_HEADER_FOR_PTR(_p) + SMALL_META_INDEX_FOR_PTR(_p))

/*
 * Determine whether a pointer known to be within a small region points to memory which is free.
 */
#define SMALL_PTR_IS_FREE(_p)		(*SMALL_METADATA_FOR_PTR(_p) & SMALL_IS_FREE)

/*
 * Extract the msize value for a pointer known to be within a small region.
 */
#define SMALL_PTR_SIZE(_p)		(*SMALL_METADATA_FOR_PTR(_p) & ~SMALL_IS_FREE)

/*********************************************************************
** struct szone_t is the topmost heap data
*********************************************************************/
typedef struct szone_s {				// vm_allocate()'d, so page-aligned to begin with.
    malloc_zone_t		basic_zone;		// first page will be given read-only protection
    uint8_t			pad[vm_page_size - sizeof(malloc_zone_t)];

    pthread_key_t		cpu_id_key;		// remainder of structure is R/W (contains no function pointers)
    unsigned			debug_flags;
    void			*log_address;

    /* Regions for tiny objects */
    pthread_lock_t		tiny_regions_lock CACHE_ALIGN;
    darwin_size_t			num_tiny_regions;
    darwin_size_t			num_tiny_regions_dealloc;
    region_hash_generation_t	*tiny_region_generation;
    region_hash_generation_t	trg[2];

    int				num_tiny_magazines;
    unsigned			num_tiny_magazines_mask;
    int				num_tiny_magazines_mask_shift;
    magazine_t			*tiny_magazines; // array of per-processor magazines

#if TARGET_OS_EMBEDDED
    uintptr_t			last_tiny_advise;
#endif

    /* Regions for small objects */
    pthread_lock_t		small_regions_lock CACHE_ALIGN;
    darwin_size_t			num_small_regions;
    darwin_size_t			num_small_regions_dealloc;
    region_hash_generation_t	*small_region_generation;
    region_hash_generation_t	srg[2];

    unsigned			num_small_slots; // determined by physmem size

    int				num_small_magazines;
    unsigned			num_small_magazines_mask;
    int				num_small_magazines_mask_shift;
    magazine_t			*small_magazines; // array of per-processor magazines

#if TARGET_OS_EMBEDDED
    uintptr_t			last_small_advise;
#endif

    /* large objects: all the rest */
    pthread_lock_t		large_szone_lock CACHE_ALIGN; // One customer at a time for large
    unsigned			num_large_objects_in_use;
    unsigned			num_large_entries;
    large_entry_t		*large_entries; // hashed by location; null entries don't count
    darwin_size_t			num_bytes_in_large_objects;

#if LARGE_CACHE
    int				large_entry_cache_oldest;
    int				large_entry_cache_newest;
    large_entry_t		large_entry_cache[LARGE_ENTRY_CACHE_SIZE]; // "death row" for large malloc/free
    boolean_t			large_legacy_reset_mprotect;
    darwin_size_t			large_entry_cache_reserve_bytes;
    darwin_size_t			large_entry_cache_reserve_limit;
    darwin_size_t			large_entry_cache_bytes; // total size of death row, bytes
#endif

    /* flag and limits pertaining to altered malloc behavior for systems with
       large amounts of physical memory */
    unsigned  is_largemem;
    unsigned  large_threshold;
    unsigned  vm_copy_threshold;

    /* security cookie */
    uintptr_t cookie;

    /* Initial region list */
    region_t			initial_tiny_regions[INITIAL_NUM_REGIONS];
    region_t			initial_small_regions[INITIAL_NUM_REGIONS];

	/* The purgeable zone constructed by create_purgeable_zone() would like to hand off tiny and small
	 * allocations to the default scalable zone. Record the latter as the "helper" zone here. */
    struct szone_s		*helper_zone;

    boolean_t			flotsam_enabled;
} szone_t;

#endif /* _MM_DARWIN_H */
