/*
 * heap_darwin.c
 *
 *  Created on: July 8, 2013
 *      Author: myan
 */
#include "heap_darwin.h"
#include "segment.h"

/***************************************************************************
 * Implementation specific data structures
 ***************************************************************************/
enum REGION_TYPE {
	ENUM_TINY_REGION, ENUM_SMALL_REGION, ENUM_LARGE_REGION
};

#define BLOCK_INUSE ((address_t)0x1)
#define BLOCK_MASK  (~BLOCK_INUSE)
#define block_inuse(addr) ((addr) & BLOCK_INUSE)
#define block_addr(addr)  ((addr) & BLOCK_MASK)
#define set_inuse(addr)   ((addr) | BLOCK_INUSE)

struct ca_region {
	unsigned int zone_index;
	enum REGION_TYPE type;
	address_t start;
	address_t end;
	address_t* blocks; // array of starting addresses of all blocks in the region
	unsigned int num_blocks; // array size
	unsigned int corrupt :1; // find invalid heap data of the region
	unsigned int reserved :31;
};

struct ca_zones {
	szone_t* malloc_zones; // array of struct szone_t
	unsigned int malloc_num_zone;
	struct ca_region* regions;
	unsigned int num_regions;
	unsigned int region_capacity;
};

struct ca_region_stats {
	unsigned int num_inuse;
	unsigned int num_free;
	size_t       inuse_bytes;
	size_t       free_bytes;
};

/***************************************************************************
 * Globals
 ***************************************************************************/
static bool g_heap_initialized = false;
static struct ca_zones g_ca_zones;

/***************************************************************************
 * Forward declaration
 ***************************************************************************/
static bool szone_walk(szone_t*, bool, struct ca_region_stats*);
static bool build_szones(void);
static struct ca_region* search_sorted_regions(address_t);
static bool find_block_in_region(struct ca_region*, address_t,
		struct heap_block*);
static void add_one_big_block(struct heap_block*, unsigned int,
		struct heap_block*);
static void build_region_blocks(struct ca_region* regionp);
static bool tiny_region_walk(szone_t*, region_t, bool, struct ca_region_stats*);
static bool small_region_walk(szone_t*, region_t, bool, struct ca_region_stats*);
static msize_t get_tiny_meta_header(const void *, boolean_t *, tiny_header_inuse_pair_t*);
static void check_sorted_region_blocks(struct ca_region*);

/***************************************************************************
 * Exposed functions
 ***************************************************************************/
bool init_heap(void)
{
	bool rc = build_szones();
	return rc;
}

bool heap_walk(address_t addr, bool verbose)
{
	bool rc = true;
	unsigned int zone_index;
	struct ca_region_stats stats = {0, 0, 0, 0};

	if (!g_heap_initialized)
		return false;

	if (addr)
	{
		struct ca_region* regionp = search_sorted_regions(addr);
		if (regionp)
		{
			szone_t* szonep = &g_ca_zones.malloc_zones[regionp->zone_index];
			region_t region;
			if (regionp->type == ENUM_TINY_REGION)
			{
				region = TINY_REGION_FOR_PTR(regionp->start);
				tiny_region_walk(szonep, region, true, &stats);
			}
			else if (regionp->type == ENUM_SMALL_REGION)
			{
				region = SMALL_REGION_FOR_PTR(regionp->start);
				small_region_walk(szonep, region, true, &stats);
			}
			else if (regionp->type == ENUM_LARGE_REGION)
			{
				int inuse = block_inuse(regionp->start);
				address_t addr = block_addr(regionp->start);
				size_t size = regionp->end - addr;
				if (inuse)
					CA_PRINT("\t\tlarge block "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=%ld in-use\n",
							addr, addr + size, size);
				else
					CA_PRINT("\tlarge block "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=%ld cached\n",
							addr, addr + size, size);
			}
			if (regionp->type == ENUM_TINY_REGION || regionp->type == ENUM_SMALL_REGION)
			{
				CA_PRINT("\tTotal %d in-use blocks of %ld bytes\n", stats.num_inuse, stats.inuse_bytes);
				CA_PRINT("\tTotal %d free blocks of %ld bytes\n", stats.num_free, stats.free_bytes);
			}
		}
		else
			rc = false;
	}
	else
	{
		if (verbose)
			init_mem_histogram(16);
		// walk each zone
		for (zone_index = 0; zone_index < g_ca_zones.malloc_num_zone; zone_index++)
		{
			szone_t* szonep = g_ca_zones.malloc_zones + zone_index;
			char zone_name[32];
			if (szonep->basic_zone.zone_name
				&& read_memory_wrapper(NULL, (address_t) szonep->basic_zone.zone_name, zone_name, sizeof(zone_name)))
				zone_name[31] = '\0'; // in case the name is long
			else
				zone_name[0] = '\0';
			CA_PRINT("zone[%d] name={%s}\n", zone_index, zone_name);
			if (!szone_walk(szonep, false, &stats))
				rc = false;
		}
		CA_PRINT("Total Heap Memory ");
		print_size(stats.inuse_bytes + stats.free_bytes);
		CA_PRINT(" = In-use %d(", stats.num_inuse);
		print_size(stats.inuse_bytes);
		CA_PRINT(") + Free %d(", stats.num_free);
		print_size(stats.free_bytes);
		CA_PRINT(")\n");

		if (verbose)
		{
			CA_PRINT("\n");
			display_mem_histogram("");
			release_mem_histogram();
		}
	}

	return rc;
}

/* Return true if the block belongs to a heap */
bool is_heap_block(address_t addr)
{
	struct ca_region* regionp;

	if (!g_heap_initialized)
		return false;

	regionp = search_sorted_regions(addr);
	if (regionp)
		return true;
	else
		return false;
}

/*
 * Return true and detail info if the input addr belongs to a heap memory block
 */
bool get_heap_block_info(address_t addr, struct heap_block* blk)
{
	struct ca_region* regionp;

	if (!g_heap_initialized)
		return false;

	regionp = search_sorted_regions(addr);
	if (regionp)
		return find_block_in_region(regionp, addr, blk);
	else
		return false;
}

/*
 * Return true and detail info of the heap block after the input addr
 */
bool get_next_heap_block(address_t addr, struct heap_block* blk)
{
	struct ca_region* regionp = NULL;
	address_t next_addr = 0;

	if (!g_heap_initialized)
		return false;

	if (addr)
	{
		// If an address is given, it must belong to a heap block
		// otherwise, there is no sense of its next
		regionp = search_sorted_regions(addr);
		if (regionp && find_block_in_region(regionp, addr, blk))
		{
			next_addr = blk->addr + blk->size;
			if (next_addr >= regionp->end)
			{
				// the given address is the last block of the region
				// move to the next region if any
				unsigned int index;
				for (index = 0; index < g_ca_zones.num_regions; index++)
				{
					if (&g_ca_zones.regions[index] == regionp)
						break;
				}
				if (index + 1 < g_ca_zones.num_regions)
				{
					regionp = &g_ca_zones.regions[index + 1];
					next_addr = block_addr(regionp->start);
				}
				else
				{
					regionp = NULL;
					next_addr = 0;
				}
			}
		}
	}
	else
	{
		if (g_ca_zones.num_regions > 0)
		{
			regionp = &g_ca_zones.regions[0];
			next_addr = block_addr(regionp->start);
		}
	}

	// Hopefully we have locate the next heap block's address by now
	if (regionp && next_addr && find_block_in_region(regionp, next_addr, blk)
			&& blk->addr > addr)
		return true;
	else
		return false;
}

bool get_biggest_blocks(struct heap_block* blks, unsigned int num)
{
	unsigned int i;
	struct heap_block* smallest = &blks[num - 1];
	struct ca_region* regionp;
	struct heap_block blk;

	if (!g_heap_initialized)
		return false;

	// large region/block should be bigger than any other block in tiny/small regions
	for (i = 0; i < g_ca_zones.num_regions; i++)
	{
		regionp = &g_ca_zones.regions[i];
		if (regionp->type == ENUM_LARGE_REGION && block_inuse(regionp->start))
		{
			blk.size = regionp->end - block_addr(regionp->start);
			if (blk.size > smallest->size)
			{
				blk.addr = block_addr(regionp->start);
				blk.inuse = true;
				add_one_big_block(blks, num, &blk);
			}
		}
	}
	if (smallest->size > 0)
		return true;

	// if user requests more big blocks than in-used large region, walk through tiny/small regions
	for (i = 0; i < g_ca_zones.num_regions; i++)
	{
		regionp = &g_ca_zones.regions[i];
		if (regionp->type != ENUM_LARGE_REGION)
		{
			unsigned int k;
			// Prepare an array of all blocks
			if (regionp->blocks == NULL)
				build_region_blocks(regionp);
			// Now check each block's size
			for (k = 0; k < regionp->num_blocks; k++)
			{
				if (block_inuse(regionp->blocks[k]))
				{
					blk.size = block_addr(regionp->blocks[k+1])	- block_addr(regionp->blocks[k]);
					if (blk.size > smallest->size)
					{
						blk.addr = block_addr(regionp->blocks[k]);
						blk.inuse = true;
						add_one_big_block(blks, num, &blk);
					}
				}
			}
		}
	}

	return true;
}

bool walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount)
{
	unsigned int i;
	struct inuse_block* pBlockinfo = opBlocks;
	*opCount = 0;

	if (!g_heap_initialized)
		return false;

	for (i = 0; i < g_ca_zones.num_regions; i++)
	{
		struct ca_region* regionp = &g_ca_zones.regions[i];
		if (regionp->type == ENUM_TINY_REGION || regionp->type == ENUM_SMALL_REGION)
		{
			unsigned int blk_index;
			// Prepare an array of all blocks
			if (regionp->blocks == NULL)
				build_region_blocks(regionp);
			// Now check each block's size
			for (blk_index = 0; blk_index < regionp->num_blocks; blk_index++)
			{
				if (block_inuse(regionp->blocks[blk_index]))
				{
					(*opCount)++;
					if (pBlockinfo)
					{
						pBlockinfo->addr = block_addr(regionp->blocks[blk_index]);
						pBlockinfo->size = block_addr(regionp->blocks[blk_index+1])	- block_addr(regionp->blocks[blk_index]);
						pBlockinfo++;
					}
				}
			}
		}
		else if (regionp->type == ENUM_LARGE_REGION)
		{
			if (block_inuse(regionp->start))
			{
				(*opCount)++;
				if (pBlockinfo)
				{
					pBlockinfo->addr = block_addr(regionp->start);
					pBlockinfo->size = regionp->end - block_addr(regionp->start);
					pBlockinfo++;
				}
			}
		}
		else
		{
			CA_PRINT("Internal error: unknown region type %d\n", regionp->type);
			continue;
		}
	}
	return true;
}

/*
bool walk_inuse_blocks_old(struct inuse_block* opBlocks, unsigned long* opCount)
{
	unsigned int zone_index;
	struct inuse_block* pBlockinfo = opBlocks;
	*opCount = 0;

	if (!g_heap_initialized)
		return false;

	// walk each zone
	for (zone_index = 0; zone_index < g_ca_zones.malloc_num_zone; zone_index++)
	{
		szone_t* szonep = g_ca_zones.malloc_zones + zone_index;
		region_hash_generation_t region_hash_gen;
		darwin_size_t num_regions, index;
		region_t* regions;
		region_t region;

		// tiny regions
		if (read_memory_wrapper(NULL, (address_t) szonep->tiny_region_generation,
				&region_hash_gen, sizeof(region_hash_gen)))
		{
			num_regions = region_hash_gen.num_regions_allocated;
			if (num_regions > 0)
			{
				regions = (region_t*) malloc(sizeof(region_t) * num_regions);
				if (read_memory_wrapper(NULL, (address_t) region_hash_gen.hashed_regions, &regions[0],
						sizeof(region_t) * num_regions))
				{
					for (index = 0; index < num_regions; index++)
					{
						region = regions[index];
						if (region && region != HASHRING_REGION_DEALLOCATED)
						{
							address_t start, region_end, ptr;
							boolean_t is_free, prev_free = 0;
							msize_t msize;
							mag_index_t mag_index;
							magazine_t tiny_mag;
							address_t mag_addr;
							tiny_header_inuse_pair_t pairs[CEIL_NUM_TINY_BLOCKS_WORDS];

							// read meta-data of this tiny region
							if (!read_memory_wrapper(NULL, (address_t) &((tiny_region_t) region)->pairs, &pairs[0], sizeof(pairs)))
								break;
							else if (!read_memory_wrapper(NULL,	(address_t) &(((tiny_region_t) region)->trailer).mag_index,
									&mag_index, sizeof(mag_index)))		// MAGAZINE_INDEX_FOR_TINY_REGION(region);
								break;
							else if (mag_index > szonep->num_tiny_magazines - 1)
								break;
							// read magzine_t of the region
							// &(szone->tiny_magazines[mag_index]);
							mag_addr = (address_t) szonep->tiny_magazines + sizeof(magazine_t) * mag_index;
							if (!read_memory_wrapper(NULL, mag_addr, &tiny_mag, sizeof(magazine_t)))
								break;

							// establish region limits
							ptr = start = (address_t) TINY_REGION_ADDRESS(region);
							if (region == tiny_mag.mag_last_region)
							{
								ptr += tiny_mag.mag_bytes_free_at_start;
								// Check the leading block's integrity here also.
								if (tiny_mag.mag_bytes_free_at_start)
								{
									msize = get_tiny_meta_header((void *) (ptr - TINY_QUANTUM),	&is_free, pairs);
									if (is_free || (msize != 1))
										break;
								}
							}
							region_end = (address_t) TINY_REGION_END(region);
							// The last region may have a trailing chunk which has not been converted into inuse/freelist
							// blocks yet.
							if (region == tiny_mag.mag_last_region)
								region_end -= tiny_mag.mag_bytes_free_at_end;

							// Scan blocks within the region.
							while (ptr < region_end)
							{
								// If the first block is free, and its size is 65536 (msize = 0) then the entire region is free
								msize = get_tiny_meta_header((void *) ptr, &is_free, pairs);
								if (is_free && !msize && (ptr == start))
									break;
								// If the block's size is 65536 (msize = 0) then since we're not the first entry the size is corrupt
								if (!msize)
									break;
								if (!is_free)
								{
									// In use blocks cannot be more than (NUM_TINY_SLOTS - 1) quanta large.
									prev_free = 0;
									if (msize > (NUM_TINY_SLOTS - 1))
										break;
									(*opCount)++;
									if (pBlockinfo)
									{
										pBlockinfo->addr = ptr;
										pBlockinfo->size = TINY_BYTES_FOR_MSIZE(msize);
										pBlockinfo->ref_count = 0;
										pBlockinfo++;
									}
									// move to next block
									ptr += TINY_BYTES_FOR_MSIZE(msize);
								}
								else
								{
									// Free blocks must have been coalesced, we cannot have a free block following another free block.
									if (prev_free)
										break;
									prev_free = 1;
									// move to next block
									ptr = (uintptr_t) FOLLOWING_TINY_PTR(ptr, msize);
								}
							}
						}
					}
				}
				free(regions);
				regions = NULL;
			}
		}

		// small regions
		if (read_memory_wrapper(NULL, (address_t) szonep->small_region_generation,
				&region_hash_gen, sizeof(region_hash_gen)))
		{
			num_regions = region_hash_gen.num_regions_allocated;
			if (num_regions > 0)
			{
				regions = (region_t*) malloc(sizeof(region_t) * num_regions);
				if (read_memory_wrapper(NULL, (address_t) region_hash_gen.hashed_regions, &regions[0],
						sizeof(region_t) * num_regions))
				{
					for (index = 0; index < num_regions; index++)
					{
						region = regions[index];
						if (region && region != HASHRING_REGION_DEALLOCATED)
						{
							address_t ptr = (address_t) SMALL_REGION_ADDRESS(region);
							msize_t meta_headers[NUM_SMALL_BLOCKS]; // SMALL_META_HEADER_FOR_PTR(ptr);
							address_t region_end = (address_t) SMALL_REGION_END(region);
							msize_t prev_free = 0;
							mag_index_t mag_index; //MAGAZINE_INDEX_FOR_SMALL_REGION(SMALL_REGION_FOR_PTR(ptr));
							magazine_t small_mag; // &(szone->small_magazines[mag_index]);
							address_t mag_addr;

							if (!read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->small_meta_words),
									&meta_headers[0], sizeof(meta_headers)))
								break;
							if (!read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->trailer).mag_index,
									&mag_index, sizeof(mag_index)))
								break;
							// read magzine_t of this region
							mag_addr = (address_t) szonep->small_magazines + sizeof(magazine_t) * mag_index;
							if (!read_memory_wrapper(NULL, mag_addr, &small_mag, sizeof(magazine_t)))
								break;

							// establish region limits
							if (region == small_mag.mag_last_region)
							{
								ptr += small_mag.mag_bytes_free_at_start;
								region_end -= small_mag.mag_bytes_free_at_end;
							}

							// Scan blocks within the region.
							while (ptr < region_end)
							{
								unsigned small_index = SMALL_META_INDEX_FOR_PTR(ptr);
								msize_t msize_and_free = meta_headers[small_index];
								msize_t msize;
								if (!(msize_and_free & SMALL_IS_FREE))
								{
									// block is in use
									msize = msize_and_free;
									if (!msize)
										break;
									if (SMALL_BYTES_FOR_MSIZE(msize) > szonep->large_threshold)
										break;
									(*opCount)++;
									if (pBlockinfo)
									{
										pBlockinfo->addr = ptr;
										pBlockinfo->size = SMALL_BYTES_FOR_MSIZE(msize);
										pBlockinfo->ref_count = 0;
										pBlockinfo++;
									}
									// move to next block
									ptr += SMALL_BYTES_FOR_MSIZE(msize);
									prev_free = 0;
								}
								else
								{
									// free pointer
									msize = msize_and_free & ~SMALL_IS_FREE;
									if (!msize || prev_free)
										break;
									// move to next block
									ptr = (address_t) FOLLOWING_SMALL_PTR(ptr, msize);
									prev_free = SMALL_IS_FREE;
								}
							}
						}
					}
				}
				free(regions);
				regions = NULL;
			}
		}

		// large
		if (szonep->num_large_objects_in_use)
		{
			// large in-use blocks are stashed in hash table
			for (index = 0; index < szonep->num_large_entries; index++)
			{
				large_entry_t entry;
				if (read_memory_wrapper(NULL, (address_t) (szonep->large_entries + index), &entry, sizeof(entry))
					&& entry.address)
				{
					(*opCount)++;
					if (pBlockinfo)
					{
						pBlockinfo->addr = entry.address;
						pBlockinfo->size = entry.size;
						pBlockinfo->ref_count = 0;
						pBlockinfo++;
					}
				}
			}
		}
	}

	return true;
}
*/

/***************************************************************************
 * Helper functions
 ***************************************************************************/
#ifndef INLINE
#define INLINE inline
#endif

static INLINE boolean_t BITARRAY_BIT(uint32_t *bits, msize_t index)
{
	return ((bits[(index >> 5) << 1]) >> (index & 31)) & 1;
}

static INLINE msize_t TINY_FREE_SIZE(const void *ptr)
{
	msize_t sz = -1;
#ifdef __LP64__
	read_memory_wrapper(NULL, (address_t) ((msize_t *)ptr + 8), &sz, sizeof(sz));
#else
	read_memory_wrapper(NULL, (address_t) ((msize_t *) ptr + 4), &sz,
			sizeof(sz));
#endif
	return sz;
}

static INLINE msize_t TINY_PREVIOUS_MSIZE(const void *ptr)
{
	msize_t sz = 0;
	read_memory_wrapper(NULL, (address_t) ptr - sizeof(msize_t), &sz,
			sizeof(sz));
	return sz;
}

/*
 * Obtain the size of a free tiny block (in msize_t units).
 */
static msize_t get_tiny_free_size(const void *ptr, uint32_t* block_header)
{
	void *next_block = (void *) ((uintptr_t) ptr + TINY_QUANTUM);
	void *region_end = TINY_REGION_END(TINY_REGION_FOR_PTR(ptr));

	// check whether the next block is outside the tiny region or a block header
	// if so, then the size of this block is one, and there is no stored size.
	if (next_block < region_end)
	{
		uint32_t *next_header = block_header; //TINY_BLOCK_HEADER_FOR_PTR(next_block);
		msize_t next_index = TINY_INDEX_FOR_PTR(next_block);

		if (!BITARRAY_BIT(next_header, next_index))
			return TINY_FREE_SIZE(ptr);
	}
	return 1;
}

static msize_t get_tiny_meta_header(const void *ptr, boolean_t *is_free, tiny_header_inuse_pair_t* pairs)
{
	// returns msize and is_free
	// may return 0 for the msize component (meaning 65536)
	uint32_t* block_header;
	msize_t index;

	block_header = (uint32_t*) TINY_BLOCK_HEADER_FOR_PTR(ptr);
	index = TINY_INDEX_FOR_PTR(ptr);

	msize_t midx = (index >> 5) << 1;
	uint32_t mask = 1 << (index & 31);

	// Now block header points to local copy
	block_header = (uint32_t*) &pairs[0];

	*is_free = 0;
	if (0 == (block_header[midx] & mask)) // if (!BITARRAY_BIT(block_header, index))
		return 0;
	if (0 == (block_header[midx + 1] & mask))// if (!BITARRAY_BIT(in_use, index))
	{
		*is_free = 1;
		return get_tiny_free_size(ptr, block_header);
	}

	// index >> 5 identifies the uint32_t to manipulate in the conceptually contiguous bits array
	// (index >> 5) << 1 identifies the uint32_t allowing for the actual interleaving
#if defined(__LP64__)
	// The return value, msize, is computed as the distance to the next 1 bit in block_header.
	// That's guaranteed to be somewhwere in the next 64 bits. And those bits could span three
	// uint32_t block_header elements. Collect the bits into a single uint64_t and measure up with ffsl.
	uint32_t *addr = ((uint32_t *)block_header) + ((index >> 5) << 1);
	uint32_t bitidx = index & 31;
	uint64_t word_lo = addr[0];
	uint64_t word_mid = addr[2];
	uint64_t word_hi = addr[4];
	uint64_t word_lomid = (word_lo >> bitidx) | (word_mid << (32 - bitidx));
	uint64_t word = bitidx ? word_lomid | (word_hi << (64 - bitidx)) : word_lomid;
	uint32_t result = __builtin_ffsl(word >> 1);
#else
	// The return value, msize, is computed as the distance to the next 1 bit in block_header.
	// That's guaranteed to be somwhwere in the next 32 bits. And those bits could span two
	// uint32_t block_header elements. Collect the bits into a single uint32_t and measure up with ffs.
	uint32_t *addr = ((uint32_t *) block_header) + ((index >> 5) << 1);
	uint32_t bitidx = index & 31;
	uint32_t word =
			bitidx ? (addr[0] >> bitidx) | (addr[2] << (32 - bitidx)) : addr[0];
	uint32_t result = __builtin_ffs(word >> 1);
#endif
	return result;
}

static INLINE uintptr_t free_list_gen_checksum(uintptr_t ptr)
{
	uint8_t chk;

	chk = (unsigned char) (ptr >> 0);
	chk += (unsigned char) (ptr >> 8);
	chk += (unsigned char) (ptr >> 16);
	chk += (unsigned char) (ptr >> 24);
#if  __LP64__
	chk += (unsigned char)(ptr >> 32);
	chk += (unsigned char)(ptr >> 40);
	chk += (unsigned char)(ptr >> 48);
	chk += (unsigned char)(ptr >> 56);
#endif

	return chk & (uintptr_t) 0xF;
}

static void free_list_checksum_botch(szone_t *szone, free_list_t *ptr)
{
	CA_PRINT("incorrect checksum for freed object "PRINT_FORMAT_POINTER"- object was probably modified after being freed.\n",
			(address_t) ptr);
}

#define NYBBLE 4
#if  __LP64__
#define ANTI_NYBBLE (64 - NYBBLE)
#else
#define ANTI_NYBBLE (32 - NYBBLE)
#endif

static INLINE void *
free_list_unchecksum_ptr(szone_t *szone, ptr_union *ptr_addr)
{
	ptr_union ptr;
	ptr_union p;
	uintptr_t t; // = ptr->u;

	if (!read_memory_wrapper(NULL, (address_t) ptr_addr, &ptr, sizeof(ptr)))
		return NULL;
	else
		t = ptr.u;

	t = (t << NYBBLE) | (t >> ANTI_NYBBLE); // compiles to rotate instruction
	p.u = t & ~(uintptr_t) 0xF;

	if ((t & (uintptr_t) 0xF) != free_list_gen_checksum(p.u ^ szone->cookie))
	{
		free_list_checksum_botch(szone, (free_list_t *) ptr_addr);
		return NULL;
	}
	return p.p;
}

static bool small_region_walk(szone_t* szonep,
								region_t region,
								bool display_each_block,
								struct ca_region_stats* stats)
{
	bool rc = true;
	unsigned int num_inuse = 0, num_free = 0;
	size_t inuse_bytes = 0, free_bytes = 0;
	address_t ptr = (address_t) SMALL_REGION_ADDRESS(region);
	msize_t meta_headers[NUM_SMALL_BLOCKS]; // SMALL_META_HEADER_FOR_PTR(ptr);
	address_t region_end = (address_t) SMALL_REGION_END(region);
	msize_t prev_free = 0;
	unsigned index;
	msize_t msize_and_free;
	msize_t msize;
	free_list_t* free_head;
	void *previous, *next;
	msize_t *follower;
	mag_index_t mag_index; //MAGAZINE_INDEX_FOR_SMALL_REGION(SMALL_REGION_FOR_PTR(ptr));
	magazine_t small_mag; // &(szone->small_magazines[mag_index]);
	address_t mag_addr;
	msize_t prev_msize;

	if (!read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->small_meta_words),
			&meta_headers[0], sizeof(meta_headers)))
	{
		CA_PRINT(
				"Failed to read small_meta_words of small region "PRINT_FORMAT_POINTER"\n",
				(address_t) region);
		return false;
	}
	if (!read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->trailer).mag_index,
			&mag_index, sizeof(mag_index)))
	{
		CA_PRINT(
				"Failed to read mag_index of small region "PRINT_FORMAT_POINTER"\n",
				(address_t) region);
		return false;
	}
	// read magzine_t of this region
	mag_addr = (address_t) szonep->small_magazines + sizeof(magazine_t) * mag_index;
	if (!read_memory_wrapper(NULL, mag_addr, &small_mag, sizeof(magazine_t)))
	{
		CA_PRINT("Failed to read szone's small_magazines[%d] at "PRINT_FORMAT_POINTER"\n",
				mag_index, mag_addr);
		return false;
	}

	// establish region limits
	if (region == small_mag.mag_last_region)
	{
		ptr += small_mag.mag_bytes_free_at_start;
		region_end -= small_mag.mag_bytes_free_at_end;
	}

	//if (verbose)
	CA_PRINT("\tsmall region "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" Total ",
			ptr, region_end);
	print_size(region_end - ptr);
	if (display_each_block)
		CA_PRINT("\n");
	// Scan blocks within the region.
	while (ptr < region_end)
	{
		index = SMALL_META_INDEX_FOR_PTR(ptr);
		msize_and_free = meta_headers[index];

		if (!(msize_and_free & SMALL_IS_FREE))
		{
			// block is in use
			msize = msize_and_free;
			if (!msize)
			{
				CA_PRINT("invariant broken: null msize ptr="PRINT_FORMAT_POINTER" num_small_regions=%ld end="PRINT_FORMAT_POINTER"\n",
						ptr, szonep->num_small_regions, region_end);
				rc = false;
				break;
			}
			if (SMALL_BYTES_FOR_MSIZE(msize) > szonep->large_threshold)
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" this small msize=%d - size is too large\n",
						ptr, msize_and_free);
				rc = false;
				break;
			}
			if (display_each_block)
			{
				CA_PRINT("\t\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=%d in-use\n",
						ptr, ptr + SMALL_BYTES_FOR_MSIZE(msize),
						SMALL_BYTES_FOR_MSIZE(msize));
			}
			num_inuse++;
			inuse_bytes += SMALL_BYTES_FOR_MSIZE(msize);
			add_block_mem_histogram(SMALL_BYTES_FOR_MSIZE(msize), true, 1);
			// move to next block
			ptr += SMALL_BYTES_FOR_MSIZE(msize);
			prev_free = 0;
		}
		else
		{
			// free pointer
			msize = msize_and_free & ~SMALL_IS_FREE;
			free_head = (free_list_t *) ptr;
			follower = (msize_t *) FOLLOWING_SMALL_PTR(ptr, msize);
			if (!msize)
			{
				CA_PRINT("invariant broken for free block "PRINT_FORMAT_POINTER" this msize=%d\n",
						ptr, msize);
				rc = false;
				break;
			}
			if (prev_free)
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" (2 free in a row)\n",	ptr);
				rc = false;
				break;
			}
			// validate prev/next pointers of free node
			previous = free_list_unchecksum_ptr(szonep, &free_head->previous);
			next = free_list_unchecksum_ptr(szonep, &free_head->next);
			//if (previous && !SMALL_PTR_IS_FREE(previous))
			if (previous && !(meta_headers[SMALL_META_INDEX_FOR_PTR(previous)] & SMALL_IS_FREE))
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" (previous "PRINT_FORMAT_POINTER" is not a free pointer)\n",
						ptr, (address_t) free_head->previous.p);
				rc = false;
				break;
			}
			//if (next && !SMALL_PTR_IS_FREE(next))
			if (next && !(meta_headers[SMALL_META_INDEX_FOR_PTR(next)] & SMALL_IS_FREE))
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" (next is not a free pointer)\n", ptr);
				rc = false;
				break;
			}
			read_memory_wrapper(NULL, (address_t) &follower[-1], &prev_msize, sizeof(prev_msize));
			if (prev_msize != msize)
			{
				CA_PRINT("invariant broken for small free "PRINT_FORMAT_POINTER" followed by "PRINT_FORMAT_POINTER" in region ["PRINT_FORMAT_POINTER"-"PRINT_FORMAT_POINTER"] "
						"(end marker incorrect) should be %d; in fact %d\n",
						ptr, (address_t) follower, (address_t) SMALL_REGION_ADDRESS(region), region_end,
						msize, prev_msize);
				rc = false;
				break;
			}

			if (display_each_block)
			{
				CA_PRINT("\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=%d free\n",
						ptr, (address_t) follower, SMALL_BYTES_FOR_MSIZE(msize));
			}
			num_free++;
			free_bytes += SMALL_BYTES_FOR_MSIZE(msize);
			add_block_mem_histogram(SMALL_BYTES_FOR_MSIZE(msize), false, 1);
			// move to next block
			ptr = (address_t) follower;
			prev_free = SMALL_IS_FREE;
		}
	}

	if (!display_each_block)
	{
		CA_PRINT(" In-use %d(", num_inuse);
		print_size(inuse_bytes);
		CA_PRINT(") Free %d(", num_free);
		print_size(free_bytes);
		CA_PRINT(")\n");
	}

	if (stats)
	{
		stats->num_inuse   += num_inuse;
		stats->inuse_bytes += inuse_bytes;
		stats->num_free    += num_free;
		stats->free_bytes  += free_bytes;
	}

	return rc;
}

static INLINE boolean_t tiny_meta_header_is_free(const void *ptr, tiny_header_inuse_pair_t* pairs)
{
	uint32_t *block_header;
	uint32_t *in_use;
	msize_t index;

	tiny_header_inuse_pair_t mypairs[CEIL_NUM_TINY_BLOCKS_WORDS];

	if (pairs == NULL)
	{
		tiny_region_t region = TINY_REGION_FOR_PTR(ptr);
		// read meta-data of this tiny region
		if (!read_memory_wrapper(NULL, (address_t) &region->pairs, &mypairs[0],	sizeof(mypairs)))
			return 0;
		pairs = mypairs;
	}

	block_header = (uint32_t*) pairs; //TINY_BLOCK_HEADER_FOR_PTR(ptr);
	in_use = (uint32_t*) TINY_INUSE_FOR_HEADER(block_header);
	index = TINY_INDEX_FOR_PTR(ptr);
	if (!BITARRAY_BIT(block_header, index))
		return 0;
	return !BITARRAY_BIT(in_use, index);
}

/*
 * Get the size of the previous free block, which is stored in the last two
 * bytes of the block.  If the previous block is not free, then the result is
 * undefined.
 */
static msize_t get_tiny_previous_free_msize(const void *ptr, tiny_header_inuse_pair_t* pairs)
{
	// check whether the previous block is in the tiny region and a block header
	// if so, then the size of the previous block is one, and there is no stored
	// size.
	if (ptr != TINY_REGION_FOR_PTR(ptr))
	{
		void *prev_block = (void *) ((uintptr_t) ptr - TINY_QUANTUM);
		uint32_t *prev_header = (uint32_t*) pairs; //TINY_BLOCK_HEADER_FOR_PTR(prev_block);
		msize_t prev_index = TINY_INDEX_FOR_PTR(prev_block);
		if (BITARRAY_BIT(prev_header, prev_index))
			return 1;
		return TINY_PREVIOUS_MSIZE(ptr);
	}
	// don't read possibly unmapped memory before the beginning of the region
	return 0;
}

static bool
tiny_region_walk(szone_t* szonep, region_t region, bool display_each_block, struct ca_region_stats* stats)
{
	bool rc = true;
	unsigned int num_inuse = 0, num_free = 0;
	size_t inuse_bytes = 0, free_bytes = 0;

	address_t start, region_end, ptr;
	boolean_t is_free, prev_free = 0;
	msize_t msize;
	free_list_t *free_head;
	void *follower, *previous, *next;
	mag_index_t mag_index;
	magazine_t tiny_mag;
	address_t mag_addr;
	tiny_header_inuse_pair_t pairs[CEIL_NUM_TINY_BLOCKS_WORDS];

	// read meta-data of this tiny region
	if (!read_memory_wrapper(NULL, (address_t) &((tiny_region_t) region)->pairs, &pairs[0], sizeof(pairs)))
	{
		CA_PRINT("Failed to read pairs of tiny region "PRINT_FORMAT_POINTER"\n",
				(address_t) region);
		return false;
	}
	else if (!read_memory_wrapper(NULL,	(address_t) &(((tiny_region_t) region)->trailer).mag_index,
			&mag_index, sizeof(mag_index)))		// MAGAZINE_INDEX_FOR_TINY_REGION(region);
	{
		CA_PRINT("Failed to read mag_index of tiny region "PRINT_FORMAT_POINTER"\n",
				(address_t) region);
		return false;
	}
	else if (mag_index > szonep->num_tiny_magazines - 1)
	{
		CA_PRINT("Error: Region "PRINT_FORMAT_POINTER" mag_index %d is out of szone's range [0...%d]\n",
				(address_t) region, mag_index, szonep->num_tiny_magazines - 1);
		return false;
	}
	// read magzine_t of the region
	// &(szone->tiny_magazines[mag_index]);
	mag_addr = (address_t) szonep->tiny_magazines + sizeof(magazine_t) * mag_index;
	if (!read_memory_wrapper(NULL, mag_addr, &tiny_mag, sizeof(magazine_t)))
	{
		CA_PRINT("Failed to read szone's tiny_magazines[%d] at "PRINT_FORMAT_POINTER"\n",
				mag_index, mag_addr);
		return false;
	}

	// establish region limits
	ptr = start = (address_t) TINY_REGION_ADDRESS(region);
	if (region == tiny_mag.mag_last_region)
	{
		ptr += tiny_mag.mag_bytes_free_at_start;
		// Check the leading block's integrity here also.
		if (tiny_mag.mag_bytes_free_at_start)
		{
			msize = get_tiny_meta_header((void *) (ptr - TINY_QUANTUM),	&is_free, pairs);
			if (is_free || (msize != 1))
			{
				CA_PRINT("invariant broken for leader block "PRINT_FORMAT_POINTER" - %d %d\n",
						ptr - TINY_QUANTUM, msize, is_free);
				return false;
			}
		}
	}
	region_end = (address_t) TINY_REGION_END(region);
	// The last region may have a trailing chunk which has not been converted into inuse/freelist
	// blocks yet.
	if (region == tiny_mag.mag_last_region)
		region_end -= tiny_mag.mag_bytes_free_at_end;

	//if (verbose)
	CA_PRINT("\ttiny region "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" Total ",
			ptr, region_end);
	print_size(region_end - ptr);
	if (display_each_block)
		CA_PRINT("\n");

	// Scan blocks within the region.
	while (ptr < region_end)
	{
		// If the first block is free, and its size is 65536 (msize = 0) then the entire region is free
		msize = get_tiny_meta_header((void *) ptr, &is_free, pairs);
		if (is_free && !msize && (ptr == start))
			break;
		// If the block's size is 65536 (msize = 0) then since we're not the first entry the size is corrupt
		if (!msize)
		{
			CA_PRINT("invariant broken for tiny block "PRINT_FORMAT_POINTER" this msize=%d - size is too small\n",
					ptr, msize);
			rc = false;
			break;
		}
		if (!is_free)
		{
			// In use blocks cannot be more than (NUM_TINY_SLOTS - 1) quanta large.
			prev_free = 0;
			if (msize > (NUM_TINY_SLOTS - 1))
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" this tiny msize=%d - size is too large\n",
						ptr, msize);
				rc = false;
				break;
			}
			if (display_each_block)
			{
				CA_PRINT("\t\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=%d in-use\n",
						ptr, ptr + TINY_BYTES_FOR_MSIZE(msize),
						TINY_BYTES_FOR_MSIZE(msize));
			}
			num_inuse++;
			inuse_bytes += TINY_BYTES_FOR_MSIZE(msize);
			add_block_mem_histogram(TINY_BYTES_FOR_MSIZE(msize), true, 1);
			// move to next block
			ptr += TINY_BYTES_FOR_MSIZE(msize);
		}
		else
		{
			// Free blocks must have been coalesced, we cannot have a free block following another free block.
			if (prev_free)
			{
				CA_PRINT("invariant broken for free block "PRINT_FORMAT_POINTER" this tiny msize=%d: two free blocks in a row\n",
						ptr, msize);
				rc = false;
				break;
			}
			prev_free = 1;
			//Check the integrity of this block's entry in its freelist.
			free_head = (free_list_t *) ptr;
			previous = free_list_unchecksum_ptr(szonep, &free_head->previous);
			next = free_list_unchecksum_ptr(szonep, &free_head->next);
			// previous and next may be from another tiny region
			if (previous && !tiny_meta_header_is_free(previous,	region == TINY_REGION_FOR_PTR(previous) ? pairs : NULL))
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" (previous "PRINT_FORMAT_POINTER" is not a free pointer)\n",
						(address_t) ptr, (address_t) previous);
				rc = false;
			}
			if (next && !tiny_meta_header_is_free(next,	region == TINY_REGION_FOR_PTR(next) ? pairs : NULL))
			{
				CA_PRINT("invariant broken for "PRINT_FORMAT_POINTER" (next in free list "PRINT_FORMAT_POINTER" is not a free pointer)\n",
						(address_t) ptr, (address_t) next);
				rc = false;
				//break;
			}
			// Check the free block's trailing size value.
			follower = FOLLOWING_TINY_PTR(ptr, msize);
			if (((uintptr_t) follower != region_end)
					&& (get_tiny_previous_free_msize(follower, pairs) != msize))
			{
				CA_PRINT("invariant broken for tiny free "PRINT_FORMAT_POINTER" followed by "PRINT_FORMAT_POINTER" in region ["PRINT_FORMAT_POINTER"-"PRINT_FORMAT_POINTER"] "
						"(end marker incorrect) should be %d; in fact %d\n",
						(address_t) ptr, (address_t) follower,
						(address_t) TINY_REGION_ADDRESS(region), region_end,
						msize, get_tiny_previous_free_msize(follower, pairs));
				rc = false;
				//break;
			}
			if (display_each_block)
			{
				CA_PRINT("\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=%d free\n",
						ptr, (address_t) follower, TINY_BYTES_FOR_MSIZE(msize));
			}
			num_free++;
			free_bytes += TINY_BYTES_FOR_MSIZE(msize);
			add_block_mem_histogram(TINY_BYTES_FOR_MSIZE(msize), false, 1);
			// move to next block
			ptr = (uintptr_t) follower;
		}
	}

	// Ensure that we scanned the entire region
	if (rc && ptr != region_end)
	{
		CA_PRINT("invariant broken for region end "PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER"\n",
				ptr, region_end);
		rc = false;
	}
	// Check the trailing block's integrity.
	if (region == tiny_mag.mag_last_region)
	{
		if (tiny_mag.mag_bytes_free_at_end)
		{
			msize = get_tiny_meta_header((void *) ptr, &is_free, pairs);
			if (is_free || (msize != 1))
			{
				CA_PRINT("invariant broken for blocker block "PRINT_FORMAT_POINTER" - %d %d\n",
						ptr, msize, is_free);
				rc = false;
			}
		}
	}

	if (!display_each_block)
	{
		CA_PRINT(" In-use %d(", num_inuse);
		print_size(inuse_bytes);
		CA_PRINT(") Free %d(", num_free);
		print_size(free_bytes);
		CA_PRINT(")\n");
	}

	if (stats)
	{
		stats->num_inuse   += num_inuse;
		stats->inuse_bytes += inuse_bytes;
		stats->num_free    += num_free;
		stats->free_bytes  += free_bytes;
	}

	return rc;
}

static bool
szone_walk(szone_t* szonep, bool display_each_block, struct ca_region_stats* statsp)
{
	darwin_size_t num_regions, index;
	region_hash_generation_t region_hash_gen;
	region_t* regions;
	region_t region;
	struct ca_region_stats stats = {0, 0, 0, 0};

	// tiny regions
	if (!read_memory_wrapper(NULL, (address_t) szonep->tiny_region_generation,
			&region_hash_gen, sizeof(region_hash_gen)))
	{
		CA_PRINT("Failed to read zone's tiny_region_generation at "PRINT_FORMAT_POINTER"\n",
				(address_t) szonep->tiny_region_generation);
		return false;
	}
	num_regions = region_hash_gen.num_regions_allocated;
	if (num_regions > 0)
	{
		regions = (region_t*) malloc(sizeof(region_t) * num_regions);
		if (!read_memory_wrapper(NULL, (address_t) region_hash_gen.hashed_regions, &regions[0],
				sizeof(region_t) * num_regions))
		{
			CA_PRINT("Failed to read zone's tiny_region_generation->hashed_regions at "PRINT_FORMAT_POINTER"\n",
					(address_t) region_hash_gen.hashed_regions);
			return false;
		}
		for (index = 0; index < num_regions; index++)
		{
			region = regions[index];
			if (region && region != HASHRING_REGION_DEALLOCATED)
			{
				struct ca_region_stats tiny_stats = {0, 0, 0, 0};
				tiny_region_walk(szonep, region, display_each_block, &tiny_stats);
				stats.num_inuse += tiny_stats.num_inuse;
				stats.num_free  += tiny_stats.num_free;
				stats.inuse_bytes += tiny_stats.inuse_bytes;
				stats.free_bytes  += tiny_stats.free_bytes;
			}
		}
		free(regions);
		regions = NULL;
	}

	// small regions
	if (!read_memory_wrapper(NULL, (address_t) szonep->small_region_generation,
			&region_hash_gen, sizeof(region_hash_gen)))
	{
		CA_PRINT("Failed to read zone's tiny_region_generation at "PRINT_FORMAT_POINTER"\n",
				(address_t) szonep->small_region_generation);
		return false;
	}
	num_regions = region_hash_gen.num_regions_allocated;
	if (num_regions > 0)
	{
		regions = (region_t*) malloc(sizeof(region_t) * num_regions);
		if (!read_memory_wrapper(NULL, (address_t) region_hash_gen.hashed_regions, &regions[0],
				sizeof(region_t) * num_regions))
		{
			CA_PRINT("Failed to read zone's tiny_region_generation->hashed_regions at "PRINT_FORMAT_POINTER"\n",
					(address_t) region_hash_gen.hashed_regions);
			return false;
		}
		for (index = 0; index < num_regions; index++)
		{
			region = regions[index];
			if (region && region != HASHRING_REGION_DEALLOCATED)
			{
				struct ca_region_stats small_stats = {0, 0, 0, 0};
				small_region_walk(szonep, region, display_each_block, &stats);
				stats.num_inuse += small_stats.num_inuse;
				stats.num_free  += small_stats.num_free;
				stats.inuse_bytes += small_stats.inuse_bytes;
				stats.free_bytes  += small_stats.free_bytes;
			}
		}
		free(regions);
		regions = NULL;
	}

	// large
	if (szonep->num_large_objects_in_use)
	{
		unsigned num_large_entries = szonep->num_large_entries;
		// large in-use blocks are stashed in hash table
		CA_PRINT("\tIn-use large regions:\n");
		for (index = 0; index < num_large_entries; index++)
		{
			large_entry_t entry;
			if (read_memory_wrapper(NULL, (address_t) (szonep->large_entries + index), &entry, sizeof(entry))
				&& entry.address)
			{
				stats.num_inuse++;
				stats.inuse_bytes += entry.size;
				CA_PRINT("\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=",
						entry.address, entry.address + entry.size);
				print_size(entry.size);
				CA_PRINT("\n");
			}
		}
		// cached large entries
		CA_PRINT("\tCached large regions:\n");
		for (index = 0; index < LARGE_ENTRY_CACHE_SIZE; index++)
		{
			large_entry_t* entryp = &szonep->large_entry_cache[index];
			if (entryp->address)
			{
				stats.num_free++;
				stats.free_bytes += entryp->size;
				CA_PRINT("\t\t"PRINT_FORMAT_POINTER" - "PRINT_FORMAT_POINTER" size=",
						entryp->address, entryp->address + entryp->size);
				print_size(entryp->size);
				CA_PRINT("\n");
			}
		}
	}
	if (statsp)
	{
		statsp->num_inuse += stats.num_inuse;
		statsp->num_free  += stats.num_free;
		statsp->inuse_bytes += stats.inuse_bytes;
		statsp->free_bytes  += stats.free_bytes;
	}

	return true;
}

static void
add_one_region(unsigned int zone_index, enum REGION_TYPE type, address_t start, address_t end)
{
	struct ca_region* regionp;
	// replenish buffer if necessary
	if (g_ca_zones.num_regions == g_ca_zones.region_capacity)
	{
		if (g_ca_zones.region_capacity == 0)
		{
			g_ca_zones.region_capacity = 128;
			g_ca_zones.regions = (struct ca_region*) malloc(sizeof(struct ca_region) * g_ca_zones.region_capacity);
		}
		else
		{
			g_ca_zones.region_capacity *= 2;
			g_ca_zones.regions = (struct ca_region*) realloc(g_ca_zones.regions, sizeof(struct ca_region) * g_ca_zones.region_capacity);
		}
	}
	// add this region to the array
	regionp = &g_ca_zones.regions[g_ca_zones.num_regions++];
	regionp->zone_index = zone_index;
	regionp->type = type;
	regionp->start = start;
	regionp->end = end;
	regionp->blocks = NULL;
	regionp->num_blocks = 0;
	regionp->corrupt = 0;
}

static bool
build_small_region(unsigned int zone_index, szone_t* szonep, region_t region)
{
	bool rc = true;
	address_t ptr = (address_t) SMALL_REGION_ADDRESS(region);
	address_t region_end = (address_t) SMALL_REGION_END(region);
	mag_index_t mag_index;
	magazine_t small_mag;
	address_t mag_addr;

	if (!read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->trailer).mag_index,
			&mag_index, sizeof(mag_index)))		//MAGAZINE_INDEX_FOR_SMALL_REGION(SMALL_REGION_FOR_PTR(ptr))
		return false;
	// &(szone->small_magazines[mag_index])
	mag_addr = (address_t) szonep->small_magazines + sizeof(magazine_t) * mag_index;
	if (!read_memory_wrapper(NULL, mag_addr, &small_mag, sizeof(magazine_t)))
		return false;

	// establish region limits
	if (region == small_mag.mag_last_region)
	{
		ptr += small_mag.mag_bytes_free_at_start;
		region_end -= small_mag.mag_bytes_free_at_end;
	}

	add_one_region(zone_index, ENUM_SMALL_REGION, ptr, region_end);

	return rc;
}

static bool
build_tiny_region(unsigned int zone_index, szone_t* szonep, region_t region)
{
	bool rc = true;

	address_t start, region_end, ptr;
	mag_index_t mag_index;
	magazine_t tiny_mag;
	address_t mag_addr;
	tiny_header_inuse_pair_t pairs[CEIL_NUM_TINY_BLOCKS_WORDS];

	// read meta-data of this tiny region
	if (!read_memory_wrapper(NULL, (address_t) &((tiny_region_t) region)->pairs,
			&pairs[0], sizeof(pairs)))
	{
		CA_PRINT("Failed to read pairs of tiny region "PRINT_FORMAT_POINTER"\n",
				(address_t) region);
		return false;
	}
	else if (!read_memory_wrapper(NULL, (address_t) &(((tiny_region_t) region)->trailer).mag_index,
			&mag_index, sizeof(mag_index)))		// MAGAZINE_INDEX_FOR_TINY_REGION(region)
	{
		CA_PRINT("Failed to read mag_index of tiny region "PRINT_FORMAT_POINTER"\n",
				(address_t) region);
		return false;
	}
	else if (mag_index > szonep->num_tiny_magazines - 1)
	{
		CA_PRINT("Error: Region "PRINT_FORMAT_POINTER" mag_index %d is out of szone's range [0...%d]\n",
				(address_t) region, mag_index, szonep->num_tiny_magazines - 1);
		return false;
	}
	// read magazine_t of this region
	// &(szone->tiny_magazines[mag_index])
	mag_addr = (address_t) szonep->tiny_magazines + sizeof(magazine_t) * mag_index;
	if (!read_memory_wrapper(NULL, mag_addr, &tiny_mag, sizeof(magazine_t)))
	{
		CA_PRINT("Failed to read szone's tiny_magazines[%d] at "PRINT_FORMAT_POINTER"\n",
				mag_index, mag_addr);
		return false;
	}

	// establish region limits
	ptr = start = (address_t) TINY_REGION_ADDRESS(region);
	if (region == tiny_mag.mag_last_region)
		ptr += tiny_mag.mag_bytes_free_at_start;
	region_end = (address_t) TINY_REGION_END(region);
	// The last region may have a trailing chunk which has not been converted into
	// inuse/freelist blocks yet.
	if (region == tiny_mag.mag_last_region)
		region_end -= tiny_mag.mag_bytes_free_at_end;

	add_one_region(zone_index, ENUM_TINY_REGION, ptr, region_end);

	return rc;
}

static bool
build_regions(unsigned int zone_index, szone_t* szonep)
{
	darwin_size_t num_regions, index;
	region_hash_generation_t region_hash_gen;
	region_t* regions;
	region_t region;

	// tiny regions
	if (!read_memory_wrapper(NULL, (address_t) szonep->tiny_region_generation,
			&region_hash_gen, sizeof(region_hash_gen)))
	{
		CA_PRINT("Failed to read zone's tiny_region_generation at "PRINT_FORMAT_POINTER"\n",
				(address_t) szonep->tiny_region_generation);
		return false;
	}
	num_regions = region_hash_gen.num_regions_allocated;
	if (num_regions > 0)
	{
		regions = (region_t*) malloc(sizeof(region_t) * num_regions);
		if (!read_memory_wrapper(NULL, (address_t) region_hash_gen.hashed_regions, &regions[0],
				sizeof(region_t) * num_regions))
		{
			CA_PRINT("Failed to read zone's tiny_region_generation->hashed_regions at "PRINT_FORMAT_POINTER"\n",
					(address_t) region_hash_gen.hashed_regions);
			return false;
		}
		for (index = 0; index < num_regions; index++)
		{
			region = regions[index];
			if (region && region != HASHRING_REGION_DEALLOCATED)
				build_tiny_region(zone_index, szonep, region);
		}
		free(regions);
		regions = NULL;
	}

	// small regions
	if (!read_memory_wrapper(NULL, (address_t) szonep->small_region_generation,
			&region_hash_gen, sizeof(region_hash_gen)))
	{
		CA_PRINT("Failed to read zone's tiny_region_generation at "PRINT_FORMAT_POINTER"\n",
				(address_t) szonep->small_region_generation);
		return false;
	}
	num_regions = region_hash_gen.num_regions_allocated;
	if (num_regions > 0)
	{
		regions = (region_t*) malloc(sizeof(region_t) * num_regions);
		if (!read_memory_wrapper(NULL, (address_t) region_hash_gen.hashed_regions, &regions[0],
				sizeof(region_t) * num_regions))
		{
			CA_PRINT("Failed to read zone's tiny_region_generation->hashed_regions at "PRINT_FORMAT_POINTER"\n",
					(address_t) region_hash_gen.hashed_regions);
			return false;
		}
		for (index = 0; index < num_regions; index++)
		{
			region = regions[index];
			if (region && region != HASHRING_REGION_DEALLOCATED)
				build_small_region(zone_index, szonep, region);
		}
		free(regions);
		regions = NULL;
	}

	// large
	if (szonep->num_large_objects_in_use)
	{
		unsigned index;
		unsigned num_large_entries = szonep->num_large_entries;
		// large in-use blocks are stashed in hash table
		for (index = 0; index < num_large_entries; index++)
		{
			large_entry_t entry;
			if (read_memory_wrapper(NULL, (address_t) (szonep->large_entries + index), &entry, sizeof(entry))
				&& entry.address)
			{
				add_one_region(zone_index, ENUM_LARGE_REGION, set_inuse(entry.address),
							entry.address + entry.size);
			}
		}
		// cached large entries
		for (index = 0; index < LARGE_ENTRY_CACHE_SIZE; index++)
		{
			large_entry_t* entryp = &szonep->large_entry_cache[index];
			if (entryp->address)
			{
				add_one_region(zone_index, ENUM_LARGE_REGION, entryp->address,
						entryp->address + entryp->size);
			}
		}
	}

	return true;
}

// release old and possibly stale data structures
static void destruct_ca_zones()
{
	if (g_ca_zones.malloc_zones)
	{
		free(g_ca_zones.malloc_zones);
		g_ca_zones.malloc_zones = NULL;
	}
	g_ca_zones.malloc_num_zone = 0;
	if (g_ca_zones.regions)
	{
		unsigned int i;
		for (i = 0; i < g_ca_zones.num_regions; i++)
		{
			struct ca_region* regionp = &g_ca_zones.regions[i];
			if (regionp->blocks)
				free(regionp->blocks);
		}
		free(g_ca_zones.regions);
	}
	g_ca_zones.regions = NULL;
	g_ca_zones.num_regions = 0;
	g_ca_zones.region_capacity = 0;
}

/*
 * compare two struct ca_region by their starting address
 */
static int compare_ca_region(const void* lhs, const void* rhs)
{
	const struct ca_region* region1 = (const struct ca_region*) lhs;
	const struct ca_region* region2 = (const struct ca_region*) rhs;
	// they can't be equal
	if (region1->start < region2->start)
		return -1;
	else if (region1->start > region2->start)
		return 1;
	else
	{
		CA_PRINT("Internal error: two struct ca_region are of the same start address.\n");
		return 0;
	}
}

static bool build_szones(void)
{
	bool rc = true;
	unsigned int zone_index, region_index;
	address_t malloc_zone_vaddr = 0;
	address_t malloc_num_zone_vaddr = 0;
	address_t szone_array_addr;

	g_heap_initialized = false;
	destruct_ca_zones();

	// Get the address of global variable malloc_zones/malloc_num_zone
	malloc_zone_vaddr = get_var_addr_by_name("malloc_zones", true);
	malloc_num_zone_vaddr = get_var_addr_by_name("malloc_num_zones", true);
	if (!malloc_zone_vaddr || !malloc_num_zone_vaddr)
	{
		CA_PRINT("Address of global variable malloc_zones/malloc_num_zone is zero\n");
		return false;
	}

	// read the value of malloc_num_zone
	if (!read_memory_wrapper(NULL, malloc_num_zone_vaddr,
			&g_ca_zones.malloc_num_zone, sizeof(g_ca_zones.malloc_num_zone)))
	{
		CA_PRINT("Failed to read global variable malloc_num_zone at "PRINT_FORMAT_POINTER"\n",
				malloc_num_zone_vaddr);
		return false;
	}
	if (g_ca_zones.malloc_num_zone == 0)
	{
		CA_PRINT("Error global variable malloc_num_zone = 0\n");
		return false;
	}
	// read the value of malloc_zones
	if (!read_memory_wrapper(NULL, malloc_zone_vaddr, &szone_array_addr, sizeof(szone_array_addr)))
	{
		CA_PRINT("Failed to read global variable malloc_zones at "PRINT_FORMAT_POINTER"\n",
				malloc_zone_vaddr);
		return false;
	}

	// allocate buffer for all szones
	g_ca_zones.malloc_zones = (szone_t*) malloc(sizeof(szone_t) * g_ca_zones.malloc_num_zone);
	if (!g_ca_zones.malloc_zones)
		return false;
	// read all szone_t into local copy
	for (zone_index = 0; zone_index < g_ca_zones.malloc_num_zone; zone_index++)
	{
		address_t szone_addr;
		szone_t* szonep = &g_ca_zones.malloc_zones[zone_index];

		if (!read_memory_wrapper(NULL, szone_array_addr + sizeof(szone_t*) * zone_index, &szone_addr,
				sizeof(szone_addr)))
		{
			CA_PRINT("Failed to read global variable malloc_zones[%d] at "PRINT_FORMAT_POINTER"\n",
					zone_index,	szone_array_addr + sizeof(szone_t*) * zone_index);
			rc = false;
			break;
		}
		if (!read_memory_wrapper(NULL, szone_addr, szonep, sizeof(szone_t)))
		{
			CA_PRINT("Failed to read szone_t at "PRINT_FORMAT_POINTER"\n",
					szone_addr);
			rc = false;
			break;
		}
		// regions of the zone
		build_regions(zone_index, szonep);
	}

	// something horribly wrong
	if (!rc)
	{
		destruct_ca_zones();
		return false;
	}

	// sort the regions in ascending address
	qsort(g_ca_zones.regions, g_ca_zones.num_regions,
			sizeof(g_ca_zones.regions[0]), compare_ca_region);

	// mark heap segments
	for (region_index = 0; region_index < g_ca_zones.num_regions;
			region_index++)
	{
		struct ca_region* regionp = &g_ca_zones.regions[region_index];
		struct ca_segment* segment = get_segment(regionp->start, regionp->end - regionp->start);
		if (segment->m_type == ENUM_UNKNOWN)
			segment->m_type = ENUM_HEAP;
	}

	// Now we are ready
	g_heap_initialized = true;
	return true;
}

static struct ca_region* search_sorted_regions(address_t addr)
{
	unsigned int l_index = 0;
	unsigned int u_index = g_ca_zones.num_regions;

	// sanity check
	if (!g_ca_zones.regions || u_index == 0)
		return NULL;
	// bail out for out of bound addr
	if (addr < g_ca_zones.regions[0].start
		|| addr >= g_ca_zones.regions[u_index - 1].end)
		return NULL;

	while (l_index < u_index)
	{
		unsigned int m_index = (l_index + u_index) / 2;
		struct ca_region* regionp = &g_ca_zones.regions[m_index];
		if (addr < block_addr(regionp->start))
			u_index = m_index;
		else if (addr >= regionp->end)
			l_index = m_index + 1;
		else
			return regionp;
	}
	return NULL;
}

static void build_tiny_region_blocks(struct ca_region* regionp)
{
	address_t start, region_end, first_block, ptr;
	boolean_t is_free, prev_free;
	msize_t msize;
	mag_index_t mag_index;
	magazine_t tiny_mag;
	tiny_header_inuse_pair_t pairs[CEIL_NUM_TINY_BLOCKS_WORDS];
	szone_t* szonep = &g_ca_zones.malloc_zones[regionp->zone_index];
	region_t region = TINY_REGION_FOR_PTR(regionp->start);
	unsigned int count;

	// read meta-data of this tiny region
	// mag_index = MAGAZINE_INDEX_FOR_TINY_REGION(region)
	// tiny_mag  = &(szone->tiny_magazines[mag_index])
	if (!read_memory_wrapper(NULL, (address_t) &((tiny_region_t) region)->pairs, &pairs[0], sizeof(pairs))
		|| !read_memory_wrapper(NULL, (address_t) &(((tiny_region_t) region)->trailer).mag_index,
					&mag_index, sizeof(mag_index))
		|| mag_index > szonep->num_tiny_magazines - 1
		|| !read_memory_wrapper(NULL,(address_t) szonep->tiny_magazines
				+ sizeof(magazine_t) * mag_index, &tiny_mag, sizeof(magazine_t)))
	{
		regionp->corrupt = 1;
		return;
	}

	// establish region limits
	first_block = start = (address_t) TINY_REGION_ADDRESS(region);
	if (region == tiny_mag.mag_last_region)
		first_block += tiny_mag.mag_bytes_free_at_start;
	region_end = (address_t) TINY_REGION_END(region);
	// The last region may have a trailing chunk which has not been converted into inuse/freelist
	// blocks yet.
	if (region == tiny_mag.mag_last_region)
		region_end -= tiny_mag.mag_bytes_free_at_end;

	// Fisrt scan region to count number blocks
	count = 0;
	ptr = first_block;
	prev_free = 0;
	while (ptr < region_end)
	{
		// If the first block is free, and its size is 65536 (msize = 0) then the entire region is free
		msize = get_tiny_meta_header((void *) ptr, &is_free, pairs);
		if (is_free && !msize && (ptr == start))
		{
			count = 1;
			break;
		}
		// If the block's size is 65536 (msize = 0) then since we're not the first entry the size is corrupt
		if (!msize)
		{
			regionp->corrupt = 1;
			break;
		}
		if (!is_free)
		{
			// In use blocks cannot be more than (NUM_TINY_SLOTS - 1) quanta large.
			prev_free = 0;
			if (msize > (NUM_TINY_SLOTS - 1))
			{
				regionp->corrupt = 1;
				break;
			}
			// move to next block
			ptr += TINY_BYTES_FOR_MSIZE(msize);
		}
		else
		{
			// Free blocks must have been coalesced, we cannot have a free block following another free block.
			if (prev_free)
			{
				regionp->corrupt = 1;
				break;
			}
			prev_free = 1;
			// move to next block
			ptr = (uintptr_t) FOLLOWING_TINY_PTR(ptr, msize);
		}
		count++;
	}
	// Ensure that we scanned the entire region
	if (ptr != region_end)
		regionp->corrupt = 1;

	// allocate an array for starting addresses of all blocks
	regionp->num_blocks = count;
	if (count == 0)
		return;
	regionp->blocks = (address_t*) calloc(sizeof(address_t), (count + 1));
	// Second pass would populate the array with block addresses with inuse/free bit
	ptr = first_block;
	count = 0;
	prev_free = 0;
	while (ptr < region_end)
	{
		// If the first block is free, and its size is 65536 (msize = 0) then the entire region is free
		msize = get_tiny_meta_header((void *) ptr, &is_free, pairs);
		if (is_free && !msize && (ptr == start))
		{
			regionp->blocks[0] = ptr;
			break;
		}
		// If the block's size is 65536 (msize = 0) then since we're not the first entry the size is corrupt
		if (!msize)
			break;
		if (!is_free)
		{
			// In use blocks cannot be more than (NUM_TINY_SLOTS - 1) quanta large.
			prev_free = 0;
			if (msize > (NUM_TINY_SLOTS - 1))
				break;
			regionp->blocks[count] = set_inuse(ptr);
			// move to next block
			ptr += TINY_BYTES_FOR_MSIZE(msize);
		}
		else
		{
			// Free blocks must have been coalesced, we cannot have a free block following another free block.
			if (prev_free)
				break;
			prev_free = 1;
			// move to next block
			regionp->blocks[count] = ptr;
			ptr = (uintptr_t) FOLLOWING_TINY_PTR(ptr, msize);
		}
		count++;
	}
	// Seal the array with region's end address
	regionp->blocks[count] = region_end;
	// sanity check
	check_sorted_region_blocks(regionp);
}

static void check_sorted_region_blocks(struct ca_region* regionp)
{
	if (regionp->corrupt)
		CA_PRINT("Corrupted region "PRINT_FORMAT_POINTER"\n", regionp->start);
	else
	{
		unsigned int index;
		for (index = 0; index < regionp->num_blocks; index++)
		{
			if (block_addr(regionp->blocks[index]) >= block_addr(regionp->blocks[index+1]))
			{
				CA_PRINT("Internal error: region "PRINT_FORMAT_POINTER" incorrectly sorted blocks(%d)\n",
						regionp->start, regionp->num_blocks);
				CA_PRINT("\t[%d] addr="PRINT_FORMAT_POINTER"\n", index, regionp->blocks[index]);
				CA_PRINT("\t[%d] addr="PRINT_FORMAT_POINTER"\n", index+1, regionp->blocks[index]);
			}
		}
	}
}

static void build_small_region_blocks(struct ca_region* regionp)
{
	szone_t* szonep = &g_ca_zones.malloc_zones[regionp->zone_index];
	region_t region = SMALL_REGION_FOR_PTR(regionp->start);
	address_t ptr, first_block, region_end;
	msize_t meta_headers[NUM_SMALL_BLOCKS];
	msize_t prev_free;
	unsigned int index, count;
	msize_t msize_and_free;
	msize_t msize;
	mag_index_t mag_index;
	magazine_t small_mag;

	// mag_index = MAGAZINE_INDEX_FOR_SMALL_REGION(SMALL_REGION_FOR_PTR(ptr));
	// small_mag = &(szone->small_magazines[mag_index]);
	if (!read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->small_meta_words),
			&meta_headers[0], sizeof(meta_headers))
		|| !read_memory_wrapper(NULL, (address_t) &(((small_region_t) region)->trailer).mag_index,
					&mag_index, sizeof(mag_index))
		|| !read_memory_wrapper(NULL,(address_t) szonep->small_magazines
							+ sizeof(magazine_t) * mag_index, &small_mag,
					sizeof(magazine_t)))
	{
		regionp->corrupt = 1;
		return;
	}

	// establish region limits
	first_block = (address_t) SMALL_REGION_ADDRESS(region);
	region_end = (address_t) SMALL_REGION_END(region);
	if (region == small_mag.mag_last_region)
	{
		first_block += small_mag.mag_bytes_free_at_start;
		region_end -= small_mag.mag_bytes_free_at_end;
	}

	// First scan the region to count number of blocks
	ptr = first_block;
	count = 0;
	prev_free = 0;
	while (ptr < region_end)
	{
		index = SMALL_META_INDEX_FOR_PTR(ptr);
		msize_and_free = meta_headers[index];
		if (!(msize_and_free & SMALL_IS_FREE))
		{
			// block is in use
			msize = msize_and_free;
			if (!msize || SMALL_BYTES_FOR_MSIZE(msize) > szonep->large_threshold)
			{
				regionp->corrupt = 1;
				break;
			}
			// move to next block
			ptr += SMALL_BYTES_FOR_MSIZE(msize);
			prev_free = 0;
		}
		else
		{
			// free block
			msize = msize_and_free & ~SMALL_IS_FREE;
			if (!msize || prev_free)
			{
				regionp->corrupt = 1;
				break;
			}
			// move to next block
			ptr = (address_t) FOLLOWING_SMALL_PTR(ptr, msize);
			prev_free = SMALL_IS_FREE;
		}
		count++;
	}
	// allocate an array for starting addresses of all blocks
	regionp->num_blocks = count;
	if (count == 0)
		return;
	regionp->blocks = (address_t*) calloc(sizeof(address_t), (count + 1));
	// Second pass would populate the array with block addresses with inuse/free bit
	ptr = first_block;
	count = 0;
	prev_free = 0;
	while (ptr < region_end)
	{
		index = SMALL_META_INDEX_FOR_PTR(ptr);
		msize_and_free = meta_headers[index];

		if (!(msize_and_free & SMALL_IS_FREE))
		{
			// block is in use
			msize = msize_and_free;
			if (!msize || SMALL_BYTES_FOR_MSIZE(msize) > szonep->large_threshold)
			{
				regionp->corrupt = 1;
				break;
			}
			regionp->blocks[count] = set_inuse(ptr);
			// move to next block
			ptr += SMALL_BYTES_FOR_MSIZE(msize);
			prev_free = 0;
		}
		else
		{
			msize = msize_and_free & ~SMALL_IS_FREE;
			// free block
			if (!msize || prev_free)
			{
				regionp->corrupt = 1;
				break;
			}
			regionp->blocks[count] = ptr;
			// move to next block
			ptr = (address_t) FOLLOWING_SMALL_PTR(ptr, msize);
			prev_free = SMALL_IS_FREE;
		}
		count++;
	}
	// Seal the array with region's end address
	regionp->blocks[count] = region_end;
	// Sanity check
	check_sorted_region_blocks(regionp);
}

static void build_region_blocks(struct ca_region* regionp)
{
	if (regionp->type == ENUM_TINY_REGION)
		build_tiny_region_blocks(regionp);
	else if (regionp->type == ENUM_SMALL_REGION)
		build_small_region_blocks(regionp);
}

/*
 * Binary search of the malloc_chunk within a heap
 */
static int search_block_index(struct ca_region* regionp, address_t addr)
{
	unsigned int l_index = 0;
	unsigned int u_index = regionp->num_blocks;

	while (l_index < u_index)
	{
		unsigned int m_index = (l_index + u_index) / 2;
		if (addr < block_addr(regionp->blocks[m_index]))
			u_index = m_index;
		else if (addr >= block_addr(regionp->blocks[m_index+1]))
			l_index = m_index + 1;
		else
			return m_index;
	}
	return -1;
}

/*
 * Locate the memory block containing addr
 * We have verified that "addr" falls within this region
 */
static bool
find_block_in_region(struct ca_region* regionp, address_t addr,	struct heap_block* blk)
{
	int index;
	// Large region is single block
	if (regionp->type == ENUM_LARGE_REGION)
	{
		blk->addr = block_addr(regionp->start);
		blk->size = regionp->end - blk->addr;
		blk->inuse = block_inuse(regionp->start);
		return true;
	}

	// tiny/small regions
	if (regionp->blocks == NULL)
		build_region_blocks(regionp);

	// blocks in the region are prepared and sorted by now
	index = search_block_index(regionp, addr);
	if (index >= 0 && index < regionp->num_blocks)
	{
		blk->addr = block_addr(regionp->blocks[index]);
		if (index < regionp->num_blocks - 1)
			blk->size = block_addr(regionp->blocks[index + 1]) - blk->addr;
		else
			blk->size = regionp->end - blk->addr;
		blk->inuse = block_inuse(regionp->blocks[index]);
		return true;
	}

	return false;
}

// The input array blks is assumed to be sorted by size already
static void
add_one_big_block(struct heap_block* blks, unsigned int num, struct heap_block* blk)
{
	unsigned int i;
	for (i = 0; i < num; i++)
	{
		if (blk->size > blks[i].size)
		{
			int k;
			// Insert blk->blks[i]
			// Move blks[i]->blks[i+1], .., blks[num-2]->blks[num-1]
			for (k = ((int) num) - 2; k >= (int) i; k--)
				blks[k + 1] = blks[k];
			blks[i] = *blk;
			break;
		}
	}
}
