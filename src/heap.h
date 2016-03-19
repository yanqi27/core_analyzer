/*
 * heap.h
 *
 *  Created on: Dec 13, 2011
 *      Author: myan
 */
#ifndef _HEAP_H
#define _HEAP_H

#include "ref.h"

/*
 * Exposed functions
 */
extern CA_BOOL init_heap(void);

extern CA_BOOL heap_walk(address_t addr, CA_BOOL verbose);

extern CA_BOOL is_heap_block(address_t addr);

extern CA_BOOL get_heap_block_info(address_t addr, struct heap_block* blk);

extern CA_BOOL get_next_heap_block(address_t addr, struct heap_block* blk);

extern CA_BOOL get_biggest_blocks(struct heap_block* blks, unsigned int num);

extern void print_size(size_t sz);

/*
 * Memory usage/leak
 * Aggregated memory is the collection of memory blocks that are reachable from a variable
 */
struct reachable
{
	size_t        aggr_size;	// cached reachable count/size by me (solely)
	unsigned long aggr_count;
	unsigned int* index_map;	// cached indexes of all sub in-use blocks
};

struct inuse_block
{
	address_t addr;
	size_t    size;
	struct reachable reachable;
};

/*
 * Get all in-use memory blocks
 * 	If param opBlocks is NULL, return number of in-use only,
 * 	otherwise, populate the array with all in-use block info
 */
extern CA_BOOL walk_inuse_blocks(struct inuse_block* opBlocks, unsigned long* opCount);

extern struct inuse_block* build_inuse_heap_blocks(unsigned long*);
extern void free_inuse_heap_blocks(struct inuse_block*, unsigned long);

extern struct inuse_block* find_inuse_block(address_t, struct inuse_block*, unsigned long);

extern CA_BOOL display_heap_leak_candidates(void);

extern CA_BOOL biggest_blocks(unsigned int num);
extern CA_BOOL biggest_heap_owners_generic(unsigned int num, CA_BOOL all_reachable_blocks);

extern CA_BOOL
calc_aggregate_size(const struct object_reference *ref,
					size_t var_len,
					CA_BOOL all_reachable_blocks,
					struct inuse_block *inuse_blocks,
					unsigned long num_inuse_blocks,
					size_t *aggr_size,
					unsigned long *count);

/*
 * Histogram of heap blocks
 */
struct MemHistogram
{
	unsigned int   num_buckets;
	size_t*        bucket_sizes;
	unsigned long* inuse_cnt;
	size_t*        inuse_bytes;
	unsigned long* free_cnt;
	size_t*        free_bytes;
};
extern void display_mem_histogram(const char*);
extern void init_mem_histogram(unsigned int nbuckets);
extern void release_mem_histogram(void);
extern void add_block_mem_histogram(size_t, CA_BOOL, unsigned int);

#endif
