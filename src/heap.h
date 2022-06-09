/*
 * heap.h
 *
 *  Created on: Dec 13, 2011
 *  Modifed on: May 15, 2022
 *      Author: myan
 */
#ifndef _HEAP_H
#define _HEAP_H
#include <string>
#include <map>
#include "ref.h"
/*
 * Memory usage/leak
 * Aggregated memory is the collection of memory blocks that are reachable from
 * either a global variable or a local variable
 */
struct reachable {
	size_t        aggr_size;	// cached reachable count/size by me (solely)
	unsigned long aggr_count;
	unsigned int* index_map;	// cached indexes of all sub in-use blocks
};

struct search_reachable_block {
	address_t addr;
	size_t    size;
	struct reachable reachable;
};

struct inuse_block
{
	address_t addr;
	size_t    size;
	struct reachable reachable;
};


typedef const char * (*HeapVersionFunc)(void);
typedef bool (*InitHeapFunc)(void);
typedef bool (*HeapWalkFunc)(address_t addr, bool verbose);
typedef bool (*IsHeapBlockFunc)(address_t addr);
typedef bool (*GetHeapBlockInfoFunc)(address_t addr, struct heap_block* blk);
typedef bool (*GetNextHeapBlockFunc)(address_t addr, struct heap_block* blk);
typedef bool (*GetBiggestBlocksFunc)(struct heap_block* blks, unsigned int num);
typedef void (*PrintSizeFunc)(size_t sz);
typedef bool (*WalkInuseBlocksFunc)(struct inuse_block* opBlocks, unsigned long* opCount);

/** Different programs might use different heap managers
 * This heap interface is the abstract interface for each heap manager
 * 
**/
struct CoreAnalyzerHeapInterface {
    HeapVersionFunc heap_version;
    InitHeapFunc init_heap;
    HeapWalkFunc heap_walk;
    IsHeapBlockFunc is_heap_block;
    GetHeapBlockInfoFunc get_heap_block_info;
    GetNextHeapBlockFunc get_next_heap_block;
    GetBiggestBlocksFunc get_biggest_blocks;
    /*
    * Get all in-use memory blocks
    * 	If param opBlocks is NULL, return number of in-use only,
    * 	otherwise, populate the array with all in-use block info
    */
    WalkInuseBlocksFunc walk_inuse_blocks;

};

extern std::map<std::string, CoreAnalyzerHeapInterface*> gCoreAnalyzerHeaps;

extern CoreAnalyzerHeapInterface* gCAHeap;
#define CA_HEAP gCAHeap

/*
* This function is called at bootstrap or when target is changed
* and after target memory layout is scanned.
*/
extern bool init_heap_managers();

/*
* Individual heap manager calls this function in its init function
* to declare its name, heap interface, and whether it detects its heap data in the target.
*/
extern void register_heap_manager(std::string, CoreAnalyzerHeapInterface*, bool);

/*
* Each heap manager implements an init function
* Maybe we don't need to explicitly expose them. We may scape these functions at compile time
* the same way gdb commands initializers are collected.
*/
extern void register_pt_malloc_2_27();
extern void register_pt_malloc_2_31();
extern void register_pt_malloc_2_35();
extern void register_tc_malloc();
extern void register_mscrt_malloc();

extern std::string get_supported_heaps();

extern struct inuse_block* build_inuse_heap_blocks(unsigned long*);
extern struct inuse_block* find_inuse_block(address_t, struct inuse_block*, unsigned long);

extern struct search_reachable_block* build_search_reachable_blocks(unsigned long*);
extern void free_search_reachable_blocks(struct search_reachable_block*, unsigned long);

//extern struct search_reachable_block* find_reachable_block(address_t,
//    struct search_reachable_block*, unsigned long);

extern bool display_heap_leak_candidates(void);

extern bool biggest_blocks(unsigned int num);
extern bool biggest_heap_owners_generic(unsigned int num, bool all_reachable_blocks);
extern void print_size(size_t sz);

extern bool
calc_aggregate_size(const struct object_reference *ref,
					size_t var_len,
					bool all_reachable_blocks,
					struct search_reachable_block *inuse_blocks,
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
extern void add_block_mem_histogram(size_t, bool, unsigned int);

#endif
