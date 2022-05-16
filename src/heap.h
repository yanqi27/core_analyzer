// ==============================================================================================
// FILENAME	:	heap_interface.h
// AUTHOR	:	Xianting Lu
// CREATION	:	2022-05-15
// ==============================================================================================

/** Different programs might use different heap managers
 * Thi heap interface is the abstract interface for each heap manager
 * 
**/
#ifndef _HEAP_INTERFACE_H
#define _HEAP_INTERFACE_H
#include "ref.h"
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

/**
 * @brief each heap manager is assigned to an enum
 * 
 */
enum EnumHeapManager {
    HeapManagerReserved = 0,
    HeapManagerPtMalloc = 1,
    HeapManagerTcMalloc = 2,
	HeapManagerLastOne,
};

typedef const char * (*HeapVersionFunc)(void);
typedef bool (*InitHeapFunc)(void);
typedef  bool (*HeapWalkFunc)(address_t addr, bool verbose);
typedef bool (*IsHeapBlockFunc)(address_t addr);
typedef bool (*GetHeapBlockInfoFunc)(address_t addr, struct heap_block* blk);
typedef bool (*GetNextHeapBlockFunc)(address_t addr, struct heap_block* blk);
typedef bool (*GetBiggestBlocksFunc)(struct heap_block* blks, unsigned int num);
typedef void (*PrintSizeFunc)(size_t sz);
typedef bool (*WalkInuseBlocksFunc)(struct inuse_block* opBlocks, unsigned long* opCount);

typedef struct inuse_block* (*FindInuseBlockFunc)(address_t, struct inuse_block*, unsigned long);

typedef bool (*DisplayHeapLeakCandidatesFunc)(void);

typedef bool (*BiggestBlocksFunc)(unsigned int num);
typedef bool (*BiggestHeapOwnersGenericFunc)(unsigned int num, bool all_reachable_blocks);

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

// global heaps analyzers
extern CoreAnalyzerHeapInterface* gCoreAnalyzerHeaps[HeapManagerLastOne];
extern EnumHeapManager gCurrentHeap;
#define CA_HEAP gCoreAnalyzerHeaps[gCurrentHeap]
extern void register_heap_managers();

extern struct inuse_block* build_inuse_heap_blocks(unsigned long*);
extern void free_inuse_heap_blocks(struct inuse_block*, unsigned long);

extern struct inuse_block* find_inuse_block(address_t, struct inuse_block*, unsigned long);

extern bool display_heap_leak_candidates(void);

extern bool biggest_blocks(unsigned int num);
extern bool biggest_heap_owners_generic(unsigned int num, bool all_reachable_blocks);
extern void print_size(size_t sz);

extern bool
calc_aggregate_size(const struct object_reference *ref,
					size_t var_len,
					bool all_reachable_blocks,
					struct inuse_block *inuse_blocks,
					unsigned long num_inuse_blocks,
					size_t *aggr_size,
					unsigned long *count);
extern void display_mem_histogram(const char*);
extern void init_mem_histogram(unsigned int nbuckets);
extern void release_mem_histogram(void);
extern void add_block_mem_histogram(size_t, bool, unsigned int);

extern CoreAnalyzerHeapInterface* get_pt_malloc_heap_manager();
extern CoreAnalyzerHeapInterface* get_tc_malloc_heap_manager();

#endif
