/*
 * heap_jemalloc.h
 *  JEMalloc data structure
 *
 *  Created on: March 1, 2023
 *      Author: myan
 */
#pragma once
#include "heap.h"
#include <list>
#include <set>
#include <vector>

#define LG_VADDR 48
#define RTREE_LEAF_STATE_MASK ((((((uint64_t)0x1U) << (3)) - 1)) << (2))
#define RTREE_LEAF_STATE_SHIFT 2
#define EDATA_ALIGNMENT 128
#define RTREE_NHIB ((1U << (3+3)) - 48)

struct je_bitmap_info_t {
	size_t nbits = 0;
	size_t ngroups = 0;
};

struct je_bin_info_t {
	size_t reg_size = 0;
	size_t slab_size = 0;
	uint32_t nregs = 0;
	uint32_t n_shards = 0;
	je_bitmap_info_t bitmap_info;
};

struct je_arena_stats_t {
	unsigned int free_cnt = 0;
	unsigned int inuse_cnt = 0;
	size_t free_bytes = 0;
	size_t inuse_bytes = 0;
};

struct je_bin_stats_t {
	size_t curslabs;
	size_t nonfull_slabs;
};

typedef unsigned long je_bitmap_t;
struct je_slab_data_t {
	je_bitmap_t bitmap[8];
};

#define PAGE (1<<12)
#define EDATA_SIZE_MASK	((size_t)~(PAGE-1))
#define PAGE_MASK	((size_t)(PAGE - 1))
#define PAGE_ADDR2BASE(a) (((uintptr_t)(a) & ~PAGE_MASK))

enum je_extent_state_t {
	extent_state_active   = 0,
	extent_state_dirty    = 1,
	extent_state_muzzy    = 2,
	extent_state_retained = 3,
	extent_state_transition = 4, /* States below are intermediate. */
	extent_state_merging = 5,
	extent_state_max = 5 /* Sanity checking only. */
};

// extent, which is a contiguous chunk
struct je_edata_t {
	uint64_t e_bits = 0;
	uintptr_t e_addr = 0;
	uintptr_t base = 0;
	size_t e_size = 0;
	unsigned int arena_ind = 0;
	unsigned int free_cnt = 0;
	unsigned int inuse_cnt = 0;
	size_t free_bytes = 0;
	size_t inuse_bytes = 0;
	bool slab = false;
};

// slab set
struct je_edata_cmp {
	bool operator() (je_edata_t *a, je_edata_t *b) const {
		return a->e_addr < b->e_addr;
	}
};
typedef std::set<je_edata_t *, je_edata_cmp> je_edata_set;

struct je_bin_t {
	je_bin_t() {}
	~je_bin_t() {
		for (auto itr : slabs) {
			delete itr;
		}
	}

    je_bin_stats_t stats;
	je_edata_set slabs;
};

struct je_arena {
	je_arena() {}
	~je_arena() {
		delete [] bins;
	}

	je_arena_stats_t stats;
	// bins is an array of length 'nbins_total'
	je_bin_t *bins = nullptr;
};

struct je_rtree_level_t {
    unsigned int bits;
    unsigned int cumbits;
};

struct je_rtree_metadata_t {
    unsigned int szind;
    unsigned int state;
    bool is_head;
    bool slab;
};

struct je_rtree_contents_t {
	uintptr_t edata;	//edata_t*
	je_rtree_metadata_t metadata;
};

struct jemalloc {
	jemalloc() {}
	~jemalloc() {
		for (auto arena : je_arenas) {
			delete arena;
		}
	}

	// arena_s::bins array size
	unsigned int nbins_total = 0;

	// total arenas
	unsigned int narenas_total = 0;

	// parsed arenas
	std::vector<je_arena *> je_arenas;

	// fixed bin_info indexed by size class
	std::vector<je_bin_info_t> bin_infos;

	// sorted slabs for quick search
	std::vector<je_edata_t*> edata_sorted;

	// sorted blocks(regions)
	std::vector<heap_block> blocks;

	// blocks cached in tcache_t
	std::set<uintptr_t> cached_addr;

	// radix tree of the slabs
	je_rtree_level_t rtree_level[2];

	// size table
	std::vector<size_t> sz_table;
};

/******************************************************************************
 * Helper Functions
 *****************************************************************************/
#define MASK(CURRENT_FIELD_WIDTH, CURRENT_FIELD_SHIFT) ((((((uint64_t)0x1U) << (CURRENT_FIELD_WIDTH)) - 1)) << (CURRENT_FIELD_SHIFT))

#define EDATA_BITS_ARENA_WIDTH  12
#define EDATA_BITS_ARENA_SHIFT  0
#define EDATA_BITS_ARENA_MASK  MASK(EDATA_BITS_ARENA_WIDTH, EDATA_BITS_ARENA_SHIFT)

#define EDATA_BITS_SLAB_WIDTH  1
#define EDATA_BITS_SLAB_SHIFT  (EDATA_BITS_ARENA_WIDTH + EDATA_BITS_ARENA_SHIFT)
#define EDATA_BITS_SLAB_MASK  MASK(EDATA_BITS_SLAB_WIDTH, EDATA_BITS_SLAB_SHIFT)

#define EDATA_BITS_COMMITTED_WIDTH  1
#define EDATA_BITS_COMMITTED_SHIFT  (EDATA_BITS_SLAB_WIDTH + EDATA_BITS_SLAB_SHIFT)
#define EDATA_BITS_COMMITTED_MASK  MASK(EDATA_BITS_COMMITTED_WIDTH, EDATA_BITS_COMMITTED_SHIFT)

#define EDATA_BITS_PAI_WIDTH  1
#define EDATA_BITS_PAI_SHIFT  (EDATA_BITS_COMMITTED_WIDTH + EDATA_BITS_COMMITTED_SHIFT)
#define EDATA_BITS_PAI_MASK  MASK(EDATA_BITS_PAI_WIDTH, EDATA_BITS_PAI_SHIFT)

#define EDATA_BITS_ZEROED_WIDTH  1
#define EDATA_BITS_ZEROED_SHIFT  (EDATA_BITS_PAI_WIDTH + EDATA_BITS_PAI_SHIFT)
#define EDATA_BITS_ZEROED_MASK  MASK(EDATA_BITS_ZEROED_WIDTH, EDATA_BITS_ZEROED_SHIFT)

#define EDATA_BITS_GUARDED_WIDTH  1
#define EDATA_BITS_GUARDED_SHIFT  (EDATA_BITS_ZEROED_WIDTH + EDATA_BITS_ZEROED_SHIFT)
#define EDATA_BITS_GUARDED_MASK  MASK(EDATA_BITS_GUARDED_WIDTH, EDATA_BITS_GUARDED_SHIFT)

#define EDATA_BITS_STATE_WIDTH  3
#define EDATA_BITS_STATE_SHIFT  (EDATA_BITS_GUARDED_WIDTH + EDATA_BITS_GUARDED_SHIFT)
#define EDATA_BITS_STATE_MASK  MASK(EDATA_BITS_STATE_WIDTH, EDATA_BITS_STATE_SHIFT)

#define EDATA_BITS_SZIND_WIDTH  8
#define EDATA_BITS_SZIND_SHIFT  (EDATA_BITS_STATE_WIDTH + EDATA_BITS_STATE_SHIFT)
#define EDATA_BITS_SZIND_MASK  MASK(EDATA_BITS_SZIND_WIDTH, EDATA_BITS_SZIND_SHIFT)

#define SC_LG_SLAB_MAXREGS 9
#define EDATA_BITS_NFREE_WIDTH  (SC_LG_SLAB_MAXREGS + 1)
#define EDATA_BITS_NFREE_SHIFT  (EDATA_BITS_SZIND_WIDTH + EDATA_BITS_SZIND_SHIFT)
#define EDATA_BITS_NFREE_MASK  MASK(EDATA_BITS_NFREE_WIDTH, EDATA_BITS_NFREE_SHIFT)

#define EDATA_BITS_BINSHARD_WIDTH  6
#define EDATA_BITS_BINSHARD_SHIFT  (EDATA_BITS_NFREE_WIDTH + EDATA_BITS_NFREE_SHIFT)
#define EDATA_BITS_BINSHARD_MASK  MASK(EDATA_BITS_BINSHARD_WIDTH, EDATA_BITS_BINSHARD_SHIFT)

#define EDATA_BITS_IS_HEAD_WIDTH 1
#define EDATA_BITS_IS_HEAD_SHIFT  (EDATA_BITS_BINSHARD_WIDTH + EDATA_BITS_BINSHARD_SHIFT)
#define EDATA_BITS_IS_HEAD_MASK  MASK(EDATA_BITS_IS_HEAD_WIDTH, EDATA_BITS_IS_HEAD_SHIFT)


static inline bool
edata_slab_get(uint64_t e_bits) {
	return (bool)((e_bits & EDATA_BITS_SLAB_MASK) >>
	    EDATA_BITS_SLAB_SHIFT);
}

static inline unsigned
edata_nfree_get(uint64_t e_bits) {
	return (unsigned)((e_bits & EDATA_BITS_NFREE_MASK) >>
	    EDATA_BITS_NFREE_SHIFT);
}

static inline unsigned int
edata_szind_get(uint64_t e_bits) {
	unsigned int szind = (unsigned int)((e_bits & EDATA_BITS_SZIND_MASK) >>
	    EDATA_BITS_SZIND_SHIFT);
	return szind;
}

static inline je_extent_state_t
edata_state_get(uint64_t e_bits) {
	return (je_extent_state_t)((e_bits & EDATA_BITS_STATE_MASK) >>
	    EDATA_BITS_STATE_SHIFT);
}

static inline unsigned int
edata_arena_ind_get(uint64_t e_bits) {
	unsigned int arena_ind = (unsigned int)((e_bits &
	    EDATA_BITS_ARENA_MASK) >> EDATA_BITS_ARENA_SHIFT);
	return arena_ind;
}
