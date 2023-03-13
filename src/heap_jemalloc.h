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
	size_t base = 0;
	size_t resident = 0;
	/*
	size_t metadata_thp;
	size_t mapped;
	atomic_zu_t internal;
	size_t allocated_large;
	uint64_t nmalloc_large;
	uint64_t ndalloc_large;
	uint64_t nfills_large;
	uint64_t nflushes_large;
	uint64_t nrequests_large;
	pa_shard_stats_t pa_shard_stats;
	size_t tcache_bytes;
	size_t tcache_stashed_bytes;
	mutex_prof_data_t mutex_prof_data[12];
	arena_stats_large_t lstats[196];
	nstime_t uptime;
	*/
};

struct je_bin_stats_t {
	//uint64_t nmalloc;
	//uint64_t ndalloc;
	//uint64_t nrequests;
	//size_t curregs;
	//uint64_t nfills;
	//uint64_t nflushes;
	//uint64_t nslabs;
	//uint64_t reslabs;
	size_t curslabs;
	size_t nonfull_slabs;
};

typedef unsigned long je_bitmap_t;
struct je_slab_data_t {
	je_bitmap_t bitmap[8];
};

enum ENUM_SLAB_OWNER {
	ENUM_SLAB_UNKNOWN,
	ENUM_SLAB_CUR,
	ENUM_SLAB_FULL,
	ENUM_SLAB_NONFULL
};

#define PAGE (1<<12)
#define EDATA_SIZE_MASK	((size_t)~(PAGE-1))

// slab, aka extent, edata_t.
struct je_edata_t {
    uint64_t e_bits = 0;
    uintptr_t e_addr = 0;
	size_t e_size = 0;
	/*
    union {
        size_t e_size_esn;
        size_t e_bsize;
    };
    hpdata_t *e_ps;
    uint64_t e_sn;
    union {
        struct {...} ql_link_active;
        union {...};
    };
    union {
        struct {...} ql_link_inactive;
        slab_data_t e_slab_data;
        e_prof_info_t e_prof_info;
    };
	*/
	unsigned int free_cnt = 0;
	unsigned int inuse_cnt = 0;
	ENUM_SLAB_OWNER slab_owner = ENUM_SLAB_UNKNOWN;
};

// heap block comparator
inline bool heap_block_cmp_func(heap_block a, heap_block b) {
	return a.addr + a.size <= b.addr + b.size;
}

// slab comparator
inline bool je_edata_cmp_func (je_edata_t *a, je_edata_t *b) {
	return a->e_addr < b->e_addr;
}

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
    //edata_t slabcur;
    //edata_heap_t slabs_nonfull;
    //edata_list_active_t slabs_full;
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
	std::vector<je_edata_t*> slabs_sorted;

	// sorted blocks(regions)
	std::vector<heap_block> blocks;

	// radix tree of the slabs
	je_rtree_level_t rtree_level[2];

	/* v4 only */
	//size_t map_misc_offset;
	//size_t ntbins;		/* NTBINS */
	//size_t tiny_max;	/* LG_TINY_MAXCLASS */
	//size_t lg_quantum;	/* LG_QUANTUM */
	//size_t large_maxclass;	/* arena.c:large_maxclass */
	//bool config_cache_oblivious;	/* JEMALLOC_CACHE_OBLIVIOUS */

	/* v410+ */
	//unsigned int runs_avail_nclasses;

	/*
	struct {
		void *arenas;
		void *arena_chunk_type;
		void *arena_run_type;
		void *arena_run_type_container;
		void *arena_chunk_map_misc_type;
		size_t misc_run_offset;
		size_t sizeof_map_misc_type;
	} cache;

	struct {
		bool tcache;
	} options;
	*/
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
