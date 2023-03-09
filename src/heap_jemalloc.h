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
#include <vector>

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

struct je_edata_t {
    uint64_t e_bits = 0;
    void *e_addr = nullptr;
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
};

struct je_bin_t {
	je_bin_t() {}
	~je_bin_t() {
		for (auto itr : slabs_nonfull) {
			delete itr;
		}
		for (auto itr : slabs_full) {
			delete itr;
		}
	}
    //malloc_mutex_t lock;
    je_bin_stats_t stats;
    je_edata_t slabcur;
    //edata_heap_t slabs_nonfull;
    //edata_list_active_t slabs_full;
	std::list<je_edata_t *> slabs_nonfull;
	std::list<je_edata_t *> slabs_full;
};

struct je_arena {
	je_arena() {}
	~je_arena() {
		delete [] bins;
	}

	/*
	atomic_u_t nthreads[2];
	atomic_u_t binshard_next;
	tsdn_t *last_thd;
	*/
	je_arena_stats_t stats;
	/*
	struct {
		tcache_slow_t *qlh_first;
	} tcache_ql;
	struct {
		cache_bin_array_descriptor_t *qlh_first;
	} cache_bin_array_descriptor_ql;
	malloc_mutex_t tcache_ql_mtx;
	atomic_u_t dss_prec;
	edata_list_active_t large;
	malloc_mutex_t large_mtx;
	pa_shard_t pa_shard;
	unsigned int ind;
	base_t *base;
	nstime_t create_time;
	char name[32];
	*/
	je_bin_t *bins = nullptr;
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

	//unsigned long heap_flags;
	//size_t je_bitmap_max_levels;
	unsigned int narenas_total = 0;
	//size_t chunk_npages;
	//unsigned long long chunksize;
	// target's address of je_arenas[...]
	std::vector<je_arena *> je_arenas;

	std::vector<je_bin_info_t> bin_infos;
	//size_t n_bin_info;
	//struct je_tcache_bin_info *tcache_bin_info;
	//size_t tcache_bin_count; /* aka nhbins */
	//size_t map_bias;

	/* v3 only */
	//uint8_t *je_small_size2bin;

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
