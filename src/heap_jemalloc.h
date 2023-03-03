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

struct chunk_cache_entry {
	uintptr_t region;
	unsigned int size;
	bool stale;
};

struct je_arena_stat {
	size_t mapped;
	unsigned long long npurge;
	unsigned long long nmadvise;
	unsigned long long purged;

	size_t allocated_large;
	unsigned long long nmalloc_large;
	unsigned long long ndalloc_large;
	unsigned long long nrequests_large;
};

struct je_arena_bin_stat {
	size_t allocated;		/* JE_VER_MAJOR < 4 only */
	unsigned long long nmalloc;
	unsigned long long ndalloc;
	unsigned long long nrequests;
	unsigned long long curregs;	/* JE_VER_MAJOR >= 4 only */
	unsigned long long nfills;
	unsigned long long nflushes;
	unsigned long long nruns;
	unsigned long long reruns;
	size_t curruns;
};

struct je_arena_run {
	/* Beginning offset of run. */
	uintptr_t address;

	/* First region in run. */
	uintptr_t reg0;
	struct je_arena_bin_info *form;
	unsigned int nfree;
	size_t bits;
};

struct je_arena_bin {
	struct je_arena_bin_info *bin;
	struct je_arena_bin_stat stat;
	struct je_arena_run runcur;
};

struct je_arena {
	unsigned long long address;
	unsigned int nthreads;
	size_t nactive;
	size_t ndirty;
	size_t npurgatory;
	struct je_arena_stat stat;
	struct je_arena_bin *bins;
	size_t nbins;
	void *runs_avail;
	std::list<chunk_cache_entry> tcache;
};

struct jemalloc {
	unsigned long heap_flags;
	size_t je_bitmap_max_levels;
	unsigned int narenas_total;
	size_t chunk_npages;
	unsigned long long chunksize;
	struct je_arena *je_arenas;

	struct je_arena_bin_info *je_arena_bin_info;
	size_t n_bin_info;
	struct je_tcache_bin_info *tcache_bin_info;
	size_t tcache_bin_count; /* aka nhbins */
	size_t map_bias;

	/* v3 only */
	uint8_t *je_small_size2bin;

	/* v4 only */
	size_t map_misc_offset;
	size_t ntbins;		/* NTBINS */
	size_t tiny_max;	/* LG_TINY_MAXCLASS */
	size_t lg_quantum;	/* LG_QUANTUM */
	size_t large_maxclass;	/* arena.c:large_maxclass */
	bool config_cache_oblivious;	/* JEMALLOC_CACHE_OBLIVIOUS */

	/* v410+ */
	unsigned int runs_avail_nclasses;

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
};
