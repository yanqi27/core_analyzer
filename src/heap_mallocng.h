/*
 * heap_mallocng.h
 *  musl mallocng data structure
 *
 *  Created on: Feb 15, 2022
 *      Author: gamingrobot
 */
#ifndef _MM_MALLOCNG_H
#define _MM_MALLOCNG_H

#include <pthread.h>
#include "heap.h"

// musl added mallocng in v1.2.1

#define UNIT 16
//#define PAGESIZE 4096

const uint16_t class_to_size[] = {
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 12, 15,
	18, 20, 25, 31,
	36, 42, 50, 63,
	72, 84, 102, 127,
	146, 170, 204, 255,
	292, 340, 409, 511,
	584, 682, 818, 1023,
	1169, 1364, 1637, 2047,
	2340, 2730, 3276, 4095,
	4680, 5460, 6552, 8191,
};

// struct group {
// 	struct meta *meta;
// 	unsigned char active_idx:5;
// 	char pad[UNIT - sizeof(struct meta *) - 1];
// 	unsigned char storage[];
// };

// struct meta {
// 	struct meta *prev, *next;
// 	struct group *mem;
// 	volatile int avail_mask, freed_mask;
// 	uintptr_t last_idx:5;
// 	uintptr_t freeable:1;
// 	uintptr_t sizeclass:6;
// 	uintptr_t maplen:8*sizeof(uintptr_t)-12;
// };

// struct meta_area {
// 	uint64_t check;
// 	struct meta_area *next;
// 	int nslots;
// 	struct meta slots[];
// };

// struct malloc_context {
// 	uint64_t secret;
// 	// size_t pagesize;
// 	int init_done;
// 	unsigned mmap_counter;
// 	struct meta *free_meta_head;
// 	struct meta *avail_meta;
// 	size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
// 	struct meta_area *meta_area_head, *meta_area_tail;
// 	unsigned char *avail_meta_areas;
// 	struct meta *active[48];
// 	size_t usage_by_class[48];
// 	uint8_t unmap_seq[32], bounces[32];
// 	uint8_t seq;
// 	uintptr_t brk;
// };

struct ca_meta {
	value* next;
	value* prev;
	address_t address;
	uint avail_mask; //active never-allocated slots
	uint freed_mask; //freed slots and inactive never-allocated slots
	uint inuse_mask; //~(avail_mask | freed_mask)
	int freeable;
	uint size_class;
	uint maplen;
	uint last_slot_count; //last_idx
	//group
	unsigned long storage_start;
	uint active_slot_count; //active_idx
};

#endif /* _MM_MALLOCNG_H */
